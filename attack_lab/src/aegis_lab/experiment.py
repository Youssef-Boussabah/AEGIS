"""REA-style controlled iterative reconstruction over already bound Ghidra evidence.

No REA branding/integration claim, shell, runtime oracle, file-reading tool or
candidate execution. Live inference requires its own narrow operator approval.
Only the prepared prompt's target evidence can be inspected. Provider replies,
explicit analysis text and revisions are private, content-addressed artifacts.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from .canonical import canonical_json_bytes, canonical_sha256
from .fake_provider import FakeProvider
from .disclosure import InferenceApproval
from .inference import check_inference_approval, claim_approval, worst_request_cost
from .manifest import Hash, TrialManifest
from .private_evidence import PrivateEvidence
from .provider import (
    CompletionParser, LEGACY_COMPLETION_PARSER, NEBIUS_REASONING_COMPLETION_PARSER,
    InferenceProvider, InferenceRequest, Message, ProviderError, ProviderIdentity, Usage,
)
from .reconstruction import (
    AuthorizationError, PreparedReconstruction, _checked_response, parse_candidate_envelope,
    prepare_reconstruction, prompt_token_bound, verify_effective_configuration, verify_prepared,
)
from .safe_io import parse_strict_json, publish_new_file, read_regular_file

SCHEMA = "aegis.lab.controlled-experiment.v1"
MAX_RECORD_BYTES = 2 * 1024 * 1024
TOOLS = ("inspect_target",)
_INSTRUCTIONS = (
    'This is an REA-style controlled iterative workflow, not the REA tool. '
    'Return the requested candidate envelope to finish, or JSON '
    '{"action":"inspect_target","analysis":"optional analysis"} to inspect the same target evidence, '
    'or {"action":"revise_candidate","source":"C source","analysis":"optional analysis"} '
    'to retain a candidate revision and continue. Return {"action":"finish"} to select the last revision. '
    'Tools cannot execute code or access files, source repositories, hidden tests or reference answers.'
)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkflowConfig(Strict):
    schema_version: Literal["aegis.lab.controlled-workflow.v1"] = "aegis.lab.controlled-workflow.v1"
    max_steps: Annotated[StrictInt, Field(ge=1, le=16)] = 4
    max_context_bytes: Annotated[StrictInt, Field(ge=1024, le=200_000)] = 64_000
    max_spend_microusd: Literal[0] = 0
    tools: tuple[Literal["inspect_target"], ...] = TOOLS

    @model_validator(mode="after")
    def _tools(self):
        if len(set(self.tools)) != len(self.tools):
            raise ValueError("duplicate_tool")
        return self


class Action(Strict):
    action: Literal["inspect_target", "revise_candidate", "finish"]
    source: str | None = Field(default=None, max_length=100_000)
    analysis: str | None = Field(default=None, max_length=16_000)

    @model_validator(mode="after")
    def _source(self):
        if (self.action == "revise_candidate") != (self.source is not None):
            raise ValueError("source_only_for_revision")
        return self


class Step(Strict):
    index: Annotated[StrictInt, Field(ge=1, le=16)]
    request_sha256: Hash
    response_sha256: Hash | None
    parsed_response_sha256: Hash | None
    reservation_tokens: Annotated[StrictInt, Field(ge=1)]
    charged_tokens: Annotated[StrictInt, Field(ge=0)]
    usage: Usage | None
    reported_model: str | None
    system_fingerprint: str | None
    latency_seconds: float = Field(ge=0, allow_inf_nan=False)
    outcome: str = Field(min_length=1, max_length=100)
    candidate_sha256: Hash | None
    submission: Literal["completed", "not_submitted", "rejected", "uncertain"] = "completed"


class ExperimentRecord(Strict):
    schema_version: Literal["aegis.lab.controlled-experiment.v1"] = SCHEMA
    workflow_label: Literal["REA-style controlled iterative reconstruction"] = "REA-style controlled iterative reconstruction"
    trial_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    pair_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    manifest_sha256: Hash
    report_sha256: Hash
    artifact_sha256: Hash
    prepared_prompt_sha256: Hash
    prepared_request_sha256: Hash
    provider: ProviderIdentity
    completion_parser: CompletionParser = LEGACY_COMPLETION_PARSER
    requested_model: str
    configuration: WorkflowConfig
    max_model_tokens: Annotated[StrictInt, Field(ge=1)]
    max_wall_seconds: Annotated[StrictInt, Field(ge=1)]
    max_requests: Annotated[StrictInt, Field(ge=1, le=16)]
    steps: tuple[Step, ...] = Field(max_length=16)
    charged_tokens: Annotated[StrictInt, Field(ge=0)]
    reported_tokens: Annotated[StrictInt, Field(ge=0)]
    cost_microusd: Annotated[StrictInt, Field(ge=0)] | None = 0
    cost_basis: Literal["offline_no_inference_charge", "provider_invoice_unknown"] = "offline_no_inference_charge"
    inference_approval_sha256: Hash | None = None
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
    catalogue_sha256: Hash | None = None
    account_models_sha256: Hash | None = None
    reserved_spend_microusd: Annotated[StrictInt, Field(ge=0)] = 0
    estimated_reported_cost_microusd: Annotated[StrictInt, Field(ge=0)] | None = None
    candidate_sha256: Hash | None
    generation_status: str = Field(min_length=1, max_length=100)
    behavioral_scoring: Literal["pending_authorized_core_runtime"] = "pending_authorized_core_runtime"
    attack_effectiveness: Literal["not_established"] = "not_established"
    execution_performed: Literal[False] = False
    source_access: Literal["bound_decompilation_only"] = "bound_decompilation_only"
    limitations: tuple[str, ...] = (
        "FakeOffline is a scripted test double; it performs no AI inference.",
        "Token reservations use the existing unverified UTF-8 heuristic; live inference is disabled.",
        "Artifact/report hashes establish consistency, not a signed chain of authorship.",
        "No candidate is compiled or executed; generated candidates are behaviorally unscored.",
    )

    @field_validator("execution_performed", mode="before")
    @classmethod
    def exact_execution_boolean(cls, value):
        if type(value) is not bool:
            raise ValueError("strict_boolean_required")
        return value

    @model_validator(mode="after")
    def _ledger(self):
        if self.provider.external_disclosure:
            if (self.inference_approval_sha256 is None or self.cost_microusd is not None
                    or self.cost_basis != "provider_invoice_unknown" or self.started_at is None or self.finished_at is None
                    or self.finished_at < self.started_at):
                raise ValueError("live_record_requires_approval_and_truthful_cost")
            if self.steps and (self.catalogue_sha256 is None or self.account_models_sha256 is None):
                raise ValueError("live_record_requires_model_verification")
        elif self.inference_approval_sha256 is not None or self.cost_microusd != 0 or self.reserved_spend_microusd:
            raise ValueError("offline_record_must_not_claim_live_inference")
        if len(self.steps) > self.max_requests or self.max_requests > self.configuration.max_steps:
            raise ValueError("request_budget_exceeded")
        if [s.index for s in self.steps] != list(range(1, len(self.steps) + 1)):
            raise ValueError("steps_out_of_order")
        if self.charged_tokens != sum(s.charged_tokens for s in self.steps):
            raise ValueError("token_ledger_mismatch")
        if self.reported_tokens != sum(s.usage.total_tokens for s in self.steps if s.usage):
            raise ValueError("usage_ledger_mismatch")
        # A provider overrun is retained as an error, never silently clipped.
        if self.charged_tokens > self.max_model_tokens and self.generation_status != "provider_usage_overrun":
            raise ValueError("token_budget_exceeded")
        if self.candidate_sha256 is not None and self.candidate_sha256 not in [s.candidate_sha256 for s in self.steps]:
            raise ValueError("candidate_not_proposed")
        if self.generation_status == "generated_but_behaviorally_unscored" and self.candidate_sha256 is None:
            raise ValueError("generated_requires_candidate")
        return self


def live_workflow_sha256(configuration):
    return canonical_sha256({"schema": "aegis.lab.live-workflow.v1", "instructions": _INSTRUCTIONS,
                             "configuration": configuration.model_dump(mode="json"),
                             "action_schema": Action.model_json_schema(), "store": False,
                             "max_completion_tokens": "same_as_max_output_tokens_including_reasoning",
                             "service_tier": "default", "instructions_placement": "append_to_initial_system_message",
                             "token_reservation": "published_full_context_plus_output_per_request"})


def initial_messages(prepared):
    return (Message(role="system", content=prepared.request.messages[0].content + "\n\n" + _INSTRUCTIONS),
            *prepared.request.messages[1:])


def evaluate_response(prepared, configuration, response, *, input_bound, candidate_present,
                      tool_calls, evidence_matches=True, late=False):
    """Pure classification shared by generation and offline evidence verification.

    A syntactically valid candidate is text only. This function never compiles it.
    """
    if not evidence_matches:
        return "missing_or_mismatched_provider_evidence", None
    if late:
        return "deadline_exhausted", None
    if response.usage_status == "invalid":
        return "provider_usage_invalid", None
    if response.usage and (response.usage.prompt_tokens > input_bound
                           or response.usage.completion_tokens > prepared.request.max_output_tokens):
        return "provider_usage_overrun", None
    if response.model != prepared.request.model:
        return "model_identity_mismatch", None
    if response.refusal or response.finish_reason == "content_filter":
        return "provider_refusal", None
    if not (response.content_status == "present" and response.finish_reason == "stop"
            and not response.unsupported_fields and not response.tool_calls):
        return "invalid_output", None
    source, error = parse_candidate_envelope(response.content, language=prepared.language,
                                             interface=prepared.expected_interface)
    if error is None:
        return "generated_but_behaviorally_unscored", source
    try:
        action = Action.model_validate(parse_strict_json(response.content.encode("utf-8")))
    except (ValueError, TypeError):
        return "tool_or_output_invalid", None
    if action.action == "inspect_target":
        if action.action not in configuration.tools or tool_calls >= prepared.manifest.budget.max_tool_calls:
            return "tool_budget_or_allowlist_refused", None
        return "inspect_target", None
    if action.action == "revise_candidate":
        envelope = json.dumps({"schema": "aegis.lab.candidate.v1", "language": prepared.language,
                               "interface": prepared.expected_interface, "source": action.source})
        source, error = parse_candidate_envelope(envelope, language=prepared.language,
                                                 interface=prepared.expected_interface)
        return ("candidate_revision", source) if error is None else ("invalid_output", None)
    return ("generated_but_behaviorally_unscored" if candidate_present else "invalid_output"), None


ProviderFactory = Callable[[Callable[[str, bytes], None]], InferenceProvider]


def offline_factory(sink):
    return FakeProvider(evidence_sink=sink)


def run_experiment(prepared: PreparedReconstruction, artifact: Path, output_dir: Path, *,
                   configuration: WorkflowConfig = WorkflowConfig(), provider_factory: ProviderFactory = offline_factory,
                   monotonic: Callable[[], float] = time.monotonic,
                   inference_approval: InferenceApproval | None = None, allow_live: bool = False,
                   approval_state_dir: Path | None = None) -> ExperimentRecord:
    """Run offline or explicitly approved bounded inference, archive all outcomes. No code execution."""
    verify_prepared(prepared)
    artifact_bytes = read_regular_file(artifact, 64 * 1024 * 1024)
    if hashlib.sha256(artifact_bytes).hexdigest() != prepared.artifact_sha256:
        raise ValueError("artifact_digest_mismatch")
    if inference_approval is not None:
        inference_approval = check_inference_approval(prepared, configuration, inference_approval, allow_live=allow_live)
        if approval_state_dir is None:
            raise ValueError("approval_state_directory_required")
    captured: dict[str, bytes] = {}

    def sink(kind, data):
        if kind not in ("request", "response", "account_models", "public_catalogue") or type(data) is not bytes or len(data) > 8 * 1024 * 1024:
            raise ValueError("invalid_provider_evidence")
        captured[kind] = data

    provider = provider_factory(sink)
    verify_effective_configuration(prepared, provider.identity)
    completion_parser = getattr(provider, "completion_parser", LEGACY_COMPLETION_PARSER)
    if completion_parser not in (LEGACY_COMPLETION_PARSER, NEBIUS_REASONING_COMPLETION_PARSER):
        raise ValueError("unknown_completion_parser")
    live = provider.identity.external_disclosure
    if getattr(provider, "external_disclosure", False) and not live:
        raise AuthorizationError("inference_scope_mismatch")
    if live:
        inference_approval = check_inference_approval(prepared, configuration, inference_approval, allow_live=allow_live)
        if provider.identity.endpoint != inference_approval.disclosure.endpoint:
            raise AuthorizationError("endpoint_not_approved")
        if not getattr(provider, "hard_deadline", False) or not callable(getattr(provider, "verify_model", None)):
            raise AuthorizationError("bounded_transport_required")
        if approval_state_dir is None:
            raise ValueError("approval_state_directory_required")
    elif inference_approval is not None:
        raise AuthorizationError("inference_scope_mismatch")
    output_dir = Path(output_dir)
    output_dir.mkdir(mode=0o700)
    store = PrivateEvidence(output_dir / "private-evidence")
    manifest_sha = store.put(prepared.manifest.canonical_bytes())
    report_sha = store.put(prepared.report_bytes)
    store.put(artifact_bytes)
    approval_sha = None
    catalogue_sha = account_sha = None
    if live:
        approval_sha = store.put(canonical_json_bytes(inference_approval.model_dump(mode="json")))
        claim_approval(inference_approval, approval_state_dir)
    messages = initial_messages(prepared)
    started_at = datetime.now(UTC)
    start = monotonic()
    deadline = start + prepared.max_wall_seconds
    steps: list[Step] = []
    charged = 0
    candidate = None
    status = "steps_exhausted"
    max_requests = min(configuration.max_steps, prepared.max_attempts)
    tool_calls = 0
    reserved_spend = 0
    if live:
        try:
            provider.verify_model(prepared.request.model, context_tokens=inference_approval.context_tokens,
                                  input_price=inference_approval.input_microusd_per_million,
                                  output_price=inference_approval.output_microusd_per_million,
                                  timeout=min(inference_approval.request_timeout_seconds,
                                              max(0.001, deadline - monotonic()),
                                              max(0.001, (inference_approval.request_deadline - datetime.now(UTC)).total_seconds())))
            catalogue_sha = store.put(captured["public_catalogue"])
            account_sha = store.put(captured["account_models"])
        except KeyboardInterrupt:
            status = "interrupted"
        except ProviderError as exc:
            status = "model_verification_" + exc.category
        except Exception:
            status = "model_verification_failed"
    for index in range(1, max_requests + 1):
        if live and (catalogue_sha is None or account_sha is None):
            break
        remaining = deadline - monotonic()
        if live:
            remaining = min(remaining, inference_approval.request_timeout_seconds,
                            (inference_approval.request_deadline - datetime.now(UTC)).total_seconds(),
                            (inference_approval.disclosure.expires_at - datetime.now(UTC)).total_seconds())
        if remaining <= 0:
            status = "deadline_exhausted"
            break
        context_size = sum(len(m.content.encode("utf-8")) for m in messages)
        if context_size > configuration.max_context_bytes or len(messages) > 64:
            status = "context_budget_exhausted"
            break
        input_bound = inference_approval.context_tokens if live else prompt_token_bound(messages)
        reserve = input_bound + prepared.request.max_output_tokens
        if charged + reserve > prepared.max_model_tokens:
            status = "token_budget_exhausted"
            break
        if live:
            next_cost = worst_request_cost(inference_approval, prepared.request.max_output_tokens)
            if reserved_spend + next_cost > inference_approval.max_spend_microusd:
                status = "spend_budget_exhausted"
                break
            reserved_spend += next_cost
        request = InferenceRequest(**{**prepared.request.model_dump(), "messages": messages,
                                      "store": False if live else prepared.request.store})
        request_bytes = json.dumps(request.to_body(), ensure_ascii=False, allow_nan=False).encode("utf-8")
        request_sha = store.put(request_bytes)
        captured.clear()
        began = monotonic()
        response = None
        step_candidate = None
        usage = None
        step_charge = reserve
        outcome = "provider_contract_violation"
        submission = "uncertain"
        try:
            response = _checked_response(provider.complete(request, timeout=remaining))
            submission = "completed"
        except KeyboardInterrupt:
            outcome = "interrupted"
        except ProviderError as exc:
            outcome = "provider_" + exc.category
            submission = exc.submission
            if exc.submission == "not_submitted":
                step_charge = 0
        except Exception:
            pass  # never retain arbitrary exception text or assume no billing
        elapsed = max(0.0, monotonic() - began)
        raw_response = captured.get("response")
        response_sha = None if raw_response is None else store.put(raw_response)
        parsed_sha = None if response is None else store.put(canonical_json_bytes(response.model_dump(mode="json")))
        if response is not None:
            usage = response.usage
            if usage:
                step_charge = max(reserve, usage.total_tokens)
            outcome, source = evaluate_response(prepared, configuration, response,
                input_bound=input_bound, candidate_present=candidate is not None, tool_calls=tool_calls,
                evidence_matches=response_sha == response.body_sha256 and captured.get("request") == request_bytes,
                late=monotonic() > deadline)
            if source is not None:
                step_candidate = candidate = store.put(source.encode("utf-8"))
            if outcome == "inspect_target":
                tool_calls += 1
                messages = (*messages, Message(role="assistant", content=response.content),
                            Message(role="user", content=prepared.request.messages[-1].content))
            elif outcome == "candidate_revision":
                messages = (*messages, Message(role="assistant", content=response.content),
                            Message(role="user", content="Revise using permitted evidence, or finish."))
        charged += step_charge
        steps.append(Step(index=index, request_sha256=request_sha, response_sha256=response_sha,
                          parsed_response_sha256=parsed_sha, reservation_tokens=reserve, charged_tokens=step_charge,
                          usage=usage, reported_model=None if response is None else response.model,
                          system_fingerprint=None if response is None else response.system_fingerprint,
                          latency_seconds=elapsed, outcome=outcome, candidate_sha256=step_candidate,
                          submission=submission))
        status = outcome
        if outcome not in ("inspect_target", "candidate_revision"):
            break  # answered/uncertain POSTs are never automatically retried
        status = "steps_exhausted"
    record = ExperimentRecord(trial_id=prepared.trial_id, pair_id=prepared.pair_id, manifest_sha256=manifest_sha,
                              report_sha256=report_sha, artifact_sha256=prepared.artifact_sha256,
                              prepared_prompt_sha256=prepared.rendered_prompt_sha256, provider=provider.identity,
                              completion_parser=completion_parser,
                              prepared_request_sha256=store.put(canonical_json_bytes(prepared.request.to_body())),
                              requested_model=prepared.request.model, configuration=configuration,
                              max_model_tokens=prepared.max_model_tokens, max_wall_seconds=prepared.max_wall_seconds,
                              max_requests=max_requests, steps=tuple(steps), charged_tokens=charged,
                              reported_tokens=sum(s.usage.total_tokens for s in steps if s.usage),
                              candidate_sha256=candidate, generation_status=status,
                              **({"cost_microusd": None, "cost_basis": "provider_invoice_unknown",
                                  "inference_approval_sha256": approval_sha, "catalogue_sha256": catalogue_sha,
                                  "started_at": started_at, "finished_at": datetime.now(UTC),
                                  "account_models_sha256": account_sha, "reserved_spend_microusd": reserved_spend,
                                  "estimated_reported_cost_microusd": (sum(
                                      (s.usage.prompt_tokens * inference_approval.input_microusd_per_million
                                       + s.usage.completion_tokens * inference_approval.output_microusd_per_million
                                       + 999_999) // 1_000_000 for s in steps) if all(s.usage for s in steps) else None),
                                  "limitations": ("Live inference only; no candidate was compiled or executed.",
                                      "Model identity and token usage are provider reports, not weight verification.",
                                      "Full published context is reserved per request; invoice and uncertain usage remain unknown.",
                                      "store=false requests no storage for model distillation; other retention follows the reviewed policy.",
                                      "Private archive deletion is an operator duty at the approved retention deadline.")}
                                 if live else {}))
    if live:
        for kind, data in captured.items():
            store.put(data)
    publish_new_file(output_dir / "experiment.json", canonical_json_bytes(record.model_dump(mode="json")), MAX_RECORD_BYTES)
    return record


def verify_experiment(directory: Path, *, expected_sha256: str | None = None) -> ExperimentRecord:
    """Offline audit using the recorded parser (v1 for historical unversioned records)."""
    data = read_regular_file(directory / "experiment.json", MAX_RECORD_BYTES)
    if expected_sha256 is not None and hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("experiment_record_digest_mismatch")
    record = ExperimentRecord.model_validate(parse_strict_json(data))
    store = PrivateEvidence(directory / "private-evidence", create=False)
    manifest = TrialManifest.model_validate_json(store.get(record.manifest_sha256))
    artifact = store.get(record.artifact_sha256)
    original_request = parse_strict_json(store.get(record.prepared_request_sha256))
    prepared = prepare_reconstruction(manifest, store.get(record.report_sha256),
                                      max_output_tokens=original_request["max_tokens"], top_p=original_request.get("top_p"),
                                      enable_thinking=original_request.get("chat_template_kwargs", {}).get("enable_thinking"))
    if prepared.request.to_body() != original_request:
        raise ValueError("prepared_request_mismatch")
    if (prepared.rendered_prompt_sha256 != record.prepared_prompt_sha256 or manifest.trial_id != record.trial_id
            or manifest.pair_id != record.pair_id or hashlib.sha256(artifact).hexdigest() != prepared.artifact_sha256
            or prepared.request.model != record.requested_model or prepared.max_model_tokens != record.max_model_tokens
            or prepared.max_wall_seconds != record.max_wall_seconds
            or min(record.configuration.max_steps, prepared.max_attempts) != record.max_requests):
        raise ValueError("experiment_binding_mismatch")
    verify_effective_configuration(prepared, record.provider)
    live = record.provider.external_disclosure
    if live:
        from .bounded_provider import verify_model_evidence

        approval = InferenceApproval.model_validate(parse_strict_json(store.get(record.inference_approval_sha256)))
        check_inference_approval(prepared, record.configuration, approval, allow_live=True,
                                 now=approval.disclosure.valid_from)
        if record.provider.endpoint != approval.disclosure.endpoint or record.provider.provider != approval.disclosure.provider:
            raise ValueError("approval_provider_mismatch")
        if record.steps and not (approval.disclosure.valid_from <= record.started_at < approval.request_deadline):
            raise ValueError("experiment_outside_approval_window")
        if record.catalogue_sha256 is not None or record.account_models_sha256 is not None:
            verify_model_evidence(store.get(record.account_models_sha256), store.get(record.catalogue_sha256),
                                  record.requested_model, context_tokens=approval.context_tokens,
                                  input_price=approval.input_microusd_per_million,
                                  output_price=approval.output_microusd_per_million)
        expected_spend = worst_request_cost(approval, prepared.request.max_output_tokens) * len(record.steps)
        if expected_spend != record.reserved_spend_microusd or expected_spend > approval.max_spend_microusd:
            raise ValueError("spend_ledger_mismatch")
        estimated = (sum((s.usage.prompt_tokens * approval.input_microusd_per_million
                         + s.usage.completion_tokens * approval.output_microusd_per_million
                         + 999_999) // 1_000_000 for s in record.steps)
                     if all(s.usage for s in record.steps) else None)
        if record.estimated_reported_cost_microusd != estimated:
            raise ValueError("estimated_cost_mismatch")
    messages = initial_messages(prepared)
    candidate = None
    tool_calls = 0
    continuation = {"inspect_target", "candidate_revision"}
    budget_stops = {"steps_exhausted", "deadline_exhausted", "context_budget_exhausted",
                   "token_budget_exhausted", "spend_budget_exhausted"}
    from .provider import PROVIDER_ERROR_CATEGORIES

    error_states = {"provider_" + c for c in PROVIDER_ERROR_CATEGORIES} | {"interrupted", "provider_contract_violation"}
    for step in record.steps:
        request = parse_strict_json(store.get(step.request_sha256))
        expected_request = InferenceRequest(**{**prepared.request.model_dump(), "messages": messages,
                                              "store": False if live else prepared.request.store})
        if request != expected_request.to_body():
            raise ValueError("experiment_conversation_mismatch")
        input_bound = approval.context_tokens if live else prompt_token_bound(messages)
        reserve = input_bound + prepared.request.max_output_tokens
        expected_charge = (0 if step.submission == "not_submitted" else
                           max(reserve, step.usage.total_tokens if step.usage else 0))
        if step.reservation_tokens != reserve or step.charged_tokens != expected_charge:
            raise ValueError("step_reservation_mismatch")
        if step.parsed_response_sha256 is not None and step.response_sha256 is None:
            raise ValueError("parsed_response_without_wire_evidence")
        if step.response_sha256:
            raw = store.get(step.response_sha256)
        if step.parsed_response_sha256:
            from .provider import parse_completion

            parsed = parse_completion(raw, parser=record.completion_parser)
            if canonical_json_bytes(parsed.model_dump(mode="json")) != store.get(step.parsed_response_sha256):
                raise ValueError("response_provenance_mismatch")
            if (step.usage, step.reported_model, step.system_fingerprint) != (parsed.usage, parsed.model, parsed.system_fingerprint):
                raise ValueError("step_accounting_mismatch")
            if step.submission != "completed":
                raise ValueError("response_submission_mismatch")
            outcome, proposed = evaluate_response(prepared, record.configuration, parsed,
                input_bound=input_bound, candidate_present=candidate is not None, tool_calls=tool_calls,
                late=step.outcome == "deadline_exhausted")
            if outcome != step.outcome:
                raise ValueError("step_outcome_mismatch")
            if proposed is not None:
                proposed_sha = hashlib.sha256(proposed.encode("utf-8")).hexdigest()
                if step.candidate_sha256 != proposed_sha or store.get(proposed_sha) != proposed.encode("utf-8"):
                    raise ValueError("candidate_response_mismatch")
                candidate = proposed_sha
            elif step.candidate_sha256 is not None:
                raise ValueError("unexpected_candidate")
            if outcome == "inspect_target":
                tool_calls += 1
                messages = (*messages, Message(role="assistant", content=parsed.content),
                            Message(role="user", content=prepared.request.messages[-1].content))
            elif outcome == "candidate_revision":
                messages = (*messages, Message(role="assistant", content=parsed.content),
                            Message(role="user", content="Revise using permitted evidence, or finish."))
        elif (step.outcome not in error_states or step.usage is not None
              or step.reported_model is not None or step.system_fingerprint is not None or step.candidate_sha256 is not None):
            raise ValueError("unsubstantiated_step_result")
        if step.index < len(record.steps) and step.outcome not in continuation:
            raise ValueError("request_after_terminal_outcome")
    if record.candidate_sha256 != candidate:
        raise ValueError("selected_candidate_mismatch")
    if record.steps:
        last = record.steps[-1].outcome
        allowed = budget_stops if last in continuation else {last}
    else:
        allowed = budget_stops | {"interrupted", "model_verification_failed"} | {
            "model_verification_" + c for c in PROVIDER_ERROR_CATEGORIES}
    if record.generation_status not in allowed:
        raise ValueError("generation_status_mismatch")

    return record


class ControlledPairRecord(Strict):
    schema_version: Literal["aegis.lab.controlled-pair.v1"] = "aegis.lab.controlled-pair.v1"
    pair_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    order: tuple[Literal["baseline", "protected"], Literal["baseline", "protected"]]
    order_seed: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
    configuration_sha256: Hash
    baseline_record_sha256: Hash
    protected_record_sha256: Hash
    generation_outcomes: tuple[str, str]
    reported_model_identity_comparable: bool
    behavioral_scoring: Literal["pending_authorized_core_runtime"] = "pending_authorized_core_runtime"
    protection_effect: Literal["not_established"] = "not_established"


def run_controlled_pair(manifests: dict[str, TrialManifest], reports: dict[str, bytes], artifacts: dict[str, Path],
                        output_dir: Path, *, configuration: WorkflowConfig = WorkflowConfig(), order_seed: int = 0,
                        provider_factory: ProviderFactory = offline_factory,
                        inference_approvals: dict[str, InferenceApproval] | None = None,
                        allow_live: bool = False, approval_state_dir: Path | None = None) -> ControlledPairRecord:
    """Existing pair validation controls matching objectives, access, model and budgets."""
    from .paired_trial import execution_order, prepare_pair

    pair = prepare_pair(manifests["baseline"], manifests["protected"], reports["baseline"], reports["protected"])
    if len(pair.prepared) != 2:
        raise ValueError("controlled_pair_requires_decompiled_targets")
    # Validate both on-disk identities before either provider is created.
    for variant in ("baseline", "protected"):
        if hashlib.sha256(read_regular_file(artifacts[variant], 64 * 1024 * 1024)).hexdigest() != pair.prepared[variant].artifact_sha256:
            raise ValueError("artifact_digest_mismatch")
    if inference_approvals is not None:
        for variant in ("baseline", "protected"):
            check_inference_approval(pair.prepared[variant], configuration, inference_approvals.get(variant), allow_live=allow_live)
        limits = [(a.max_requests, a.max_total_tokens, a.max_spend_microusd, a.context_tokens,
                   a.input_microusd_per_million, a.output_microusd_per_million, a.request_timeout_seconds)
                  for a in (inference_approvals[v] for v in ("baseline", "protected"))]
        if limits[0] != limits[1]:
            raise AuthorizationError("inference_budget_not_approved")
    order = execution_order(order_seed, pair_id=pair.pair.baseline.pair_id,
                             baseline_trial_id=pair.pair.baseline.trial_id, protected_trial_id=pair.pair.protected.trial_id)
    output_dir.mkdir(mode=0o700)
    records = {}
    made = []

    def fresh(sink):
        provider = provider_factory(sink)
        if any(provider is previous for previous in made):
            raise ValueError("provider_session_reused")
        if made and provider.identity != made[0].identity:
            raise ValueError("paired_provider_identity_mismatch")
        made.append(provider)
        return provider

    for variant in order:
        records[variant] = run_experiment(pair.prepared[variant], artifacts[variant], output_dir / variant,
                                           configuration=configuration, provider_factory=fresh,
                                           inference_approval=None if inference_approvals is None else inference_approvals[variant],
                                           allow_live=allow_live, approval_state_dir=approval_state_dir)
    def identities(record):
        return {(s.reported_model, s.system_fingerprint) for s in record.steps if s.parsed_response_sha256}

    identity_sets = [identities(records[v]) for v in ("baseline", "protected")]
    comparable = (identity_sets[0] == identity_sets[1] and len(identity_sets[0]) == 1
                  and all(model and fingerprint for model, fingerprint in identity_sets[0]))
    result = ControlledPairRecord(pair_id=pair.pair.baseline.pair_id, order=order, order_seed=order_seed,
        configuration_sha256=canonical_sha256(configuration.model_dump(mode="json")),
        baseline_record_sha256=canonical_sha256(records["baseline"].model_dump(mode="json")),
        protected_record_sha256=canonical_sha256(records["protected"].model_dump(mode="json")),
        generation_outcomes=tuple(records[v].generation_status for v in ("baseline", "protected")),
        reported_model_identity_comparable=comparable)
    publish_new_file(output_dir / "controlled-pair.json", canonical_json_bytes(result.model_dump(mode="json")), MAX_RECORD_BYTES)
    return result


def main(argv=None):
    import argparse

    from .manifest import load_manifest

    parser = argparse.ArgumentParser(description="Offline controlled iterative reconstruction; candidates never execute")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--reply", required=True, type=Path, help="scripted fake response; no live inference")
    parser.add_argument("--steps", type=int, default=4)
    args = parser.parse_args(argv)
    try:
        prepared = prepare_reconstruction(load_manifest(args.manifest), read_regular_file(args.report, 8 * 1024 * 1024))
        reply = read_regular_file(args.reply, 128 * 1024).decode("utf-8")
        result = run_experiment(prepared, args.artifact, args.output_dir,
                                configuration=WorkflowConfig(max_steps=args.steps),
                                provider_factory=lambda sink: FakeProvider(content=reply, evidence_sink=sink))
        print(result.generation_status)
        return 0 if result.generation_status == "generated_but_behaviorally_unscored" else 1
    except Exception:
        print("experiment_failed: invalid_input_or_publication")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
