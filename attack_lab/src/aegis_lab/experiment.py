"""REA-style controlled iterative reconstruction over already bound Ghidra evidence.

No REA branding/integration claim, shell, runtime oracle, file-reading tool or
candidate execution. Live inference remains closed by the existing Lab gate.
Only the prepared prompt's target evidence can be inspected. Provider replies,
explicit analysis text and revisions are private, content-addressed artifacts.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from .canonical import canonical_json_bytes, canonical_sha256
from .fake_provider import FakeProvider
from .manifest import Hash, TrialManifest
from .private_evidence import PrivateEvidence
from .provider import InferenceProvider, InferenceRequest, Message, ProviderError, ProviderIdentity, Usage
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
    requested_model: str
    configuration: WorkflowConfig
    max_model_tokens: Annotated[StrictInt, Field(ge=1)]
    max_wall_seconds: Annotated[StrictInt, Field(ge=1)]
    max_requests: Annotated[StrictInt, Field(ge=1, le=16)]
    steps: tuple[Step, ...] = Field(max_length=16)
    charged_tokens: Annotated[StrictInt, Field(ge=0)]
    reported_tokens: Annotated[StrictInt, Field(ge=0)]
    cost_microusd: Literal[0] = 0
    cost_basis: Literal["offline_no_inference_charge"] = "offline_no_inference_charge"
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

    @model_validator(mode="after")
    def _ledger(self):
        if self.provider.external_disclosure:
            raise ValueError("live_inference_disabled")
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


ProviderFactory = Callable[[Callable[[str, bytes], None]], InferenceProvider]


def offline_factory(sink):
    return FakeProvider(evidence_sink=sink)


def run_experiment(prepared: PreparedReconstruction, artifact: Path, output_dir: Path, *,
                   configuration: WorkflowConfig = WorkflowConfig(), provider_factory: ProviderFactory = offline_factory,
                   monotonic: Callable[[], float] = time.monotonic) -> ExperimentRecord:
    """Validate identity, run bounded offline steps, publish private evidence. Never execute code."""
    verify_prepared(prepared)
    artifact_bytes = read_regular_file(artifact, 64 * 1024 * 1024)
    if hashlib.sha256(artifact_bytes).hexdigest() != prepared.artifact_sha256:
        raise ValueError("artifact_digest_mismatch")
    captured: dict[str, bytes] = {}

    def sink(kind, data):
        if kind not in ("request", "response") or type(data) is not bytes or len(data) > 8 * 1024 * 1024:
            raise ValueError("invalid_provider_evidence")
        captured[kind] = data

    provider = provider_factory(sink)
    verify_effective_configuration(prepared, provider.identity)
    if provider.identity.external_disclosure or getattr(provider, "external_disclosure", False):
        raise AuthorizationError("live_inference_disabled")
    output_dir = Path(output_dir)
    output_dir.mkdir(mode=0o700)
    store = PrivateEvidence(output_dir / "private-evidence")
    manifest_sha = store.put(prepared.manifest.canonical_bytes())
    report_sha = store.put(prepared.report_bytes)
    store.put(artifact_bytes)
    messages = (*prepared.request.messages, Message(role="system", content=_INSTRUCTIONS))
    start = monotonic()
    deadline = start + prepared.max_wall_seconds
    steps: list[Step] = []
    charged = 0
    candidate = None
    status = "steps_exhausted"
    max_requests = min(configuration.max_steps, prepared.max_attempts)
    tool_calls = 0
    for index in range(1, max_requests + 1):
        remaining = deadline - monotonic()
        if remaining <= 0:
            status = "deadline_exhausted"
            break
        context_size = sum(len(m.content.encode("utf-8")) for m in messages)
        if context_size > configuration.max_context_bytes or len(messages) > 64:
            status = "context_budget_exhausted"
            break
        reserve = prompt_token_bound(messages) + prepared.request.max_output_tokens
        if charged + reserve > prepared.max_model_tokens:
            status = "token_budget_exhausted"
            break
        request = InferenceRequest(**{**prepared.request.model_dump(), "messages": messages})
        request_bytes = json.dumps(request.to_body(), ensure_ascii=False, allow_nan=False).encode("utf-8")
        request_sha = store.put(request_bytes)
        captured.clear()
        began = monotonic()
        response = None
        step_candidate = None
        usage = None
        step_charge = reserve
        outcome = "provider_contract_violation"
        try:
            response = _checked_response(provider.complete(request, timeout=remaining))
        except KeyboardInterrupt:
            outcome = "interrupted"
        except ProviderError as exc:
            outcome = "provider_" + exc.category
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
            outcome = "invalid_output"
            if response_sha != response.body_sha256 or captured.get("request") != request_bytes:
                outcome = "missing_or_mismatched_provider_evidence"
            elif monotonic() > deadline:
                outcome = "deadline_exhausted"
            elif response.usage_status == "invalid":
                outcome = "provider_usage_invalid"
            elif usage and (usage.prompt_tokens > prompt_token_bound(messages)
                            or usage.completion_tokens > request.max_output_tokens):
                outcome = "provider_usage_overrun"
            elif response.model != request.model:
                outcome = "model_identity_mismatch"
            elif response.refusal or response.finish_reason == "content_filter":
                outcome = "provider_refusal"
            elif (response.content_status == "present" and response.finish_reason == "stop"
                  and not response.unsupported_fields and not response.tool_calls):
                source, error = parse_candidate_envelope(response.content, language=prepared.language,
                                                         interface=prepared.expected_interface)
                if error is None:
                    step_candidate = candidate = store.put(source.encode("utf-8"))
                    outcome = "generated_but_behaviorally_unscored"
                else:
                    try:
                        action = Action.model_validate(parse_strict_json(response.content.encode("utf-8")))
                        if action.action == "inspect_target":
                            if action.action not in configuration.tools or tool_calls >= prepared.manifest.budget.max_tool_calls:
                                outcome = "tool_budget_or_allowlist_refused"
                            else:
                                tool_calls += 1
                                outcome = "inspect_target"
                                messages = (*messages, Message(role="assistant", content=response.content),
                                            Message(role="user", content=prepared.request.messages[-1].content))
                        elif action.action == "revise_candidate":
                            envelope = json.dumps({"schema": "aegis.lab.candidate.v1", "language": prepared.language,
                                                   "interface": prepared.expected_interface, "source": action.source})
                            source, error = parse_candidate_envelope(envelope, language=prepared.language,
                                                                     interface=prepared.expected_interface)
                            if error is None:
                                step_candidate = candidate = store.put(source.encode("utf-8"))
                                outcome = "candidate_revision"
                                messages = (*messages, Message(role="assistant", content=response.content),
                                            Message(role="user", content="Revise using permitted evidence, or finish."))
                        elif candidate is not None:
                            outcome = "generated_but_behaviorally_unscored"
                    except (ValueError, TypeError):
                        outcome = "tool_or_output_invalid"
        charged += step_charge
        steps.append(Step(index=index, request_sha256=request_sha, response_sha256=response_sha,
                          parsed_response_sha256=parsed_sha, reservation_tokens=reserve, charged_tokens=step_charge,
                          usage=usage, reported_model=None if response is None else response.model,
                          system_fingerprint=None if response is None else response.system_fingerprint,
                          latency_seconds=elapsed, outcome=outcome, candidate_sha256=step_candidate))
        status = outcome
        if outcome not in ("inspect_target", "candidate_revision"):
            break  # answered/uncertain POSTs are never automatically retried
        status = "steps_exhausted"
    record = ExperimentRecord(trial_id=prepared.trial_id, pair_id=prepared.pair_id, manifest_sha256=manifest_sha,
                              report_sha256=report_sha, artifact_sha256=prepared.artifact_sha256,
                              prepared_prompt_sha256=prepared.rendered_prompt_sha256, provider=provider.identity,
                              prepared_request_sha256=store.put(canonical_json_bytes(prepared.request.to_body())),
                              requested_model=prepared.request.model, configuration=configuration,
                              max_model_tokens=prepared.max_model_tokens, max_wall_seconds=prepared.max_wall_seconds,
                              max_requests=max_requests, steps=tuple(steps), charged_tokens=charged,
                              reported_tokens=sum(s.usage.total_tokens for s in steps if s.usage),
                              candidate_sha256=candidate, generation_status=status)
    publish_new_file(output_dir / "experiment.json", canonical_json_bytes(record.model_dump(mode="json")), MAX_RECORD_BYTES)
    return record


def verify_experiment(directory: Path) -> ExperimentRecord:
    """Offline audit: reload every blob, reparse responses/candidates, recheck inputs."""
    record = ExperimentRecord.model_validate(parse_strict_json(read_regular_file(directory / "experiment.json", MAX_RECORD_BYTES)))
    store = PrivateEvidence(directory / "private-evidence", create=False)
    manifest = TrialManifest.model_validate_json(store.get(record.manifest_sha256))
    artifact = store.get(record.artifact_sha256)
    original_request = parse_strict_json(store.get(record.prepared_request_sha256))
    prepared = prepare_reconstruction(manifest, store.get(record.report_sha256),
                                      max_output_tokens=original_request["max_tokens"], top_p=original_request.get("top_p"))
    if prepared.request.to_body() != original_request:
        raise ValueError("prepared_request_mismatch")
    if (prepared.rendered_prompt_sha256 != record.prepared_prompt_sha256 or manifest.trial_id != record.trial_id
            or manifest.pair_id != record.pair_id or hashlib.sha256(artifact).hexdigest() != prepared.artifact_sha256
            or prepared.request.model != record.requested_model or prepared.max_model_tokens != record.max_model_tokens
            or prepared.max_wall_seconds != record.max_wall_seconds
            or min(record.configuration.max_steps, prepared.max_attempts) != record.max_requests):
        raise ValueError("experiment_binding_mismatch")
    for step in record.steps:
        request = parse_strict_json(store.get(step.request_sha256))
        if request["model"] != record.requested_model:
            raise ValueError("request_model_mismatch")
        if step.response_sha256:
            raw = store.get(step.response_sha256)
            if step.parsed_response_sha256:
                from .provider import parse_completion

                parsed = parse_completion(raw)
                if canonical_json_bytes(parsed.model_dump(mode="json")) != store.get(step.parsed_response_sha256):
                    raise ValueError("response_provenance_mismatch")
                if (step.usage, step.reported_model, step.system_fingerprint) != (parsed.usage, parsed.model, parsed.system_fingerprint):
                    raise ValueError("step_accounting_mismatch")
                if step.candidate_sha256:
                    if step.outcome == "candidate_revision":
                        proposed = Action.model_validate(parse_strict_json(parsed.content.encode("utf-8"))).source
                    else:
                        proposed, error = parse_candidate_envelope(parsed.content, language=prepared.language,
                                                                    interface=prepared.expected_interface)
                        if error:
                            raise ValueError("candidate_envelope_mismatch")
                    if proposed is None or store.get(step.candidate_sha256) != proposed.encode("utf-8"):
                        raise ValueError("candidate_response_mismatch")
        if step.candidate_sha256:
            store.get(step.candidate_sha256).decode("utf-8")
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
                        provider_factory: ProviderFactory = offline_factory) -> ControlledPairRecord:
    """Existing pair validation controls matching objectives, access, model and budgets."""
    from .paired_trial import execution_order, prepare_pair

    pair = prepare_pair(manifests["baseline"], manifests["protected"], reports["baseline"], reports["protected"])
    if len(pair.prepared) != 2:
        raise ValueError("controlled_pair_requires_decompiled_targets")
    # Validate both on-disk identities before either provider is created.
    for variant in ("baseline", "protected"):
        if hashlib.sha256(read_regular_file(artifacts[variant], 64 * 1024 * 1024)).hexdigest() != pair.prepared[variant].artifact_sha256:
            raise ValueError("artifact_digest_mismatch")
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
                                           configuration=configuration, provider_factory=fresh)
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
