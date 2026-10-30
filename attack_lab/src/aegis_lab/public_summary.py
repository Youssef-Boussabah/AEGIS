"""Strict public projections of privately verified reconstruction evidence.

No record, prompt, code, free-form diagnostic, endpoint or local path is copied.
Hashes verify local consistency, not provider authenticity or research success.
"""
from __future__ import annotations

from enum import StrEnum
import hashlib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from .canonical import canonical_json_bytes
from .experiment import verify_experiment
from .manifest import Hash, TrialId
from .provider import PROVIDER_ERROR_CATEGORIES, CompletionParser, LEGACY_COMPLETION_PARSER
from .safe_io import read_regular_file

_STATES = {
    "generated_but_behaviorally_unscored", "steps_exhausted", "deadline_exhausted",
    "context_budget_exhausted", "token_budget_exhausted", "spend_budget_exhausted",
    "invalid_output", "tool_or_output_invalid", "tool_budget_or_allowlist_refused",
    "provider_refusal", "provider_usage_invalid", "provider_usage_overrun",
    "model_identity_mismatch", "missing_or_mismatched_provider_evidence",
    "provider_contract_violation", "interrupted", "model_verification_failed",
    "operational_failure", "not_started",
} | {prefix + c for prefix in ("provider_", "model_verification_") for c in PROVIDER_ERROR_CATEGORIES}
GenerationStatus = StrEnum("GenerationStatus", {s.upper(): s for s in sorted(_STATES)})
Count = Annotated[StrictInt, Field(ge=0, le=2**53 - 1)]
ModelId = Annotated[str, Field(max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)?$")]
Limitation = Literal[
    "unsigned_local_evidence_not_provider_attestation", "candidate_text_is_not_reconstruction_success",
    "no_candidate_compilation_execution_or_behavioral_score", "no_established_protection_effect",
    "provider_identity_and_usage_are_reported_not_independently_measured",
    "billing_unknown_reservations_are_not_invoice", "offline_scripted_no_model_inference",
    "selected_function_only_decoy_inventory_not_disclosed", "variant_build_provenance_operator_declared",
    "synthetic_fixture_not_live_evidence",
]
COMMON_LIMITATIONS = (
    "unsigned_local_evidence_not_provider_attestation", "candidate_text_is_not_reconstruction_success",
    "no_candidate_compilation_execution_or_behavioral_score", "no_established_protection_effect",
)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("execution_performed", mode="before", check_fields=False)
    @classmethod
    def exact_execution_boolean(cls, value):
        if type(value) is not bool:
            raise ValueError("strict_boolean_required")
        return value


class PostHocSummary(Strict):
    analysis_kind: Literal["post_hoc_parser_compatibility_review"]
    report_sha256: Hash
    historical_experiment_sha256: Hash
    response_sha256: Hash
    historical_generation_status: Literal["invalid_output"]
    historical_completion_parser: Literal["aegis.lab.completion-parser.v1"]
    revalidation_completion_parser: Literal["aegis.lab.nebius-reasoning-text.v2"]
    post_hoc_status: Literal["candidate_text_revalidated_but_behaviorally_unscored", "rejected"]
    candidate_envelope_valid: StrictBool
    candidate_sha256: Hash | None

    @model_validator(mode="after")
    def separate_candidate_state(self):
        accepted = self.post_hoc_status == "candidate_text_revalidated_but_behaviorally_unscored"
        if accepted != (self.candidate_sha256 is not None) or (accepted and not self.candidate_envelope_valid):
            raise ValueError("post_hoc_candidate_state_mismatch")
        return self


class ReconstructionSummary(Strict):
    evidence_label: Literal["offline_scripted", "external_provider_record", "synthetic_fixture"]
    trial_id: TrialId
    pair_id: TrialId
    artifact_sha256: Hash
    candidate_sha256: Hash | None
    generation_status: GenerationStatus
    behavioral_scoring: Literal["pending_authorized_core_runtime"]
    provider: Literal["FakeOffline", "Nebius"]
    requested_model: ModelId
    reported_model: ModelId | None
    reported_model_status: Literal["matched", "missing", "mismatch", "mixed"]
    reported_identity_sha256: Hash | None
    steps: Count
    charged_tokens: Count
    known_reported_tokens: Count
    reported_tokens: Count | None
    prompt_tokens: Count | None
    completion_tokens: Count | None
    usage_status: Literal["complete", "partial", "unknown", "no_requests"]
    cost_microusd: Count | None
    cost_basis: Literal["offline_no_inference_charge", "provider_invoice_unknown"]
    reserved_spend_microusd: Count
    estimated_reported_cost_microusd: Count | None
    execution_performed: Literal[False]
    attack_effectiveness: Literal["not_established"]
    limitations: tuple[Limitation, ...] = Field(min_length=1, max_length=10)
    # Optional additions retain compatibility with existing v2 summaries.
    completion_parser: CompletionParser | None = None
    post_hoc_review: PostHocSummary | None = None

    @model_validator(mode="after")
    def truthful_claims(self):
        if not set(COMMON_LIMITATIONS) <= set(self.limitations):
            raise ValueError("required_limitations_missing")
        if (self.provider == "Nebius") != (self.cost_basis == "provider_invoice_unknown"):
            raise ValueError("provider_cost_basis_mismatch")
        if self.provider == "Nebius" and (self.cost_microusd is not None or not self.requested_model.startswith("nvidia/")):
            raise ValueError("unknown_live_bill_required")
        if self.provider == "FakeOffline" and (self.cost_microusd != 0 or self.reserved_spend_microusd != 0):
            raise ValueError("offline_cost_mismatch")
        if self.evidence_label == "offline_scripted" and self.provider != "FakeOffline":
            raise ValueError("offline_label_mismatch")
        if self.evidence_label == "external_provider_record" and self.provider != "Nebius":
            raise ValueError("external_label_mismatch")
        if self.evidence_label == "synthetic_fixture" and "synthetic_fixture_not_live_evidence" not in self.limitations:
            raise ValueError("synthetic_notice_required")
        if self.reported_model_status == "matched":
            if self.reported_model != self.requested_model:
                raise ValueError("reported_model_mismatch")
        elif self.reported_model is not None:
            raise ValueError("unmatched_model_must_be_omitted")
        totals = (self.reported_tokens, self.prompt_tokens, self.completion_tokens)
        if self.usage_status == "complete":
            if (self.steps == 0 or any(n is None for n in totals)
                    or self.prompt_tokens + self.completion_tokens != self.reported_tokens
                    or self.known_reported_tokens != self.reported_tokens):
                raise ValueError("complete_usage_inconsistent")
        elif any(n is not None for n in totals):
            raise ValueError("unknown_usage_must_be_null")
        if (self.steps == 0) != (self.usage_status == "no_requests"):
            raise ValueError("request_count_mismatch")
        if self.generation_status == "generated_but_behaviorally_unscored" and self.candidate_sha256 is None:
            raise ValueError("candidate_required")
        if self.post_hoc_review is not None and (
                self.provider != "Nebius" or self.completion_parser != LEGACY_COMPLETION_PARSER
                or self.generation_status != "invalid_output" or self.candidate_sha256 is not None):
            raise ValueError("post_hoc_review_must_preserve_historical_state")
        return self


class ReconstructionEvidence(Strict):
    schema_version: Literal["aegis.product.evidence.v2"] = Field(alias="schema")
    kind: Literal["reconstruction"]
    source_sha256: Hash
    verification: Literal["offline_hash_bindings_checked"]
    summary: ReconstructionSummary

    @model_validator(mode="after")
    def bind_post_hoc_source(self):
        if self.summary.post_hoc_review and self.summary.post_hoc_review.historical_experiment_sha256 != self.source_sha256:
            raise ValueError("post_hoc_source_mismatch")
        return self


def summarize_experiment(record):
    live = record.provider.external_disclosure
    models = {s.reported_model for s in record.steps}
    status = ("matched" if models == {record.requested_model} else "missing" if models <= {None}
              else "mismatch" if len(models) == 1 else "mixed")
    identities = {(s.reported_model, s.system_fingerprint) for s in record.steps}
    identity = None
    if len(identities) == 1 and all(next(iter(identities))):
        identity = hashlib.sha256(canonical_json_bytes(sorted(identities))).hexdigest()
    usage = [s.usage for s in record.steps if s.usage is not None]
    complete = bool(record.steps) and len(usage) == len(record.steps)
    limitations = COMMON_LIMITATIONS + ((
        "provider_identity_and_usage_are_reported_not_independently_measured",
        "billing_unknown_reservations_are_not_invoice",
    ) if live else ("offline_scripted_no_model_inference",))
    return ReconstructionSummary(
        evidence_label="external_provider_record" if live else "offline_scripted",
        trial_id=record.trial_id, pair_id=record.pair_id, artifact_sha256=record.artifact_sha256,
        candidate_sha256=record.candidate_sha256, generation_status=record.generation_status,
        behavioral_scoring=record.behavioral_scoring, provider=record.provider.provider,
        requested_model=record.requested_model, reported_model=record.requested_model if status == "matched" else None,
        reported_model_status=status, reported_identity_sha256=identity, steps=len(record.steps),
        charged_tokens=record.charged_tokens, known_reported_tokens=record.reported_tokens,
        reported_tokens=record.reported_tokens if complete else None,
        prompt_tokens=sum(u.prompt_tokens for u in usage) if complete else None,
        completion_tokens=sum(u.completion_tokens for u in usage) if complete else None,
        usage_status="complete" if complete else "partial" if usage else "unknown" if record.steps else "no_requests",
        cost_microusd=record.cost_microusd, cost_basis=record.cost_basis,
        reserved_spend_microusd=record.reserved_spend_microusd,
        estimated_reported_cost_microusd=record.estimated_reported_cost_microusd,
        execution_performed=False, attack_effectiveness="not_established", limitations=limitations,
        completion_parser=record.completion_parser)


def export_experiment(directory: Path, *, post_hoc_report: Path | None = None):
    digest = hashlib.sha256(read_regular_file(directory / "experiment.json", 2 * 1024 * 1024)).hexdigest()
    record = verify_experiment(directory, expected_sha256=digest)
    summary = summarize_experiment(record)
    if post_hoc_report is not None:
        from .completion_review import verify_review

        review, review_digest = verify_review(directory, post_hoc_report, expected_experiment_sha256=digest)
        projection = {key: getattr(review, key) for key in PostHocSummary.model_fields if key != "report_sha256"}
        summary = ReconstructionSummary.model_validate({**summary.model_dump(), "post_hoc_review":
            PostHocSummary(report_sha256=review_digest, **projection).model_dump()})
    return ReconstructionEvidence(schema="aegis.product.evidence.v2", kind="reconstruction",
        verification="offline_hash_bindings_checked", source_sha256=digest, summary=summary)


class ComparisonRow(Strict):
    variant: Literal["baseline", "shield", "mirage"]
    source_sha256: Hash | None
    generation_status: GenerationStatus
    summary: ReconstructionSummary | None


class ComparisonSummary(Strict):
    evidence_label: Literal["external_provider_record", "synthetic_fixture"]
    order: tuple[Literal["baseline", "shield", "mirage"], ...] = Field(min_length=3, max_length=3)
    order_seed: Count
    experiments: tuple[ComparisonRow, ...] = Field(min_length=3, max_length=3)
    reported_identity_comparable: StrictBool
    behavioral_scoring: Literal["pending_authorized_core_runtime"]
    execution_performed: Literal[False]
    protection_effect: Literal["not_established"]
    limitations: tuple[Limitation, ...] = Field(min_length=1, max_length=10)

    @model_validator(mode="after")
    def consistent_rows(self):
        names = {"baseline", "shield", "mirage"}
        if not set(COMMON_LIMITATIONS) <= set(self.limitations):
            raise ValueError("required_limitations_missing")
        if self.evidence_label == "synthetic_fixture" and "synthetic_fixture_not_live_evidence" not in self.limitations:
            raise ValueError("synthetic_notice_required")
        if set(self.order) != names or {r.variant for r in self.experiments} != names:
            raise ValueError("three_unique_variants_required")
        identities = set()
        for row in self.experiments:
            if (row.summary is None) != (row.source_sha256 is None):
                raise ValueError("comparison_source_required")
            if row.summary is not None:
                if row.summary.provider != "Nebius" or row.summary.evidence_label != self.evidence_label:
                    raise ValueError("comparison_evidence_label_mismatch")
                if row.generation_status != row.summary.generation_status:
                    raise ValueError("comparison_status_mismatch")
                if row.summary.post_hoc_review and row.summary.post_hoc_review.historical_experiment_sha256 != row.source_sha256:
                    raise ValueError("comparison_post_hoc_source_mismatch")
                identities.add(row.summary.reported_identity_sha256)
        comparable = all(r.summary is not None for r in self.experiments) and len(identities) == 1 and None not in identities
        if self.reported_identity_comparable != comparable:
            raise ValueError("comparison_identity_mismatch")
        return self


class ComparisonEvidence(Strict):
    schema_version: Literal["aegis.product.evidence.v2"] = Field(alias="schema")
    kind: Literal["reconstruction_comparison"]
    source_sha256: Hash
    verification: Literal["offline_hash_bindings_checked"]
    summary: ComparisonSummary


def export_comparison(directory: Path):
    from .live_trial import NAMES, verify_trial

    digest = hashlib.sha256(read_regular_file(directory / "live-trial.json", 1024 * 1024)).hexdigest()
    result, records = verify_trial(directory, expected_sha256=digest)
    rows = []
    for name in NAMES:
        outcome = result["outcomes"][name]
        status = outcome["generation_status"]
        rows.append(ComparisonRow(variant=name, source_sha256=outcome.get("record_sha256"),
            generation_status=status if status in _STATES else "operational_failure",
            summary=summarize_experiment(records[name]) if name in records else None))
    return ComparisonEvidence(schema="aegis.product.evidence.v2", kind="reconstruction_comparison",
        verification="offline_hash_bindings_checked", source_sha256=digest, summary=ComparisonSummary(
        evidence_label="external_provider_record", order=result["order"], order_seed=result["order_seed"],
        experiments=rows, reported_identity_comparable=result["reported_identity_comparable"],
        behavioral_scoring="pending_authorized_core_runtime", execution_performed=False,
        protection_effect="not_established", limitations=COMMON_LIMITATIONS + (
            "selected_function_only_decoy_inventory_not_disclosed", "variant_build_provenance_operator_declared")))
