"""Controlled paired reconstruction trials (``aegis.lab.paired-trial.v2``), offline only.

Phase 3B. This module composes the existing Lab stages into one paired
experiment; it does not reimplement any of them:

1. Phase 1 ``validate_pair``: the two manifests must be a comparable
   baseline/protected pair, passed in their declared roles.
2. Phase 2 ``bind_ghidra_evidence`` / ``compare_pair_evidence``: each Ghidra
   report must belong to its own manifest's artifact, tool and configuration,
   and both reports must have observed the same Ghidra runtime.
3. Phase 3A ``prepare_reconstruction``: both requests are prepared, with the same
   settings, *before* either trial runs. The runner then checks that everything
   except the artifact-derived evidence is identical across the two requests.
4. Phase 3A ``run_reconstruction``: each trial runs separately, in an order
   derived from a recorded seed, against its own fresh offline provider instance.

Target-analysis observations. A valid, bound *wildcard* Ghidra report may show
that the trial's target function failed to decompile while other functions
succeeded. That trial is kept as ``analysis_failure_recorded``: no model request
is prepared, no provider is created or called, and zero attempts and tokens are
recorded. Its declared settings are still verified. The other trial runs
normally. Such a failure is never interpreted (no protection, resistance, failed
reconstruction or test result). Exact-selector and whole-analysis failures have
no bound failure evidence (Phase 2 rejects those reports) and stay invalid input.

Each trial's ``aegis.lab.reconstruction.v2`` record is published as soon as the
trial ends, so a later failure cannot lose it. The paired record
(``paired-trial.json``) is published last and references both by digest.

What this does **not** do:

- It runs only the offline ``FakeOffline`` provider. Live inference stays
  disabled; Core's two attack-lab gates are not connected to this runner. The
  manifests' authorization reference is audit metadata, never permission.
- It does not compile, execute or score candidates. ``completed`` means a
  candidate envelope was received; it does not mean the software was
  reconstructed. No ``resisted``/``bypassed`` outcome is derived.
- Comparable declarations and identical effective settings do not prove that an
  experiment was fair.
- Records are unsigned; they are not authenticated provenance.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationError,
    model_validator,
)

from .canonical import canonical_json_bytes
from .diagnostics import model_field_names, validation_issues
from .disclosure import ALLOWED_LANGUAGES, AuthorizationError, DisclosurePolicyError, scan_findings
from .evidence import (
    MAX_GHIDRA_REPORT_BYTES,
    EvidenceBindingError,
    GhidraEvidence,
    bind_ghidra_evidence,
    compare_pair_evidence,
    parse_ghidra_report,
)
from .fake_provider import FakeProvider
from .ghidra import (
    MAX_DECOMPILER_MESSAGE_CHARS,
    OBSERVED_RUNTIME_FIELDS,
    SUCCESS_STATUSES,
    AnalysisReport,
    DecompileStatus,
    ReportInvariantError,
)
from .manifest import (
    MANIFEST_ERROR_TYPES,
    ManifestPairError,
    PairValidation,
    TrialManifest,
    TrialVariant,
    load_manifest,
    validate_pair,
)
from .provider import OFFLINE_ENDPOINT, OFFLINE_PROVIDER_NAME, InferenceProvider, ProviderIdentity
from .reconstruction import (
    EXIT_COMPLETED,
    EXIT_INTERNAL,
    EXIT_INTERRUPTED,
    EXIT_INVALID,
    EXIT_NOT_COMPLETED,
    EXIT_PUBLICATION_FAILED,
    HARD_MAX_OUTPUT_TOKENS,
    MAX_RECORD_BYTES,
    BudgetError,
    ConfigurationError,
    PreparedReconstruction,
    ReconstructionInputError,
    ReconstructionInterrupted,
    ReconstructionRecord,
    Status,
    StopReason,
    _privileged_values,
    _verify_declared_configuration,
    default_max_output_tokens,
    parse_reconstruction_record,
    prepare_reconstruction,
    run_reconstruction,
    verify_effective_configuration,
    verify_prepared,
)
from .safe_io import (
    PUBLISH_ERROR_CATEGORIES,
    LoadError,
    PublishError,
    parse_strict_json,
    publish_new_file,
    read_regular_file,
)

# v2 adds per-trial target-analysis observations and the analysis_failure_recorded state.
# A v1 record cannot express them and is rejected as retired rather than reinterpreted.
PAIRED_TRIAL_SCHEMA = "aegis.lab.paired-trial.v2"
RETIRED_PAIRED_TRIAL_SCHEMAS = ("aegis.lab.paired-trial.v1",)
ORDER_DERIVATION = "aegis.lab.trial-order.v1"
PAIRED_RECORD_FILE = "paired-trial.json"
RECONSTRUCTION_FILES = {
    "baseline": "baseline-reconstruction.json",
    "protected": "protected-reconstruction.json",
}
MAX_PAIRED_RECORD_BYTES = 1024 * 1024
MAX_ORDER_SEED = 2**63 - 1
EXECUTION_MODES = ("offline",)
VARIANTS = ("baseline", "protected")

# Prepared fields that must be identical for both trials. Everything else in a
# PreparedReconstruction is identity (trial id, variant, digests) or derives from
# the artifact-specific evidence (prompt text, prompt bound, findings).
SHARED_PREPARED_FIELDS = (
    "pair_id",
    "target_function",
    "function_label",
    "expected_interface",
    "platform",
    "artifact_format",
    "language",
    "blinded",
    "evidence_schema",
    "declared_provider",
    "declared_model",
    "declared_prompt_sha256",
    "declared_sampling_sha256",
    "declared_workflow_sha256",
    "max_attempts",
    "max_wall_seconds",
    "max_model_tokens",
)
SHARED_REQUEST_FIELDS = ("model", "max_output_tokens", "temperature", "top_p", "seed", "stop", "n")

Variant = Literal["baseline", "protected"]
TrialState = Literal["record_produced", "interrupted", "execution_refused", "internal_error", "not_started",
                     "analysis_failure_recorded"]
# What happened to the trial, derived from its state and record (never stored independently).
TrialOutcome = Literal[
    "candidate_received",                     # a candidate envelope arrived; not compiled, run or scored
    "reconstruction_not_completed",           # attempted; the reconstruction record has another status
    "reconstruction_interrupted",
    "execution_error",                        # refused or crashed before producing a record
    "not_attempted_target_analysis_failed",   # valid evidence; the target did not decompile
    "not_attempted_run_stopped",
]
RunStatus = Literal["finished", "interrupted", "execution_refused", "internal_error", "publication_failed"]
PairStatus = Literal["candidates_received_for_both_trials", "target_analysis_failure_observed", "trial_failures",
                     "incomplete"]
PublicationError = Literal[tuple(sorted(PUBLISH_ERROR_CATEGORIES | {"interrupted"}))]  # type: ignore[valid-type]

_RUN_STATUS_FOR_STATE = {
    "interrupted": "interrupted",
    "execution_refused": "execution_refused",
    "internal_error": "internal_error",
}


def _derive_run_status(ordered: list[Any]) -> str:
    """Run status from trials in execution order (shared by the runner and the record validator).

    The first trial that stopped the run decides it: an interruption, a refused or
    crashed execution, or a record that could not be published. Every later trial
    must not have started, and no trial may be skipped before the run stopped. A
    trial whose target analysis failed is recorded at preparation and never runs,
    so it neither stops the run nor depends on whether the run stopped.
    """
    run_status, stopped = "finished", False
    for trial in ordered:
        if trial.state == "analysis_failure_recorded":
            continue  # decided during preparation; it never runs, so a stop cannot affect it
        if stopped:
            if trial.state != "not_started":
                raise ValueError("a trial after the run stopped must not have started")
            continue
        if trial.state == "not_started":
            raise ValueError("a trial was skipped although the run had not stopped")
        if trial.state != "record_produced":
            run_status, stopped = _RUN_STATUS_FOR_STATE[trial.state], True
        elif trial.reconstruction is not None and trial.reconstruction.publication == "failed":
            run_status, stopped = "publication_failed", True
    return run_status


# --- Errors ---------------------------------------------------------------------------------------

class PairedTrialInputError(ValueError):
    """The pair cannot be run. Raised before any inference and before any output exists.

    ``issues`` are ``<role>: <field path>: <code>`` lines built from schema field
    names and fixed codes only; they never contain input values or paths.
    """

    def __init__(self, issues: list[str] | tuple[str, ...]) -> None:
        if not issues:
            raise AssertionError("an input error needs at least one issue")
        self.issues = tuple(issues)
        super().__init__("paired trial input rejected: " + "; ".join(self.issues))


class PairedTrialPublicationError(OSError):
    """The output directory could not be created. Raised before any inference."""

    def __init__(self, category: str) -> None:
        if category not in PUBLISH_ERROR_CATEGORIES:
            raise AssertionError(f"unregistered publish error category {category!r}")
        self.category = category
        super().__init__(category)


class ExperimentVerificationError(ValueError):
    """A published experiment does not revalidate. ``issues`` follow the input-error format."""

    def __init__(self, issues: list[str] | tuple[str, ...]) -> None:
        if not issues:
            raise AssertionError("a verification error needs at least one issue")
        self.issues = tuple(issues)
        super().__init__("paired trial verification failed: " + "; ".join(self.issues))


# --- Execution order ------------------------------------------------------------------------------

def execution_order(seed: int, *, pair_id: str, baseline_trial_id: str, protected_trial_id: str) -> tuple[str, str]:
    """The trial order for ``seed``: a pure function of the seed and the pair identity.

    SHA-256 over ``aegis.lab.canonical-json.v1`` of the inputs; the low bit of the
    first digest byte selects the order. It does not depend on Python's ``random``
    implementation, so a recorded seed reproduces the order on any platform.
    """
    if type(seed) is not int or not 0 <= seed <= MAX_ORDER_SEED:
        raise ValueError("order seed out of range")
    digest = hashlib.sha256(canonical_json_bytes({
        "schema": ORDER_DERIVATION,
        "seed": seed,
        "pair_id": pair_id,
        "baseline_trial_id": baseline_trial_id,
        "protected_trial_id": protected_trial_id,
    })).digest()
    return ("baseline", "protected") if digest[0] & 1 == 0 else ("protected", "baseline")


# --- Preparation ----------------------------------------------------------------------------------

REPORT_FIELDS = model_field_names(AnalysisReport)
MANIFEST_FIELDS = model_field_names(TrialManifest)


@dataclass(frozen=True)
class PreparedPair:
    """Both trials checked and, where the target decompiled, prepared before either runs.

    ``analysis`` holds a target-analysis observation for both trials. ``prepared``
    holds a Phase 3A request only for trials whose target decompiled; a trial whose
    target failed to decompile in a valid wildcard report has no request at all.
    Holds no provider.
    """

    pair: PairValidation
    report_bytes: dict[str, bytes] = field(repr=False)
    evidence: dict[str, GhidraEvidence]
    analysis: dict[str, TargetAnalysis]
    prepared: dict[str, PreparedReconstruction]
    ghidra_runtime: dict[str, str]
    cross_trial_value_findings: dict[str, int]
    language: str
    blinded_requested: bool
    max_output_tokens_override: int | None
    top_p: float | None

    @property
    def prompts_compared(self) -> bool:
        return len(self.prepared) == 2


def _preparation_issues(role: str, exc: Exception) -> list[str]:
    if isinstance(exc, LoadError):
        return [f"{role}: report: {exc.category}"]
    if isinstance(exc, ValidationError):
        return [f"{role}: report: {issue}" for issue in validation_issues(exc, REPORT_FIELDS)]
    if isinstance(exc, ReportInvariantError):
        return [f"{role}: report: {f}: {r}" for f, r in exc.violations]
    if isinstance(exc, EvidenceBindingError):
        return [f"{role}: binding: {f}: {r}" for f, r in zip(exc.fields, exc.reasons)]
    if isinstance(exc, ReconstructionInputError):
        return [f"{role}: input: {exc.code}"]
    if isinstance(exc, BudgetError):
        return [f"{role}: budget: {exc.code}"]
    if isinstance(exc, ConfigurationError):
        return [f"{role}: configuration: {code}" for code in exc.codes]
    if isinstance(exc, DisclosurePolicyError):
        return [f"{role}: disclosure: {exc.code}"]
    raise TypeError("unsupported failure type")


_PREPARATION_ERRORS = (LoadError, ValidationError, ReportInvariantError, EvidenceBindingError,
                       ReconstructionInputError, BudgetError, ConfigurationError, DisclosurePolicyError)


def _cross_trial_findings(own: TrialManifest, other: TrialManifest, prepared: PreparedReconstruction) -> int:
    """Count the *other* trial's privileged values in this trial's model-facing text.

    The pipeline never inserts them (task fields are checked by Phase 3A and are
    identical across the pair), so a hit can only come from artifact-derived
    evidence. It is recorded as a finding, as Phase 3A does for its own values.
    """
    own_values = {v.casefold() for v in _privileged_values(own)}
    other_only = [v for v in _privileged_values(other) if v.casefold() not in own_values]
    texts = [m.content for m in prepared.prompt_messages()]
    return scan_findings(texts, other_function_names=(), artifact_names=(),
                         privileged_values=other_only).get("privileged_trial_value", 0)


def _diagnostic_text(value: str) -> DiagnosticText:
    """Exporter text, already bounded by Phase 2; kept verbatim only when it is valid text."""
    raw = value.encode("utf-8", "surrogatepass")
    keep = "\x00" not in value and all(not 0xD800 <= ord(ch) <= 0xDFFF for ch in value)
    return DiagnosticText(sha256=hashlib.sha256(raw).hexdigest(), chars=len(value),
                          text=value if keep else None, withheld=None if keep else "invalid_text")


def _target_analysis(manifest: TrialManifest, report: AnalysisReport, evidence: GhidraEvidence
                     ) -> TargetAnalysis | None:
    """The observation for the manifest's target in a bound report, or None if it is not attributable.

    Not attributable: the target is absent or matches more than one function (Phase 3A
    reports those as invalid input), or it failed under an exact selector (Phase 2
    already rejects such a report, so it cannot be bound evidence of a failure).
    """
    wanted = manifest.target.function
    matches = [fn for fn in report.analysis.functions if wanted in (fn.name, fn.qualified_name)]
    if len(matches) != 1:
        return None
    fn = matches[0]
    selector = "wildcard" if report.export.selected_function == "*" else "exact"
    failure = None
    if not fn.decompile_success:
        if selector != "wildcard":
            return None
        failure = TargetFailure(
            decompile_status=fn.decompile_status,
            error=_diagnostic_text(fn.error),
            decompiler_message=_diagnostic_text(fn.decompiler_message) if fn.decompiler_message else None,
            decompiler_message_truncated=fn.decompiler_message_truncated,
        )
    observed = evidence.observed
    return TargetAnalysis(
        selector=selector,
        status="decompiled" if fn.decompile_success else "decompilation_failed",
        decompile_status=fn.decompile_status,
        report_function_count=observed["exported_function_count"],
        report_decompiled_count=observed["decompiled_ok_count"],
        report_failed_count=observed["decompile_failed_count"],
        failure=failure,
    )


def _verify_unreached_configuration(manifest: TrialManifest, *, language: str, blinded: bool,
                                    max_output_tokens: int | None, top_p: float | None) -> None:
    """The Phase 3A settings checks for a trial that never reaches them.

    ``prepare_reconstruction`` selects the function before it verifies budgets and
    declared digests, so a failed target stops it early. Without this, a manifest
    with unverifiable digests could pass as an analysis-failure observation.
    Applies the same rules and error codes as Phase 3A's own checks.
    """
    if not isinstance(language, str) or language not in ALLOWED_LANGUAGES:
        raise DisclosurePolicyError("language_not_allowed")
    budget = manifest.budget
    output = default_max_output_tokens(budget.max_model_tokens) if max_output_tokens is None else max_output_tokens
    if type(output) is not int or output < 1:
        raise BudgetError("output_tokens_unbounded")
    if output > HARD_MAX_OUTPUT_TOKENS:
        raise BudgetError("output_tokens_exceed_hard_limit")
    if output > budget.max_model_tokens:
        raise BudgetError("output_tokens_exceed_budget")
    effective_blinded = bool(blinded) or not manifest.access.access_to_symbols
    _verify_declared_configuration(manifest, language=language, blinded=effective_blinded,
                                   max_output_tokens=output, top_p=top_p, temperature=None, seed=None)


def prepare_pair(
    baseline_manifest: TrialManifest,
    protected_manifest: TrialManifest,
    baseline_report: bytes,
    protected_report: bytes,
    *,
    language: str = "c",
    blinded: bool = False,
    max_output_tokens: int | None = None,
    top_p: float | None = None,
) -> PreparedPair:
    """Validate, bind and prepare both trials. Raises ``PairedTrialInputError`` on any problem.

    Manifests and reports are taken by role and never re-ordered: a protected
    manifest passed as the baseline is rejected rather than silently swapped, so
    trial identities cannot depend on argument order.

    A trial whose target failed to decompile in a valid, bound **wildcard** report is
    kept as an analysis-failure observation, without a model request, provided
    Phase 3A refuses it for exactly that reason (``selected_function_failed``) and
    its declared settings pass the same checks as a prepared trial. Every other
    evidence or preparation problem remains invalid input.
    """
    issues: list[str] = []
    if not isinstance(baseline_manifest, TrialManifest) or not isinstance(protected_manifest, TrialManifest):
        raise PairedTrialInputError(["pair: manifest: invalid_type"])
    if type(baseline_report) is not bytes or type(protected_report) is not bytes:
        raise PairedTrialInputError(["pair: evidence: invalid_type"])
    if baseline_manifest.variant != TrialVariant.BASELINE:
        issues.append("baseline-manifest: variant: not_baseline")
    if protected_manifest.variant != TrialVariant.PROTECTED:
        issues.append("protected-manifest: variant: not_protected")
    if issues:
        raise PairedTrialInputError(issues)
    try:
        pair = validate_pair(baseline_manifest, protected_manifest)
    except ManifestPairError as exc:
        raise PairedTrialInputError([f"pair: {f}: differs" for f in exc.fields]) from None

    evidence: dict[str, GhidraEvidence] = {}
    for variant, manifest, report in (("baseline", pair.baseline, baseline_report),
                                      ("protected", pair.protected, protected_report)):
        try:
            evidence[variant] = bind_ghidra_evidence(manifest, report)
        except (LoadError, ValidationError, ReportInvariantError, EvidenceBindingError) as exc:
            issues.extend(_preparation_issues(f"{variant}-evidence", exc))
    if issues:
        raise PairedTrialInputError(issues)
    try:
        compare_pair_evidence(pair, evidence["baseline"], evidence["protected"])
    except EvidenceBindingError as exc:
        raise PairedTrialInputError([f"pair-evidence: {f}: {r}" for f, r in zip(exc.fields, exc.reasons)]) from None

    options = {"language": language, "blinded": blinded, "max_output_tokens": max_output_tokens, "top_p": top_p}
    analysis: dict[str, TargetAnalysis] = {}
    prepared: dict[str, PreparedReconstruction] = {}
    for variant, manifest, report in (("baseline", pair.baseline, baseline_report),
                                      ("protected", pair.protected, protected_report)):
        role = f"{variant}-preparation"
        # The report is already bound: parsing cannot fail here.
        observation = _target_analysis(manifest, parse_ghidra_report(report), evidence[variant])
        try:
            prepared[variant] = prepare_reconstruction(manifest, report, **options)
        except ReconstructionInputError as exc:
            if (exc.code != "selected_function_failed" or observation is None
                    or observation.status != "decompilation_failed"):
                issues.extend(_preparation_issues(role, exc))
                continue
            try:
                _verify_unreached_configuration(manifest, **options)
            except (BudgetError, ConfigurationError, DisclosurePolicyError) as config_exc:
                issues.extend(_preparation_issues(role, config_exc))
                continue
            analysis[variant] = observation
            continue
        except _PREPARATION_ERRORS as exc:
            issues.extend(_preparation_issues(role, exc))
            continue
        if observation is None or observation.status != "decompiled":
            issues.append(f"{role}: input: analysis_observation_inconsistent")  # defense in depth
            continue
        analysis[variant] = observation
    if issues:
        raise PairedTrialInputError(issues)

    # Generated requests are compared only where both exist; the declared settings they derive
    # from are already identical (validate_pair) and verified for every trial.
    if len(prepared) == 2:
        base, prot = prepared["baseline"], prepared["protected"]
        for name in SHARED_PREPARED_FIELDS:
            if getattr(base, name) != getattr(prot, name):
                issues.append(f"pair: prepared.{name}: differs")
        for name in SHARED_REQUEST_FIELDS:
            if getattr(base.request, name) != getattr(prot.request, name):
                issues.append(f"pair: request.{name}: differs")
        # The model-facing task and the fixed system text must be identical; only evidence may differ.
        if base.request.messages[0] != prot.request.messages[0]:
            issues.append("pair: request.system_message: differs")
        base_data, prot_data = (json.loads(p.request.messages[-1].content) for p in (base, prot))
        if (base_data.get("schema"), base_data.get("task")) != (prot_data.get("schema"), prot_data.get("task")):
            issues.append("pair: request.task: differs")
        if issues:
            raise PairedTrialInputError(issues)

    manifests = {"baseline": (pair.baseline, pair.protected), "protected": (pair.protected, pair.baseline)}
    runtime = {name: evidence["baseline"].observed[name] for name in OBSERVED_RUNTIME_FIELDS}
    return PreparedPair(
        pair=pair,
        report_bytes={"baseline": baseline_report, "protected": protected_report},
        evidence=evidence,
        analysis=analysis,
        prepared=prepared,
        ghidra_runtime=runtime,
        cross_trial_value_findings={
            variant: _cross_trial_findings(*manifests[variant], request) for variant, request in prepared.items()
        },
        language=language,
        blinded_requested=bool(blinded),
        max_output_tokens_override=max_output_tokens,
        top_p=top_p,
    )


def _verify_prepared_pair(prepared_pair: PreparedPair) -> None:
    """Rebind all pair facts, including trials with no Phase 3A request.

    The frozen dataclass contains mutable dictionaries. Re-derive their contents
    from the retained manifests and exact report bytes before creating providers,
    just as Phase 3A rechecks each prepared request before execution.
    """
    try:
        fresh = prepare_pair(
            prepared_pair.pair.baseline, prepared_pair.pair.protected,
            prepared_pair.report_bytes["baseline"], prepared_pair.report_bytes["protected"],
            language=prepared_pair.language, blinded=prepared_pair.blinded_requested,
            max_output_tokens=prepared_pair.max_output_tokens_override, top_p=prepared_pair.top_p,
        )
    except (PairedTrialInputError, KeyError, TypeError, AttributeError):
        raise PairedTrialInputError(["pair: prepared: inconsistent"]) from None
    if fresh != prepared_pair:
        issues = [f"{variant}-preparation: configuration: prepared_request_inconsistent"
                  for variant in VARIANTS
                  if fresh.prepared.get(variant) != prepared_pair.prepared.get(variant)]
        raise PairedTrialInputError(issues or ["pair: prepared: inconsistent"])


# --- Record ---------------------------------------------------------------------------------------

class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Id32 = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
NonNegInt = Annotated[StrictInt, Field(ge=0)]
Seconds = Annotated[float, Field(ge=0, allow_inf_nan=False)]
Code = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:+-]{1,120}$")]
Note = Annotated[str, Field(min_length=1, max_length=500)]
RuntimeText = Annotated[str, Field(min_length=1, max_length=200)]


class ProviderRecord(StrictRecord):
    provider: Literal["FakeOffline"]
    endpoint: Literal["offline:fake"]
    external_disclosure: Literal[False]
    independent_instance_per_trial: Literal[True]


class AuthorizationRecord(StrictRecord):
    """The manifests' shared audit reference. It is never execution permission."""

    reference: Annotated[str, Field(min_length=1, max_length=200)]
    authorized_scope: Annotated[str, Field(min_length=1, max_length=2000)]
    is_execution_permission: Literal[False]
    core_attack_lab_gates: Literal["not_integrated"]
    live_inference: Literal["disabled"]


class OrderRecord(StrictRecord):
    derivation: Literal["aegis.lab.trial-order.v1"]
    seed: Annotated[StrictInt, Field(ge=0, le=MAX_ORDER_SEED)]
    seed_source: Literal["operator", "generated"]
    sequence: tuple[Variant, Variant]


class PreparationRecord(StrictRecord):
    """Options both trials were prepared with; required to re-prepare and revalidate."""

    language: Literal["c"]
    blinded_requested: StrictBool
    max_output_tokens_override: Annotated[StrictInt, Field(ge=1)] | None
    top_p: Annotated[float, Field(gt=0.0, le=1.0, allow_inf_nan=False)] | None
    prepared_before_execution: Literal[True]


class ComparabilityRecord(StrictRecord):
    """Controls the runner checked. Each is necessary for a fair comparison; none is sufficient.

    Shared experimental settings (``declared_configuration``, ``declared_settings``)
    are checked for both trials whatever their analysis observed. Generated requests
    are compared only when both exist; otherwise they are ``not_compared``.
    """

    declared_configuration: Literal["comparable"]
    declared_settings: Literal["verified_for_both_trials"]
    evidence_binding: Literal["consistent"]
    ghidra_runtime: dict[Literal["ghidra_release_name", "ghidra_build_date", "java_version"], RuntimeText]
    final_artifacts_identical: StrictBool
    effective_request_settings: Literal["identical", "not_compared"]
    model_facing_task: Literal["identical", "not_compared"]
    checks: tuple[Note, ...]


class DiagnosticText(StrictRecord):
    """Bounded exporter text (Phase 2 limit). Kept verbatim only when it is valid text."""

    sha256: Hash  # over the UTF-8 bytes (lone surrogates encoded with surrogatepass)
    chars: Annotated[StrictInt, Field(ge=0, le=MAX_DECOMPILER_MESSAGE_CHARS)]
    text: Annotated[str, Field(max_length=MAX_DECOMPILER_MESSAGE_CHARS)] | None
    withheld: Literal["invalid_text"] | None

    @model_validator(mode="after")
    def _digest(self) -> DiagnosticText:
        if (self.text is None) == (self.withheld is None):
            raise ValueError("diagnostic text is either kept or withheld with a reason")
        if self.text is not None:
            if "\x00" in self.text or any(0xD800 <= ord(ch) <= 0xDFFF for ch in self.text):
                raise ValueError("kept diagnostic text must be valid text")
            if hashlib.sha256(self.text.encode("utf-8")).hexdigest() != self.sha256 or len(self.text) != self.chars:
                raise ValueError("diagnostic digest or length does not match the text")
        return self


class TargetFailure(StrictRecord):
    """Ghidra's own report that the target function did not decompile."""

    decompile_status: Literal["timed_out", "cancelled", "failed_to_start", "failed"]
    error: DiagnosticText
    decompiler_message: DiagnosticText | None
    decompiler_message_truncated: StrictBool

    @model_validator(mode="after")
    def _diagnostics(self) -> TargetFailure:
        if self.error.chars < 1:
            raise ValueError("a failed decompilation carries an error")
        if self.decompiler_message is not None and self.decompiler_message.chars < 1:
            raise ValueError("an empty decompiler message is recorded as absent")
        if self.decompiler_message_truncated and self.decompiler_message is None:
            raise ValueError("message truncation flag without a message")
        return self


class TargetAnalysis(StrictRecord):
    """What the bound Ghidra report observed about the trial's target function.

    ``decompilation_failed`` is an observation about this Ghidra configuration on
    this artifact. It is not evidence of protection, resistance, a failed
    behavioral reconstruction or any hidden-test result. It is supported only for
    wildcard reports: an exact-selector report with a failed target is rejected by
    Phase 2, so no bound evidence of such a failure exists.
    """

    selector: Literal["exact", "wildcard"]
    status: Literal["decompiled", "decompilation_failed"]
    decompile_status: DecompileStatus
    report_function_count: Annotated[StrictInt, Field(ge=1)]
    report_decompiled_count: Annotated[StrictInt, Field(ge=1)]
    report_failed_count: NonNegInt
    failure: TargetFailure | None

    @model_validator(mode="after")
    def _observation(self) -> TargetAnalysis:
        decompiled = self.decompile_status in SUCCESS_STATUSES
        if (self.status == "decompiled") != decompiled or decompiled != (self.failure is None):
            raise ValueError("status, decompile_status and failure details disagree")
        if self.failure is not None:
            if self.failure.decompile_status != self.decompile_status:
                raise ValueError("failure status differs from decompile_status")
            if self.selector != "wildcard":
                raise ValueError("a target failure is only bound evidence in a wildcard report")
            if self.report_failed_count < 1:
                raise ValueError("a failed target must be counted as a failed function")
        if self.report_decompiled_count + self.report_failed_count != self.report_function_count:
            raise ValueError("report function counts do not add up")
        if self.selector == "exact" and (self.report_function_count, self.report_decompiled_count,
                                         self.report_failed_count) != (1, 1, 0):
            raise ValueError("an exact selector reports exactly one successfully decompiled function")
        return self


class TrialPrepared(StrictRecord):
    rendered_prompt_sha256: Hash
    prompt_token_bound: Annotated[StrictInt, Field(ge=1)]
    reserved_tokens_per_attempt: Annotated[StrictInt, Field(ge=1)]
    neutralized_symbol_occurrences: NonNegInt
    cross_trial_value_findings: NonNegInt


class TrialEvidence(StrictRecord):
    evidence_schema: Literal["aegis.lab.ghidra.v1"]
    evidence_sha256: Hash
    evidence_size_bytes: Annotated[StrictInt, Field(ge=1)]


class ResourceRecord(StrictRecord):
    """Consumption observed in the trial's reconstruction record (all zero when none was attempted)."""

    attempts: NonNegInt
    submitted_attempts: NonNegInt
    charged_tokens: NonNegInt
    reported_tokens: NonNegInt
    usage_complete: StrictBool
    reservation_exceeded: StrictBool
    reconstruction_elapsed_seconds: Seconds

    @model_validator(mode="after")
    def _counts(self) -> ResourceRecord:
        if self.submitted_attempts > self.attempts:
            raise ValueError("more submitted attempts than attempts")
        return self


class ReconstructionRef(StrictRecord):
    """A trial's ``aegis.lab.reconstruction.v2`` record, referenced by digest."""

    file: Literal["baseline-reconstruction.json", "protected-reconstruction.json"] | None
    publication: Literal["published", "failed"]
    publication_error: PublicationError | None = None
    file_sha256: Hash
    record_sha256: Hash
    status: Status
    stop_reason: StopReason
    candidate_sha256: Hash | None

    @model_validator(mode="after")
    def _publication(self) -> ReconstructionRef:
        if (self.publication == "published") != (self.file is not None):
            raise ValueError("a file name is recorded exactly when the record was published")
        if (self.publication == "failed") != (self.publication_error is not None):
            raise ValueError("a publication error is recorded exactly when publication failed")
        if (self.candidate_sha256 is not None) != (self.status == "completed"):
            raise ValueError("a candidate digest is present exactly when the status is completed")
        return self


class TrialError(StrictRecord):
    stage: Literal["execution", "publication"]
    codes: Annotated[tuple[Code, ...], Field(min_length=1, max_length=10)]


class TrialRecord(StrictRecord):
    variant: Variant
    trial_id: Id32
    manifest_sha256: Hash
    artifact_sha256: Hash
    evidence: TrialEvidence
    analysis: TargetAnalysis
    prepared: TrialPrepared | None
    execution_position: Literal[1, 2]
    state: TrialState
    outcome: TrialOutcome
    runner_wall_seconds: Seconds | None
    reconstruction: ReconstructionRef | None
    resources: ResourceRecord | None
    error: TrialError | None

    @model_validator(mode="after")
    def _state(self) -> TrialRecord:  # noqa: C901 - one table of state invariants
        def fail(message: str) -> None:
            raise ValueError(message)

        ref, state = self.reconstruction, self.state
        if self.outcome != _trial_outcome(state, ref):
            fail("trial outcome does not follow from its state and record")
        analysis_failed = self.analysis.status == "decompilation_failed"
        if analysis_failed != (self.prepared is None):
            fail("a model request is prepared exactly when the target decompiled")
        if analysis_failed != (state == "analysis_failure_recorded"):
            fail("analysis_failure_recorded is the state exactly of a trial whose target analysis failed")
        if state == "analysis_failure_recorded":
            if ref is not None or self.error is not None or self.runner_wall_seconds is not None:
                fail("a trial without a model request has no record, error or timing")
            if self.resources != ZERO_RESOURCES:
                fail("a trial without a model request records zero attempts and tokens")
            return self
        if (ref is None) != (self.resources is None):
            fail("resources are recorded exactly when a reconstruction record exists")
        if ref is not None and ref.file is not None and ref.file != RECONSTRUCTION_FILES[self.variant]:
            fail("reconstruction file name does not match the variant")
        if state == "not_started":
            if ref is not None or self.error is not None or self.runner_wall_seconds is not None:
                fail("a trial that did not start has no record, error or timing")
            return self
        if self.runner_wall_seconds is None:
            fail("a started trial records its runner wall time")
        if state == "record_produced" and ref is None:
            fail("record_produced requires a reconstruction record")
        if state in ("execution_refused", "internal_error"):
            if ref is not None:
                fail("a refused or failed execution has no reconstruction record")
            if self.error is None or self.error.stage != "execution":
                fail("a refused or failed execution records its execution error")
        if ref is not None and ref.status == "interrupted" and state != "interrupted":
            fail("an interrupted reconstruction record requires the interrupted state")
        if state == "record_produced" and ref is not None and ref.status == "interrupted":
            fail("record_produced cannot hold an interrupted record")
        if state in ("record_produced", "interrupted"):
            publication_failed = ref is not None and ref.publication == "failed"
            if publication_failed:
                if self.error is None or self.error.stage != "publication" or self.error.codes != (
                        ref.publication_error,):
                    fail("a failed publication is recorded as the trial's publication error")
            elif self.error is not None:
                fail("only a publication failure is recorded as an error for a trial with a record")
        return self


ZERO_RESOURCES = ResourceRecord(attempts=0, submitted_attempts=0, charged_tokens=0, reported_tokens=0,
                                usage_complete=True, reservation_exceeded=False, reconstruction_elapsed_seconds=0.0)


def _trial_outcome(state: str, ref: ReconstructionRef | None) -> str:
    if state == "analysis_failure_recorded":
        return "not_attempted_target_analysis_failed"
    if state == "not_started":
        return "not_attempted_run_stopped"
    if state == "interrupted":
        return "reconstruction_interrupted"
    if state in ("execution_refused", "internal_error") or ref is None:
        return "execution_error"
    return "candidate_received" if ref.status == "completed" else "reconstruction_not_completed"


def _pair_summary(trials: list[Any] | tuple[Any, ...], run_status: str) -> dict[str, Any]:
    """Pair-level counts and status, shared by the runner and the record validator."""
    with_record = [t for t in trials if t.reconstruction is not None]
    completed = [t for t in with_record if t.reconstruction.status == "completed"]
    analysis_failed = [t for t in trials if t.state == "analysis_failure_recorded"]
    done = all(t.state == "analysis_failure_recorded"
               or (t.reconstruction is not None and t.reconstruction.publication == "published"
                   and t.state == "record_produced") for t in trials)
    workflow_complete = run_status == "finished" and done
    if not workflow_complete:
        pair_status = "incomplete"
    elif analysis_failed:
        pair_status = "target_analysis_failure_observed"
    elif len(completed) == 2:
        pair_status = "candidates_received_for_both_trials"
    else:
        pair_status = "trial_failures"
    return {"workflow_complete": workflow_complete, "trials_with_record": len(with_record),
            "trials_completed": len(completed), "trials_not_attempted_analysis_failed": len(analysis_failed),
            "pair_status": pair_status}


class ResourceTotals(StrictRecord):
    attempts: NonNegInt
    submitted_attempts: NonNegInt
    charged_tokens: NonNegInt
    reported_tokens: NonNegInt
    usage_complete: StrictBool


class PairOutcome(StrictRecord):
    """Workflow completion only. Nothing here is a reconstruction or security result.

    ``target_analysis_failure_observed`` means at least one trial's target did not
    decompile, so no model request was made for it. ``interpretation`` stays
    ``not_evaluated``: such a failure establishes neither protection, nor
    reverse-engineering resistance, nor a failed behavioral reconstruction, nor any
    hidden-test result.
    """

    run_status: RunStatus
    workflow_complete: StrictBool
    trials_with_record: Annotated[StrictInt, Field(ge=0, le=2)]
    trials_completed: Annotated[StrictInt, Field(ge=0, le=2)]
    trials_not_attempted_analysis_failed: Annotated[StrictInt, Field(ge=0, le=2)]
    pair_status: PairStatus
    interpretation: Literal["not_evaluated"]
    # Offline candidates are scripted by the fake provider: they are not model output and scoring
    # them would measure nothing about reconstruction.
    candidate_origin: Literal["offline_fake_provider"]
    scoring: Literal["not_performed"]
    reconstruction_success_established: Literal[False]
    protection_effect_established: Literal[False]


class ErrorEntry(StrictRecord):
    variant: Variant
    stage: Literal["execution", "publication"]
    codes: tuple[Code, ...]


class PairedTrialRecord(StrictRecord):
    """The versioned, strictly validated Phase 3B record.

    Parsing re-derives the execution order from the seed, every trial's state
    rules, the run status, the pair outcome, the totals and the error list, so a
    stored summary cannot contradict the stored trial facts. It does not prove who
    wrote the record (unsigned) or that the referenced files exist; use
    ``verify_experiment`` to revalidate the published files.
    """

    schema_version: Literal["aegis.lab.paired-trial.v2"] = PAIRED_TRIAL_SCHEMA
    experiment_id: Id32
    pair_id: Id32
    execution_mode: Literal["offline"]
    started_at: AwareDatetime
    finished_at: AwareDatetime
    provider: ProviderRecord
    authorization: AuthorizationRecord
    order: OrderRecord
    preparation: PreparationRecord
    comparability: ComparabilityRecord
    trials: tuple[TrialRecord, TrialRecord]
    totals: ResourceTotals
    outcome: PairOutcome
    errors: tuple[ErrorEntry, ...]
    fingerprints: Literal["manifest_sha256 and record_sha256: sha256 over aegis.lab.canonical-json.v1; "
                          "evidence_sha256 and file_sha256: sha256 of file bytes"]
    record_signed: Literal[False]
    not_established: Annotated[tuple[Note, ...], Field(min_length=1, max_length=32)]
    limitations: Annotated[tuple[Note, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _integrity(self) -> PairedTrialRecord:  # noqa: C901 - one list of record invariants
        def fail(message: str) -> None:
            raise ValueError(message)

        base, prot = self.trials
        if (base.variant, prot.variant) != ("baseline", "protected"):
            fail("trials are listed as baseline, then protected")
        if base.trial_id == prot.trial_id:
            fail("the two trials must have distinct trial ids")
        if self.finished_at < self.started_at:
            fail("finished_at precedes started_at")
        expected = execution_order(self.order.seed, pair_id=self.pair_id, baseline_trial_id=base.trial_id,
                                   protected_trial_id=prot.trial_id)
        if self.order.sequence != expected:
            fail("execution sequence does not follow from the recorded seed")
        by_variant = {t.variant: t for t in self.trials}
        for position, variant in enumerate(self.order.sequence, start=1):
            if by_variant[variant].execution_position != position:
                fail("execution positions do not follow the sequence")
        if self.comparability.final_artifacts_identical != (base.artifact_sha256 == prot.artifact_sha256):
            fail("final_artifacts_identical inconsistent with the artifact digests")
        if set(self.comparability.ghidra_runtime) != set(OBSERVED_RUNTIME_FIELDS):
            fail("ghidra_runtime must record every observed runtime field")
        both_prepared = base.prepared is not None and prot.prepared is not None
        expected_comparison = "identical" if both_prepared else "not_compared"
        if (self.comparability.effective_request_settings, self.comparability.model_facing_task) != (
                expected_comparison, expected_comparison):
            fail("generated requests are compared exactly when both trials have one")
        ordered = [by_variant[v] for v in self.order.sequence]
        run_status = _derive_run_status(ordered)
        out = self.outcome
        if out.run_status != run_status:
            fail("run_status does not follow from the trial states")
        derived = _pair_summary(self.trials, run_status)
        for name, value in derived.items():
            if getattr(out, name) != value:
                fail(f"{name} does not follow from the trials")
        resources = [t.resources for t in self.trials if t.resources is not None]
        totals = ResourceTotals(
            attempts=sum(r.attempts for r in resources),
            submitted_attempts=sum(r.submitted_attempts for r in resources),
            charged_tokens=sum(r.charged_tokens for r in resources),
            reported_tokens=sum(r.reported_tokens for r in resources),
            usage_complete=all(r.usage_complete for r in resources),
        )
        if self.totals != totals:
            fail("totals do not equal the sum over trials")
        errors = tuple(ErrorEntry(variant=t.variant, stage=t.error.stage, codes=t.error.codes)
                       for t in ordered if t.error is not None)
        if self.errors != errors:
            fail("errors do not equal the trials' errors in execution order")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_json_bytes(self) -> bytes:
        data = (json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=True) + "\n")
        encoded = data.encode("utf-8")
        if len(encoded) > MAX_PAIRED_RECORD_BYTES:
            raise ValueError("paired record exceeds the maximum serialized size")
        return encoded

    def summary(self) -> dict[str, Any]:
        """Terminal-safe summary: identities, order and statuses only (no paths, no evidence)."""
        return {
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "pair_id": self.pair_id,
            "paired_record_sha256": self.sha256(),
            "order": {"seed": self.order.seed, "seed_source": self.order.seed_source,
                      "sequence": list(self.order.sequence)},
            "trials": {
                t.variant: {
                    "trial_id": t.trial_id,
                    "target_analysis": t.analysis.status,
                    "state": t.state,
                    "outcome": t.outcome,
                    "status": None if t.reconstruction is None else t.reconstruction.status,
                    "stop_reason": None if t.reconstruction is None else t.reconstruction.stop_reason,
                    "publication": None if t.reconstruction is None else t.reconstruction.publication,
                }
                for t in self.trials
            },
            "run_status": self.outcome.run_status,
            "pair_status": self.outcome.pair_status,
            "interpretation": self.outcome.interpretation,
            "candidate_origin": self.outcome.candidate_origin,
            "scoring": "not_performed",
            "reconstruction_success_established": False,
            "protection_effect_established": False,
            "authorizes_execution": False,
        }


def parse_paired_trial_record(data: bytes) -> PairedTrialRecord:
    """Parse untrusted record bytes. Raises ``LoadError`` or ``pydantic.ValidationError``."""
    if len(data) > MAX_PAIRED_RECORD_BYTES:
        raise LoadError("too_large")
    document = parse_strict_json(data)  # duplicate keys, NaN and invalid UTF-8 are rejected first
    if isinstance(document, dict) and document.get("schema_version") in RETIRED_PAIRED_TRIAL_SCHEMAS:
        raise LoadError("retired_schema_version")
    return PairedTrialRecord.model_validate_json(data)


_NOT_ESTABLISHED = (
    "That the experiment was fair: comparable declarations and identical effective settings are necessary, "
    "not sufficient.",
    "Successful software reconstruction: candidates were not compiled, executed or scored.",
    "Any protection effect: no resisted or bypassed outcome is derived from this record.",
    "That the Ghidra reports came from the AEGIS worker, or that artifacts on disk have the declared hashes.",
    "That the protection was retained in the final protected artifact.",
    "Who produced this record: it is unsigned and is not authenticated provenance.",
)
_BASE_LIMITATIONS = (
    "Offline FakeOffline workflow only: replies and token usage are scripted by the fake provider, not "
    "produced or consumed by a model.",
    "Live inference is disabled; Core's two attack-lab gates are not connected to this runner, and the "
    "manifests' authorization reference is audit metadata, not permission.",
    "max_tool_calls is neither consumed nor enforced: the workflow gives the model no tools, and the Ghidra "
    "analysis ran before the trial and is not counted.",
    "Each trial's prompt token bound depends on its own evidence size, so per-attempt reservations, and the "
    "number of attempts a token budget allows, can differ between the trials.",
    "The order seed is recorded, not committed in advance; an operator-chosen seed could have been selected "
    "after the fact.",
    "runner_wall_seconds comes from the local monotonic clock and is not revalidated on reload.",
)
_CHECKS = (
    "Phase 1: the manifests are a comparable baseline/protected pair, given in their declared roles.",
    "Phase 2: each Ghidra report is bound to its own manifest's artifact, tool and configuration, and both "
    "reports observed the same Ghidra runtime.",
    "Declared budgets, access, workflow and configuration digests were verified for both trials, including any "
    "trial whose target did not decompile.",
)
_CHECKS_BOTH_PREPARED = (
    "Phase 3A: both requests were prepared and policy-checked before either trial ran.",
    "Identical effective request settings, budgets, system message and model-facing task; only "
    "artifact-derived evidence differs.",
    "A separate provider instance per trial; each request was re-verified immediately before it ran.",
)
_CHECKS_NOT_BOTH_PREPARED = (
    "Generated requests were not compared: at least one trial's target did not decompile, so that trial has "
    "no model request and its provider was never created or called.",
    "Every prepared request was policy-checked before any trial ran and re-verified immediately before it ran, "
    "on its own provider instance.",
)
_ANALYSIS_FAILURE_LIMITATION = (
    "A target-function decompilation failure is an observation about this Ghidra configuration on this "
    "artifact. It is not evaluated: it does not establish protection, reverse-engineering resistance, a failed "
    "behavioral reconstruction or any hidden-test result."
)


# --- Execution ------------------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _TrialRun:
    variant: str
    position: int
    state: str = "not_started"
    record: ReconstructionRecord | None = None
    record_bytes: bytes | None = None
    publication: str | None = None
    publication_error: str | None = None
    error: tuple[str, tuple[str, ...]] | None = None
    wall: float | None = None


@dataclass(frozen=True)
class PairedTrialResult:
    record: PairedTrialRecord
    reconstructions: dict[str, ReconstructionRecord] = field(repr=False)
    paired_record_published: bool
    paired_record_publication_error: str | None

    @property
    def exit_code(self) -> int:
        run_status = self.record.outcome.run_status
        if not self.paired_record_published or run_status == "publication_failed":
            return EXIT_PUBLICATION_FAILED
        if run_status == "interrupted":
            return EXIT_INTERRUPTED
        if run_status == "internal_error":
            return EXIT_INTERNAL
        if self.record.outcome.pair_status == "candidates_received_for_both_trials":
            return EXIT_COMPLETED
        return EXIT_NOT_COMPLETED


def _directory_identity(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise PublishError("directory_replaced")
    return st.st_dev, st.st_ino


def _create_output_directory(path: Path) -> tuple[int, int]:
    """Create a new private directory. An existing entry (even a symlink) is never reused."""
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        raise PublishError("already_exists") from None
    except FileNotFoundError:
        raise PublishError("parent_not_found") from None
    except PermissionError:
        raise PublishError("permission_denied") from None
    except NotADirectoryError:
        raise PublishError("parent_not_directory") from None
    except (OSError, ValueError):
        raise PublishError("invalid_path") from None
    try:
        return _directory_identity(path)
    except OSError:
        raise PublishError("directory_replaced") from None


def _publish(directory: Path, identity: tuple[int, int], name: str, data: bytes, limit: int) -> None:
    try:
        if _directory_identity(directory) != identity:
            raise PublishError("directory_replaced")
    except PublishError:
        raise
    except OSError:
        raise PublishError("directory_replaced") from None
    publish_new_file(directory / name, data, limit)


def _published_matches(path: Path, data: bytes) -> bool:
    try:
        return read_regular_file(path, max(len(data), 1)) == data
    except LoadError:
        return False


def _resources(record: ReconstructionRecord) -> ResourceRecord:
    return ResourceRecord(
        attempts=len(record.attempts),
        submitted_attempts=sum(1 for a in record.attempts if a.submission != "not_submitted"),
        charged_tokens=record.budget.charged_tokens,
        reported_tokens=sum(a.total_tokens for a in record.attempts if a.usage_status == "reported"),
        usage_complete=record.budget.usage_complete,
        reservation_exceeded=record.budget.reservation_exceeded,
        reconstruction_elapsed_seconds=record.budget.elapsed_seconds,
    )


def _check_providers(providers: list[object], prepared_pair: PreparedPair, attempting: list[str]) -> None:
    issues: list[str] = []
    if len(providers) == 2 and providers[0] is providers[1]:
        issues.append("providers: provider_instance_shared")
    # A trial without a model request gets no provider, but its manifest must still declare the
    # provider this runner uses, exactly as verify_effective_configuration requires of the others.
    for variant in VARIANTS:
        manifest = getattr(prepared_pair.pair, variant)
        if variant not in attempting and manifest.attack.provider != OFFLINE_PROVIDER_NAME:
            issues.append(f"{variant}-preparation: configuration: provider_mismatch")
    for variant, provider in zip(attempting, providers):
        identity = getattr(provider, "identity", None)
        if not isinstance(identity, ProviderIdentity):
            issues.append(f"{variant}-provider: identity: invalid_type")
            continue
        if identity.external_disclosure or getattr(provider, "external_disclosure", False) or (
                identity.provider, identity.endpoint) != (OFFLINE_PROVIDER_NAME, OFFLINE_ENDPOINT):
            issues.append(f"{variant}-provider: live_inference_disabled")
            continue
        # Identity strings are declarations, not proof of an offline implementation.
        # Factories may configure scripted fakes, but may not select another transport
        # by impersonating FakeOffline (including subclasses or instance overrides).
        if type(provider) is not FakeProvider or any(
                name in vars(provider) for name in ("complete", "_body", "identity")):
            issues.append(f"{variant}-provider: offline_provider_required")
            continue
        prepared = prepared_pair.prepared[variant]
        try:
            verify_prepared(prepared)
            verify_effective_configuration(prepared, identity)
        except ConfigurationError as exc:
            issues.extend(f"{variant}-preparation: configuration: {code}" for code in exc.codes)
    if issues:
        raise PairedTrialInputError(issues)


def _execute_trial(run: _TrialRun, prepared: PreparedReconstruction, provider: InferenceProvider, *,
                   monotonic: Callable[[], float], sleep: Callable[[float], None]) -> None:
    start = monotonic()
    try:
        run.record = run_reconstruction(prepared, provider, monotonic=monotonic, sleep=sleep)
        run.state = "record_produced"
    except ReconstructionInterrupted as exc:
        run.record, run.state = exc.record, "interrupted"
    except KeyboardInterrupt:
        run.state = "interrupted"
    except ConfigurationError as exc:
        run.state, run.error = "execution_refused", ("execution", tuple(f"configuration:{c}" for c in exc.codes))
    except BudgetError as exc:
        run.state, run.error = "execution_refused", ("execution", (f"budget:{exc.code}",))
    except AuthorizationError as exc:
        run.state, run.error = "execution_refused", ("execution", (f"authorization:{exc.code}",))
    except Exception as exc:  # recorded as an internal error; the other trial's evidence is preserved
        run.state, run.error = "internal_error", ("execution", (f"internal_error:{type(exc).__name__}"[:120],))
    finally:
        run.wall = max(0.0, monotonic() - start)


def _publish_trial(run: _TrialRun, directory: Path, identity: tuple[int, int]) -> bool:
    """Publish a trial's reconstruction record. Returns False if the run must stop."""
    if run.record is None:
        return run.state == "record_produced"
    name = RECONSTRUCTION_FILES[run.variant]
    try:
        run.record_bytes = run.record.to_json_bytes()
    except ValueError:
        run.record_bytes = run.record.canonical_bytes()
        run.publication, run.publication_error = "failed", "too_large"
    else:
        try:
            _publish(directory, identity, name, run.record_bytes, MAX_RECORD_BYTES)
            run.publication = "published"
        except PublishError as exc:
            run.publication, run.publication_error = "failed", exc.category
        except KeyboardInterrupt:
            # publish_new_file is atomic: the file is either complete at its name or absent.
            if _published_matches(directory / name, run.record_bytes):
                run.publication = "published"
            else:
                run.publication, run.publication_error = "failed", "interrupted"
            run.state = "interrupted"
    if run.publication == "failed":
        run.error = ("publication", (run.publication_error,))
    return run.state == "record_produced" and run.publication == "published"


def _build_paired_record(prepared_pair: PreparedPair, runs: dict[str, _TrialRun], *, experiment_id: str,
                         seed: int, seed_source: str, sequence: tuple[str, str],
                         started_at: datetime, finished_at: datetime) -> PairedTrialRecord:
    pair = prepared_pair.pair
    trials = []
    for variant, manifest in (("baseline", pair.baseline), ("protected", pair.protected)):
        run, evidence = runs[variant], prepared_pair.evidence[variant]
        prepared = prepared_pair.prepared.get(variant)
        ref = None
        resources = ZERO_RESOURCES if run.state == "analysis_failure_recorded" else None
        if run.record is not None:
            record = run.record
            ref = ReconstructionRef(
                file=RECONSTRUCTION_FILES[variant] if run.publication == "published" else None,
                publication=run.publication,
                publication_error=run.publication_error,
                file_sha256=hashlib.sha256(run.record_bytes).hexdigest(),
                record_sha256=record.sha256(),
                status=record.outcome.status,
                stop_reason=record.outcome.stop_reason,
                candidate_sha256=None if record.candidate is None else record.candidate.sha256,
            )
            resources = _resources(record)
        trials.append(TrialRecord(
            variant=variant,
            trial_id=manifest.trial_id,
            manifest_sha256=evidence.manifest_sha256,
            artifact_sha256=evidence.artifact_sha256,
            evidence=TrialEvidence(evidence_schema=evidence.record()["evidence_schema"],
                                   evidence_sha256=evidence.evidence_sha256,
                                   evidence_size_bytes=evidence.evidence_size_bytes),
            analysis=prepared_pair.analysis[variant],
            prepared=None if prepared is None else TrialPrepared(
                rendered_prompt_sha256=prepared.rendered_prompt_sha256,
                prompt_token_bound=prepared.prompt_token_bound,
                reserved_tokens_per_attempt=prepared.reserved_tokens_per_attempt,
                neutralized_symbol_occurrences=prepared.neutralized_count,
                cross_trial_value_findings=prepared_pair.cross_trial_value_findings[variant],
            ),
            execution_position=run.position,
            state=run.state,
            outcome=_trial_outcome(run.state, ref),
            runner_wall_seconds=None if run.wall is None else round(run.wall, 6),
            reconstruction=ref,
            resources=resources,
            error=None if run.error is None else TrialError(stage=run.error[0], codes=run.error[1]),
        ))
    by_variant = {t.variant: t for t in trials}
    ordered = [by_variant[v] for v in sequence]
    # The outcome and totals are derived exactly as the record validator re-derives them.
    run_status = _derive_run_status(ordered)
    summary = _pair_summary(trials, run_status)
    pair_status = summary["pair_status"]
    limitations = list(_BASE_LIMITATIONS)
    if summary["trials_not_attempted_analysis_failed"]:
        limitations.append(_ANALYSIS_FAILURE_LIMITATION)
    if pair.final_artifacts_identical:
        limitations.append("The final artifacts are byte-identical; any outcome difference cannot be attributed "
                           "to protection.")
    if any(prepared_pair.cross_trial_value_findings.values()):
        limitations.append("A trial's evidence contains privileged values of the other trial "
                           "(cross_trial_value_findings); review the evidence before interpreting outcomes.")
    if pair_status == "trial_failures":
        limitations.append("At least one trial did not receive a candidate; its recorded status is preserved and "
                           "the pair is not a completed comparison.")
    if run_status != "finished":
        limitations.append(f"The run stopped early ({run_status}); the pair is incomplete.")
    resources = [t.resources for t in trials if t.resources is not None]
    compared = "identical" if prepared_pair.prompts_compared else "not_compared"
    checks = _CHECKS + (_CHECKS_BOTH_PREPARED if prepared_pair.prompts_compared else _CHECKS_NOT_BOTH_PREPARED)
    attack = pair.baseline
    return PairedTrialRecord(
        experiment_id=experiment_id,
        pair_id=attack.pair_id,
        execution_mode="offline",
        started_at=started_at,
        finished_at=finished_at,
        provider=ProviderRecord(provider=OFFLINE_PROVIDER_NAME, endpoint=OFFLINE_ENDPOINT, external_disclosure=False,
                                independent_instance_per_trial=True),
        authorization=AuthorizationRecord(
            reference=attack.authorization.reference, authorized_scope=attack.authorization.authorized_scope,
            is_execution_permission=False, core_attack_lab_gates="not_integrated", live_inference="disabled"),
        order=OrderRecord(derivation=ORDER_DERIVATION, seed=seed, seed_source=seed_source, sequence=sequence),
        preparation=PreparationRecord(
            language=prepared_pair.language, blinded_requested=prepared_pair.blinded_requested,
            max_output_tokens_override=prepared_pair.max_output_tokens_override, top_p=prepared_pair.top_p,
            prepared_before_execution=True),
        comparability=ComparabilityRecord(
            declared_configuration="comparable", declared_settings="verified_for_both_trials",
            evidence_binding="consistent", ghidra_runtime=dict(prepared_pair.ghidra_runtime),
            final_artifacts_identical=pair.final_artifacts_identical,
            effective_request_settings=compared, model_facing_task=compared, checks=checks),
        trials=tuple(trials),
        totals=ResourceTotals(
            attempts=sum(r.attempts for r in resources),
            submitted_attempts=sum(r.submitted_attempts for r in resources),
            charged_tokens=sum(r.charged_tokens for r in resources),
            reported_tokens=sum(r.reported_tokens for r in resources),
            usage_complete=all(r.usage_complete for r in resources),
        ),
        outcome=PairOutcome(
            run_status=run_status, **summary, interpretation="not_evaluated",
            candidate_origin="offline_fake_provider",
            scoring="not_performed", reconstruction_success_established=False, protection_effect_established=False),
        errors=tuple(ErrorEntry(variant=t.variant, stage=t.error.stage, codes=t.error.codes)
                     for t in ordered if t.error is not None),
        fingerprints=("manifest_sha256 and record_sha256: sha256 over aegis.lab.canonical-json.v1; "
                      "evidence_sha256 and file_sha256: sha256 of file bytes"),
        record_signed=False,
        not_established=_NOT_ESTABLISHED,
        limitations=tuple(limitations),
    )


def run_paired_trial(
    prepared_pair: PreparedPair,
    output_dir: str | os.PathLike[str],
    *,
    execution_mode: str = "offline",
    order_seed: int | None = None,
    provider_factory: Callable[[], InferenceProvider] = FakeProvider,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], datetime] = _utc_now,
    experiment_id: str | None = None,
) -> PairedTrialResult:
    """Run both prepared trials offline, in seeded order, and publish every record.

    Before any inference this checks the execution mode and seed, creates one
    provider per trial *with a model request* (distinct ``FakeProvider``
    instances), re-verifies each prepared request against its provider, and creates
    ``output_dir`` as a new private directory (an existing entry is never reused).
    Those failures raise ``PairedTrialInputError`` or
    ``PairedTrialPublicationError`` and leave nothing behind but, for the latter,
    no directory.

    A trial whose target did not decompile is recorded as
    ``analysis_failure_recorded`` with zero attempts and tokens; the other trial
    still runs. After that, every outcome yields a ``PairedTrialResult``: a failed
    trial keeps its record and the other trial still runs; an interruption, a refused or
    crashed execution, or a failed publication stops the run, marks the
    remaining trial ``not_started`` and is recorded. No trial is retried.
    """
    if execution_mode not in EXECUTION_MODES:
        raise PairedTrialInputError(["mode: execution_mode_not_supported"])
    if not isinstance(prepared_pair, PreparedPair):
        raise PairedTrialInputError(["pair: prepared: invalid_type"])
    if order_seed is None:
        seed, seed_source = secrets.randbelow(MAX_ORDER_SEED + 1), "generated"
    elif type(order_seed) is not int or not 0 <= order_seed <= MAX_ORDER_SEED:
        raise PairedTrialInputError(["order-seed: out_of_range"])
    else:
        seed, seed_source = order_seed, "operator"
    if experiment_id is None:
        experiment_id = secrets.token_hex(16)
    pair = prepared_pair.pair
    sequence = execution_order(seed, pair_id=pair.baseline.pair_id, baseline_trial_id=pair.baseline.trial_id,
                               protected_trial_id=pair.protected.trial_id)
    _verify_prepared_pair(prepared_pair)
    # Only trials with a model request get a provider; a trial whose target did not decompile
    # never has one created, let alone called.
    attempting = [variant for variant in sequence if variant in prepared_pair.prepared]
    providers = [provider_factory() for _ in attempting]
    _check_providers(providers, prepared_pair, attempting)

    directory = Path(output_dir)
    try:
        identity = _create_output_directory(directory)
    except PublishError as exc:
        raise PairedTrialPublicationError(exc.category) from None

    started_at = now()
    runs = {variant: _TrialRun(variant=variant, position=position) for position, variant in enumerate(sequence, 1)}
    for variant in sequence:
        if variant not in prepared_pair.prepared:
            runs[variant].state = "analysis_failure_recorded"
    current: _TrialRun | None = None
    try:
        for variant, provider in zip(attempting, providers):
            current = runs[variant]
            _execute_trial(current, prepared_pair.prepared[variant], provider, monotonic=monotonic, sleep=sleep)
            if not _publish_trial(current, directory, identity):
                break
            current = None
    except KeyboardInterrupt:
        # Arrived outside the per-trial handlers. If it fell between two trials, the next
        # trial is the one interrupted (before it produced anything).
        if current is None:
            current = next((runs[v] for v in sequence if runs[v].state == "not_started"), None)
        if current is not None and current.state in ("not_started", "record_produced"):
            if current.record is not None and current.publication is None:
                _publish_trial(current, directory, identity)
            current.state = "interrupted"
            if current.wall is None:
                current.wall = 0.0
    finished_at = now()
    record = _build_paired_record(prepared_pair, runs, experiment_id=experiment_id, seed=seed,
                                  seed_source=seed_source, sequence=sequence, started_at=started_at,
                                  finished_at=finished_at)
    reconstructions = {v: r.record for v, r in runs.items() if r.record is not None}
    try:
        _publish(directory, identity, PAIRED_RECORD_FILE, record.to_json_bytes(), MAX_PAIRED_RECORD_BYTES)
    except PublishError as exc:
        return PairedTrialResult(record=record, reconstructions=reconstructions, paired_record_published=False,
                                 paired_record_publication_error=exc.category)
    return PairedTrialResult(record=record, reconstructions=reconstructions, paired_record_published=True,
                             paired_record_publication_error=None)


# --- Verification ---------------------------------------------------------------------------------

PAIRED_RECORD_FIELDS = model_field_names(PairedTrialRecord)
RECONSTRUCTION_RECORD_FIELDS = model_field_names(ReconstructionRecord)


def _reference_mismatches(trial: TrialRecord, paired: PairedTrialRecord, record: ReconstructionRecord,
                          data: bytes) -> list[str]:
    ref = trial.reconstruction
    checks = {
        "file_sha256": hashlib.sha256(data).hexdigest() == ref.file_sha256,
        "record_sha256": record.sha256() == ref.record_sha256,
        "trial_id": record.trial_id == trial.trial_id,
        "pair_id": record.pair_id == paired.pair_id,
        "variant": record.variant == trial.variant,
        "inputs.manifest_sha256": record.inputs.manifest_sha256 == trial.manifest_sha256,
        "inputs.artifact_sha256": record.inputs.artifact_sha256 == trial.artifact_sha256,
        "inputs.evidence_sha256": record.inputs.evidence_sha256 == trial.evidence.evidence_sha256,
        "inputs.evidence_schema": record.inputs.evidence_schema == trial.evidence.evidence_schema,
        "declared.rendered_prompt_sha256": record.declared.rendered_prompt_sha256
        == trial.prepared.rendered_prompt_sha256,
        "budget.prompt_token_bound": record.budget.prompt_token_bound == trial.prepared.prompt_token_bound,
        "budget.reserved_tokens_per_attempt": record.budget.reserved_tokens_per_attempt
        == trial.prepared.reserved_tokens_per_attempt,
        "task.neutralized_symbol_occurrences": record.task.neutralized_symbol_occurrences
        == trial.prepared.neutralized_symbol_occurrences,
        "provider": (record.provider.provider, record.provider.endpoint, record.provider.external_disclosure)
        == (paired.provider.provider, paired.provider.endpoint, paired.provider.external_disclosure),
        "outcome.status": record.outcome.status == ref.status,
        "outcome.stop_reason": record.outcome.stop_reason == ref.stop_reason,
        "candidate.sha256": (None if record.candidate is None else record.candidate.sha256) == ref.candidate_sha256,
        "resources": _resources(record) == trial.resources,
    }
    return [name for name, ok in checks.items() if not ok]


def verify_experiment(
    directory: str | os.PathLike[str],
    *,
    baseline_manifest: TrialManifest | None = None,
    protected_manifest: TrialManifest | None = None,
    baseline_report: bytes | None = None,
    protected_report: bytes | None = None,
) -> PairedTrialRecord:
    """Reload a published experiment and revalidate every hash and reference.

    Always: strict parsing of ``paired-trial.json`` (which re-derives its own
    invariants), and for each published trial record its file digest, canonical
    digest, strict Phase 3A parsing and every field the paired record repeats.
    With all four inputs, also re-runs ``prepare_pair`` and requires the recorded
    manifest, artifact and evidence digests, the target-analysis observation and
    the prepared-request facts (or their absence) to match. A trial whose target
    did not decompile has no reconstruction record to reload, so its observation is
    revalidated only against the inputs. Raises
    ``ExperimentVerificationError``. This checks consistency, not authorship.
    """
    root = Path(directory)
    try:
        data = read_regular_file(root / PAIRED_RECORD_FILE, MAX_PAIRED_RECORD_BYTES)
        paired = parse_paired_trial_record(data)
    except LoadError as exc:
        raise ExperimentVerificationError([f"paired-record: {exc.category}"]) from None
    except ValidationError as exc:
        raise ExperimentVerificationError(
            [f"paired-record: {issue}" for issue in validation_issues(exc, PAIRED_RECORD_FIELDS)]) from None
    issues: list[str] = []
    for trial in paired.trials:
        ref = trial.reconstruction
        if ref is None or ref.publication != "published":
            continue
        role = f"{trial.variant}-reconstruction"
        try:
            record_bytes = read_regular_file(root / ref.file, MAX_RECORD_BYTES)
            record = parse_reconstruction_record(record_bytes)
        except LoadError as exc:
            issues.append(f"{role}: {exc.category}")
            continue
        except ValidationError as exc:
            issues.extend(f"{role}: {issue}" for issue in validation_issues(exc, RECONSTRUCTION_RECORD_FIELDS))
            continue
        issues.extend(f"{role}: {name}: mismatch" for name in _reference_mismatches(trial, paired, record,
                                                                                     record_bytes))
    inputs = (baseline_manifest, protected_manifest, baseline_report, protected_report)
    if any(item is not None for item in inputs):
        if any(item is None for item in inputs):
            issues.append("inputs: incomplete: all four inputs are needed to re-prepare the pair")
        else:
            try:
                fresh = prepare_pair(
                    baseline_manifest, protected_manifest, baseline_report, protected_report,
                    language=paired.preparation.language, blinded=paired.preparation.blinded_requested,
                    max_output_tokens=paired.preparation.max_output_tokens_override, top_p=paired.preparation.top_p)
            except PairedTrialInputError as exc:
                issues.extend(f"inputs: {issue}" for issue in exc.issues)
            else:
                if fresh.pair.baseline.pair_id != paired.pair_id:
                    issues.append("inputs: pair_id: mismatch")
                audit = fresh.pair.baseline.authorization
                for name in ("reference", "authorized_scope"):
                    if getattr(paired.authorization, name) != getattr(audit, name):
                        issues.append(f"inputs: authorization.{name}: mismatch")
                if fresh.ghidra_runtime != paired.comparability.ghidra_runtime:
                    issues.append("inputs: comparability.ghidra_runtime: mismatch")
                for trial in paired.trials:
                    variant = trial.variant
                    evidence, prepared = fresh.evidence[variant], fresh.prepared.get(variant)
                    expected: dict[str, Any] = {
                        "trial_id": getattr(fresh.pair, variant).trial_id,
                        "manifest_sha256": evidence.manifest_sha256,
                        "artifact_sha256": evidence.artifact_sha256,
                        "evidence.evidence_sha256": evidence.evidence_sha256,
                        "evidence.evidence_schema": evidence.record()["evidence_schema"],
                        "evidence.evidence_size_bytes": evidence.evidence_size_bytes,
                        "analysis": fresh.analysis[variant],
                        "prepared": None if prepared is None else TrialPrepared(
                            rendered_prompt_sha256=prepared.rendered_prompt_sha256,
                            prompt_token_bound=prepared.prompt_token_bound,
                            reserved_tokens_per_attempt=prepared.reserved_tokens_per_attempt,
                            neutralized_symbol_occurrences=prepared.neutralized_count,
                            cross_trial_value_findings=fresh.cross_trial_value_findings[variant],
                        ),
                    }
                    actual: dict[str, Any] = {
                        "trial_id": trial.trial_id,
                        "manifest_sha256": trial.manifest_sha256,
                        "artifact_sha256": trial.artifact_sha256,
                        "evidence.evidence_sha256": trial.evidence.evidence_sha256,
                        "evidence.evidence_schema": trial.evidence.evidence_schema,
                        "evidence.evidence_size_bytes": trial.evidence.evidence_size_bytes,
                        "analysis": trial.analysis,
                        "prepared": trial.prepared,
                    }
                    issues.extend(f"inputs: {variant}.{name}: mismatch" for name in expected
                                  if expected[name] != actual[name])
    if issues:
        raise ExperimentVerificationError(issues)
    return paired


# --- Command-line interface -----------------------------------------------------------------------
# Output follows the diagnostics policy: role, field path and fixed code only. No rejected values,
# file contents, paths or provider messages reach the terminal.

def _load_inputs(args: Any) -> tuple[dict[str, TrialManifest], dict[str, bytes], list[str]]:
    manifests: dict[str, TrialManifest] = {}
    reports: dict[str, bytes] = {}
    issues: list[str] = []
    for variant in VARIANTS:
        role = f"{variant}-manifest"
        try:
            manifests[variant] = load_manifest(getattr(args, f"{variant}_manifest"))
        except LoadError as exc:
            issues.append(f"{role}: {exc.category}")
        except ValidationError as exc:
            issues.extend(f"{role}: {i}" for i in validation_issues(exc, MANIFEST_FIELDS, MANIFEST_ERROR_TYPES))
        role = f"{variant}-evidence"
        try:
            reports[variant] = read_regular_file(getattr(args, f"{variant}_evidence"), MAX_GHIDRA_REPORT_BYTES)
        except LoadError as exc:
            issues.append(f"{role}: {exc.category}")
    return manifests, reports, issues


def main(argv: list[str] | None = None) -> int:  # noqa: C901 - one dispatcher with fixed error mapping
    import sys

    from .diagnostics import SafeArgumentParser, terminal_text

    parser = SafeArgumentParser(
        prog="python -m aegis_lab.paired_trial",
        description="Run a controlled baseline/protected reconstruction trial pair offline (FakeOffline only)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="validate, prepare and run both trials; publish every record")
    verify = sub.add_parser("verify", help="revalidate a published experiment directory")
    for p, required in ((run, True), (verify, False)):
        for variant in VARIANTS:
            p.add_argument(f"--{variant}-manifest", type=Path, required=required)
            p.add_argument(f"--{variant}-evidence", type=Path, required=required,
                           help=f"{variant} Ghidra report (ghidra-analysis.json)")
    run.add_argument("--output-dir", type=Path, required=True,
                     help="new directory for the records (must not exist; never reused)")
    run.add_argument("--mode", choices=EXECUTION_MODES, required=True,
                     help="execution mode; only the local offline FakeOffline workflow is available")
    run.add_argument("--order-seed", type=int, default=None,
                     help=f"trial-order seed (0..{MAX_ORDER_SEED}); generated and recorded when omitted")
    run.add_argument("--blinded", action="store_true", help="withhold the target symbol name in both trials")
    run.add_argument("--max-output-tokens", type=int, default=None)
    run.add_argument("--top-p", type=float, default=None)
    verify.add_argument("directory", type=Path)
    args = parser.parse_args(argv)

    def fail(lines: list[str] | tuple[str, ...], code: int = EXIT_INVALID) -> int:
        print(f"paired trial {args.command} failed:", file=sys.stderr)
        for line in lines[:40]:
            print(f"  {terminal_text(line)}", file=sys.stderr)
        if len(lines) > 40:
            print(f"  <{len(lines) - 40} more issues not shown>", file=sys.stderr)
        return code

    try:
        if args.command == "verify":
            given = [getattr(args, f"{v}_{k}") for v in VARIANTS for k in ("manifest", "evidence")]
            kwargs: dict[str, Any] = {}
            if any(item is not None for item in given):
                if any(item is None for item in given):
                    return fail(["inputs: incomplete: give both manifests and both evidence files, or none"])
                manifests, reports, issues = _load_inputs(args)
                if issues:
                    return fail(issues)
                kwargs = {"baseline_manifest": manifests["baseline"], "protected_manifest": manifests["protected"],
                          "baseline_report": reports["baseline"], "protected_report": reports["protected"]}
            try:
                paired = verify_experiment(args.directory, **kwargs)
            except ExperimentVerificationError as exc:
                return fail(exc.issues)
            summary = paired.summary()
            summary["verification"] = ("consistent: paired record, referenced reconstruction records"
                                       + (" and re-prepared inputs" if kwargs else ""))
            print(json.dumps(summary, indent=2, sort_keys=True))
            return EXIT_COMPLETED

        if args.order_seed is not None and not 0 <= args.order_seed <= MAX_ORDER_SEED:
            return fail(["order-seed: out_of_range"])
        manifests, reports, issues = _load_inputs(args)
        if issues:
            return fail(issues)
        try:
            prepared_pair = prepare_pair(
                manifests["baseline"], manifests["protected"], reports["baseline"], reports["protected"],
                blinded=args.blinded, max_output_tokens=args.max_output_tokens, top_p=args.top_p)
            result = run_paired_trial(prepared_pair, args.output_dir, execution_mode=args.mode,
                                      order_seed=args.order_seed)
        except PairedTrialInputError as exc:
            return fail(exc.issues)
        except PairedTrialPublicationError as exc:
            return fail([f"output-dir: {exc.category}"], EXIT_PUBLICATION_FAILED)
        summary = result.record.summary()
        if not result.paired_record_published:
            # v2 records can contain exporter diagnostics and audit metadata. Only
            # the allowlisted summary may reach the terminal, even on publication failure.
            print(json.dumps(summary, indent=2, sort_keys=True))
            print(f"paired trial run: paired record not published: {result.paired_record_publication_error}",
                  file=sys.stderr)
            return result.exit_code
        print(json.dumps(summary, indent=2, sort_keys=True))
        if result.exit_code != EXIT_COMPLETED:
            print(f"paired trial run: {result.record.outcome.run_status}, {result.record.outcome.pair_status}",
                  file=sys.stderr)
        return result.exit_code
    except KeyboardInterrupt:
        print(f"paired trial {args.command} failed: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as exc:  # never let an unexpected message reach the terminal
        print(f"paired trial {args.command} failed: internal_error ({type(exc).__name__})", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
