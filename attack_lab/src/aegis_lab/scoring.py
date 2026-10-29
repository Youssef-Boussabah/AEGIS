"""Phase 4 paired scoring and comparison (``aegis.lab.behavior-comparison.v1``) and its CLI.

``score_paired_experiment`` scores both candidates of an existing
``aegis.lab.paired-trial.v2`` experiment and publishes, in a **new** directory:

- ``baseline-behavior-score.json`` and ``protected-behavior-score.json``
  (``aegis.lab.behavior-score.v1``), one per variant;
- ``behavior-comparison.json``, which references the paired experiment and both
  score records by digest.

The experiment directory is only read. Its records keep saying
``scoring: "not_performed"``: scoring is a separate, later record, and nothing
historical is rewritten.

Before anything is created, the runner re-verifies the paired experiment against
its four inputs (``verify_experiment``), prepares **both** trials
(``prepare_scoring``), requires identical controls (suite digest, interface,
scorer, policy) and checks execution permission for every trial that has a
candidate. Both variants use the same suite, interface, rules and policy, and
each gets its own fresh worker instance.

The comparison keeps four things apart:

- a **valid reconstruction candidate** (a verified candidate exists);
- a **behaviorally successful reconstruction** (``established`` only when the
  hidden suite passed in real isolated execution of a model-generated candidate;
  in this revision it is never established);
- a **completed paired comparison** (both variants reached a candidate-attributable
  outcome: match, mismatch or compilation failure);
- **evidence of a protection effect**, which is fixed to ``false`` in v1: one
  pair is not statistical evidence, whatever the two outcomes are.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, StrictInt, ValidationError, \
    model_validator

from .behavior_score import (
    CANDIDATE_ATTRIBUTABLE_STATUSES,
    MAX_SCORE_RECORD_BYTES,
    SCORE_RECORD_FIELDS,
    BehaviorScoreRecord,
    ExperimentReference,
    PreparedScoring,
    ScoreStatus,
    ScoringInputError,
    ScoringInterrupted,
    StopReason,
    not_started_record,
    parse_behavior_score,
    prepare_scoring,
    score_opened,
    score_trial,
)
from .canonical import canonical_json_bytes, canonical_sha256
from .diagnostics import SafeArgumentParser, model_field_names, terminal_text, validation_issues
from .hidden_suite import MAX_SUITE_BYTES, SUITE_ERROR_TYPES, HiddenSuite, parse_hidden_suite, suite_sha256
from .manifest import MANIFEST_ERROR_TYPES, ToolIdentity, TrialManifest, load_manifest
from .paired_trial import (
    _directory_identity,
    MAX_PAIRED_RECORD_BYTES,
    PAIRED_RECORD_FILE,
    ExperimentVerificationError,
    PairedTrialRecord,
    _create_output_directory,
    _publish,
    verify_experiment,
)
from .evidence import MAX_GHIDRA_REPORT_BYTES
from .reconstruction import MAX_RECORD_BYTES
from .safe_io import LoadError, PublishError, parse_strict_json, read_regular_file
from .scoring_policy import (
    POLICY_ERROR_TYPES,
    ExecutionRefused,
    SandboxPolicy,
    load_policy,
    planned_scorer_tool,
)
from .core_execution import OpenedSession, check_grant_binding, lab_bindings, open_trial_session, precheck_core

if TYPE_CHECKING:  # pragma: no cover
    from aegis_core.config import AegisConfig
    from aegis_core.lab_authorization import CandidateExecutionGrant
    from aegis_core.lab_execution import IsolationRuntime

COMPARISON_SCHEMA = "aegis.lab.behavior-comparison.v1"
COMPARISON_FILE = "behavior-comparison.json"
SCORE_FILES = {"baseline": "baseline-behavior-score.json", "protected": "protected-behavior-score.json"}
VARIANTS = ("baseline", "protected")
MAX_COMPARISON_BYTES = 256 * 1024

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Id32 = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Code = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:+-]{1,120}$")]
Note = Annotated[str, Field(min_length=1, max_length=500)]
NonNegInt = Annotated[StrictInt, Field(ge=0)]
Established = Literal["established", "not_established"]


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ScoreReference(StrictRecord):
    variant: Literal["baseline", "protected"]
    trial_id: Id32
    file: Literal["baseline-behavior-score.json", "protected-behavior-score.json"]
    file_sha256: Hash
    record_sha256: Hash
    result_sha256: Hash
    status: ScoreStatus
    stop_reason: StopReason
    criterion_satisfied: StrictBool
    required_cases: NonNegInt
    matched_cases: NonNegInt
    valid_candidate: StrictBool
    candidate_origin: Literal["offline_fake_provider", "model_provider", "none"]
    worker_kind: Literal["test_double", "isolated_sandbox", "none"]
    counts_as_behavioral_evidence: StrictBool
    behaviorally_successful_reconstruction: Established
    # Digests of the limits the runtime reported it enforced (None for a test double or no run).
    enforced_compile_limits_sha256: Hash | None
    enforced_execute_limits_sha256: Hash | None

    @model_validator(mode="after")
    def _file(self) -> ScoreReference:
        if self.file != SCORE_FILES[self.variant]:
            raise ValueError("score file name does not match the variant")
        return self


def _limits_digest(limits: Any) -> str | None:
    return None if limits is None else canonical_sha256(limits.model_dump(mode="json"))


def _score_reference(variant: str, record: BehaviorScoreRecord, data: bytes) -> ScoreReference:
    result = record.result
    return ScoreReference(
        variant=variant, trial_id=result.trial.trial_id, file=SCORE_FILES[variant],
        file_sha256=hashlib.sha256(data).hexdigest(), record_sha256=record.sha256(),
        result_sha256=record.result_sha256, status=result.outcome.status, stop_reason=result.outcome.stop_reason,
        criterion_satisfied=result.outcome.criterion_satisfied, required_cases=result.summary.required_cases,
        matched_cases=result.summary.matched_cases, valid_candidate=result.trial.candidate_origin != "none",
        candidate_origin=result.trial.candidate_origin, worker_kind=result.worker.kind,
        counts_as_behavioral_evidence=result.evidence.counts_as_behavioral_evidence,
        behaviorally_successful_reconstruction=result.outcome.behaviorally_successful_reconstruction,
        enforced_compile_limits_sha256=_limits_digest(result.worker.enforced_compile_limits),
        enforced_execute_limits_sha256=_limits_digest(result.worker.enforced_execute_limits))


class SharedControls(StrictRecord):
    """Settings both variants were scored with. They are required to be identical."""

    hidden_test_suite_sha256: Hash
    expected_interface: Annotated[str, Field(min_length=1, max_length=200)]
    abi: Literal["aegis.lab.c-abi.scalar-u32.v1"]
    scorer: ToolIdentity
    score_rule: Literal["all_hidden_tests_pass"]
    sandbox_policy_sha256: Hash
    scorer_configuration_sha256: Hash


def _controls(record: BehaviorScoreRecord) -> SharedControls:
    r = record.result
    return SharedControls(hidden_test_suite_sha256=r.suite.sha256, expected_interface=r.interface.text,
                          abi=r.interface.abi, scorer=r.scorer, score_rule=r.score_rule,
                          sandbox_policy_sha256=r.configuration.policy_sha256,
                          scorer_configuration_sha256=r.configuration.scorer_configuration_sha256)


class VariantFlags(StrictRecord):
    baseline: StrictBool
    protected: StrictBool


class VariantEstablished(StrictRecord):
    baseline: Established
    protected: Established


class ComparisonOutcome(StrictRecord):
    status: Literal["completed", "not_comparable"]
    reasons: tuple[Code, ...]
    pattern: Literal["both_passed", "both_failed", "baseline_only_passed", "protected_only_passed"] | None


class Distinctions(StrictRecord):
    valid_candidate: VariantFlags
    hidden_suite_passed: VariantFlags
    behaviorally_successful_reconstruction: VariantEstablished
    paired_comparison_completed: StrictBool
    protection_effect_established: Literal[False]
    protection_effect_reasons: Annotated[tuple[Code, ...], Field(min_length=1)]


def _derive(refs: tuple[ScoreReference, ScoreReference], final_identical: bool) -> tuple[ComparisonOutcome,
                                                                                         Distinctions]:
    base, prot = refs
    reasons = tuple(f"{r.variant}_{r.status}" for r in refs if r.status not in CANDIDATE_ATTRIBUTABLE_STATUSES)
    for stage in ("compile", "execute"):
        a, b = (getattr(r, f"enforced_{stage}_limits_sha256") for r in refs)
        if a is not None and b is not None and a != b:
            # Requested limits were identical (shared controls); what was enforced was not.
            reasons += (f"enforced_{stage}_limits_differ",)
    completed = not reasons
    pattern = None
    if completed:
        pattern = {(True, True): "both_passed", (False, False): "both_failed",
                   (True, False): "baseline_only_passed", (False, True): "protected_only_passed"}[
            (base.criterion_satisfied, prot.criterion_satisfied)]
    outcome = ComparisonOutcome(status="completed" if completed else "not_comparable", reasons=reasons,
                                pattern=pattern)
    effect = ["single_pair_is_not_statistical_evidence"]
    if not completed:
        effect.append("paired_comparison_not_completed")
    if any(r.candidate_origin == "offline_fake_provider" for r in refs):
        effect.append("candidates_scripted_by_offline_fake_provider")
    if any(r.worker_kind == "test_double" for r in refs):
        effect.append("worker_is_test_double_no_execution")
    if final_identical:
        effect.append("final_artifacts_identical")
    distinctions = Distinctions(
        valid_candidate=VariantFlags(baseline=base.valid_candidate, protected=prot.valid_candidate),
        hidden_suite_passed=VariantFlags(baseline=base.criterion_satisfied, protected=prot.criterion_satisfied),
        behaviorally_successful_reconstruction=VariantEstablished(
            baseline=base.behaviorally_successful_reconstruction,
            protected=prot.behaviorally_successful_reconstruction),
        paired_comparison_completed=completed, protection_effect_established=False,
        protection_effect_reasons=tuple(effect))
    return outcome, distinctions


class BehaviorComparisonRecord(StrictRecord):
    schema_version: Literal["aegis.lab.behavior-comparison.v1"] = COMPARISON_SCHEMA
    comparison_id: Id32
    created_at: AwareDatetime
    experiment: ExperimentReference
    pair_id: Id32
    final_artifacts_identical: StrictBool
    controls: SharedControls
    scores: tuple[ScoreReference, ScoreReference]
    outcome: ComparisonOutcome
    distinctions: Distinctions
    record_signed: Literal[False]
    attacker_visible: Literal[False]
    not_established: Annotated[tuple[Note, ...], Field(min_length=1, max_length=32)]
    limitations: Annotated[tuple[Note, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _integrity(self) -> BehaviorComparisonRecord:
        base, prot = self.scores
        if (base.variant, prot.variant) != VARIANTS:
            raise ValueError("scores are listed as baseline, then protected")
        if base.trial_id == prot.trial_id:
            raise ValueError("the two scores must belong to distinct trials")
        if (self.outcome, self.distinctions) != _derive(self.scores, self.final_artifacts_identical):
            raise ValueError("comparison outcome and distinctions do not follow from the scores")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_json_bytes(self) -> bytes:
        data = (json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
        if len(data) > MAX_COMPARISON_BYTES:
            raise ValueError("comparison record exceeds the maximum serialized size")
        return data

    def summary(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "comparison_sha256": self.sha256(),
            "experiment_id": self.experiment.experiment_id,
            "pair_id": self.pair_id,
            "scores": {r.variant: {"status": r.status, "criterion_satisfied": r.criterion_satisfied,
                                   "required_cases": r.required_cases, "matched_cases": r.matched_cases,
                                   "worker_kind": r.worker_kind, "result_sha256": r.result_sha256}
                       for r in self.scores},
            "comparison": self.outcome.status,
            "pattern": self.outcome.pattern,
            "reasons": list(self.outcome.reasons),
            "valid_candidate": self.distinctions.valid_candidate.model_dump(),
            "behaviorally_successful_reconstruction":
                self.distinctions.behaviorally_successful_reconstruction.model_dump(),
            "paired_comparison_completed": self.distinctions.paired_comparison_completed,
            "protection_effect_established": False,
            "protection_effect_reasons": list(self.distinctions.protection_effect_reasons),
        }


COMPARISON_FIELDS = model_field_names(BehaviorComparisonRecord)


def parse_behavior_comparison(data: bytes) -> BehaviorComparisonRecord:
    if len(data) > MAX_COMPARISON_BYTES:
        raise LoadError("too_large")
    parse_strict_json(data)
    return BehaviorComparisonRecord.model_validate_json(data)


_COMPARISON_NOT_ESTABLISHED = (
    "Any protection effect: one baseline/protected pair is not statistical evidence, whatever its outcome.",
    "That the hidden suite covers all behavior of the original function.",
    "Who produced these records: they are unsigned and are not authenticated provenance.",
)
_COMPARISON_LIMITATIONS = (
    "The comparison and both score records must never enter an attacker workspace or a retry.",
    "An infrastructure failure, an incomplete run or a missing candidate makes the pair not comparable; "
    "it is never read as protection resistance.",
    "Both variants were scored in the fixed order baseline, then protected, each with a fresh worker instance.",
)


# --- Paired scoring -------------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(UTC)


class PairScoringPublicationError(OSError):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class PairScoringInterrupted(KeyboardInterrupt):
    def __init__(self, result: PairScoreResult) -> None:
        self.result = result
        super().__init__("paired scoring interrupted")


@dataclass
class PairScoreResult:
    directory: Path
    records: dict[str, BehaviorScoreRecord] = field(default_factory=dict)
    comparison: BehaviorComparisonRecord | None = None
    refusal: ExecutionRefused | None = None


def _experiment_reference(experiment_dir: Path, paired: PairedTrialRecord) -> ExperimentReference:
    try:
        data = read_regular_file(experiment_dir / PAIRED_RECORD_FILE, MAX_PAIRED_RECORD_BYTES)
    except LoadError as exc:  # pragma: no cover - verify_experiment just read it
        raise ScoringInputError([f"experiment: paired-record: {exc.category}"]) from None
    return ExperimentReference(experiment_id=paired.experiment_id, paired_record_sha256=paired.sha256(),
                               paired_file_sha256=hashlib.sha256(data).hexdigest())


def prepare_paired_scoring(experiment_dir: str | os.PathLike[str], *, manifests: dict[str, TrialManifest],
                           reports: dict[str, bytes], suite_bytes: bytes,
                           policy: SandboxPolicy) -> tuple[PairedTrialRecord, dict[str, PreparedScoring]]:
    """Re-verify the experiment and prepare both trials. Raises ``ScoringInputError``; runs nothing."""
    root = Path(experiment_dir)
    try:
        paired = verify_experiment(root, baseline_manifest=manifests.get("baseline"),
                                   protected_manifest=manifests.get("protected"),
                                   baseline_report=reports.get("baseline"), protected_report=reports.get("protected"))
    except ExperimentVerificationError as exc:
        raise ScoringInputError([f"experiment: {issue}" for issue in exc.issues]) from None
    if any(manifests.get(v) is None or reports.get(v) is None for v in VARIANTS):
        raise ScoringInputError(["inputs: incomplete: both manifests and both reports are required"])
    experiment = _experiment_reference(root, paired)
    prepared: dict[str, PreparedScoring] = {}
    issues: list[str] = []
    for trial in paired.trials:
        variant = trial.variant
        record_bytes = None
        ref = trial.reconstruction
        if ref is not None and ref.publication == "published":
            try:
                record_bytes = read_regular_file(root / ref.file, MAX_RECORD_BYTES)
            except LoadError as exc:  # pragma: no cover - verify_experiment just read it
                issues.append(f"{variant}-reconstruction: {exc.category}")
                continue
        try:
            prepared[variant] = prepare_scoring(manifests[variant], reconstruction_bytes=record_bytes,
                                                evidence_bytes=reports[variant], suite_bytes=suite_bytes,
                                                policy=policy, experiment=experiment)
        except ScoringInputError as exc:
            issues.extend(f"{variant}-{issue}" for issue in exc.issues)
    if issues:
        raise ScoringInputError(issues)
    base, prot = prepared["baseline"], prepared["protected"]
    shared = {
        "suite_sha256": (base.suite_sha256, prot.suite_sha256),
        "interface": (base.interface.text, prot.interface.text),
        "scorer": (base.manifest.scoring.scorer, prot.manifest.scoring.scorer),
        "policy": (base.policy.sha256(), prot.policy.sha256()),
    }
    differing = [f"pair: {name}: differs" for name, (a, b) in shared.items() if a != b]
    if differing:  # pragma: no cover - validate_pair and the shared suite/policy already imply equality
        raise ScoringInputError(differing)
    return paired, prepared


def _needs_execution(prepared: PreparedScoring) -> bool:
    return prepared.interface.status == "supported" and prepared.candidate_source is not None


def score_paired_experiment(
    experiment_dir: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    *,
    manifests: dict[str, TrialManifest],
    reports: dict[str, bytes],
    suite_bytes: bytes,
    policy: SandboxPolicy,
    config: AegisConfig,
    grant: CandidateExecutionGrant | None,
    runtime_factory: Callable[[], IsolationRuntime] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = _utc_now,
    comparison_id: str | None = None,
) -> PairScoreResult:
    """Score both trials of a verified paired experiment and publish three new records.

    Before the output directory exists, the runner checks the grant against the
    Lab's inputs for every trial with a candidate, asks Core to authorize it, and
    opens one Core session per such trial (each with its own runtime instance:
    ``runtime_factory()`` in tests, Core's configured runtime otherwise). Every
    refusal raises ``ExecutionRefused`` and leaves nothing behind. A runtime that
    fails to start is recorded as an infrastructure failure. Afterwards each
    variant's record is published as soon as it is complete; the comparison is
    published last.
    """
    paired, prepared = prepare_paired_scoring(experiment_dir, manifests=manifests, reports=reports,
                                              suite_bytes=suite_bytes, policy=policy)
    executing = [v for v in VARIANTS if _needs_execution(prepared[v])]
    opened: dict[str, OpenedSession] = {}
    if executing:
        check_grant_binding(grant, [prepared[v] for v in executing])
        precheck_core(config, grant, now(), [prepared[v] for v in executing])
        runtimes: list[object] = []
        try:
            for variant in executing:
                runtime = None
                if runtime_factory is not None:
                    runtime = runtime_factory()
                    if runtime is None or any(runtime is previous for previous in runtimes):
                        raise ExecutionRefused("runtime_reused")
                    runtimes.append(runtime)
                opened[variant] = open_trial_session(config, grant, lab_bindings(prepared[variant]),
                                                     runtime=runtime, clock=now)
        except BaseException:
            for session in opened.values():
                session.close_quietly()
            raise
    directory = Path(output_dir)
    try:
        identity = _create_output_directory(directory)
    except PublishError as exc:
        for session in opened.values():
            session.close_quietly()
        raise PairScoringPublicationError(exc.category) from None
    result = PairScoreResult(directory=directory)
    interrupted = False
    try:
        for variant in VARIANTS:
            if interrupted:
                record = not_started_record(prepared[variant], now=now)
                if variant in opened:
                    opened.pop(variant).close_quietly()
            elif variant in opened:
                try:
                    record = score_opened(prepared[variant], opened.pop(variant), grant=grant, monotonic=monotonic,
                                          now=now)
                except ScoringInterrupted as exc:
                    record, interrupted = exc.record, True
            else:
                record = score_opened_without_execution(prepared[variant], now=now)
            result.records[variant] = record
            # Private Core observations contain case arguments. Publish outside
            # reconstruction workspaces, keyed by the existing canonical digest.
            archive = directory / f"{variant}-core-records"
            try:
                if _directory_identity(directory) != identity:
                    raise PublishError("directory_replaced")
                archive_identity = _create_output_directory(archive)
            except PublishError as exc:
                raise PairScoringPublicationError(exc.category) from None
            for digest, data in record.private_core_records.items():
                _publish_or_raise(archive, archive_identity, digest + ".json", data, 32 * 1024 * 1024)
            _publish_or_raise(directory, identity, SCORE_FILES[variant], record.to_json_bytes(),
                              MAX_SCORE_RECORD_BYTES)
    finally:
        for session in opened.values():
            session.close_quietly()
    result.comparison = _build_comparison(paired, result.records, comparison_id=comparison_id, now=now)
    _publish_or_raise(directory, identity, COMPARISON_FILE, result.comparison.to_json_bytes(), MAX_COMPARISON_BYTES)
    if interrupted:
        raise PairScoringInterrupted(result)
    return result


def score_opened_without_execution(prepared: PreparedScoring, *, now: Callable[[], datetime]) -> BehaviorScoreRecord:
    """A trial that needs no execution (unsupported interface or no candidate): never contacts Core."""
    return score_trial(prepared, config=None, grant=None, now=now)


def _publish_or_raise(directory: Path, identity: tuple[int, int], name: str, data: bytes, limit: int) -> None:
    try:
        _publish(directory, identity, name, data, limit)
    except PublishError as exc:
        raise PairScoringPublicationError(exc.category) from None


def _build_comparison(paired: PairedTrialRecord, records: dict[str, BehaviorScoreRecord], *,
                      comparison_id: str | None, now: Callable[[], datetime]) -> BehaviorComparisonRecord:
    refs = tuple(_score_reference(v, records[v], records[v].to_json_bytes()) for v in VARIANTS)
    controls = {_controls(records[v]) for v in VARIANTS}
    if len(controls) != 1:  # pragma: no cover - prepare_paired_scoring enforces shared controls
        raise ScoringInputError(["pair: controls: differ"])
    final_identical = paired.comparability.final_artifacts_identical
    outcome, distinctions = _derive(refs, final_identical)
    limitations = list(_COMPARISON_LIMITATIONS)
    if final_identical:
        limitations.append("The final artifacts are byte-identical: any outcome difference cannot be attributed "
                           "to protection.")
    return BehaviorComparisonRecord(
        comparison_id=comparison_id or secrets.token_hex(16), created_at=now(),
        experiment=records["baseline"].result.experiment, pair_id=paired.pair_id,
        final_artifacts_identical=final_identical, controls=controls.pop(), scores=refs, outcome=outcome,
        distinctions=distinctions, record_signed=False, attacker_visible=False,
        not_established=_COMPARISON_NOT_ESTABLISHED, limitations=tuple(limitations))


# --- Verification ---------------------------------------------------------------------------------

class ScoreVerificationError(ValueError):
    def __init__(self, issues: list[str]) -> None:
        self.issues = list(issues)
        super().__init__("; ".join(self.issues))


def verify_behavior_scores(
    score_dir: str | os.PathLike[str],
    experiment_dir: str | os.PathLike[str],
    *,
    manifests: dict[str, TrialManifest] | None = None,
    reports: dict[str, bytes] | None = None,
    suite_bytes: bytes | None = None,
    policy: SandboxPolicy | None = None,
) -> BehaviorComparisonRecord:
    """Reload the comparison and both score records and revalidate every reference.

    Always: strict parsing (which re-derives each record's own invariants), file and
    canonical digests, every repeated field, identical controls, and the binding of
    each score to the paired experiment (re-verified with ``verify_experiment``,
    with its four inputs when given). With ``suite_bytes`` or ``policy``, also their
    digests. Raises ``ScoreVerificationError``. Consistency only, not authorship.
    """
    root, experiment_root = Path(score_dir), Path(experiment_dir)
    try:
        comparison = parse_behavior_comparison(read_regular_file(root / COMPARISON_FILE, MAX_COMPARISON_BYTES))
    except LoadError as exc:
        raise ScoreVerificationError([f"comparison: {exc.category}"]) from None
    except ValidationError as exc:
        raise ScoreVerificationError([f"comparison: {issue}"
                                      for issue in validation_issues(exc, COMPARISON_FIELDS)]) from None
    manifests, reports = manifests or {}, reports or {}
    try:
        paired = verify_experiment(experiment_root, baseline_manifest=manifests.get("baseline"),
                                   protected_manifest=manifests.get("protected"),
                                   baseline_report=reports.get("baseline"), protected_report=reports.get("protected"))
    except ExperimentVerificationError as exc:
        raise ScoreVerificationError([f"experiment: {issue}" for issue in exc.issues]) from None
    issues: list[str] = []
    expected_ref = _experiment_reference(experiment_root, paired)
    if comparison.experiment != expected_ref:
        issues.append("comparison: experiment: mismatch")
    if comparison.pair_id != paired.pair_id:
        issues.append("comparison: pair_id: mismatch")
    if comparison.final_artifacts_identical != paired.comparability.final_artifacts_identical:
        issues.append("comparison: final_artifacts_identical: mismatch")
    records: dict[str, BehaviorScoreRecord] = {}
    for ref, trial in zip(comparison.scores, paired.trials):
        role = f"{ref.variant}-score"
        try:
            data = read_regular_file(root / ref.file, MAX_SCORE_RECORD_BYTES)
            record = parse_behavior_score(data)
        except LoadError as exc:
            issues.append(f"{role}: {exc.category}")
            continue
        except ValidationError as exc:
            issues.extend(f"{role}: {issue}" for issue in validation_issues(exc, SCORE_RECORD_FIELDS))
            continue
        records[ref.variant] = record
        archive = root / f"{ref.variant}-core-records"
        for core_ref in record.run.core_records:
            try:
                raw = read_regular_file(archive / (core_ref.record_sha256 + ".json"), 32 * 1024 * 1024)
                if hashlib.sha256(raw).hexdigest() != core_ref.record_sha256:
                    issues.append(f"{role}: core_record: digest_mismatch")
            except LoadError:
                issues.append(f"{role}: core_record: unavailable")
        if _score_reference(ref.variant, record, data) != ref:
            issues.append(f"{role}: reference: mismatch")
        t = record.result.trial
        expected_rec = None
        if trial.reconstruction is not None and trial.reconstruction.publication == "published":
            expected_rec = (trial.reconstruction.file_sha256, trial.reconstruction.record_sha256,
                            trial.reconstruction.candidate_sha256)
        actual_rec = None
        if t.reconstruction is not None:
            actual_rec = (t.reconstruction.file_sha256, t.reconstruction.record_sha256,
                          t.reconstruction.candidate_sha256)
        checks = {
            "trial_id": t.trial_id == trial.trial_id,
            "pair_id": t.pair_id == paired.pair_id,
            "variant": t.variant == trial.variant,
            "manifest_sha256": t.manifest_sha256 == trial.manifest_sha256,
            "artifact_sha256": t.artifact_sha256 == trial.artifact_sha256,
            "evidence_sha256": t.evidence_sha256 == trial.evidence.evidence_sha256,
            "reconstruction": actual_rec == expected_rec,
            "experiment": record.result.experiment == comparison.experiment,
        }
        issues.extend(f"{role}: {name}: mismatch" for name, ok in checks.items() if not ok)
        if _controls(record) != comparison.controls:
            issues.append(f"{role}: controls: mismatch")
    if suite_bytes is not None and suite_sha256(suite_bytes) != comparison.controls.hidden_test_suite_sha256:
        issues.append("inputs: suite: mismatch")
    if policy is not None and policy.sha256() != comparison.controls.sandbox_policy_sha256:
        issues.append("inputs: policy: mismatch")
    if issues:
        raise ScoreVerificationError(issues)
    return comparison


# --- Command-line interface -----------------------------------------------------------------------
# Output follows the Lab diagnostics policy: role, field path and fixed code only.

EXIT_OK = 0
EXIT_INVALID = 2
EXIT_INTERNAL = 3
EXIT_REFUSED = 4
EXIT_PUBLICATION_FAILED = 5
EXIT_INTERRUPTED = 130

POLICY_FIELDS = model_field_names(SandboxPolicy)
SUITE_FIELDS = model_field_names(HiddenSuite)
MANIFEST_FIELDS = model_field_names(TrialManifest)


def _issues(role: str, exc: Exception, fields: frozenset[str], custom: frozenset[str] = frozenset()) -> list[str]:
    if isinstance(exc, LoadError):
        return [f"{role}: {exc.category}"]
    if isinstance(exc, ValidationError):
        return [f"{role}: {issue}" for issue in validation_issues(exc, fields, custom)]
    raise TypeError("unsupported failure type")


def _fail(issues: list[str], code: int = EXIT_INVALID) -> int:
    print("scoring failed:", file=sys.stderr)
    for issue in issues[:40]:
        print(f"  {terminal_text(issue)}", file=sys.stderr)
    return code


def _load_pair_inputs(args: Any) -> tuple[dict[str, TrialManifest], dict[str, bytes], list[str]]:
    manifests: dict[str, TrialManifest] = {}
    reports: dict[str, bytes] = {}
    issues: list[str] = []
    for variant in VARIANTS:
        manifest_path = getattr(args, f"{variant}_manifest")
        evidence_path = getattr(args, f"{variant}_evidence")
        if manifest_path is None and evidence_path is None:
            continue
        try:
            manifests[variant] = load_manifest(manifest_path)
        except (LoadError, ValidationError, TypeError) as exc:
            issues.extend(_issues(f"{variant}-manifest", exc, MANIFEST_FIELDS, MANIFEST_ERROR_TYPES)
                          if not isinstance(exc, TypeError) else [f"{variant}-manifest: missing"])
        try:
            reports[variant] = read_regular_file(evidence_path, MAX_GHIDRA_REPORT_BYTES)
        except (LoadError, TypeError) as exc:
            issues.append(f"{variant}-evidence: {exc.category}" if isinstance(exc, LoadError)
                          else f"{variant}-evidence: missing")
    return manifests, reports, issues


def main(argv: list[str] | None = None) -> int:  # noqa: C901 - one dispatcher with fixed error mapping
    parser = SafeArgumentParser(prog="python -m aegis_lab.scoring",
                                description="Phase 4 behavioral scoring (isolated execution is not enabled)")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="print the scorer identity to declare for a policy")
    plan.add_argument("--policy", type=Path, required=True)
    digest = sub.add_parser("suite-digest", help="validate a hidden suite and print its digest (never its contents)")
    digest.add_argument("suite", type=Path)
    for name in ("score-pair", "verify"):
        command = sub.add_parser(name)
        if name == "verify":
            command.add_argument("score_dir", type=Path)
        command.add_argument("experiment_dir", type=Path)
        for variant in VARIANTS:
            command.add_argument(f"--{variant}-manifest", type=Path, default=None)
            command.add_argument(f"--{variant}-evidence", type=Path, default=None)
        command.add_argument("--suite", type=Path, default=None)
        command.add_argument("--policy", type=Path, default=None)
        if name == "score-pair":
            command.add_argument("--config", type=Path, default=None)
            command.add_argument("--grant", type=Path, default=None)
            command.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            try:
                policy = load_policy(args.policy)
            except (LoadError, ValidationError) as exc:
                return _fail(_issues("policy", exc, POLICY_FIELDS, POLICY_ERROR_TYPES))
            print(json.dumps({"scorer": planned_scorer_tool(policy).model_dump(mode="json"),
                              "sandbox_policy_sha256": policy.sha256()}, indent=2, sort_keys=True))
            return EXIT_OK
        if args.command == "suite-digest":
            try:
                data = read_regular_file(args.suite, MAX_SUITE_BYTES)
                suite = parse_hidden_suite(data)
            except (LoadError, ValidationError) as exc:
                return _fail(_issues("suite", exc, SUITE_FIELDS, SUITE_ERROR_TYPES))
            print(json.dumps({"hidden_test_suite_sha256": suite_sha256(data), "abi": suite.abi,
                              "case_count": len(suite.cases)}, indent=2, sort_keys=True))
            return EXIT_OK
        manifests, reports, issues = _load_pair_inputs(args)
        suite_bytes = policy = None
        if args.suite is not None:
            try:
                suite_bytes = read_regular_file(args.suite, MAX_SUITE_BYTES)
            except LoadError as exc:
                issues.append(f"suite: {exc.category}")
        if args.policy is not None:
            try:
                policy = load_policy(args.policy)
            except (LoadError, ValidationError) as exc:
                issues.extend(_issues("policy", exc, POLICY_FIELDS, POLICY_ERROR_TYPES))
        if args.command == "verify":
            if issues:
                return _fail(issues)
            try:
                comparison = verify_behavior_scores(args.score_dir, args.experiment_dir, manifests=manifests,
                                                    reports=reports, suite_bytes=suite_bytes, policy=policy)
            except ScoreVerificationError as exc:
                return _fail(exc.issues)
            print(json.dumps({**comparison.summary(), "verification": "consistent"}, indent=2, sort_keys=True))
            return EXIT_OK
        # score-pair: Core decides. With Core's configured runtime it refuses in this revision.
        from aegis_core.config import load_config
        from aegis_core.errors import AegisError
        from aegis_core.lab_authorization import load_grant

        if suite_bytes is None:
            issues.append("suite: missing")
        if policy is None:
            issues.append("policy: missing")
        config = grant = None
        for role, path, loader in (("config", args.config, load_config), ("grant", args.grant, load_grant)):
            if path is None:
                issues.append(f"{role}: missing")
                continue
            try:
                loaded = loader(path)
            except AegisError as exc:
                issues.append(f"{role}: {exc.code.value}")
                continue
            if role == "config":
                config = loaded
            else:
                grant = loaded
        if issues:
            return _fail(issues)
        try:
            result = score_paired_experiment(args.experiment_dir, args.output_dir, manifests=manifests,
                                             reports=reports, suite_bytes=suite_bytes, policy=policy, config=config,
                                             grant=grant)
        except ScoringInputError as exc:
            return _fail(exc.issues)
        except ExecutionRefused as exc:
            print(f"scoring refused: {exc.code} ({', '.join(exc.reasons)})", file=sys.stderr)
            return EXIT_REFUSED
        except PairScoringPublicationError as exc:
            print(f"scoring failed: publication: {exc.category}", file=sys.stderr)
            return EXIT_PUBLICATION_FAILED
        except PairScoringInterrupted as exc:
            print(json.dumps({**exc.result.comparison.summary(), "run": "interrupted"}, indent=2, sort_keys=True))
            return EXIT_INTERRUPTED
        print(json.dumps(result.comparison.summary(), indent=2, sort_keys=True))
        return EXIT_OK
    except Exception as exc:  # never let an unexpected message reach the terminal
        print(f"scoring failed: internal_error ({type(exc).__name__})", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
