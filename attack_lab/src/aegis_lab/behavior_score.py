"""Independent behavioral scoring of one reconstruction candidate (``aegis.lab.behavior-score.v1``).

Phase 4. The trusted coordinator in this module:

1. **Validates inputs** before anything runs (``prepare_scoring``): the trial
   manifest; the Phase 2 Ghidra evidence bound to that manifest (exact report
   bytes); the Phase 3A ``aegis.lab.reconstruction.v2`` record and its
   candidate (digest recomputed by strict parsing); the record's trial, pair,
   variant, manifest, artifact and evidence identities; the hidden suite, whose
   file digest must equal ``scoring.hidden_test_suite_sha256``; and the scorer
   identity, which must equal ``planned_scorer_tool(policy)``.
2. **Classifies the interface** against ``aegis.lab.c-abi.scalar-u32.v1``.
3. **Defers authorization to Core.** The Lab holds no execution permission. It
   checks that Core's ``CandidateExecutionGrant`` describes exactly its inputs
   (``aegis_lab.core_execution.check_grant_binding``: reference, Lab bindings,
   candidate digest, target artifact, flags, limits, budgets). Core then decides
   (three gates, window, ceilings) and opens a session, re-checking its gates
   before every stage. Refusals raise ``ExecutionRefused`` before any candidate
   byte is sent. With Core's configured runtime, every attempt is refused in this
   revision (``SANDBOX_UNAVAILABLE``). Tests inject Core's non-executing scripted
   runtime, and records then say ``test_double``.
4. **Drives the worker**: preflight (runtime, compiler and *effective* limits
   must equal the policy), one compilation, then one fresh execution per case.
   The worker gets the case arguments only. Expected values stay here.
5. **Classifies** each case and the trial, and builds a strict record whose
   ``result`` section is deterministic and fingerprinted (``result_sha256``).

Classification never turns an infrastructure problem into a candidate result:
a worker error, contract violation or failed cleanup is ``infrastructure_failure``
and is never evidence about the candidate or about any protection. The
``all_hidden_tests_pass`` criterion is satisfied only when every case of the
suite completed and matched.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, PrivateAttr, StrictBool, StrictInt, ValidationError, \
    model_validator

from .c_abi import (
    ABI_VERSION,
    CANDIDATE_FILE,
    CANDIDATE_UNIT_FILE,
    HARNESS_FILE,
    HARNESS_VERSION,
    OBSERVATION_PROTOCOL,
    InterfaceError,
    check_symbol,
    encode_arguments,
    harness_sha256,
    harness_sources,
    parse_interface,
    parse_result_line,
)
from .canonical import canonical_json_bytes, canonical_sha256
from .diagnostics import model_field_names, validation_issues
from .evidence import EvidenceBindingError, GhidraEvidence, bind_ghidra_evidence
from .ghidra import AnalysisReport, ReportInvariantError
from .hidden_suite import HIDDEN_SUITE_SCHEMA, SUITE_ERROR_TYPES, HiddenSuite, parse_hidden_suite, suite_sha256
from .manifest import ToolIdentity, TrialManifest
from .provider import OFFLINE_ENDPOINT, OFFLINE_PROVIDER_NAME
from .reconstruction import ReconstructionRecord, parse_reconstruction_record
from .safe_io import LoadError, parse_strict_json
from .core_execution import (
    CORE_CONTRACT,
    CoreSessionWorker,
    OpenedSession,
    check_grant_binding,
    lab_bindings,
    open_trial_session,
    precheck_core,
)
from .scoring_policy import (
    BEHAVIOR_SCORE_SCHEMA,
    SCORE_RULE,
    SCORER_NAME,
    CompileLimits,
    SandboxPolicy,
    SandboxRuntime,
    StageLimits,
    planned_scorer_tool,
    scorer_configuration_sha256,
)
from .scoring_worker import (
    WORKER_ERROR_CODES,
    WORKER_PROTOCOL,
    CompileObservation,
    CompileRequest,
    EnforcedLimits,
    ExecuteObservation,
    ExecuteRequest,
    StageRefused,
    WorkerError,
    WorkerPreflight,
)

if TYPE_CHECKING:  # pragma: no cover
    from aegis_core.config import AegisConfig
    from aegis_core.lab_authorization import CandidateExecutionGrant
    from aegis_core.lab_execution import IsolationRuntime

MAX_SCORE_RECORD_BYTES = 8 * 1024 * 1024
# Compiled units, in order. ``candidate.c`` is staged and included by the candidate unit, never compiled alone.
TRANSLATION_UNITS = (HARNESS_FILE, CANDIDATE_UNIT_FILE)
MAX_DIAGNOSTIC_TEXT_BYTES = 16 * 1024

CaseClass = Literal["match", "mismatch", "runtime_crash", "timeout", "resource_limit_exceeded",
                    "malformed_output", "infrastructure_failure", "not_evaluated"]
CASE_CLASSES: tuple[str, ...] = CaseClass.__args__  # type: ignore[attr-defined]
# Outcomes the candidate itself produced inside the declared limits.
CANDIDATE_CASE_CLASSES = frozenset({"match", "mismatch", "runtime_crash", "timeout", "resource_limit_exceeded",
                                    "malformed_output"})
ScoreStatus = Literal["behavioral_match", "behavioral_mismatch", "compilation_failed", "unsupported_interface",
                      "infrastructure_failure", "incomplete", "not_evaluated"]
SCORE_STATUSES: tuple[str, ...] = ScoreStatus.__args__  # type: ignore[attr-defined]
# Statuses that describe the candidate (and so could be compared across a pair).
CANDIDATE_ATTRIBUTABLE_STATUSES = frozenset({"behavioral_match", "behavioral_mismatch", "compilation_failed"})
StopReason = Literal["all_cases_evaluated", "no_candidate", "interface_not_supported", "compilation_failed",
                     "worker_preflight_failed", "worker_failure", "worker_cleanup_failed",
                     "scoring_deadline_exceeded", "core_refused", "interrupted", "not_started"]
_STATUS_FOR_STOP = {
    "no_candidate": "not_evaluated",
    "interface_not_supported": "unsupported_interface",
    "compilation_failed": "compilation_failed",
    "worker_preflight_failed": "infrastructure_failure",
    "worker_failure": "infrastructure_failure",
    "worker_cleanup_failed": "infrastructure_failure",
    "scoring_deadline_exceeded": "incomplete",
    "core_refused": "incomplete",
    "interrupted": "incomplete",
    "not_started": "incomplete",
}
_PRE_EXECUTION_STOPS = frozenset({"no_candidate", "interface_not_supported", "worker_preflight_failed",
                                  "not_started"})

# Infrastructure codes: the worker's own plus what the coordinator detects in its replies.
INFRASTRUCTURE_CODES = WORKER_ERROR_CODES | frozenset({
    "worker_contract_violation",
    "observation_exceeds_limit",
    "binary_missing",
    "runtime_mismatch",
    "compiler_identity_mismatch",
    "limits_mismatch",
    "limits_not_enforced",
    "identity_not_observed",
})
InfrastructureCode = Literal[tuple(sorted(INFRASTRUCTURE_CODES))]  # type: ignore[valid-type]
LimitName = Literal["cpu", "memory", "processes", "scratch", "stdout", "stderr", "binary"]

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Id32 = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
NonNegInt = Annotated[StrictInt, Field(ge=0)]
Seconds = Annotated[float, Field(ge=0, allow_inf_nan=False)]
Note = Annotated[str, Field(min_length=1, max_length=500)]
Code = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:+-]{1,120}$")]
ExitCode = Annotated[StrictInt, Field(ge=0, le=255)]
Signal = Annotated[StrictInt, Field(ge=1, le=64)]


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- Record ---------------------------------------------------------------------------------------

class ReconstructionBinding(StrictRecord):
    file_sha256: Hash
    record_sha256: Hash
    status: Annotated[str, Field(min_length=1, max_length=64)]
    provider: Annotated[str, Field(min_length=1, max_length=200)]
    endpoint: Annotated[str, Field(min_length=1, max_length=2048)]
    external_disclosure: StrictBool
    candidate_sha256: Hash | None


class TrialBinding(StrictRecord):
    trial_id: Id32
    pair_id: Id32
    variant: Literal["baseline", "protected"]
    manifest_sha256: Hash
    artifact_sha256: Hash
    evidence_schema: Literal["aegis.lab.ghidra.v1"]
    evidence_sha256: Hash
    reconstruction: ReconstructionBinding | None
    candidate_origin: Literal["offline_fake_provider", "model_provider", "none"]

    @model_validator(mode="after")
    def _origin(self) -> TrialBinding:
        if _candidate_origin(self.reconstruction) != self.candidate_origin:
            raise ValueError("candidate_origin does not follow from the reconstruction record")
        return self


def _candidate_origin(ref: ReconstructionBinding | None) -> str:
    if ref is None or ref.candidate_sha256 is None:
        return "none"
    if (ref.provider, ref.endpoint, ref.external_disclosure) == (OFFLINE_PROVIDER_NAME, OFFLINE_ENDPOINT, False):
        return "offline_fake_provider"
    return "model_provider"


class ExperimentReference(StrictRecord):
    """The ``aegis.lab.paired-trial.v2`` experiment the candidate came from (never modified)."""

    experiment_id: Id32
    paired_record_sha256: Hash
    paired_file_sha256: Hash


class SuiteBinding(StrictRecord):
    schema_version: Literal["aegis.lab.hidden-suite.v1"]
    sha256: Hash
    parsed: StrictBool
    suite_id: Id32 | None
    case_count: Annotated[StrictInt, Field(ge=1)] | None
    reference_method: Literal["frozen_reference_outputs"] | None
    reference_implementation_sha256: Hash | None

    @model_validator(mode="after")
    def _parsed(self) -> SuiteBinding:
        details = (self.suite_id, self.case_count, self.reference_method, self.reference_implementation_sha256)
        if self.parsed != all(v is not None for v in details) or (not self.parsed and any(
                v is not None for v in details)):
            raise ValueError("suite details are recorded exactly when the suite was parsed")
        return self


class InterfaceRecord(StrictRecord):
    text: Annotated[str, Field(min_length=1, max_length=200)]
    abi: Literal["aegis.lab.c-abi.scalar-u32.v1"]
    symbol: Annotated[str, Field(min_length=1, max_length=200)] | None
    status: Literal["supported", "unsupported", "invalid"]
    code: Code | None
    arity: Annotated[StrictInt, Field(ge=0, le=16)] | None

    @model_validator(mode="after")
    def _recomputed(self) -> InterfaceRecord:
        if (self.status, self.code, self.arity) != _interface_facts(self.text, self.symbol):
            raise ValueError("interface classification does not follow from the interface and symbol")
        return self


def _interface_facts(text: str, symbol: str | None) -> tuple[str, str | None, int | None]:
    try:
        arity = parse_interface(text).arity
        if symbol is not None:
            check_symbol(symbol)
    except InterfaceError as exc:
        return exc.kind, exc.code, None
    return "supported", None, arity


class ConfigurationRecord(StrictRecord):
    policy: SandboxPolicy
    policy_sha256: Hash
    scorer_configuration_sha256: Hash
    abi: Literal["aegis.lab.c-abi.scalar-u32.v1"]
    harness_version: Literal["aegis.lab.c-harness.scalar-u32.v1"]
    observation_protocol: Literal["aegis.lab.c-observation.result-line.v1"]
    harness_sha256: Hash | None

    @model_validator(mode="after")
    def _digests(self) -> ConfigurationRecord:
        if self.policy.sha256() != self.policy_sha256:
            raise ValueError("policy_sha256 does not match the policy")
        if scorer_configuration_sha256(self.policy) != self.scorer_configuration_sha256:
            raise ValueError("scorer_configuration_sha256 does not match the policy")
        return self


class GrantRecord(StrictRecord):
    """The Core execution grant this trial ran under. Core is the only execution authority."""

    schema_version: Literal["aegis.core.candidate-execution-grant.v1"]
    grant_id: Id32
    grant_sha256: Hash
    authorization_reference: Annotated[str, Field(min_length=1, max_length=200)]
    core_gates: Literal["checked_by_core_before_every_stage"]
    lab_bindings: Literal["computed_by_lab_bound_by_core"]
    grant_signed: Literal[False]


class WorkerRecord(StrictRecord):
    kind: Literal["test_double", "isolated_sandbox", "none"]
    protocol: Literal["aegis.lab.candidate-worker.v1"]
    core_contract: Literal["aegis.core.isolated-worker.v1"] | None
    preflight: Literal["passed", "failed", "not_run"]
    preflight_code: InfrastructureCode | None
    runtime: SandboxRuntime | None
    compiler_version: Annotated[str, Field(min_length=1, max_length=200)] | None
    compiler_executable_sha256: Hash | None
    identity_observed: StrictBool | None
    limits_enforcement: Literal["verified_by_runtime", "not_enforced_test_double"] | None
    # Requested: the per-stage limits bound by Core's grant (equal to the policy). Not a measurement.
    granted_compile_limits: CompileLimits | None
    granted_execute_limits: StageLimits | None
    # Enforced: what the isolating runtime reported it enforced (cgroup read-back and microVM
    # configuration), identical for every invocation of the stage. Never derived from the request.
    enforced_compile_limits: EnforcedLimits | None
    enforced_execute_limits: EnforcedLimits | None
    cleanup: Literal["completed", "failed", "not_required"]

    @model_validator(mode="after")
    def _consistent(self) -> WorkerRecord:  # noqa: C901 - one table of field rules
        enforced = (self.enforced_compile_limits, self.enforced_execute_limits)
        if self.kind != "isolated_sandbox" and enforced != (None, None):
            raise ValueError("only an isolating runtime reports enforced limits")
        if any(v is not None for v in enforced) and self.preflight != "passed":
            raise ValueError("enforced limits are observed only after a passed preflight")
        if self.enforced_compile_limits is not None and not self.enforced_compile_limits.covers(
                self.granted_compile_limits):
            raise ValueError("enforced compile limits leave no room for the granted job")
        if self.enforced_execute_limits is not None and not self.enforced_execute_limits.covers(
                self.granted_execute_limits):
            raise ValueError("enforced execute limits leave no room for the granted job")
        observed = (self.runtime, self.compiler_version, self.compiler_executable_sha256, self.identity_observed,
                    self.limits_enforcement, self.granted_compile_limits, self.granted_execute_limits)
        if (self.preflight == "passed") != all(v is not None for v in observed) or (
                self.preflight != "passed" and any(v is not None for v in observed)):
            raise ValueError("preflight observations are recorded exactly when preflight passed")
        if (self.preflight == "failed") != (self.preflight_code is not None):
            raise ValueError("a preflight code is recorded exactly when preflight failed")
        if self.kind == "none" and self.preflight != "not_run":
            raise ValueError("preflight runs only with a worker")
        if (self.kind == "none") != (self.cleanup == "not_required"):
            raise ValueError("cleanup is required exactly when a worker was used")
        if (self.kind == "none") != (self.core_contract is None):
            raise ValueError("every worker is a Core session")
        if self.kind == "test_double" and self.preflight == "passed" and (
                self.identity_observed or self.limits_enforcement != "not_enforced_test_double"):
            raise ValueError("a test double neither observes identities nor enforces limits")
        if self.kind == "isolated_sandbox" and self.preflight == "passed" and (
                not self.identity_observed or self.limits_enforcement != "verified_by_runtime"):
            raise ValueError("an isolated sandbox must observe identities and enforce limits")
        return self


class DiagnosticRecord(StrictRecord):
    """Compiler output. Kept as text only when it is valid UTF-8 without NUL and small enough."""

    sha256: Hash
    byte_count: NonNegInt
    truncated_by_worker: StrictBool
    text: Annotated[str, Field(max_length=MAX_DIAGNOSTIC_TEXT_BYTES)] | None
    withheld: Literal["invalid_text", "too_large", "empty"] | None

    @model_validator(mode="after")
    def _text(self) -> DiagnosticRecord:
        if (self.text is None) == (self.withheld is None):
            raise ValueError("diagnostic text is either kept or withheld with a reason")
        if self.text is not None:
            encoded = self.text.encode("utf-8", "surrogatepass")
            if ("\x00" in self.text or any(0xD800 <= ord(c) <= 0xDFFF for c in self.text)
                    or hashlib.sha256(encoded).hexdigest() != self.sha256 or len(encoded) != self.byte_count):
                raise ValueError("kept diagnostic text does not match its digest and size")
        if (self.withheld == "empty") != (self.byte_count == 0):
            raise ValueError("empty diagnostics are withheld as empty")
        return self


CompileStatus = Literal["succeeded", "failed", "timeout", "resource_limit_exceeded", "infrastructure_failure"]


class CompilationRecord(StrictRecord):
    status: CompileStatus
    exit_code: ExitCode | None
    signal: Signal | None
    limit: LimitName | None
    infrastructure_code: InfrastructureCode | None
    diagnostics: DiagnosticRecord | None
    binary_sha256: Hash | None
    binary_bytes: Annotated[StrictInt, Field(ge=1)] | None

    @model_validator(mode="after")
    def _consistent(self) -> CompilationRecord:
        infra = self.status == "infrastructure_failure"
        if infra != (self.infrastructure_code is not None):
            raise ValueError("an infrastructure code is recorded exactly for an infrastructure failure")
        if (self.status == "succeeded") != (self.binary_sha256 is not None) or (
                (self.binary_sha256 is None) != (self.binary_bytes is None)):
            raise ValueError("a binary digest is recorded exactly for a successful compilation")
        if (self.status == "resource_limit_exceeded") != (self.limit is not None):
            raise ValueError("a limit is recorded exactly when one was exceeded")
        if self.status == "succeeded" and self.exit_code != 0:
            raise ValueError("a successful compilation exited 0")
        if self.status == "failed" and (self.exit_code in (None, 0)) and self.signal is None:
            raise ValueError("a failed compilation exited nonzero or was signaled")
        if self.status in ("timeout", "resource_limit_exceeded", "infrastructure_failure") and (
                self.exit_code is not None or self.signal is not None):
            raise ValueError("no exit status is recorded for a stopped or failed worker")
        if infra and self.diagnostics is not None:
            raise ValueError("an infrastructure failure has no compiler diagnostics")
        if not infra and self.diagnostics is None:
            raise ValueError("compiler diagnostics are recorded for every compiler run")
        return self


class CaseResult(StrictRecord):
    case_id: Annotated[str, Field(pattern=r"^c[0-9]{4}$")]
    classification: CaseClass
    exit_code: ExitCode | None = None
    signal: Signal | None = None
    limit: LimitName | None = None
    infrastructure_code: InfrastructureCode | None = None
    detail: Literal["result_line_invalid", "stdout_truncated"] | None = None
    stdout_bytes: NonNegInt | None = None
    stderr_bytes: NonNegInt | None = None

    @model_validator(mode="after")
    def _consistent(self) -> CaseResult:  # noqa: C901 - one table of field rules
        c = self.classification
        observed = (self.stdout_bytes, self.stderr_bytes)
        if c in ("not_evaluated", "infrastructure_failure"):
            if any(v is not None for v in (self.exit_code, self.signal, self.limit, self.detail, *observed)):
                raise ValueError("no process observation is recorded for this classification")
        elif any(v is None for v in observed):
            raise ValueError("output sizes are recorded for every candidate observation")
        if (c == "infrastructure_failure") != (self.infrastructure_code is not None):
            raise ValueError("an infrastructure code is recorded exactly for an infrastructure failure")
        if (c == "resource_limit_exceeded") != (self.limit is not None):
            raise ValueError("a limit is recorded exactly when one was exceeded")
        if c in ("match", "mismatch") and (self.exit_code != 0 or self.signal is not None or self.detail is not None):
            raise ValueError("a compared result comes from a clean exit")
        if c == "malformed_output" and (self.exit_code != 0 or self.detail is None):
            raise ValueError("malformed output is a clean exit with a detail code")
        if c != "malformed_output" and self.detail is not None:
            raise ValueError("a detail code is recorded only for malformed output")
        if c == "runtime_crash" and not ((self.exit_code not in (None, 0)) != (self.signal is not None)):
            raise ValueError("a crash is a nonzero exit or a signal")
        if c in ("timeout", "resource_limit_exceeded") and (self.exit_code is not None or self.signal is not None):
            raise ValueError("a stopped process has no exit status")
        return self


class ScoreSummary(StrictRecord):
    required_cases: NonNegInt
    evaluated_cases: NonNegInt
    matched_cases: NonNegInt
    counts: dict[CaseClass, NonNegInt]


class ScoreOutcome(StrictRecord):
    status: ScoreStatus
    stop_reason: StopReason
    refusal_reason: Code | None
    criterion: Literal["all_hidden_tests_pass"]
    criterion_satisfied: StrictBool
    behaviorally_successful_reconstruction: Literal["established", "not_established"]


class EvidenceRecord(StrictRecord):
    """Whether this record is evidence about a model's reconstruction. Usually it is not."""

    candidate_origin: Literal["offline_fake_provider", "model_provider", "none"]
    worker_kind: Literal["test_double", "isolated_sandbox", "none"]
    counts_as_behavioral_evidence: StrictBool
    reasons: tuple[Code, ...]


class ScoreResult(StrictRecord):
    """The deterministic part of a score record: no ids, timestamps or durations."""

    trial: TrialBinding
    experiment: ExperimentReference | None
    suite: SuiteBinding
    interface: InterfaceRecord
    scorer: ToolIdentity
    score_rule: Literal["all_hidden_tests_pass"]
    configuration: ConfigurationRecord
    grant: GrantRecord | None
    worker: WorkerRecord
    compilation: CompilationRecord | None
    cases: Annotated[tuple[CaseResult, ...], Field(max_length=4096)]
    summary: ScoreSummary
    outcome: ScoreOutcome
    evidence: EvidenceRecord
    not_established: Annotated[tuple[Note, ...], Field(min_length=1, max_length=32)]
    limitations: Annotated[tuple[Note, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _integrity(self) -> ScoreResult:  # noqa: C901 - one list of record invariants
        def fail(message: str) -> None:
            raise ValueError(message)

        out, cases, compilation, worker = self.outcome, self.cases, self.compilation, self.worker
        stop = out.stop_reason
        if self.scorer.name != SCORER_NAME or self.scorer.version != BEHAVIOR_SCORE_SCHEMA:
            fail("scorer identity is not this scorer")
        if self.scorer.configuration_sha256 != self.configuration.scorer_configuration_sha256:
            fail("scorer configuration digest differs from the recorded configuration")
        if self.suite.parsed:
            if len(cases) != self.suite.case_count:
                fail("one case result per suite case")
        elif cases:
            fail("an unparsed suite has no case results")
        for index, case in enumerate(cases, start=1):
            if case.case_id != f"c{index:04d}":
                fail("case results follow the suite order")
        if (self.interface.status == "supported") == (stop == "interface_not_supported"):
            fail("interface_not_supported is the stop reason exactly for an unsupported interface")
        if self.suite.parsed != (stop != "interface_not_supported"):
            fail("the suite is parsed exactly when the interface is supported")
        has_candidate = self.trial.candidate_origin != "none"
        if stop == "no_candidate" and has_candidate:
            fail("no_candidate is recorded only without a candidate")
        if not has_candidate and stop not in ("no_candidate", "interface_not_supported", "not_started"):
            fail("a trial without a candidate stops with no_candidate")
        if self.experiment is None and stop == "not_started":
            fail("not_started is recorded only within a paired experiment")
        # Per-stop structure.
        classes = [c.classification for c in cases]
        evaluated = [c in CANDIDATE_CASE_CLASSES for c in classes]
        infra = [c == "infrastructure_failure" for c in classes]
        unevaluated = [c == "not_evaluated" for c in classes]
        if stop in _PRE_EXECUTION_STOPS or stop == "compilation_failed":
            if not all(unevaluated):
                fail("no case is evaluated before a compiled binary exists")
        if stop in _PRE_EXECUTION_STOPS and compilation is not None:
            fail("no compilation before the worker passed preflight")
        if (stop == "worker_preflight_failed") != (worker.preflight == "failed"):
            fail("worker_preflight_failed is the stop reason exactly when preflight failed")
        if stop in ("no_candidate", "interface_not_supported", "not_started") and worker.kind != "none":
            fail("no worker is used without an execution")
        if stop not in ("no_candidate", "interface_not_supported", "not_started") and worker.kind == "none":
            fail("an execution attempt records its worker")
        if worker.kind == "isolated_sandbox":
            if (compilation is not None and compilation.status != "infrastructure_failure"
                    and worker.enforced_compile_limits is None):
                fail("an isolating runtime reports enforced limits for every compilation")
            if any(evaluated) and worker.enforced_execute_limits is None:
                fail("an isolating runtime reports enforced limits for every execution")
        if worker.kind != "none" and worker.preflight == "not_run" and stop != "interrupted":
            fail("a used worker ran preflight unless the run was interrupted first")
        if (worker.kind == "none") != (self.grant is None):
            fail("a Core grant is recorded exactly when a worker was used")
        if (stop == "core_refused") != (out.refusal_reason is not None):
            fail("a refusal reason is recorded exactly when Core refused a stage")
        if stop == "core_refused" and not _prefix_shape(classes, require_tail=True):
            fail("a refused stage leaves at least one unevaluated case after the evaluated ones")
        if compilation is not None and worker.preflight != "passed":
            fail("compilation requires a passed preflight")
        if stop == "compilation_failed" and (compilation is None or compilation.status not in (
                "failed", "timeout", "resource_limit_exceeded")):
            fail("compilation_failed requires a candidate-attributable compilation failure")
        if stop == "all_cases_evaluated" and (compilation is None or compilation.status != "succeeded"
                                              or not all(evaluated) or not cases):
            fail("all_cases_evaluated requires a successful compilation and every case evaluated")
        if any(evaluated) and (compilation is None or compilation.status != "succeeded"):
            fail("cases are evaluated only with a compiled binary")
        if stop == "worker_failure":
            compile_infra = compilation is not None and compilation.status == "infrastructure_failure"
            if compile_infra:
                if not all(unevaluated):
                    fail("no case is evaluated after a failed compilation worker")
            elif not _prefix_shape(classes, middle="infrastructure_failure", require_middle=True):
                fail("a worker failure stops the run at exactly one infrastructure case")
        elif any(infra):
            fail("an infrastructure case stops the run as worker_failure")
        if compilation is not None and compilation.status == "infrastructure_failure" and stop != "worker_failure":
            fail("an infrastructure failure during compilation stops the run as worker_failure")
        if stop == "scoring_deadline_exceeded" and not _prefix_shape(classes, require_tail=True):
            fail("a deadline leaves at least one unevaluated case after the evaluated ones")
        if stop in ("interrupted", "worker_cleanup_failed") and not _prefix_shape(classes):
            fail("unevaluated cases follow the evaluated ones")
        if (stop == "worker_cleanup_failed") and worker.cleanup != "failed":
            fail("worker_cleanup_failed requires a failed cleanup")
        if worker.cleanup == "failed" and stop in ("all_cases_evaluated", "compilation_failed",
                                                   "scoring_deadline_exceeded"):
            fail("a failed cleanup replaces a completed stop reason")
        # Summary and outcome.
        counts = {name: classes.count(name) for name in CASE_CLASSES}
        summary = ScoreSummary(required_cases=len(cases), evaluated_cases=sum(evaluated),
                               matched_cases=counts["match"], counts=counts)
        if self.summary != summary:
            fail("summary does not follow from the case results")
        status = _derive_status(stop, classes, worker.cleanup)
        if out.status != status:
            fail("status does not follow from the stop reason and cases")
        satisfied = status == "behavioral_match"
        if out.criterion_satisfied != satisfied:
            fail("criterion_satisfied holds exactly when every required case completed and matched")
        evidence = _evidence(self.trial.candidate_origin, worker.kind, status)
        if self.evidence != evidence:
            fail("evidence assessment does not follow from the record")
        established = "established" if satisfied and evidence.counts_as_behavioral_evidence else "not_established"
        if out.behaviorally_successful_reconstruction != established:
            fail("behaviorally_successful_reconstruction does not follow from the record")
        harness_expected = compilation is not None
        if (self.configuration.harness_sha256 is not None) != harness_expected:
            fail("a harness digest is recorded exactly when a compilation was attempted")
        return self


def _prefix_shape(classes: list[str], *, middle: str | None = None, require_middle: bool = False,
                  require_tail: bool = False) -> bool:
    """Candidate-evaluated cases, then optionally one ``middle`` case, then only ``not_evaluated``."""
    i = 0
    while i < len(classes) and classes[i] in CANDIDATE_CASE_CLASSES:
        i += 1
    if middle is not None and i < len(classes) and classes[i] == middle:
        i += 1
    elif require_middle:
        return False
    tail = classes[i:]
    if require_tail and not tail:
        return False
    return all(c == "not_evaluated" for c in tail)


def _derive_status(stop: str, classes: list[str], cleanup: str) -> str:
    if cleanup == "failed":
        return "infrastructure_failure"
    if stop == "all_cases_evaluated":
        return "behavioral_match" if classes and all(c == "match" for c in classes) else "behavioral_mismatch"
    return _STATUS_FOR_STOP[stop]


def _evidence(origin: str, worker_kind: str, status: str) -> EvidenceRecord:
    reasons = []
    if origin == "none":
        reasons.append("no_candidate")
    elif origin == "offline_fake_provider":
        reasons.append("candidate_scripted_by_offline_fake_provider")
    if worker_kind == "test_double":
        reasons.append("worker_is_test_double_no_execution")
    elif worker_kind == "none":
        reasons.append("candidate_not_executed")
    elif worker_kind == "isolated_sandbox":
        # Containment attestation and vsock authentication do not establish
        # guest integrity: the guest has its own HMAC key.
        reasons.append("guest_integrity_not_independently_verified")
    if status not in CANDIDATE_ATTRIBUTABLE_STATUSES:
        reasons.append("outcome_not_attributable_to_candidate")
    return EvidenceRecord(candidate_origin=origin, worker_kind=worker_kind,
                          counts_as_behavioral_evidence=not reasons, reasons=tuple(reasons))


class CoreRecordRef(StrictRecord):
    """One ``aegis.core.candidate-execution-record.v1`` returned by Core, by id and digest.

    Full records are retained separately in private storage; they contain hidden
    inputs and must never enter an attacker workspace. ``record_sha256`` is SHA-256
    over canonical JSON of the record as Core returned it.
    """

    stage: Literal["compile", "execute"]
    case_id: Annotated[str, Field(pattern=r"^c[0-9]{4}$")] | None
    record_id: Id32
    record_sha256: Hash

    @model_validator(mode="after")
    def _case(self) -> CoreRecordRef:
        if (self.stage == "execute") != (self.case_id is not None):
            raise ValueError("an execute record names its case; a compile record does not")
        return self


class HostAccountingRef(StrictRecord):
    """Host-measured accounting for one Core record (isolating runtimes only). Not a limit."""

    stage: Literal["compile", "execute"]
    case_id: Annotated[str, Field(pattern=r"^c[0-9]{4}$")] | None
    host_cpu_usec: NonNegInt | None
    host_memory_peak_bytes: NonNegInt | None
    host_oom_kills: NonNegInt


class RunRecord(StrictRecord):
    """Non-deterministic run facts: coordinator timings, Core identifiers and host measurements."""

    score_id: Id32
    started_at: AwareDatetime
    finished_at: AwareDatetime
    compile_seconds: Seconds | None
    case_seconds: tuple[Seconds | None, ...]
    core_session_id: Id32 | None
    core_records: Annotated[tuple[CoreRecordRef, ...], Field(max_length=4097)]
    host_accounting: Annotated[tuple[HostAccountingRef, ...], Field(max_length=4097)]


class BehaviorScoreRecord(StrictRecord):
    """The versioned, strictly validated Phase 4 record. Unsigned; never attacker-visible."""

    _private_core_records: dict[str, bytes] = PrivateAttr(default_factory=dict)

    @property
    def private_core_records(self) -> dict[str, bytes]:
        """Exact canonical Core records for private archival, excluded from JSON."""
        return dict(self._private_core_records)

    def __eq__(self, other: object) -> bool:
        # Private archival attachments do not change the versioned score value.
        if type(other) is not type(self):
            return NotImplemented
        return self.model_dump() == other.model_dump()

    schema_version: Literal["aegis.lab.behavior-score.v1"] = BEHAVIOR_SCORE_SCHEMA
    result: ScoreResult
    result_sha256: Hash
    run: RunRecord
    fingerprints: Literal["result_sha256: sha256 over aegis.lab.canonical-json.v1 of result"]
    record_signed: Literal[False]
    attacker_visible: Literal[False]

    @model_validator(mode="after")
    def _integrity(self) -> BehaviorScoreRecord:
        if canonical_sha256(self.result.model_dump(mode="json")) != self.result_sha256:
            raise ValueError("result_sha256 does not match the result")
        if self.run.finished_at < self.run.started_at:
            raise ValueError("finished_at precedes started_at")
        if len(self.run.case_seconds) != len(self.result.cases):
            raise ValueError("one duration slot per case")
        for case, seconds in zip(self.result.cases, self.run.case_seconds):
            if (seconds is None) != (case.classification == "not_evaluated"):
                raise ValueError("a duration is recorded exactly for each attempted case")
        if (self.run.compile_seconds is None) != (self.result.compilation is None):
            raise ValueError("a compile duration is recorded exactly for an attempted compilation")
        if (self.run.core_session_id is None) != (self.result.worker.preflight != "passed"):
            raise ValueError("a Core session id is recorded exactly when preflight passed")
        refs = self.run.core_records
        compiles = [r for r in refs if r.stage == "compile"]
        executes = [r.case_id for r in refs if r.stage == "execute"]
        compilation = self.result.compilation
        if len(compiles) > 1 or (refs and refs[0].stage != "compile") or (
                compilation is not None and compilation.status != "infrastructure_failure" and len(compiles) != 1):
            raise ValueError("exactly one Core compile record precedes the execute records")
        if compilation is None and refs:
            raise ValueError("no Core record without a compilation")
        evaluated = [c.case_id for c in self.result.cases if c.classification in CANDIDATE_CASE_CLASSES]
        if executes[:len(evaluated)] != evaluated or len(executes) > len(evaluated) + 1:
            raise ValueError("one Core execute record per evaluated case, in order")
        worker = self.result.worker
        accounting = self.run.host_accounting
        if worker.kind == "isolated_sandbox":
            if [(a.stage, a.case_id) for a in accounting] != [(r.stage, r.case_id) for r in refs]:
                raise ValueError("an isolating runtime reports host accounting for every Core record")
            for item in accounting:
                limits = worker.enforced_compile_limits if item.stage == "compile" else worker.enforced_execute_limits
                if limits is None:
                    raise ValueError("host accounting requires enforced limits for its stage")
        elif accounting:
            raise ValueError("host accounting is recorded only for an isolating runtime")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_json_bytes(self) -> bytes:
        data = (json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
        if len(data) > MAX_SCORE_RECORD_BYTES:
            raise ValueError("score record exceeds the maximum serialized size")
        return data

    def summary(self) -> dict[str, Any]:
        """Terminal-safe: identities, digests and counts only. No case ids, values or diagnostics."""
        result = self.result
        return {
            "schema_version": self.schema_version,
            "trial_id": result.trial.trial_id,
            "variant": result.trial.variant,
            "result_sha256": self.result_sha256,
            "status": result.outcome.status,
            "stop_reason": result.outcome.stop_reason,
            "criterion_satisfied": result.outcome.criterion_satisfied,
            "required_cases": result.summary.required_cases,
            "matched_cases": result.summary.matched_cases,
            "worker_kind": result.worker.kind,
            "counts_as_behavioral_evidence": result.evidence.counts_as_behavioral_evidence,
            "behaviorally_successful_reconstruction": result.outcome.behaviorally_successful_reconstruction,
        }


SCORE_RECORD_FIELDS = model_field_names(BehaviorScoreRecord)


def parse_behavior_score(data: bytes) -> BehaviorScoreRecord:
    """Parse untrusted record bytes. Raises ``LoadError`` or ``pydantic.ValidationError``."""
    if len(data) > MAX_SCORE_RECORD_BYTES:
        raise LoadError("too_large")
    parse_strict_json(data)
    return BehaviorScoreRecord.model_validate_json(data)


_NOT_ESTABLISHED = (
    "That the Ghidra report, reconstruction record or hidden suite were produced by the tools they name: "
    "all are unsigned local files.",
    "That the frozen expectations are correct for the original software: they are the suite author's "
    "reference outputs.",
    "That passing the hidden suite means the candidate is equivalent to the original on all inputs.",
    "Any protection effect: a single trial's score says nothing about protection.",
    "Who produced this record: it is unsigned and is not authenticated provenance.",
)
_BASE_LIMITATIONS = (
    "This record and the hidden suite must never enter an attacker workspace or a retry: per-case "
    "pass/fail is feedback about hidden tests.",
    "Expected values are never retained. Case arguments and observed bytes are confined to private Core archives; "
    "they are excluded from the score JSON.",
    "Guest-generated results are not independently verified truth. A vsock HMAC with a guest-held key does not "
    "establish guest integrity; containment and host accounting establish different facts.",
    "Execution was authorized only by Core's grant, an operator-attested file that is not a cryptographic "
    "credential.",
)
_TEST_DOUBLE_LIMITATION = ("Core ran the session with its scripted test-double runtime: nothing was compiled or "
                           "executed, every observation was scripted by the caller, and limits were bound by the "
                           "grant but not enforced.")
_FAKE_LIMITATION = ("The candidate was scripted by the offline FakeOffline provider; it is not model output and "
                    "says nothing about reconstruction.")


# --- Preparation (pure; nothing runs) -----------------------------------------------------------

class ScoringInputError(ValueError):
    """Inputs are invalid or do not belong together. ``issues`` are ``role: field: code`` strings."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = list(issues) or ["inputs: invalid"]
        super().__init__("; ".join(self.issues))


class ScoringInterrupted(KeyboardInterrupt):
    """Scoring was interrupted; ``record`` holds what was evaluated so far (stop reason interrupted)."""

    def __init__(self, record: BehaviorScoreRecord) -> None:
        self.record = record
        super().__init__("scoring interrupted")


REPORT_FIELDS = model_field_names(AnalysisReport)
RECONSTRUCTION_FIELDS = model_field_names(ReconstructionRecord)
SUITE_FIELDS = model_field_names(HiddenSuite)


@dataclass(frozen=True)
class PreparedScoring:
    manifest: TrialManifest
    evidence: GhidraEvidence
    reconstruction: ReconstructionRecord | None
    reconstruction_file_sha256: str | None
    suite: HiddenSuite | None
    suite_sha256: str
    policy: SandboxPolicy
    interface: InterfaceRecord
    experiment: ExperimentReference | None

    @property
    def candidate_source(self) -> str | None:
        candidate = None if self.reconstruction is None else self.reconstruction.candidate
        return None if candidate is None else candidate.source

    @property
    def candidate_sha256(self) -> str | None:
        candidate = None if self.reconstruction is None else self.reconstruction.candidate
        return None if candidate is None else candidate.sha256


def _evidence_issues(exc: Exception) -> list[str]:
    if isinstance(exc, LoadError):
        return [f"evidence: report: {exc.category}"]
    if isinstance(exc, ValidationError):
        return [f"evidence: report: {issue}" for issue in validation_issues(exc, REPORT_FIELDS)]
    if isinstance(exc, ReportInvariantError):
        return [f"evidence: report: {f}: {r}" for f, r in exc.violations]
    if isinstance(exc, EvidenceBindingError):
        return [f"evidence: binding: {f}: {r}" for f, r in zip(exc.fields, exc.reasons)]
    raise TypeError("unsupported failure type")


def prepare_scoring(manifest: TrialManifest, *, reconstruction_bytes: bytes | None, evidence_bytes: bytes,
                    suite_bytes: bytes, policy: SandboxPolicy,
                    experiment: ExperimentReference | None = None) -> PreparedScoring:
    """Validate every input binding. Raises ``ScoringInputError``; never compiles or runs anything."""
    issues: list[str] = []
    try:
        evidence = bind_ghidra_evidence(manifest, evidence_bytes)
    except (LoadError, ValidationError, ReportInvariantError, EvidenceBindingError) as exc:
        raise ScoringInputError(_evidence_issues(exc)) from None
    record = None
    record_file_sha256 = None
    if reconstruction_bytes is not None:
        try:
            record = parse_reconstruction_record(reconstruction_bytes)
        except LoadError as exc:
            raise ScoringInputError([f"reconstruction: {exc.category}"]) from None
        except ValidationError as exc:
            raise ScoringInputError([f"reconstruction: {issue}"
                                     for issue in validation_issues(exc, RECONSTRUCTION_FIELDS)]) from None
        record_file_sha256 = hashlib.sha256(reconstruction_bytes).hexdigest()
        checks = {
            "trial_id": record.trial_id == manifest.trial_id,
            "pair_id": record.pair_id == manifest.pair_id,
            "variant": record.variant == manifest.variant.value,
            "inputs.manifest_sha256": record.inputs.manifest_sha256 == evidence.manifest_sha256,
            "inputs.artifact_sha256": record.inputs.artifact_sha256 == manifest.target.final_artifact_sha256,
            "inputs.evidence_sha256": record.inputs.evidence_sha256 == evidence.evidence_sha256,
            "task.target_function": record.task.target_function == manifest.target.function,
            "task.expected_interface": record.task.expected_interface == manifest.scoring.expected_interface,
        }
        issues.extend(f"reconstruction: {name}: mismatch" for name, ok in checks.items() if not ok)
        if record.candidate is not None and (
                hashlib.sha256(record.candidate.source.encode("utf-8")).hexdigest() != record.candidate.sha256):
            issues.append("reconstruction: candidate.sha256: mismatch")  # pragma: no cover - parser enforces
    digest = suite_sha256(suite_bytes)
    if digest != manifest.scoring.hidden_test_suite_sha256:
        issues.append("suite: hidden_test_suite_sha256: mismatch")
    if manifest.scoring.score_rule != SCORE_RULE:  # pragma: no cover - the manifest schema fixes the rule
        issues.append("manifest: scoring.score_rule: unsupported")
    planned = planned_scorer_tool(policy)
    for name in ("name", "version", "executable_sha256", "configuration_sha256"):
        if getattr(manifest.scoring.scorer, name) != getattr(planned, name):
            issues.append(f"manifest: scoring.scorer.{name}: mismatch")
    if issues:
        raise ScoringInputError(issues)
    symbol = None if record is None else record.task.function_label
    status, code, arity = _interface_facts(manifest.scoring.expected_interface, symbol)
    interface = InterfaceRecord(text=manifest.scoring.expected_interface, abi=ABI_VERSION, symbol=symbol,
                                status=status, code=code, arity=arity)
    suite = None
    if status == "supported":
        try:
            suite = parse_hidden_suite(suite_bytes)
        except LoadError as exc:
            raise ScoringInputError([f"suite: {exc.category}"]) from None
        except ValidationError as exc:
            raise ScoringInputError([f"suite: {issue}"
                                     for issue in validation_issues(exc, SUITE_FIELDS, SUITE_ERROR_TYPES)]) from None
        if suite.interface != manifest.scoring.expected_interface:
            raise ScoringInputError(["suite: interface: mismatch"])
        if len(suite.cases) > policy.max_cases:
            raise ScoringInputError(["suite: cases: exceeds_policy_max_cases"])
    return PreparedScoring(manifest=manifest, evidence=evidence, reconstruction=record,
                           reconstruction_file_sha256=record_file_sha256, suite=suite, suite_sha256=digest,
                           policy=policy, interface=interface, experiment=experiment)


# --- Execution ------------------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Run:
    prepared: PreparedScoring
    started_at: datetime
    score_id: str
    grant: CandidateExecutionGrant | None = None
    worker: CoreSessionWorker | None = None
    worker_kind: str = "none"
    preflight: str = "not_run"
    preflight_code: str | None = None
    preflight_facts: WorkerPreflight | None = None
    cleanup: str = "not_required"
    harness_sha256: str | None = None
    compilation: CompilationRecord | None = None
    compile_seconds: float | None = None
    binary: bytes | None = None
    cases: list[CaseResult] | None = None
    case_seconds: list[float | None] | None = None
    stop_reason: str | None = None
    refusal_reason: str | None = None


def _diagnostics(data: bytes, truncated: bool) -> DiagnosticRecord:
    digest = hashlib.sha256(data).hexdigest()
    if not data:
        return DiagnosticRecord(sha256=digest, byte_count=0, truncated_by_worker=truncated, text=None,
                                withheld="empty")
    if len(data) > MAX_DIAGNOSTIC_TEXT_BYTES:
        return DiagnosticRecord(sha256=digest, byte_count=len(data), truncated_by_worker=truncated, text=None,
                                withheld="too_large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None or "\x00" in text:
        return DiagnosticRecord(sha256=digest, byte_count=len(data), truncated_by_worker=truncated, text=None,
                                withheld="invalid_text")
    return DiagnosticRecord(sha256=digest, byte_count=len(data), truncated_by_worker=truncated, text=text,
                            withheld=None)


def _checked(model: type[BaseModel], value: object) -> BaseModel:
    """Re-validate a worker reply field by field; anything else is a contract violation."""
    if type(value) is not model:
        raise WorkerError("protocol_violation")
    try:
        return model.model_validate(value.model_dump())
    except (ValidationError, TypeError, ValueError, AttributeError):
        raise WorkerError("protocol_violation") from None


def _infra_code(exc: BaseException) -> str:
    if isinstance(exc, WorkerError):
        return "worker_contract_violation" if exc.code == "protocol_violation" else exc.code
    return "worker_contract_violation"


def _check_preflight(facts: WorkerPreflight, policy: SandboxPolicy, kind: str) -> str | None:
    if facts.runtime != policy.runtime or facts.network != "none":
        return "runtime_mismatch"
    if (facts.compiler_name, facts.compiler_version, facts.compiler_executable_sha256) != (
            policy.compiler.name, policy.compiler.version, policy.compiler.executable_sha256):
        return "compiler_identity_mismatch"
    if facts.compile_limits != policy.compile or facts.execute_limits != policy.execute:
        return "limits_mismatch"
    if kind == "test_double":
        if facts.identity_observed or facts.limits_enforcement != "not_enforced_test_double":
            return "worker_contract_violation"
    else:
        if not facts.identity_observed:
            return "identity_not_observed"
        if facts.limits_enforcement != "verified_by_runtime":
            return "limits_not_enforced"
    return None


def _compilation(observation: CompileObservation, limits: CompileLimits) -> tuple[CompilationRecord, bytes | None]:
    if len(observation.diagnostics) > limits.stderr_bytes:
        return _compile_infra("observation_exceeds_limit"), None
    diagnostics = _diagnostics(observation.diagnostics, observation.diagnostics_truncated)
    base = {"exit_code": None, "signal": None, "limit": None, "infrastructure_code": None,
            "diagnostics": diagnostics, "binary_sha256": None, "binary_bytes": None}
    if observation.status == "timeout":
        return CompilationRecord(status="timeout", **base), None
    if observation.status == "limit_exceeded":
        return CompilationRecord(status="resource_limit_exceeded", **{**base, "limit": observation.limit}), None
    if observation.status == "signaled":
        return CompilationRecord(status="failed", **{**base, "signal": observation.signal}), None
    if observation.exit_code != 0:
        return CompilationRecord(status="failed", **{**base, "exit_code": observation.exit_code}), None
    binary = observation.binary
    if not binary:
        return _compile_infra("binary_missing"), None
    if len(binary) > limits.binary_bytes:
        # The worker should have refused it; an oversized binary is a worker contract breach.
        return _compile_infra("observation_exceeds_limit"), None
    record = CompilationRecord(status="succeeded", **{**base, "exit_code": 0,
                                                      "binary_sha256": hashlib.sha256(binary).hexdigest(),
                                                      "binary_bytes": len(binary)})
    return record, binary


def _compile_infra(code: str) -> CompilationRecord:
    return CompilationRecord(status="infrastructure_failure", exit_code=None, signal=None, limit=None,
                             infrastructure_code=code, diagnostics=None, binary_sha256=None, binary_bytes=None)


def _case_result(case_id: str, observation: ExecuteObservation, expected: int, limits: StageLimits) -> CaseResult:
    if len(observation.stdout) > limits.stdout_bytes or observation.stderr_bytes > limits.stderr_bytes:
        return CaseResult(case_id=case_id, classification="infrastructure_failure",
                          infrastructure_code="observation_exceeds_limit")
    sizes = {"stdout_bytes": len(observation.stdout), "stderr_bytes": observation.stderr_bytes}
    if observation.status == "timeout":
        return CaseResult(case_id=case_id, classification="timeout", **sizes)
    if observation.status == "limit_exceeded":
        return CaseResult(case_id=case_id, classification="resource_limit_exceeded", limit=observation.limit,
                          **sizes)
    if observation.status == "signaled":
        return CaseResult(case_id=case_id, classification="runtime_crash", signal=observation.signal, **sizes)
    if observation.exit_code != 0:
        return CaseResult(case_id=case_id, classification="runtime_crash", exit_code=observation.exit_code, **sizes)
    if observation.stdout_truncated:
        return CaseResult(case_id=case_id, classification="malformed_output", exit_code=0,
                          detail="stdout_truncated", **sizes)
    value = parse_result_line(observation.stdout)
    if value is None:
        return CaseResult(case_id=case_id, classification="malformed_output", exit_code=0,
                          detail="result_line_invalid", **sizes)
    return CaseResult(case_id=case_id, classification="match" if value == expected else "mismatch", exit_code=0,
                      **sizes)


def _finish(run: _Run, *, now: Callable[[], datetime]) -> BehaviorScoreRecord:
    prepared = run.prepared
    manifest, record = prepared.manifest, prepared.reconstruction
    suite = prepared.suite
    if run.cases is None:
        run.cases = [] if suite is None else [CaseResult(case_id=c.case_id, classification="not_evaluated")
                                              for c in suite.cases]
        run.case_seconds = [None] * len(run.cases)
    reconstruction = None
    if record is not None:
        reconstruction = ReconstructionBinding(
            file_sha256=prepared.reconstruction_file_sha256, record_sha256=record.sha256(),
            status=record.outcome.status, provider=record.provider.provider, endpoint=record.provider.endpoint,
            external_disclosure=record.provider.external_disclosure, candidate_sha256=prepared.candidate_sha256)
    trial = TrialBinding(
        trial_id=manifest.trial_id, pair_id=manifest.pair_id, variant=manifest.variant.value,
        manifest_sha256=prepared.evidence.manifest_sha256, artifact_sha256=manifest.target.final_artifact_sha256,
        evidence_schema="aegis.lab.ghidra.v1", evidence_sha256=prepared.evidence.evidence_sha256,
        reconstruction=reconstruction, candidate_origin=_candidate_origin(reconstruction))
    suite_binding = SuiteBinding(
        schema_version=HIDDEN_SUITE_SCHEMA, sha256=prepared.suite_sha256, parsed=suite is not None,
        suite_id=None if suite is None else suite.suite_id,
        case_count=None if suite is None else len(suite.cases),
        reference_method=None if suite is None else suite.reference.method,
        reference_implementation_sha256=None if suite is None else suite.reference.reference_implementation_sha256)
    policy = prepared.policy
    configuration = ConfigurationRecord(
        policy=policy, policy_sha256=policy.sha256(), scorer_configuration_sha256=scorer_configuration_sha256(policy),
        abi=ABI_VERSION, harness_version=HARNESS_VERSION, observation_protocol=OBSERVATION_PROTOCOL,
        harness_sha256=run.harness_sha256 if run.compilation is not None else None)
    grant = None
    if run.grant is not None and run.worker_kind != "none":
        grant = GrantRecord(schema_version=run.grant.schema_version, grant_id=run.grant.grant_id,
                            grant_sha256=run.worker.grant_sha256,
                            authorization_reference=run.grant.authorization.reference,
                            core_gates="checked_by_core_before_every_stage",
                            lab_bindings="computed_by_lab_bound_by_core", grant_signed=False)
    facts = run.preflight_facts if run.preflight == "passed" else None
    worker = WorkerRecord(
        kind=run.worker_kind, protocol=WORKER_PROTOCOL,
        core_contract=None if run.worker_kind == "none" else CORE_CONTRACT,
        preflight=run.preflight, preflight_code=run.preflight_code,
        runtime=None if facts is None else facts.runtime,
        compiler_version=None if facts is None else facts.compiler_version,
        compiler_executable_sha256=None if facts is None else facts.compiler_executable_sha256,
        identity_observed=None if facts is None else facts.identity_observed,
        limits_enforcement=None if facts is None else facts.limits_enforcement,
        granted_compile_limits=None if facts is None else facts.compile_limits,
        granted_execute_limits=None if facts is None else facts.execute_limits,
        enforced_compile_limits=None if run.worker is None else run.worker.enforced.get("compile"),
        enforced_execute_limits=None if run.worker is None else run.worker.enforced.get("execute"),
        cleanup=run.cleanup)
    stop = run.stop_reason
    if run.cleanup == "failed" and stop in ("all_cases_evaluated", "compilation_failed", "scoring_deadline_exceeded"):
        stop = "worker_cleanup_failed"
    classes = [c.classification for c in run.cases]
    counts = {name: classes.count(name) for name in CASE_CLASSES}
    summary = ScoreSummary(required_cases=len(classes),
                           evaluated_cases=sum(c in CANDIDATE_CASE_CLASSES for c in classes),
                           matched_cases=counts["match"], counts=counts)
    status = _derive_status(stop, classes, run.cleanup)
    evidence = _evidence(trial.candidate_origin, run.worker_kind, status)
    satisfied = status == "behavioral_match"
    outcome = ScoreOutcome(
        status=status, stop_reason=stop, refusal_reason=run.refusal_reason if stop == "core_refused" else None,
        criterion=SCORE_RULE, criterion_satisfied=satisfied,
        behaviorally_successful_reconstruction="established" if satisfied and evidence.counts_as_behavioral_evidence
        else "not_established")
    limitations = list(_BASE_LIMITATIONS)
    if run.worker_kind == "test_double":
        limitations.append(_TEST_DOUBLE_LIMITATION)
    if trial.candidate_origin == "offline_fake_provider":
        limitations.append(_FAKE_LIMITATION)
    if status == "infrastructure_failure":
        limitations.append("An infrastructure failure is not a candidate result and is never evidence of protection.")
    result = ScoreResult(
        trial=trial, experiment=prepared.experiment, suite=suite_binding, interface=prepared.interface,
        scorer=manifest.scoring.scorer, score_rule=SCORE_RULE, configuration=configuration, grant=grant,
        worker=worker, compilation=run.compilation, cases=tuple(run.cases), summary=summary, outcome=outcome,
        evidence=evidence, not_established=_NOT_ESTABLISHED, limitations=tuple(limitations))
    finished = now()
    refs = []
    if run.worker is not None:
        for ref in run.worker.records:
            refs.append(CoreRecordRef(stage=ref.stage, record_id=ref.record_id, record_sha256=ref.record_sha256,
                                      case_id=None if ref.case_index is None else f"c{ref.case_index + 1:04d}"))
    session_id = run.worker.session_id if run.worker is not None and run.preflight == "passed" else None
    record = BehaviorScoreRecord(
        result=result, result_sha256=canonical_sha256(result.model_dump(mode="json")),
        run=RunRecord(score_id=run.score_id, started_at=run.started_at, finished_at=max(finished, run.started_at),
                      compile_seconds=run.compile_seconds, case_seconds=tuple(run.case_seconds),
                      core_session_id=session_id, core_records=tuple(refs),
                      host_accounting=tuple(
                          HostAccountingRef(stage=stage, case_id=None if case is None else f"c{case + 1:04d}",
                                            **observed.accounting.model_dump())
                          for stage, case, observed in ([] if run.worker is None else run.worker.accounting))),
        fingerprints="result_sha256: sha256 over aegis.lab.canonical-json.v1 of result",
        record_signed=False, attacker_visible=False)
    record._private_core_records = {} if run.worker is None else dict(run.worker.private_records)
    return record


def not_started_record(prepared: PreparedScoring, *, now: Callable[[], datetime] = _utc_now,
                       score_id: str | None = None) -> BehaviorScoreRecord:
    """A trial of a paired experiment that was never scored because the run stopped first."""
    if prepared.experiment is None:
        raise ValueError("not_started applies only within a paired experiment")
    run = _Run(prepared=prepared, started_at=now(), score_id=score_id or secrets.token_hex(16))
    run.stop_reason = "interface_not_supported" if prepared.interface.status != "supported" else "not_started"
    return _finish(run, now=now)


def score_trial(prepared: PreparedScoring, *, config: AegisConfig, grant: CandidateExecutionGrant | None,
                runtime: IsolationRuntime | None = None, monotonic: Callable[[], float] = time.monotonic,
                now: Callable[[], datetime] = _utc_now, score_id: str | None = None) -> BehaviorScoreRecord:
    """Score one prepared trial through a Core candidate-execution session.

    Order: an unsupported interface or a missing candidate is recorded without
    contacting Core. Otherwise the grant must describe the Lab's inputs
    (``check_grant_binding``), Core must authorize it (``precheck_core``), and Core
    opens a session (``open_session``, runtime preflight). Refusals raise
    ``ExecutionRefused`` before any candidate byte is sent. ``runtime=None`` uses
    Core's configured runtime, which refuses in this revision. Raises
    ``ScoringInterrupted`` carrying the partial record; every other outcome,
    including infrastructure failures, is a record.
    """
    started = now()
    if prepared.interface.status != "supported" or prepared.candidate_source is None:
        run = _Run(prepared=prepared, started_at=started, score_id=score_id or secrets.token_hex(16))
        run.stop_reason = "interface_not_supported" if prepared.interface.status != "supported" else "no_candidate"
        return _finish(run, now=now)
    check_grant_binding(grant, [prepared])
    precheck_core(config, grant, started, [prepared])
    opened = open_trial_session(config, grant, lab_bindings(prepared), runtime=runtime, clock=now)
    return score_opened(prepared, opened, grant=grant, monotonic=monotonic, now=now, score_id=score_id)


def score_opened(prepared: PreparedScoring, opened: OpenedSession, *, grant: CandidateExecutionGrant,
                 monotonic: Callable[[], float] = time.monotonic, now: Callable[[], datetime] = _utc_now,
                 score_id: str | None = None) -> BehaviorScoreRecord:
    """Score a trial whose Core session was already opened (or failed to open) for it."""
    run = _Run(prepared=prepared, started_at=now(), score_id=score_id or secrets.token_hex(16))
    worker = CoreSessionWorker(opened=opened, candidate_id=prepared.manifest.trial_id,
                               candidate_sha256=prepared.candidate_sha256, grant=grant,
                               bindings=lab_bindings(prepared))
    run.worker, run.worker_kind, run.grant = worker, worker.kind, grant
    try:
        _drive(run, worker, monotonic=monotonic)
    except KeyboardInterrupt:
        run.stop_reason = "interrupted"
        _complete_cases(run)
        _close(run, worker)
        raise ScoringInterrupted(_finish(run, now=now)) from None
    _close(run, worker)
    return _finish(run, now=now)


def _close(run: _Run, worker: object) -> None:
    try:
        worker.close()
    except BaseException:  # noqa: BLE001 - any failure to clean up fails closed
        run.cleanup = "failed"
    else:
        run.cleanup = "completed"


def _complete_cases(run: _Run) -> None:
    suite = run.prepared.suite
    cases = list(run.cases or [])
    seconds = list(run.case_seconds or [])
    for case in suite.cases[len(cases):]:
        cases.append(CaseResult(case_id=case.case_id, classification="not_evaluated"))
        seconds.append(None)
    run.cases, run.case_seconds = cases, seconds


def _drive(run: _Run, worker: object, *, monotonic: Callable[[], float]) -> None:
    prepared, policy = run.prepared, run.prepared.policy
    start = monotonic()
    run.cases, run.case_seconds = [], []
    try:
        facts = _checked(WorkerPreflight, worker.preflight(policy))
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001 - every worker failure is an infrastructure fact
        run.preflight, run.preflight_code = "failed", _infra_code(exc)
        run.stop_reason = "worker_preflight_failed"
        _complete_cases(run)
        return
    code = _check_preflight(facts, policy, run.worker_kind)
    if code is not None:
        run.preflight, run.preflight_code = "failed", code
        run.stop_reason = "worker_preflight_failed"
        _complete_cases(run)
        return
    run.preflight, run.preflight_facts = "passed", facts
    sources = harness_sources(parse_interface(prepared.interface.text), prepared.interface.symbol)
    run.harness_sha256 = harness_sha256(sources)
    request = CompileRequest(candidate_name=CANDIDATE_FILE, candidate=prepared.candidate_source.encode("utf-8"),
                             support=((HARNESS_FILE, sources[HARNESS_FILE]),
                                      (CANDIDATE_UNIT_FILE, sources[CANDIDATE_UNIT_FILE])),
                             translation_units=TRANSLATION_UNITS, limits=policy.compile)
    began = monotonic()
    try:
        observation = _checked(CompileObservation, worker.compile(request))
    except KeyboardInterrupt:
        raise
    except StageRefused as exc:
        run.stop_reason, run.refusal_reason = "core_refused", _refusal_code(exc.reason)
        _complete_cases(run)
        return
    except Exception as exc:  # noqa: BLE001
        run.compile_seconds = max(0.0, monotonic() - began)
        run.compilation = _compile_infra(_infra_code(exc))
        run.stop_reason = "worker_failure"
        _complete_cases(run)
        return
    run.compile_seconds = max(0.0, monotonic() - began)
    run.compilation, run.binary = _compilation(observation, policy.compile)
    if run.compilation.status == "infrastructure_failure":
        run.stop_reason = "worker_failure"
        _complete_cases(run)
        return
    if run.compilation.status != "succeeded":
        run.stop_reason = "compilation_failed"
        _complete_cases(run)
        return
    deadline_ms = policy.max_total_wall_ms
    for case in prepared.suite.cases:
        if (monotonic() - start) * 1000 >= deadline_ms:
            run.stop_reason = "scoring_deadline_exceeded"
            _complete_cases(run)
            return
        request = ExecuteRequest(binary=run.binary, arguments=encode_arguments(case.arguments),
                                 limits=policy.execute)
        began = monotonic()
        try:
            observation = _checked(ExecuteObservation, worker.execute(request))
        except KeyboardInterrupt:
            raise
        except StageRefused as exc:
            run.stop_reason, run.refusal_reason = "core_refused", _refusal_code(exc.reason)
            _complete_cases(run)
            return
        except Exception as exc:  # noqa: BLE001
            run.cases.append(CaseResult(case_id=case.case_id, classification="infrastructure_failure",
                                        infrastructure_code=_infra_code(exc)))
            run.case_seconds.append(max(0.0, monotonic() - began))
            run.stop_reason = "worker_failure"
            _complete_cases(run)
            return
        result = _case_result(case.case_id, observation, case.expected, policy.execute)
        run.cases.append(result)
        run.case_seconds.append(max(0.0, monotonic() - began))
        if result.classification == "infrastructure_failure":
            run.stop_reason = "worker_failure"
            _complete_cases(run)
            return
    run.stop_reason = "all_cases_evaluated"


def _refusal_code(reason: str) -> str:
    return reason if re.fullmatch(r"[A-Za-z0-9_.:+-]{1,120}", reason) else "unspecified"
