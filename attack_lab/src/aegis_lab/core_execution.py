"""Phase 4 integration with Core's candidate-execution contract (``aegis.core.isolated-worker.v1``).

Core is the **only authority** for compiling or running a candidate. Its
``CandidateExecutionGrant`` (``aegis.core.candidate-execution-grant.v1``) embeds
the operator's ``AttackLabAuthorization``. Core checks its three gates
(``[attack_lab] enabled``, the authorization, ``[attack_lab.candidate_execution]
enabled``), the grant window and the operator ceilings when a session opens, and
again before **every** compile and execute. It hashes the candidate bytes against
the grant, enforces the exact flags, limits and budgets, and runs only binaries
it compiled in the same session.

The Lab adds no permission of its own. Before contacting Core it checks only that
the grant describes the Lab's actual inputs, so a grant cannot silently authorize
something other than what is scored:

- the authorization reference is the manifest's;
- ``lab_bindings`` equal the digests the Lab computes itself (pair, hidden suite,
  sandbox policy, scorer configuration). Core cannot verify these;
- each scored trial is listed with its exact candidate SHA-256 and its own final
  target artifact. Core cannot verify the target;
- the stages, flags and per-stage limits equal the policy, so the scored limits
  are the policy's;
- the budgets cover the whole suite for every scored trial.

``CoreSessionWorker`` adapts one Core session to the Lab worker protocol. It
re-checks every record Core returns against the request (stage, candidate,
digest, grant, binary, arguments). A runtime injected by the caller (tests) must
attest ``test_double``. With no injected runtime, Core's configured runtime is
used, and in this revision it always refuses with ``SANDBOX_UNAVAILABLE``.

This module requires an ``aegis_core`` that provides ``lab_authorization`` and
``lab_execution`` (Role A, ADR 0004).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from aegis_core.config import AegisConfig
from aegis_core.errors import AegisError
from aegis_core.lab_authorization import (
    CandidateExecutionGrant,
    LabBindings,
    authorize_candidate_execution,
    grant_sha256,
)
from aegis_core.lab_execution import (
    CandidateExecutionRecord,
    CandidateExecutionSession,
    IsolationRuntime,
    SourceFile,
    open_session,
)
from aegis_core.lab_ledger import GrantLedger
from aegis_core.lab_limits import CompileLimits as CoreCompileLimits
from aegis_core.lab_limits import SandboxLimits as CoreSandboxLimits
from aegis_core.models import ErrorCode

from .canonical import canonical_sha256
from .scoring_policy import ExecutionRefused, SandboxPolicy, SandboxRuntime, scorer_configuration_sha256
from .scoring_worker import (
    CompileObservation,
    CompileRequest,
    EnforcedLimits,
    ExecuteObservation,
    ExecuteRequest,
    HostEnforcementObservation,
    StageRefused,
    WorkerError,
    WorkerPreflight,
)

if TYPE_CHECKING:  # pragma: no cover
    from .behavior_score import PreparedScoring

CORE_CONTRACT = "aegis.core.isolated-worker.v1"
_RUNTIME_NAMES = {"test_double": "aegis-test-double", "gvisor-runsc": "gvisor-runsc", "firecracker": "firecracker"}
_CORE_FAILURES = frozenset({"sandbox_start_failed", "sandbox_failed", "resource_enforcement_failed",
                            "cleanup_failed", "protocol_violation"})


def lab_bindings(prepared: PreparedScoring) -> LabBindings:
    """The digests the Lab declares to Core, computed from the Lab's own inputs."""
    policy = prepared.policy
    return LabBindings(pair_id=prepared.manifest.pair_id, hidden_test_suite_sha256=prepared.suite_sha256,
                       sandbox_policy_sha256=policy.sha256(),
                       scorer_configuration_sha256=scorer_configuration_sha256(policy))


def core_limits(policy: SandboxPolicy) -> tuple[CoreCompileLimits, CoreSandboxLimits]:
    return (CoreCompileLimits.model_validate(policy.compile.model_dump()),
            CoreSandboxLimits.model_validate(policy.execute.model_dump()))


def required_wall_ms(prepared: PreparedScoring) -> int:
    """Core's wall reservation for scoring one trial: one compilation plus one run per case."""
    return prepared.policy.compile.wall_ms + len(prepared.suite.cases) * prepared.policy.execute.wall_ms


def check_grant_binding(grant: CandidateExecutionGrant | None, trials: list[PreparedScoring]) -> None:
    """Raise ``ExecutionRefused`` unless the grant describes exactly what the Lab will run."""
    if grant is None:
        raise ExecutionRefused("grant_missing")
    if type(grant) is not CandidateExecutionGrant:
        raise ExecutionRefused("grant_missing")
    for prepared in trials:
        manifest, policy = prepared.manifest, prepared.policy
        if grant.authorization.reference != manifest.authorization.reference:
            raise ExecutionRefused("grant_reference_mismatch")
        expected = lab_bindings(prepared)
        if grant.lab_bindings != expected:
            fields = tuple(sorted(name for name, value in expected.model_dump().items()
                                  if grant.lab_bindings.model_dump()[name] != value))
            raise ExecutionRefused("grant_lab_bindings_mismatch", fields)
        if not {"compile", "execute"} <= set(grant.stages):
            raise ExecutionRefused("grant_stages_insufficient")
        if list(grant.compile_flags) != list(policy.compiler.flags):
            raise ExecutionRefused("grant_flags_mismatch")
        compile_limits, execute_limits = core_limits(policy)
        if grant.compile_limits != compile_limits or grant.execute_limits != execute_limits:
            raise ExecutionRefused("grant_limits_mismatch")
        permitted = grant.candidate(manifest.trial_id)
        if permitted is None:
            raise ExecutionRefused("grant_candidate_not_listed")
        if permitted.candidate_sha256 != prepared.candidate_sha256:
            raise ExecutionRefused("grant_candidate_mismatch")
        if permitted.target_sha256 != manifest.target.final_artifact_sha256:
            raise ExecutionRefused("grant_target_mismatch")
        if grant.max_executions_per_candidate < len(prepared.suite.cases):
            raise ExecutionRefused("grant_budget_insufficient", ("max_executions_per_candidate",))
    if sum(required_wall_ms(p) for p in trials) > grant.max_total_wall_ms:
        raise ExecutionRefused("grant_budget_insufficient", ("max_total_wall_ms",))


def _refusal(exc: AegisError) -> ExecutionRefused:
    if exc.code is ErrorCode.SANDBOX_UNAVAILABLE:
        blockers = exc.details.get("blockers") or ["unspecified"]
        return ExecutionRefused("sandbox_unavailable", tuple(str(b) for b in blockers))
    reason = exc.details.get("reason") if exc.code is ErrorCode.AUTHORIZATION_REQUIRED else exc.code.value
    return ExecutionRefused("core_refused", (str(reason or exc.code.value),))


def precheck_core(config: AegisConfig, grant: CandidateExecutionGrant, now: datetime,
                  trials: list[PreparedScoring] | None = None) -> None:
    """Core's own decision (gates 1-3, window, ceilings), asked before anything is created.

    With ``trials``, also reads Core's grant ledger (read-only) and refuses a grant whose
    *remaining* grant-wide budget cannot cover them, or whose id is bound to other contents.
    Core still reserves and enforces every run itself; this only fails early.
    """
    try:
        authorize_candidate_execution(config, grant, now)
        usage = GrantLedger.for_config(config).usage(grant.grant_id) if trials else None
    except AegisError as exc:
        raise _refusal(exc) from None
    if usage is None:
        return
    if usage.grant_sha256 != grant_sha256(grant):
        raise ExecutionRefused("core_refused", ("grant_ledger_conflict",))
    for prepared in trials:
        trial_id = prepared.manifest.trial_id
        if usage.compilations.get(trial_id, 0) + 1 > grant.max_compilations_per_candidate:
            raise ExecutionRefused("grant_budget_insufficient", ("compilations_already_used",))
        if usage.executions.get(trial_id, 0) + len(prepared.suite.cases) > grant.max_executions_per_candidate:
            raise ExecutionRefused("grant_budget_insufficient", ("executions_already_used",))
    if usage.wall_ms_reserved + sum(required_wall_ms(p) for p in trials) > grant.max_total_wall_ms:
        raise ExecutionRefused("grant_budget_insufficient", ("wall_already_reserved",))


@dataclass
class OpenedSession:
    """A Core session for one trial, or the infrastructure failure that prevented it."""

    injected: bool
    session: CandidateExecutionSession | None = None
    failure: str | None = None

    def close_quietly(self) -> None:
        if self.session is not None:
            try:
                self.session.close()
            except Exception:  # noqa: BLE001 - used only when no record depends on this session
                pass


def open_trial_session(config: AegisConfig, grant: CandidateExecutionGrant, bindings: LabBindings, *,
                       runtime: IsolationRuntime | None, clock: Callable[[], datetime]) -> OpenedSession:
    """Open a Core session. Refusals raise ``ExecutionRefused``; a runtime failure is returned."""
    injected = runtime is not None
    try:
        session = open_session(config, grant, lab_bindings=bindings, runtime=runtime, clock=clock)
    except AegisError as exc:
        if exc.code is ErrorCode.SANDBOX_FAILED:
            failure = exc.details.get("failure")
            return OpenedSession(injected=injected, failure=failure if failure in _CORE_FAILURES else "sandbox_failed")
        raise _refusal(exc) from None
    opened = OpenedSession(injected=injected, session=session)
    if injected and session.attestation.runtime != "test_double":
        # Only Core's configured runtime may attest isolation; a caller-supplied runtime is a test double.
        opened.close_quietly()
        raise ExecutionRefused("injected_runtime_not_test_double")
    return opened


@dataclass(frozen=True)
class CoreRecordReference:
    stage: str
    case_index: int | None
    record_id: str
    record_sha256: str


def core_record_sha256(record: CandidateExecutionRecord) -> str:
    return canonical_sha256(record.model_dump(mode="json"))


@dataclass
class CoreSessionWorker:
    """The Lab worker protocol over one Core session for one candidate."""

    opened: OpenedSession
    candidate_id: str
    candidate_sha256: str
    grant: CandidateExecutionGrant
    bindings: LabBindings
    records: list[CoreRecordReference] = field(default_factory=list)
    # Canonical Core bytes, never included in an attacker view or prompt.
    private_records: dict[str, bytes] = field(default_factory=dict)
    enforced: dict[str, EnforcedLimits] = field(default_factory=dict)
    accounting: list[tuple[str, int | None, HostEnforcementObservation]] = field(default_factory=list)
    _cases: int = 0

    @property
    def kind(self) -> str:
        session = self.opened.session
        if session is None:
            return "test_double" if self.opened.injected else "isolated_sandbox"
        return "test_double" if session.attestation.runtime == "test_double" else "isolated_sandbox"

    @property
    def session_id(self) -> str | None:
        return None if self.opened.session is None else self.opened.session.session_id

    @property
    def grant_sha256(self) -> str:
        return grant_sha256(self.grant)

    def preflight(self, policy: SandboxPolicy) -> WorkerPreflight:
        if self.opened.session is None:
            raise WorkerError(self.opened.failure or "sandbox_failed")
        a = self.opened.session.attestation
        test_double = a.runtime == "test_double"
        name = _RUNTIME_NAMES.get(a.runtime)
        if name is None:
            raise WorkerError("protocol_violation")
        try:
            runtime = SandboxRuntime(
                name=name, version=a.runtime_version, executable_sha256=a.runtime_sha256,
                rootfs_sha256=a.rootfs_sha256, guest_kernel_sha256=a.guest_kernel_sha256,
                guest_agent_sha256=a.guest_agent_sha256,
                containment_verification_sha256=a.containment_verification_sha256, platform=a.platform,
                rootless=a.rootless, network=a.network,
                resource_controller="none" if test_double else "systemd-user-scope-cgroup-v2",
                sandbox_per_compilation="fresh", sandbox_per_case="fresh", environment="empty",
                filesystem_layout="aegis.lab.sandbox-filesystem.v1")
        except ValueError:  # an attestation the Lab's runtime model cannot represent
            raise WorkerError("protocol_violation") from None
        grant = self.opened.session.grant
        return WorkerPreflight(
            runtime=runtime, compiler_name=a.compiler_name, compiler_version=a.compiler_version,
            compiler_executable_sha256=a.compiler_sha256,
            compile_limits=type(policy.compile).model_validate(grant.compile_limits.model_dump()),
            execute_limits=type(policy.execute).model_validate(grant.execute_limits.model_dump()),
            network=a.network, identity_observed=a.isolation_verified,
            limits_enforcement="not_enforced_test_double" if test_double else "verified_by_runtime")

    def _call(self, call: Callable[[], Any]) -> Any:
        if self.opened.session is None:
            raise WorkerError(self.opened.failure or "sandbox_failed")
        try:
            return call()
        except AegisError as exc:
            if exc.code is ErrorCode.SANDBOX_FAILED:
                failure = exc.details.get("failure")
                raise WorkerError(failure if failure in _CORE_FAILURES else "sandbox_failed") from None
            if exc.code is ErrorCode.AUTHORIZATION_REQUIRED:
                raise StageRefused(str(exc.details.get("reason") or "unspecified")) from None
            if exc.code is ErrorCode.INVALID_REQUEST:
                raise WorkerError("core_rejected_request") from None
            if exc.code is ErrorCode.STORAGE_ERROR:  # the grant ledger could not be used
                raise WorkerError("core_storage_failed") from None
            raise WorkerError("sandbox_failed") from None

    def _check_record(self, record: object, *, stage: str, binary_sha: str | None, args: list[str],
                      limits: dict[str, int], units: list[str], support: dict[str, str],
                      flags: list[str]) -> CandidateExecutionRecord:
        """Reject any Core record that does not describe exactly the authorized request."""
        session = self.opened.session
        if type(record) is not CandidateExecutionRecord:
            raise WorkerError("core_record_mismatch")
        from .canonical import canonical_json_bytes

        self.private_records[core_record_sha256(record)] = canonical_json_bytes(record.model_dump(mode="json"))
        permitted = self.grant.candidate(self.candidate_id)
        checks = (
            record.stage == stage,
            # authorized candidate
            permitted is not None and record.candidate_id == self.candidate_id
            and record.candidate_sha256 == self.candidate_sha256 == permitted.candidate_sha256,
            # grant
            record.grant_id == self.grant.grant_id,
            record.grant_sha256 == session.grant_sha256 == self.grant_sha256,
            record.lab_bindings == self.bindings == self.grant.lab_bindings,
            record.compilations_used <= self.grant.max_compilations_per_candidate,
            record.executions_used <= self.grant.max_executions_per_candidate,
            record.wall_ms_reserved <= self.grant.max_total_wall_ms,
            # run
            record.session_id == session.session_id,
            record.runtime == session.attestation,
            record.binary_sha256 == binary_sha,
            record.args == args,
            # policy (the grant's flags and limits equal the policy's; checked before the session)
            record.limits == limits,
            record.translation_units == units,
            record.support_files_sha256 == support,
            record.compile_flags == flags,
            record.stdout_sha256 == hashlib.sha256(record.observation.stdout).hexdigest(),
            record.stderr_sha256 == hashlib.sha256(record.observation.stderr).hexdigest(),
        )
        if not all(checks):
            raise WorkerError("core_record_mismatch")
        return record

    def _enforcement(self, record: CandidateExecutionRecord, stage: str, case: int | None,
                     limits: object) -> HostEnforcementObservation | None:
        """Validate the runtime's enforcement observation for one stage.

        A test double must report none. An isolating runtime must report it on every
        observation (also for host-observed timeouts and OOM kills). The enforced limits must
        give the guest room for the requested job, and must be identical for every
        invocation of the same stage in this trial. Failures are infrastructure failures.
        """
        raw = record.observation.host_enforcement
        if record.runtime.runtime == "test_double":
            if raw is not None:
                raise WorkerError("host_enforcement_invalid")
            return None
        if raw is None:
            raise WorkerError("host_enforcement_invalid")
        data = raw.model_dump()
        accounting_fields = ("host_cpu_usec", "host_memory_peak_bytes", "host_oom_kills")
        try:
            observed = HostEnforcementObservation(
                enforced=EnforcedLimits.model_validate({k: v for k, v in data.items() if k not in accounting_fields}),
                accounting={k: data[k] for k in accounting_fields})
        except ValueError:
            raise WorkerError("host_enforcement_invalid") from None
        if not observed.enforced.covers(limits):
            raise WorkerError("host_enforcement_invalid")
        previous = self.enforced.setdefault(stage, observed.enforced)
        if previous != observed.enforced:
            raise WorkerError("host_enforcement_invalid")
        self.accounting.append((stage, case, observed))
        return observed

    def compile(self, request: CompileRequest) -> CompileObservation:
        session = self.opened.session
        candidate = SourceFile(name=request.candidate_name, data=request.candidate)
        support = [SourceFile(name=name, data=data) for name, data in request.support]
        limits = CoreCompileLimits.model_validate(request.limits.model_dump())
        units = list(request.translation_units)
        flags = list(self.grant.compile_flags)
        result = self._call(lambda: session.compile(self.candidate_id, candidate, support_files=support,
                                                    translation_units=units, flags=flags, limits=limits))
        binary = result.binary
        record = self._check_record(
            result.record, stage="compile", args=[], limits=limits.model_dump(), units=units, flags=flags,
            binary_sha=None if binary is None else hashlib.sha256(binary).hexdigest(),
            support={name: hashlib.sha256(data).hexdigest() for name, data in request.support})
        enforcement = self._enforcement(record, "compile", None, request.limits)
        self.records.append(CoreRecordReference("compile", None, record.record_id, core_record_sha256(record)))
        obs = record.observation
        return CompileObservation(status=obs.status, exit_code=obs.exit_code, signal=obs.signal, limit=obs.limit,
                                  diagnostics=obs.stderr, diagnostics_truncated=obs.stderr_truncated, binary=binary,
                                  host_enforcement=enforcement)

    def execute(self, request: ExecuteRequest) -> ExecuteObservation:
        session = self.opened.session
        limits = CoreSandboxLimits.model_validate(request.limits.model_dump())
        args = list(request.arguments)
        record = self._call(lambda: session.execute(self.candidate_id, request.binary, args=args, limits=limits))
        record = self._check_record(record, stage="execute", binary_sha=hashlib.sha256(request.binary).hexdigest(),
                                    args=args, limits=limits.model_dump(), units=[], support={}, flags=[])
        enforcement = self._enforcement(record, "execute", self._cases, request.limits)
        self.records.append(CoreRecordReference("execute", self._cases, record.record_id, core_record_sha256(record)))
        self._cases += 1
        obs = record.observation
        return ExecuteObservation(status=obs.status, exit_code=obs.exit_code, signal=obs.signal, limit=obs.limit,
                                  stdout=obs.stdout, stdout_truncated=obs.stdout_truncated,
                                  stderr_bytes=len(obs.stderr), host_enforcement=enforcement)

    def close(self) -> None:
        if self.opened.session is None:
            return
        try:
            self.opened.session.close()
        except AegisError:
            raise WorkerError("cleanup_failed") from None
