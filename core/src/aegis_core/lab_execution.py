"""Core-side contract for compiling and running untrusted Lab candidates.

``open_session`` checks every gate and the grant, then asks an isolation runtime
for a preflight attestation. Each ``compile``/``execute`` call re-checks the
gates and the grant's window, binds the call to the grant (candidate digest,
flags, limits, budgets), hashes everything that crosses the boundary, and
returns a ``CandidateExecutionRecord``. Core executes only binaries it compiled
in the same session. Budgets are per grant, across sessions and processes
(``aegis_core.lab_ledger``).

The Firecracker backend is implemented but **not containment-validated or
approved**. ``configured_runtime`` returns ``UnavailableRuntime`` while ADR 0004
is unaccepted, and normal candidate execution stays disabled. The design is
docs/adr/0004-isolated-candidate-execution.md; the
integration contract for the Lab is core/docs/lab-execution-contract.md.

Candidate behavior (compile errors, crashes, timeouts, exceeded limits) is an
*observation*. Runtime failures are ``SANDBOX_FAILED`` and poison the session.
Neither is ever a success or a score.
"""

from __future__ import annotations

import hashlib
import re
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Literal, Protocol, TypeVar

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    StrictBool,
    StrictBytes,
    StrictInt,
    model_validator,
)

from .config import AegisConfig
from .errors import AegisError
from .lab_authorization import (
    CandidateExecutionGrant,
    ExecutionStage,
    LabBindings,
    authorize_candidate_execution,
    compilation_bundle_sha256,
    grant_sha256,
    refuse,
)
from .lab_ledger import GrantLedger, GrantUsage
from .lab_limits import MIB, CompileLimits, SandboxLimits
from .models import AegisModel, ErrorCode, ObjectId, Sha256, utcnow

WORKER_CONTRACT = "aegis.core.isolated-worker.v1"
RECORD_SCHEMA = "aegis.core.candidate-execution-record.v1"

SOURCE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}\.[ch]$"
ARGUMENT_PATTERN = r"^[A-Za-z0-9_.+:=,-]{1,256}$"
MAX_SOURCE_BYTES = 1 * MIB
MAX_TOTAL_SOURCE_BYTES = 4 * MIB
MAX_SUPPORT_FILES = 15
MAX_TRANSLATION_UNITS = 1 + MAX_SUPPORT_FILES
MAX_ARGUMENTS = 64
BINARY_NAME = "candidate"

# Blockers reported by the configured runtime until ADR 0004 is accepted and a
# verified runtime is implemented.
ISOLATION_BLOCKERS: tuple[str, ...] = (
    "isolation_adr_not_accepted",
    "isolated_runtime_not_implemented",
)
# Flipped only by a reviewed change once ADR 0004 (and its Firecracker amendment)
# is accepted. While False, the configured runtime always refuses.
ADR_0004_ACCEPTED = False

# Stable values of ``details["failure"]`` on SANDBOX_FAILED errors. They match the
# Lab worker protocol's WorkerError codes.
SANDBOX_FAILURES = frozenset(
    {
        "sandbox_start_failed",
        "sandbox_failed",
        "resource_enforcement_failed",
        "cleanup_failed",
        "protocol_violation",
    }
)


def sandbox_failure(failure: str, message: str, **details: Any) -> AegisError:
    """A SANDBOX_FAILED error with a registered ``details.failure``."""
    if failure not in SANDBOX_FAILURES:
        raise AssertionError(f"unregistered sandbox failure {failure!r}")
    return AegisError(ErrorCode.SANDBOX_FAILED, message, {"failure": failure, **details})


def sandbox_unavailable(blockers: tuple[str, ...] | list[str], message: str) -> AegisError:
    return AegisError(ErrorCode.SANDBOX_UNAVAILABLE, message, {"blockers": list(blockers)})


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _BytesModel(AegisModel):
    # Bytes travel as base64 in JSON so arbitrary output survives serialization.
    model_config = ConfigDict(ser_json_bytes="base64", val_json_bytes="base64")


# ------------------------------------------------------------- contract types


class SourceFile(_BytesModel):
    """One C source or header file. Names are fixed single components, never paths."""

    name: Annotated[str, Field(pattern=SOURCE_NAME_PATTERN)]
    data: Annotated[StrictBytes, Field(max_length=MAX_SOURCE_BYTES)]


class PreflightRequest(AegisModel):
    """The largest limits the session may ask for; the runtime must be able to enforce them."""

    compile_limits: CompileLimits | None
    execute_limits: SandboxLimits | None


class RuntimeAttestation(AegisModel):
    """What the runtime established about itself before any candidate input.

    A real runtime observes these values itself (binary digests, cgroup
    read-back). The test double states that nothing is isolated or enforced.
    """

    runtime: Literal["firecracker", "gvisor-runsc", "test_double"]
    runtime_version: Annotated[str, Field(min_length=1, max_length=200)]
    runtime_sha256: Sha256 | None
    platform: Literal["systrap", "kvm", "none"]
    rootless: StrictBool
    network: Literal["none"]
    rootfs_sha256: Sha256 | None
    compiler_name: Literal["gcc", "clang"]
    compiler_version: Annotated[str, Field(min_length=1, max_length=200)]
    compiler_sha256: Sha256
    limits_enforcement: Literal["verified_by_cgroup_readback", "not_enforced_test_double"]
    isolation_verified: StrictBool
    guest_kernel_sha256: Sha256 | None = None
    guest_agent_sha256: Sha256 | None = None
    containment_verification_sha256: Sha256 | None = None
    """Digest of the recorded containment report (F1-F5, V1-V11) this backend ran under."""

    @model_validator(mode="after")
    def _consistent(self) -> RuntimeAttestation:
        guest = (self.guest_kernel_sha256, self.guest_agent_sha256, self.containment_verification_sha256)
        if self.runtime == "test_double":
            ok = (
                self.runtime_sha256 is None
                and self.platform == "none"
                and self.rootfs_sha256 is None
                and self.limits_enforcement == "not_enforced_test_double"
                and not self.isolation_verified
                and guest == (None, None, None)
            )
        elif self.runtime == "firecracker":
            ok = (
                self.runtime_sha256 is not None
                and self.platform == "kvm"
                and self.rootless
                and self.rootfs_sha256 is not None
                and None not in guest
                and self.limits_enforcement == "verified_by_cgroup_readback"
                and self.isolation_verified
            )
        else:
            ok = (
                self.runtime_sha256 is not None
                and self.platform in ("systrap", "kvm")
                and self.rootless
                and self.rootfs_sha256 is not None
                and self.limits_enforcement == "verified_by_cgroup_readback"
                and self.isolation_verified
                and self.guest_kernel_sha256 is None
                and self.guest_agent_sha256 is None
            )
        if not ok:
            raise ValueError("attestation fields are inconsistent with the runtime kind")
        return self


class CompileJob(_BytesModel):
    """What Core hands the runtime for one compilation. Contains no hidden-test data.

    Every file is staged in the compilation directory under its own name, so any
    of them can be ``#include``d. Only ``translation_units`` are passed to the
    compiler, in order; a runtime must build its argv with ``compiler_arguments``.
    """

    candidate: SourceFile
    support_files: list[SourceFile]
    translation_units: Annotated[list[str], Field(min_length=1, max_length=MAX_TRANSLATION_UNITS)]
    flags: list[str]
    output_name: Literal["candidate"] = BINARY_NAME
    limits: CompileLimits

    @model_validator(mode="after")
    def _units(self) -> CompileJob:
        _check_translation_units(self.candidate, self.support_files, self.translation_units)
        return self

    def compiler_arguments(self) -> list[str]:
        """Arguments after the compiler path: ``[*flags, -o, candidate, *translation_units]``."""
        return [*self.flags, "-o", self.output_name, *self.translation_units]


class ExecuteJob(_BytesModel):
    """One test case: a binary compiled in this session and that case's arguments only."""

    binary: StrictBytes
    args: list[str]
    limits: SandboxLimits


class HostEnforcement(AegisModel):
    """Limits the host read back from the sandbox's cgroup before the job was sent,
    the microVM's configured resources, and host-side accounting after the run."""

    memory_max_bytes: Annotated[StrictInt, Field(ge=0)]
    memory_swap_max_bytes: Annotated[StrictInt, Field(ge=0)]
    pids_max: Annotated[StrictInt, Field(ge=0)]
    cpu_quota_us: Annotated[StrictInt, Field(ge=0)]
    cpu_period_us: Annotated[StrictInt, Field(ge=1)]
    vm_memory_mib: Annotated[StrictInt, Field(ge=1)]
    vcpu_count: Annotated[StrictInt, Field(ge=1)]
    block_bandwidth_bytes_per_s: Annotated[StrictInt, Field(ge=1)]
    block_ops_per_s: Annotated[StrictInt, Field(ge=1)]
    host_cpu_usec: Annotated[StrictInt, Field(ge=0)] | None = None
    host_memory_peak_bytes: Annotated[StrictInt, Field(ge=0)] | None = None
    host_oom_kills: Annotated[StrictInt, Field(ge=0)] = 0


ObservedStatus = Literal["exited", "signaled", "timeout", "limit_exceeded"]
LimitName = Literal["cpu", "memory", "processes", "scratch", "stdout", "stderr", "binary"]


class StageObservation(_BytesModel):
    """What the runtime observed about one sandbox. Never a verdict."""

    status: ObservedStatus
    exit_code: Annotated[StrictInt, Field(ge=0, le=255)] | None = None
    signal: Annotated[StrictInt, Field(ge=1, le=64)] | None = None
    limit: LimitName | None = None
    stdout: StrictBytes = b""
    stdout_truncated: StrictBool = False
    stderr: StrictBytes = b""
    stderr_truncated: StrictBool = False
    duration_ms: Annotated[StrictInt, Field(ge=0)]
    cpu_ms: Annotated[StrictInt, Field(ge=0)] | None = None
    peak_memory_bytes: Annotated[StrictInt, Field(ge=0)] | None = None
    host_enforcement: HostEnforcement | None = None
    """Set by isolating runtimes; None for the test double."""

    @model_validator(mode="after")
    def _exit_fields(self) -> StageObservation:
        if (self.status == "exited") != (self.exit_code is not None):
            raise ValueError("exit_code is set exactly for an exited process")
        if (self.status == "signaled") != (self.signal is not None):
            raise ValueError("signal is set exactly for a signaled process")
        if (self.status == "limit_exceeded") != (self.limit is not None):
            raise ValueError("limit is set exactly when a limit was exceeded")
        return self


class CompileObservation(StageObservation):
    binary: StrictBytes | None = None

    @model_validator(mode="after")
    def _binary(self) -> CompileObservation:
        if self.binary is not None and not (self.status == "exited" and self.exit_code == 0):
            raise ValueError("a binary is returned only by a successful compilation")
        if self.binary == b"":
            raise ValueError("a returned binary must not be empty")
        return self


class ExecuteObservation(StageObservation):
    @model_validator(mode="after")
    def _no_binary_limit(self) -> ExecuteObservation:
        if self.limit == "binary":
            raise ValueError("the binary limit applies to compilation only")
        return self


class CandidateExecutionRecord(_BytesModel):
    """Core's record of one stage invocation.

    ``grant_sha256``, ``candidate_sha256``, ``binary_sha256``, the output digests,
    limits, budgets and timestamps are computed or checked by Core. The
    observation fields come from the runtime named in ``runtime``; with
    ``runtime.runtime == "test_double"`` they are scripted and are never evidence.
    ``lab_bindings`` are the Lab's declarations, bound but not verified by Core.
    """

    schema_version: Literal["aegis.core.candidate-execution-record.v1"] = RECORD_SCHEMA
    record_id: ObjectId
    session_id: ObjectId
    grant_id: ObjectId
    grant_sha256: Sha256
    lab_bindings: LabBindings
    stage: ExecutionStage
    candidate_id: ObjectId
    candidate_sha256: Sha256
    support_files_sha256: dict[str, Sha256] = Field(default_factory=dict)
    translation_units: list[str] = Field(default_factory=list)
    """Compile only: the files passed to the compiler, in order."""
    compile_flags: list[str] = Field(default_factory=list)
    binary_sha256: Sha256 | None = None
    binary_bytes: Annotated[StrictInt, Field(ge=0)] | None = None
    args: list[str] = Field(default_factory=list)
    limits: dict[str, int]
    runtime: RuntimeAttestation
    observation: StageObservation
    stdout_sha256: Sha256
    stderr_sha256: Sha256
    compilations_used: Annotated[StrictInt, Field(ge=0)]
    """Compilations of this candidate under the grant, all sessions, including this one."""
    executions_used: Annotated[StrictInt, Field(ge=0)]
    """Executions of this candidate under the grant, all sessions, including this one."""
    wall_ms_reserved: Annotated[StrictInt, Field(ge=0)]
    """Wall-clock budget reserved under the grant, all sessions, including this run."""
    started_at: AwareDatetime
    finished_at: AwareDatetime


@dataclass(frozen=True)
class CompileResult:
    record: CandidateExecutionRecord
    binary: bytes | None
    """The produced binary, or None when compilation did not succeed. Untrusted bytes."""


class IsolationRuntime(Protocol):
    """An isolation runtime (``aegis.core.isolated-worker.v1``).

    Implementations must run each compile and each execute in a fresh sandbox,
    enforce every limit in the job, return bounded observations, and clean up
    before returning. Infrastructure problems must raise ``SANDBOX_FAILED`` (or
    any exception, which Core treats as one); they must never be reported as a
    candidate observation.
    """

    def preflight(self, request: PreflightRequest) -> RuntimeAttestation: ...

    def compile(self, job: CompileJob) -> CompileObservation: ...

    def execute(self, job: ExecuteJob) -> ExecuteObservation: ...

    def close(self) -> None: ...


# ----------------------------------------------------------- configured runtime


class UnavailableRuntime:
    """The runtime in this revision: refuses every request. It never runs anything."""

    def __init__(self, blockers: tuple[str, ...]):
        if not blockers:
            raise ValueError("an unavailable runtime needs at least one blocker")
        self.blockers = blockers

    def _refuse(self) -> AegisError:
        return sandbox_unavailable(
            self.blockers,
            "No approved, verified isolation runtime is available; candidate code was not "
            "compiled or run.",
        )

    def preflight(self, request: PreflightRequest) -> RuntimeAttestation:
        raise self._refuse()

    def compile(self, job: CompileJob) -> CompileObservation:
        raise self._refuse()

    def execute(self, job: ExecuteJob) -> ExecuteObservation:
        raise self._refuse()

    def close(self) -> None:
        return None


def configured_runtime(
    config: AegisConfig,
    *,
    host_blockers: Callable[[], tuple[str, ...]] | None = None,
    adr_accepted: bool | None = None,
) -> IsolationRuntime:
    """The runtime selected by ``[attack_lab.candidate_execution] runtime``.

    ``none`` always refuses. ``firecracker`` returns ``FirecrackerRuntime`` only when
    ADR 0004 is accepted, the operator pinned a containment-verification digest and
    the static host probe reports no blocker; otherwise it refuses with every
    blocker found. ``host_blockers`` and ``adr_accepted`` exist for tests.
    """
    execution = config.attack_lab.candidate_execution
    runtime_name = "firecracker" if execution.runtime == "firecracker" else "gvisor-runsc"
    if host_blockers is None:
        from .lab_host import probe_host

        def host_blockers() -> tuple[str, ...]:
            return tuple(probe_host(runtime=runtime_name).blockers)

    try:
        extra = tuple(host_blockers())
    except Exception:  # a broken probe must not hide the refusal
        extra = ("host_probe_failed",)
    if execution.runtime != "firecracker":
        blockers = ISOLATION_BLOCKERS + tuple(b for b in extra if b not in ISOLATION_BLOCKERS)
        return UnavailableRuntime(blockers)
    accepted = ADR_0004_ACCEPTED if adr_accepted is None else adr_accepted
    fc = execution.firecracker
    assert fc is not None  # guaranteed by the config validator
    found: list[str] = []
    if not accepted:
        found.append("isolation_adr_not_accepted")
    if fc.containment_verification_sha256 is None:
        found.append("containment_unverified")
    found.extend(b for b in extra if b not in found)
    if found:
        return UnavailableRuntime(tuple(found))
    from .lab_firecracker import FirecrackerRuntime

    return FirecrackerRuntime(fc)


# ---------------------------------------------------------------------- session

_Obs = TypeVar("_Obs", CompileObservation, ExecuteObservation)


def open_session(
    config: AegisConfig,
    grant: CandidateExecutionGrant,
    *,
    lab_bindings: LabBindings,
    runtime: IsolationRuntime | None = None,
    clock: Callable[[], datetime] = utcnow,
    ledger: GrantLedger | None = None,
) -> CandidateExecutionSession:
    """Authorize, bind the Lab's declarations, register with the grant ledger, then
    preflight the runtime.

    ``runtime=None`` uses ``configured_runtime(config)``, which refuses in this
    revision. Passing a runtime explicitly is for tests and future runtimes; the
    attestation it returns is recorded on every record. ``ledger=None`` uses the
    ledger under the configured store root. Once the runtime has been touched, it
    is closed on **any** failure or interruption before the session is returned.
    """
    now = clock()
    authorize_candidate_execution(config, grant, now)
    if lab_bindings != grant.lab_bindings:
        mismatched = sorted(
            name
            for name, value in lab_bindings.model_dump().items()
            if grant.lab_bindings.model_dump()[name] != value
        )
        raise refuse(
            "lab_bindings_mismatch",
            "The Lab's declared digests differ from those bound in the grant.",
            fields=mismatched,
        )
    ledger = ledger if ledger is not None else GrantLedger.for_config(config)
    # Before the runtime is touched: refuses a different grant reusing this id.
    ledger.register_session(grant, grant_sha256(grant), now)
    runtime = runtime if runtime is not None else configured_runtime(config)
    request = PreflightRequest(compile_limits=grant.compile_limits, execute_limits=grant.execute_limits)
    try:
        try:
            attestation = runtime.preflight(request)
            attestation = RuntimeAttestation.model_validate(attestation.model_dump())
        except AegisError as exc:
            if exc.code in (ErrorCode.SANDBOX_UNAVAILABLE, ErrorCode.SANDBOX_FAILED):
                raise
            raise _preflight_failed() from None
        except Exception:
            raise _preflight_failed() from None
        return CandidateExecutionSession(
            config, grant, runtime, attestation, clock=clock, ledger=ledger
        )
    except BaseException:
        # Includes KeyboardInterrupt and SystemExit: the runtime is released, then the
        # original exception propagates unchanged.
        _close_quietly(runtime)
        raise


def _preflight_failed() -> AegisError:
    return sandbox_unavailable(["runtime_preflight_failed"], "Runtime preflight failed.")


def _close_quietly(runtime: IsolationRuntime) -> None:
    try:
        runtime.close()
    except Exception:
        pass


class CandidateExecutionSession:
    """Bound to one grant and one runtime. Not reusable after close or after a failure.

    Create sessions with ``open_session``; the constructor performs no
    authorization or preflight itself (every stage still re-checks the gates).
    """

    def __init__(
        self,
        config: AegisConfig,
        grant: CandidateExecutionGrant,
        runtime: IsolationRuntime,
        attestation: RuntimeAttestation,
        *,
        clock: Callable[[], datetime] = utcnow,
        ledger: GrantLedger,
    ):
        self.session_id = uuid.uuid4().hex
        self.config = config
        # A private, re-validated copy: later changes to the caller's grant object
        # cannot widen what this session permits or desynchronize grant_sha256.
        self._grant = CandidateExecutionGrant.model_validate(grant.model_dump())
        self.grant_sha256 = grant_sha256(self._grant)
        self.attestation = attestation
        self._runtime = runtime
        self._clock = clock
        self._lock = threading.Lock()
        self._ledger = ledger
        self._closed = False
        self._cleanup_complete = False
        self._failed = False
        self._binaries: dict[str, set[str]] = {}

    # ------------------------------------------------------------- properties

    @property
    def grant(self) -> CandidateExecutionGrant:
        """A copy of the grant this session enforces."""
        return self._grant.model_copy(deep=True)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def failed(self) -> bool:
        return self._failed

    def grant_usage(self) -> GrantUsage:
        """Usage of this session's grant across all sessions (read from the ledger)."""
        usage = self._ledger.usage(self._grant.grant_id)
        assert usage is not None  # registered when the session was opened
        return usage

    @property
    def wall_ms_reserved(self) -> int:
        return self.grant_usage().wall_ms_reserved

    def compilations_used(self, candidate_id: str) -> int:
        return self.grant_usage().compilations.get(candidate_id, 0)

    def executions_used(self, candidate_id: str) -> int:
        return self.grant_usage().executions.get(candidate_id, 0)

    # ----------------------------------------------------------------- stages

    def compile(
        self,
        candidate_id: str,
        candidate: SourceFile,
        *,
        support_files: list[SourceFile] | tuple[SourceFile, ...] = (),
        translation_units: list[str] | tuple[str, ...],
        flags: list[str] | tuple[str, ...],
        limits: CompileLimits,
    ) -> CompileResult:
        """Compile in a fresh sandbox.

        All files are staged; only ``translation_units`` (names of ``candidate`` or
        ``support_files``, ``.c`` only, in order) are passed to the compiler. A unit
        that ``#include``s the candidate must not be accompanied by the candidate
        itself as a unit, or it is defined twice; Core does not parse includes.
        """
        with self._lock:
            started = self._authorize("compile")
            # Snapshot caller-owned models before checking their bytes or limits.
            try:
                candidate = SourceFile.model_validate(candidate.model_dump())
                support = [SourceFile.model_validate(f.model_dump()) for f in support_files]
            except Exception:
                raise AegisError(ErrorCode.INVALID_REQUEST, "Sources must be valid SourceFile records.") from None
            permitted = self._grant.candidate(candidate_id)
            if permitted is None:
                raise refuse("candidate_not_permitted", "The grant does not list this candidate.")
            candidate_sha = _sha256(candidate.data)
            if candidate_sha != permitted.candidate_sha256:
                raise refuse(
                    "candidate_digest_mismatch",
                    "The candidate source differs from the digest permitted by the grant.",
                    expected_sha256=permitted.candidate_sha256,
                    actual_sha256=candidate_sha,
                )
            if list(flags) != self._grant.compile_flags:
                raise refuse("compile_flags_mismatch", "Compiler flags differ from the grant.")
            flags = tuple(flags)
            assert self._grant.compile_limits is not None  # guaranteed by the grant validator
            limits = self._check_limits(limits, self._grant.compile_limits)
            _check_sources(candidate, support)
            units = _check_translation_units(candidate, support, translation_units)
            if permitted.compilation_bundle_sha256 is None:
                if support or candidate.name != "candidate.c" or units != ["candidate.c"]:
                    raise refuse("compilation_bundle_required",
                                 "A multi-file or renamed compilation requires a bound compilation bundle.")
            elif compilation_bundle_sha256({f.name: f.data for f in [candidate, *support]}, units) != permitted.compilation_bundle_sha256:
                raise refuse("compilation_bundle_mismatch", "The compilation bundle differs from the grant.")
            usage = self._reserve("compile", candidate_id, limits.wall_ms, started)

            job = CompileJob(
                candidate=candidate,
                support_files=support,
                translation_units=units,
                flags=list(flags),
                limits=limits,
            )
            obs = self._invoke(self._runtime.compile, job, CompileObservation)
            self._check_output_bounds(obs, limits)
            binary = obs.binary
            if binary is not None and len(binary) > limits.binary_bytes:
                raise self._fail("protocol_violation", "The runtime returned an oversized binary.")
            binary_sha = _sha256(binary) if binary is not None else None
            if binary_sha is not None:
                self._binaries.setdefault(binary_sha, set()).add(candidate_id)
            record = self._record(
                stage="compile",
                candidate_id=candidate_id,
                candidate_sha256=candidate_sha,
                support_files_sha256={f.name: _sha256(f.data) for f in support},
                translation_units=units,
                compile_flags=list(flags),
                binary_sha256=binary_sha,
                binary_bytes=len(binary) if binary is not None else None,
                args=[],
                limits=limits,
                observation=obs,
                started_at=started,
                usage=usage,
            )
            return CompileResult(record=record, binary=binary)

    def execute(
        self,
        candidate_id: str,
        binary: bytes,
        *,
        args: list[str] | tuple[str, ...],
        limits: SandboxLimits,
    ) -> CandidateExecutionRecord:
        with self._lock:
            started = self._authorize("execute")
            permitted = self._grant.candidate(candidate_id)
            if permitted is None:
                raise refuse("candidate_not_permitted", "The grant does not list this candidate.")
            if not isinstance(binary, bytes):
                raise AegisError(ErrorCode.INVALID_REQUEST, "binary must be bytes.")
            binary_sha = _sha256(binary)
            if candidate_id not in self._binaries.get(binary_sha, set()):
                raise refuse(
                    "binary_not_from_session",
                    "Only a binary compiled from this candidate in this session may run.",
                )
            assert self._grant.execute_limits is not None  # guaranteed by the grant validator
            limits = self._check_limits(limits, self._grant.execute_limits)
            arguments = _check_arguments(args)
            usage = self._reserve("execute", candidate_id, limits.wall_ms, started)

            job = ExecuteJob(binary=binary, args=arguments, limits=limits)
            obs = self._invoke(self._runtime.execute, job, ExecuteObservation)
            self._check_output_bounds(obs, limits)
            return self._record(
                stage="execute",
                candidate_id=candidate_id,
                candidate_sha256=permitted.candidate_sha256,
                support_files_sha256={},
                translation_units=[],
                compile_flags=[],
                binary_sha256=binary_sha,
                binary_bytes=len(binary),
                args=arguments,
                limits=limits,
                observation=obs,
                started_at=started,
                usage=usage,
            )

    def close(self) -> None:
        """Release the runtime. Idempotent. A cleanup failure poisons the session."""
        with self._lock:
            if self._cleanup_complete:
                return
            self._closed = True
            try:
                self._runtime.close()
            except AegisError as exc:
                self._failed = True
                if exc.code is ErrorCode.SANDBOX_FAILED:
                    raise
                raise sandbox_failure("cleanup_failed", "Runtime cleanup failed.") from None
            except Exception:
                self._failed = True
                raise sandbox_failure("cleanup_failed", "Runtime cleanup failed.") from None
            self._cleanup_complete = True

    def __enter__(self) -> CandidateExecutionSession:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---------------------------------------------------------------- helpers

    def _authorize(self, stage: ExecutionStage) -> datetime:
        if self._closed:
            raise refuse("session_closed", "The candidate execution session is closed.")
        if self._failed:
            raise refuse(
                "session_failed",
                "The candidate execution session had an infrastructure failure and refuses "
                "further work.",
            )
        now = self._clock()
        # The configuration and the grant's window are re-checked before every stage.
        authorize_candidate_execution(self.config, self._grant, now)
        if stage not in self._grant.stages:
            raise refuse("stage_not_permitted", f"The grant does not permit the {stage} stage.")
        return now

    def _check_limits(self, limits: SandboxLimits, ceiling: SandboxLimits) -> SandboxLimits:
        if type(limits) is not type(ceiling):
            raise AegisError(
                ErrorCode.INVALID_REQUEST,
                f"limits must be {type(ceiling).__name__} for this stage.",
            )
        try:
            limits = type(ceiling).model_validate(limits.model_dump())
        except Exception:
            raise AegisError(ErrorCode.INVALID_REQUEST, "Stage limits are invalid.") from None
        if over := limits.exceeding(ceiling):
            raise refuse("limits_exceed_grant", "Requested limits exceed the grant.", exceeding=over)
        return limits

    def _reserve(
        self, stage: ExecutionStage, candidate_id: str, wall_ms: int, now: datetime
    ) -> GrantUsage:
        # Grant-wide, across sessions and processes; never returned after a failure.
        return self._ledger.reserve(
            self._grant,
            self.grant_sha256,
            stage=stage,
            candidate_id=candidate_id,
            wall_ms=wall_ms,
            now=now,
        )

    def _fail(self, failure: str, message: str) -> AegisError:
        self._failed = True
        return sandbox_failure(failure, message)

    def _invoke(self, call: Callable[[Any], Any], job: Any, expected: type[_Obs]) -> _Obs:
        try:
            raw = call(job)
        except AegisError as exc:
            self._failed = True
            if exc.code is ErrorCode.SANDBOX_FAILED:
                raise
            raise sandbox_failure("sandbox_failed", "The isolation runtime failed.") from None
        except BaseException as exc:
            self._failed = True
            if not isinstance(exc, Exception):  # KeyboardInterrupt, SystemExit
                raise
            raise sandbox_failure("sandbox_failed", "The isolation runtime failed.") from None
        if not isinstance(raw, expected):
            raise self._fail("protocol_violation", "The runtime returned an unexpected observation.")
        try:
            # Re-validate: an observation object may have been mutated after construction.
            return expected.model_validate(raw.model_dump())
        except Exception:
            raise self._fail(
                "protocol_violation", "The runtime returned an invalid observation."
            ) from None

    def _check_output_bounds(self, obs: StageObservation, limits: SandboxLimits) -> None:
        if len(obs.stdout) > limits.stdout_bytes or len(obs.stderr) > limits.stderr_bytes:
            raise self._fail("protocol_violation", "The runtime returned output beyond the limits.")

    def _record(
        self,
        *,
        stage: ExecutionStage,
        candidate_id: str,
        candidate_sha256: str,
        support_files_sha256: dict[str, str],
        translation_units: list[str],
        compile_flags: list[str],
        binary_sha256: str | None,
        binary_bytes: int | None,
        args: list[str],
        limits: SandboxLimits,
        observation: StageObservation,
        started_at: datetime,
        usage: GrantUsage,
    ) -> CandidateExecutionRecord:
        base = StageObservation.model_validate(
            observation.model_dump(include=set(StageObservation.model_fields))
        )
        return CandidateExecutionRecord(
            record_id=uuid.uuid4().hex,
            session_id=self.session_id,
            grant_id=self._grant.grant_id,
            grant_sha256=self.grant_sha256,
            lab_bindings=self._grant.lab_bindings,
            stage=stage,
            candidate_id=candidate_id,
            candidate_sha256=candidate_sha256,
            support_files_sha256=support_files_sha256,
            translation_units=translation_units,
            compile_flags=compile_flags,
            binary_sha256=binary_sha256,
            binary_bytes=binary_bytes,
            args=args,
            limits=limits.model_dump(),
            runtime=self.attestation,
            observation=base,
            stdout_sha256=_sha256(observation.stdout),
            stderr_sha256=_sha256(observation.stderr),
            compilations_used=usage.compilations.get(candidate_id, 0),
            executions_used=usage.executions.get(candidate_id, 0),
            wall_ms_reserved=usage.wall_ms_reserved,
            started_at=started_at,
            finished_at=self._clock(),
        )


def _check_sources(candidate: SourceFile, support: list[SourceFile]) -> None:
    if not isinstance(candidate, SourceFile) or not all(isinstance(f, SourceFile) for f in support):
        raise AegisError(ErrorCode.INVALID_REQUEST, "Sources must be SourceFile records.")
    if len(support) > MAX_SUPPORT_FILES:
        raise AegisError(ErrorCode.INVALID_REQUEST, f"At most {MAX_SUPPORT_FILES} support files.")
    names = [candidate.name, *(f.name for f in support)]
    if len(set(names)) != len(names):
        raise AegisError(ErrorCode.INVALID_REQUEST, "Source file names must be unique.")
    if not candidate.name.endswith(".c"):
        raise AegisError(ErrorCode.INVALID_REQUEST, "The candidate must be a .c file.")
    if sum(len(f.data) for f in (candidate, *support)) > MAX_TOTAL_SOURCE_BYTES:
        raise AegisError(ErrorCode.INVALID_REQUEST, f"Sources exceed {MAX_TOTAL_SOURCE_BYTES} bytes.")


def _check_translation_units(
    candidate: SourceFile, support: list[SourceFile], units: list[str] | tuple[str, ...]
) -> list[str]:
    """Validate an explicit translation-unit selection and return it as a list."""
    if isinstance(units, str) or not isinstance(units, (list, tuple)):
        raise AegisError(ErrorCode.INVALID_REQUEST, "translation_units must be a list of names.")
    selected = list(units)
    if not 1 <= len(selected) <= MAX_TRANSLATION_UNITS:
        raise AegisError(
            ErrorCode.INVALID_REQUEST,
            f"Select between 1 and {MAX_TRANSLATION_UNITS} translation units.",
        )
    if not all(isinstance(name, str) for name in selected):
        raise AegisError(ErrorCode.INVALID_REQUEST, "Translation units must be names.")
    if len(set(selected)) != len(selected):
        raise AegisError(ErrorCode.INVALID_REQUEST, "A translation unit is listed twice.")
    names = {candidate.name, *(f.name for f in support)}
    for name in selected:
        if not isinstance(name, str) or name not in names:
            raise AegisError(
                ErrorCode.INVALID_REQUEST, "A translation unit is not one of the staged files."
            )
        if not name.endswith(".c"):
            raise AegisError(ErrorCode.INVALID_REQUEST, "Only .c files can be translation units.")
    return selected


def _check_arguments(args: list[str] | tuple[str, ...]) -> list[str]:
    if not isinstance(args, (list, tuple)):
        raise AegisError(ErrorCode.INVALID_REQUEST, "Arguments must be a list of tokens.")
    values = list(args)
    if len(values) > MAX_ARGUMENTS:
        raise AegisError(ErrorCode.INVALID_REQUEST, f"At most {MAX_ARGUMENTS} arguments.")
    for value in values:
        if not isinstance(value, str) or not re.fullmatch(ARGUMENT_PATTERN, value):
            # The value is never echoed: arguments are hidden test inputs.
            raise AegisError(ErrorCode.INVALID_REQUEST, "An argument is not an allowed token.")
    return values
