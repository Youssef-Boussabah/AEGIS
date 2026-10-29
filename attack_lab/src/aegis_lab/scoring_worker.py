"""Lab-side worker protocol (``aegis.lab.candidate-worker.v1``) used by the scoring coordinator.

The trusted coordinator (``aegis_lab.behavior_score``) never compiles or runs
candidate code. It hands a worker exactly two kinds of bounded request:

- ``CompileRequest``: the candidate source and the two generated harness units
  plus the policy's limits. No hidden-test data is included.
- ``ExecuteRequest``: the compiled binary bytes, the argv for **one** case (the
  case's decimal arguments only) and the execution limits. Never the expected
  value, the suite, the reference, the manifest or the grant.

The worker returns a bounded ``CompileObservation`` / ``ExecuteObservation``. It
never returns a verdict: comparison against expectations happens only in the
coordinator.

The only worker is ``aegis_lab.core_execution.CoreSessionWorker``. It forwards
each stage to a Core ``CandidateExecutionSession``, which re-checks Core's three
gates and the grant before every stage and runs it in Core's isolation runtime.
That runtime refuses in this revision (``SANDBOX_UNAVAILABLE``). Tests inject
Core's non-executing ``ScriptedIsolationRuntime``, whose records are labeled
``test_double``.

``WorkerError`` is an infrastructure failure (sandbox start, crash, enforcement,
cleanup, protocol). The scorer records it as ``infrastructure_failure``, never as
a candidate outcome. ``StageRefused`` is a Core refusal in the middle of a run
(for example, the grant expired between two cases).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictBytes, StrictInt, model_validator

from .scoring_policy import CompileLimits, SandboxRuntime, StageLimits

WORKER_PROTOCOL = "aegis.lab.candidate-worker.v1"

WORKER_ERROR_CODES = frozenset({
    "sandbox_start_failed",
    "sandbox_failed",
    "resource_enforcement_failed",
    "cleanup_failed",
    "protocol_violation",
    "core_rejected_request",
    "core_record_mismatch",
    "core_storage_failed",
    "host_enforcement_invalid",
})

ObservedStatus = Literal["exited", "signaled", "timeout", "limit_exceeded"]
LimitName = Literal["cpu", "memory", "processes", "scratch", "stdout", "stderr", "binary"]


class WorkerError(RuntimeError):
    """An infrastructure failure. Never evidence about the candidate or about protection."""

    def __init__(self, code: str) -> None:
        if code not in WORKER_ERROR_CODES:
            raise AssertionError(f"unregistered worker error code {code!r}")
        self.code = code
        super().__init__(code)


class StageRefused(PermissionError):
    """Core refused a stage after the session was opened. ``reason`` is Core's ``details.reason``."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"stage refused by Core: {reason}")


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkerPreflight(StrictRecord):
    """What Core's runtime attested before any candidate input, in Lab terms.

    The limits are the ones bound by Core's grant, which the Lab requires to equal
    the policy. ``limits_enforcement`` and ``identity_observed`` come from the
    runtime's attestation. Core's scripted test double attests neither.
    """

    runtime: SandboxRuntime
    compiler_name: Literal["gcc", "clang"]
    compiler_version: Annotated[str, Field(min_length=1, max_length=200)]
    compiler_executable_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    compile_limits: CompileLimits
    execute_limits: StageLimits
    network: Literal["none"]
    identity_observed: StrictBool
    limits_enforcement: Literal["verified_by_runtime", "not_enforced_test_double"]


MIB = 1024 * 1024


class EnforcedLimits(StrictRecord):
    """What an isolating runtime **enforced** for one sandbox, as Core reported it.

    These are the host scope's cgroup limits read back before the job was sent, plus the
    microVM's configured resources. They are not the requested limits: Firecracker's scope
    memory, for example, also holds scratch, guest and VMM overhead. The scorer records the
    requested (granted) limits and these enforced values separately and never equates them.
    """

    memory_max_bytes: Annotated[StrictInt, Field(ge=1)]
    memory_swap_max_bytes: Literal[0]
    pids_max: Annotated[StrictInt, Field(ge=1)]
    cpu_quota_us: Annotated[StrictInt, Field(ge=1)]
    cpu_period_us: Annotated[StrictInt, Field(ge=1)]
    vm_memory_mib: Annotated[StrictInt, Field(ge=1)]
    vcpu_count: Annotated[StrictInt, Field(ge=1, le=64)]
    block_bandwidth_bytes_per_s: Annotated[StrictInt, Field(ge=1)]
    block_ops_per_s: Annotated[StrictInt, Field(ge=1)]

    @model_validator(mode="after")
    def _consistent(self) -> EnforcedLimits:
        if self.memory_max_bytes < self.vm_memory_mib * MIB:
            raise ValueError("the host scope must hold the whole microVM memory")
        if self.cpu_quota_us > self.vcpu_count * self.cpu_period_us:
            raise ValueError("the CPU quota exceeds the configured vCPUs")
        return self

    def covers(self, limits: StageLimits) -> bool:
        """Whether the guest has room for the requested job memory and scratch."""
        return self.vm_memory_mib * MIB >= limits.memory_bytes + limits.scratch_bytes


class HostAccounting(StrictRecord):
    """What the host **measured** after one sandbox ran (cgroup accounting). Not a limit."""

    host_cpu_usec: Annotated[StrictInt, Field(ge=0)] | None
    host_memory_peak_bytes: Annotated[StrictInt, Field(ge=0)] | None
    host_oom_kills: Annotated[StrictInt, Field(ge=0)]


class HostEnforcementObservation(StrictRecord):
    """Limits and accounting are separate quantities.

    Linux cgroup v2 memory.peak can exceed memory.max during reclaim or OOM.
    A peak is not evidence that a limit was fabricated or was not enforced.
    """
    enforced: EnforcedLimits
    accounting: HostAccounting


def _exit_fields(status: str, exit_code: int | None, signal: int | None, limit: str | None) -> None:
    if (status == "exited") != (exit_code is not None):
        raise ValueError("exit_code is set exactly for an exited process")
    if (status == "signaled") != (signal is not None):
        raise ValueError("signal is set exactly for a signaled process")
    if (status == "limit_exceeded") != (limit is not None):
        raise ValueError("limit is set exactly when a limit was exceeded")


class CompileObservation(StrictRecord):
    status: ObservedStatus
    exit_code: Annotated[StrictInt, Field(ge=0, le=255)] | None = None
    signal: Annotated[StrictInt, Field(ge=1, le=64)] | None = None
    limit: LimitName | None = None
    diagnostics: StrictBytes = b""
    diagnostics_truncated: StrictBool = False
    binary: StrictBytes | None = None
    host_enforcement: HostEnforcementObservation | None = None

    @model_validator(mode="after")
    def _consistent(self) -> CompileObservation:
        _exit_fields(self.status, self.exit_code, self.signal, self.limit)
        if (self.binary is not None) and not (self.status == "exited" and self.exit_code == 0):
            raise ValueError("a binary is returned only by a successful compilation")
        return self


class ExecuteObservation(StrictRecord):
    status: ObservedStatus
    exit_code: Annotated[StrictInt, Field(ge=0, le=255)] | None = None
    signal: Annotated[StrictInt, Field(ge=1, le=64)] | None = None
    limit: LimitName | None = None
    stdout: StrictBytes = b""
    stdout_truncated: StrictBool = False
    stderr_bytes: Annotated[StrictInt, Field(ge=0)] = 0
    host_enforcement: HostEnforcementObservation | None = None

    @model_validator(mode="after")
    def _consistent(self) -> ExecuteObservation:
        _exit_fields(self.status, self.exit_code, self.signal, self.limit)
        if self.limit == "binary":
            raise ValueError("the binary limit applies to compilation only")
        return self


@dataclass(frozen=True)
class CompileRequest:
    """One compilation. ``candidate`` is the exact source the grant permits; ``support`` are generated units.

    All files are staged; only ``translation_units`` are compiled. The candidate is never a
    unit of its own: ``aegis_candidate_unit.c`` includes it after the interface prototype.
    """

    candidate_name: str
    candidate: bytes
    support: tuple[tuple[str, bytes], ...]
    translation_units: tuple[str, ...]
    limits: CompileLimits

    def __post_init__(self) -> None:
        names = {name for name, _ in self.support}
        if (not self.translation_units or self.candidate_name in self.translation_units
                or not set(self.translation_units) <= names
                or len(set(self.translation_units)) != len(self.translation_units)):
            raise ValueError("translation units must be distinct support files and never the candidate")


@dataclass(frozen=True)
class ExecuteRequest:
    binary: bytes
    arguments: tuple[str, ...]
    limits: StageLimits
