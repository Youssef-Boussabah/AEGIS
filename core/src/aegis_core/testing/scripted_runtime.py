"""Scripted isolation-runtime test double. Not for production use.

``ScriptedIsolationRuntime`` implements the ``IsolationRuntime`` interface but
**never compiles or executes anything**. Observations are scripted by the
caller. Its attestation says ``runtime="test_double"``, ``isolation_verified=False``
and ``limits_enforcement="not_enforced_test_double"``, and every record a session
makes with it carries that attestation. Such records are never evidence.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from ..lab_execution import (
    CompileJob,
    CompileObservation,
    ExecuteJob,
    ExecuteObservation,
    PreflightRequest,
    RuntimeAttestation,
)

SCRIPTED_BINARY_PREFIX = b"AEGIS scripted test double: not a compiled program\n"


def scripted_attestation() -> RuntimeAttestation:
    return RuntimeAttestation(
        runtime="test_double",
        runtime_version="scripted",
        runtime_sha256=None,
        platform="none",
        rootless=False,
        network="none",
        rootfs_sha256=None,
        compiler_name="gcc",
        compiler_version="scripted",
        compiler_sha256="0" * 64,
        limits_enforcement="not_enforced_test_double",
        isolation_verified=False,
    )


def scripted_binary(job: CompileJob) -> bytes:
    """Deterministic placeholder bytes per candidate source. Not executable."""
    return SCRIPTED_BINARY_PREFIX + hashlib.sha256(job.candidate.data).hexdigest().encode("ascii")


class ScriptedIsolationRuntime:
    """Test double. Records every job; returns scripted observations."""

    kind = "test_double"

    def __init__(
        self,
        *,
        compile: Callable[[CompileJob], CompileObservation] | None = None,
        execute: Callable[[ExecuteJob], ExecuteObservation] | None = None,
        attestation: RuntimeAttestation | None = None,
        preflight_error: BaseException | None = None,
        close_error: BaseException | None = None,
    ):
        self._compile = compile
        self._execute = execute
        self._attestation = attestation or scripted_attestation()
        self._preflight_error = preflight_error
        self._close_error = close_error
        self.preflights: list[PreflightRequest] = []
        self.compile_jobs: list[CompileJob] = []
        self.execute_jobs: list[ExecuteJob] = []
        self.closed = 0

    def preflight(self, request: PreflightRequest) -> RuntimeAttestation:
        self.preflights.append(request)
        if self._preflight_error is not None:
            raise self._preflight_error
        return self._attestation

    def compile(self, job: CompileJob) -> CompileObservation:
        self.compile_jobs.append(job)
        if self._compile is not None:
            return self._compile(job)
        return CompileObservation(
            status="exited", exit_code=0, duration_ms=1, binary=scripted_binary(job)
        )

    def execute(self, job: ExecuteJob) -> ExecuteObservation:
        self.execute_jobs.append(job)
        if self._execute is not None:
            return self._execute(job)
        return ExecuteObservation(status="exited", exit_code=0, duration_ms=1)

    def close(self) -> None:
        self.closed += 1
        if self._close_error is not None:
            raise self._close_error
