"""Resource limits for isolated candidate compilation and execution.

The field names and ranges match the Lab's ``StageLimits`` and ``CompileLimits``
(``aegis.lab.sandbox-policy.v1``), so a Lab policy maps onto these models field
by field. Limits apply to one sandbox (one compilation or one test case). Every
limit must be enforced by the isolation runtime, not merely declared; see
docs/adr/0004-isolated-candidate-execution.md.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, StrictInt

from .models import AegisModel

MIB = 1024 * 1024


class SandboxLimits(AegisModel):
    """Per-sandbox limits for one stage invocation."""

    wall_ms: Annotated[StrictInt, Field(ge=10, le=600_000)]
    cpu_ms: Annotated[StrictInt, Field(ge=10, le=600_000)]
    memory_bytes: Annotated[StrictInt, Field(ge=16 * MIB, le=8192 * MIB)]
    max_processes: Annotated[StrictInt, Field(ge=1, le=4096)]
    """Processes of the sandboxed application, not of the runtime itself."""
    scratch_bytes: Annotated[StrictInt, Field(ge=1 * MIB, le=1024 * MIB)]
    stdout_bytes: Annotated[StrictInt, Field(ge=1, le=1 * MIB)]
    stderr_bytes: Annotated[StrictInt, Field(ge=1, le=1 * MIB)]

    def exceeding(self, ceiling: SandboxLimits) -> list[str]:
        """Names of the fields whose value is above the same field of ``ceiling``, sorted."""
        mine = self.model_dump()
        theirs = ceiling.model_dump()
        return sorted(name for name, value in mine.items() if name in theirs and value > theirs[name])


class CompileLimits(SandboxLimits):
    """Compilation limits: the stage limits plus the size of the produced binary."""

    binary_bytes: Annotated[StrictInt, Field(ge=1, le=64 * MIB)]

    def exceeding(self, ceiling: SandboxLimits) -> list[str]:
        if not isinstance(ceiling, CompileLimits):
            raise TypeError("compile limits must be compared with compile limits")
        return super().exceeding(ceiling)


def default_compile_ceiling() -> CompileLimits:
    """Conservative operator ceiling for one compilation."""
    return CompileLimits(
        wall_ms=60_000,
        cpu_ms=60_000,
        memory_bytes=1024 * MIB,
        max_processes=64,
        scratch_bytes=256 * MIB,
        stdout_bytes=1 * MIB,
        stderr_bytes=1 * MIB,
        binary_bytes=16 * MIB,
    )


def default_execute_ceiling() -> SandboxLimits:
    """Conservative operator ceiling for one test-case execution."""
    return SandboxLimits(
        wall_ms=10_000,
        cpu_ms=10_000,
        memory_bytes=256 * MIB,
        max_processes=16,
        scratch_bytes=16 * MIB,
        stdout_bytes=64 * 1024,
        stderr_bytes=64 * 1024,
    )
