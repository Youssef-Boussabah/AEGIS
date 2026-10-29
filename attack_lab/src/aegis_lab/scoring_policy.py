"""Sandbox policy and scorer identity for Phase 4.

Two local, versioned contracts:

- ``aegis.lab.sandbox-policy.v1`` (``SandboxPolicy``): the isolation runtime the
  Lab expects Core to attest (name, version, runtime and root-filesystem
  digests), the C compiler and its fixed flags, and per-stage resource limits.
  It is an operator-trusted file. Its canonical digest is bound into the scorer
  identity and into Core's execution grant (``lab_bindings``).
- ``aegis.lab.behavior-scorer-configuration.v1``: the scorer configuration
  (ABI, harness generator, observation protocol, score rule and the full
  policy). ``planned_scorer_tool`` returns the ``ToolIdentity`` a manifest must
  declare as ``scoring.scorer``. Its ``executable_sha256`` is a digest over the
  scorer's own source files.

Authorization for compiling or running a candidate belongs to **Core**
(``aegis_core.lab_authorization.CandidateExecutionGrant``, three gates re-checked
before every stage). This module defines no permission. ``ExecutionRefused``
reports a refusal by Core, or a grant that does not describe the Lab's inputs.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator
from pydantic_core import PydanticCustomError

from .c_abi import ABI_VERSION, HARNESS_TEMPLATE_SHA256, HARNESS_VERSION, OBSERVATION_PROTOCOL
from .canonical import canonical_sha256
from .manifest import Hash, Identifier, ToolIdentity
from .safe_io import LoadError, parse_strict_json, read_regular_file

SANDBOX_POLICY_SCHEMA = "aegis.lab.sandbox-policy.v1"
SCORER_CONFIGURATION_SCHEMA = "aegis.lab.behavior-scorer-configuration.v1"
BEHAVIOR_SCORE_SCHEMA = "aegis.lab.behavior-score.v1"
SCORER_NAME = "aegis-lab-behavior-scorer"
SCORE_RULE = "all_hidden_tests_pass"
FILESYSTEM_LAYOUT = "aegis.lab.sandbox-filesystem.v1"
MAX_POLICY_BYTES = 64 * 1024
MIB = 1024 * 1024

# Source files whose bytes define the scorer implementation (``executable_sha256``).
SCORER_IMPLEMENTATION_FILES = (
    "behavior_score.py", "c_abi.py", "canonical.py", "core_execution.py", "hidden_suite.py", "safe_io.py",
    "scoring.py", "scoring_policy.py", "scoring_worker.py",
)

POLICY_ERROR_TYPES = frozenset({
    "aegis_runtime_inconsistent",
    "aegis_flag_not_allowed",
    "aegis_flags_missing_standard",
    "aegis_flags_duplicate",
})

# Compiler flags are an allowlist: none of these reads a path, loads a plugin or runs a program.
_FLAG_PATTERN = (r"^-(?:std=c11|O[0-3s]|static|fwrapv|fno-strict-aliasing|fno-builtin|fno-pie|no-pie|w|Wall|"
                 r"Wextra|pedantic|Werror=[a-z][a-z-]{0,62})$")
CompilerFlag = Annotated[str, Field(pattern=_FLAG_PATTERN)]


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StageLimits(StrictRecord):
    """Per-sandbox limits. Every one must be *enforced* by the runtime, not merely declared."""

    wall_ms: Annotated[StrictInt, Field(ge=10, le=600_000)]
    cpu_ms: Annotated[StrictInt, Field(ge=10, le=600_000)]
    memory_bytes: Annotated[StrictInt, Field(ge=16 * MIB, le=8192 * MIB)]
    max_processes: Annotated[StrictInt, Field(ge=1, le=4096)]
    scratch_bytes: Annotated[StrictInt, Field(ge=1 * MIB, le=1024 * MIB)]
    stdout_bytes: Annotated[StrictInt, Field(ge=1, le=1 * MIB)]
    stderr_bytes: Annotated[StrictInt, Field(ge=1, le=1 * MIB)]


class CompileLimits(StageLimits):
    binary_bytes: Annotated[StrictInt, Field(ge=1, le=64 * MIB)]


class SandboxRuntime(StrictRecord):
    """The runtime the Lab expects Core to attest. Every identity is pinned and compared exactly.

    - ``aegis-test-double``: Core's scripted runtime. It pins nothing and is never evidence.
    - ``firecracker``: KVM microVM inside a systemd user scope. It pins the Firecracker
      binary, the read-only guest rootfs, the guest kernel, the guest agent and the
      containment-verification report this configuration passed.
    - ``gvisor-runsc``: gVisor inside a systemd user scope. It pins the runtime and rootfs;
      it has no guest kernel or agent, and the containment report is optional.
    """

    name: Literal["firecracker", "gvisor-runsc", "aegis-test-double"]
    version: Identifier
    executable_sha256: Hash | None
    rootfs_sha256: Hash | None
    guest_kernel_sha256: Hash | None
    guest_agent_sha256: Hash | None
    containment_verification_sha256: Hash | None
    platform: Literal["systrap", "kvm", "none"]
    rootless: StrictBool
    network: Literal["none"]
    resource_controller: Literal["systemd-user-scope-cgroup-v2", "none"]
    sandbox_per_compilation: Literal["fresh"]
    sandbox_per_case: Literal["fresh"]
    environment: Literal["empty"]
    filesystem_layout: Literal["aegis.lab.sandbox-filesystem.v1"]

    @model_validator(mode="after")
    def _consistent(self) -> SandboxRuntime:
        guest = (self.guest_kernel_sha256, self.guest_agent_sha256)
        isolated = (self.executable_sha256 is not None and self.rootfs_sha256 is not None and self.rootless
                    and self.resource_controller == "systemd-user-scope-cgroup-v2")
        if self.name == "aegis-test-double":
            ok = (self.executable_sha256 is None and self.rootfs_sha256 is None and guest == (None, None)
                  and self.containment_verification_sha256 is None and self.platform == "none"
                  and self.resource_controller == "none" and not self.rootless)
        elif self.name == "firecracker":
            ok = (isolated and self.platform == "kvm" and None not in guest
                  and self.containment_verification_sha256 is not None)
        else:
            ok = isolated and self.platform in ("systrap", "kvm") and guest == (None, None)
        if not ok:
            raise PydanticCustomError("aegis_runtime_inconsistent", "runtime fields are inconsistent with its name")
        return self


class CompilerConfiguration(StrictRecord):
    """The compiler *inside* the sandbox image, pinned by digest, with fixed flags."""

    name: Literal["gcc", "clang"]
    version: Identifier
    executable: Annotated[str, Field(pattern=r"^/usr/bin/[a-z][a-z0-9.+-]{0,62}$")]
    executable_sha256: Hash
    flags: Annotated[tuple[CompilerFlag, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _flags(self) -> CompilerConfiguration:
        if "-std=c11" not in self.flags:
            raise PydanticCustomError("aegis_flags_missing_standard", "flags must select -std=c11")
        if len(set(self.flags)) != len(self.flags):
            raise PydanticCustomError("aegis_flags_duplicate", "flags must be unique")
        return self


class SandboxPolicy(StrictRecord):
    schema_version: Literal["aegis.lab.sandbox-policy.v1"] = SANDBOX_POLICY_SCHEMA
    runtime: SandboxRuntime
    compiler: CompilerConfiguration
    compile: CompileLimits
    execute: StageLimits
    max_cases: Annotated[StrictInt, Field(ge=1, le=4096)]
    max_total_wall_ms: Annotated[StrictInt, Field(ge=1000, le=86_400_000)]

    def sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))

    def compile_argv(self, *, output: str, sources: tuple[str, ...]) -> tuple[str, ...]:
        """Fixed argv: the pinned compiler, policy flags and fixed file names only (no user values)."""
        return (self.compiler.executable, *self.compiler.flags, "-o", output, *sources)


def parse_policy(data: bytes) -> SandboxPolicy:
    if len(data) > MAX_POLICY_BYTES:
        raise LoadError("too_large")
    parse_strict_json(data)
    return SandboxPolicy.model_validate_json(data)


def load_policy(path) -> SandboxPolicy:
    return parse_policy(read_regular_file(path, MAX_POLICY_BYTES))


# --- Scorer identity --------------------------------------------------------------------------------

def scorer_configuration_document(policy: SandboxPolicy) -> dict:
    return {
        "schema": SCORER_CONFIGURATION_SCHEMA,
        "score_schema": BEHAVIOR_SCORE_SCHEMA,
        "abi": ABI_VERSION,
        "harness": HARNESS_VERSION,
        "harness_template_sha256": HARNESS_TEMPLATE_SHA256,
        "observation_protocol": OBSERVATION_PROTOCOL,
        "score_rule": SCORE_RULE,
        "policy": policy.model_dump(mode="json"),
    }


def scorer_configuration_sha256(policy: SandboxPolicy) -> str:
    return canonical_sha256(scorer_configuration_document(policy))


def scorer_implementation_sha256() -> str:
    """SHA-256 over canonical JSON of {file name: SHA-256 of its bytes} for the scorer sources."""
    here = Path(__file__).resolve().parent
    return canonical_sha256({name: hashlib.sha256((here / name).read_bytes()).hexdigest()
                             for name in SCORER_IMPLEMENTATION_FILES})


def planned_scorer_tool(policy: SandboxPolicy) -> ToolIdentity:
    """The ``scoring.scorer`` identity to declare in both manifests of a pair."""
    return ToolIdentity(name=SCORER_NAME, version=BEHAVIOR_SCORE_SCHEMA,
                        executable_sha256=scorer_implementation_sha256(),
                        configuration_sha256=scorer_configuration_sha256(policy))


# --- Execution refusals -------------------------------------------------------------------------
#
# Core is the only authority for candidate execution (``aegis.core.candidate-execution-grant.v1``,
# checked before every stage). The Lab keeps no permission of its own. It only refuses a grant that
# does not describe the Lab's actual inputs (``grant_*`` codes, see ``aegis_lab.core_execution``)
# and reports Core's own refusals (``core_refused``, ``sandbox_unavailable``).

EXECUTION_REFUSAL_CODES = frozenset({
    "grant_missing",
    "grant_reference_mismatch",
    "grant_lab_bindings_mismatch",
    "grant_candidate_not_listed",
    "grant_candidate_mismatch",
    "grant_target_mismatch",
    "grant_stages_insufficient",
    "grant_flags_mismatch",
    "grant_limits_mismatch",
    "grant_budget_insufficient",
    "core_refused",
    "sandbox_unavailable",
    "injected_runtime_not_test_double",
    "runtime_reused",
})


class ExecutionRefused(PermissionError):
    """Candidate compilation/execution was refused before any candidate input was sent."""

    def __init__(self, code: str, reasons: tuple[str, ...] = ()) -> None:
        if code not in EXECUTION_REFUSAL_CODES:
            raise AssertionError(f"unregistered execution refusal code {code!r}")
        self.code = code
        self.reasons = tuple(reasons)
        detail = f" ({', '.join(self.reasons)})" if self.reasons else ""
        super().__init__(f"candidate execution refused: {code}{detail}")
