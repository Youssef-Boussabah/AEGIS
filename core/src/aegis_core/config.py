"""Loading and validating the local `aegis.toml` configuration."""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, ValidationError, field_validator, model_validator

from .errors import AegisError
from .lab_limits import (
    CompileLimits,
    SandboxLimits,
    default_compile_ceiling,
    default_execute_ceiling,
)
from .models import BACKEND_PATTERN, AegisModel, ErrorCode, Sha256, TaskKind

DEFAULT_CONFIG_NAME = "aegis.toml"
CONFIG_ENV_VAR = "AEGIS_CONFIG"
ENV_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]{0,127}$"


class StorageConfig(AegisModel):
    root: Path = Path(".aegis")
    """Artifact store directory, relative to the config file when not absolute."""
    max_input_bytes: Annotated[int, Field(ge=1, le=4 * 1024**3)] = 64 * 1024 * 1024


def _absolute(value: Path) -> Path:
    if not value.is_absolute() or ".." in value.parts:
        raise ValueError("must be an absolute path without '..'")
    return value


class FirecrackerConfig(AegisModel):
    """Operator-pinned identities and host controls for the Firecracker backend.

    Every path is absolute and every artifact is pinned by SHA-256. Nothing here
    comes from a request. See docs/adr/0004-isolated-candidate-execution.md.
    """

    firecracker_path: Path
    firecracker_sha256: Sha256
    bwrap_path: Path = Path("/usr/bin/bwrap")
    bwrap_sha256: Sha256
    systemd_run_path: Path = Path("/usr/bin/systemd-run")
    kernel_path: Path
    kernel_sha256: Sha256
    rootfs_path: Path
    """Read-only guest system image (ext4). Attached read-only and rate-limited."""
    rootfs_sha256: Sha256
    guest_agent_sha256: Sha256
    """SHA-256 of lab_guest_agent.py inside the image; the agent must report it."""
    compiler_name: Literal["gcc", "clang"]
    compiler_version: Annotated[str, Field(min_length=1, max_length=200)]
    compiler_sha256: Sha256
    state_dir: Path
    """Private (0700) directory for per-VM runtime directories and vsock sockets."""
    containment_verification_sha256: Sha256 | None = None
    """SHA-256 of the containment report file below. Absent: the backend refuses to run."""
    containment_report_path: Path | None = None
    """``aegis.core.containment-report.v1`` file. Execution needs it to match the digest,
    to have passed every required check on the candidate guest, and to be bound to
    exactly this configuration (pins and host controls)."""
    vcpu_count: Literal[1, 2] = 1
    guest_overhead_mib: Annotated[StrictInt, Field(ge=32, le=1024)] = 128
    """Guest kernel and agent memory, added to the job's memory and scratch."""
    vmm_overhead_mib: Annotated[StrictInt, Field(ge=16, le=1024)] = 64
    """Firecracker process memory beyond guest RAM, for the host scope's MemoryMax."""
    vmm_tasks: Annotated[StrictInt, Field(ge=4, le=256)] = 16
    """Host TasksMax for the scope (Firecracker threads, bwrap)."""
    boot_timeout_ms: Annotated[StrictInt, Field(ge=500, le=120_000)] = 15_000
    teardown_timeout_ms: Annotated[StrictInt, Field(ge=100, le=60_000)] = 5_000
    host_grace_ms: Annotated[StrictInt, Field(ge=100, le=60_000)] = 2_000
    """Extra time after the job's wall limit before the host kills the VM itself."""
    block_bandwidth_bytes_per_s: Annotated[StrictInt, Field(ge=1024 * 1024, le=4 * 1024**3)] = (
        64 * 1024 * 1024
    )
    block_ops_per_s: Annotated[StrictInt, Field(ge=10, le=1_000_000)] = 2_000
    agent_port: Annotated[StrictInt, Field(ge=1024, le=65_535)] = 10_000

    @field_validator(
        "firecracker_path", "bwrap_path", "systemd_run_path", "kernel_path", "rootfs_path", "state_dir",
        "containment_report_path",
    )
    @classmethod
    def _paths(cls, value: Path | None) -> Path | None:
        return None if value is None else _absolute(value)


class CandidateExecutionConfig(AegisModel):
    """Operator gate and ceilings for compiling and running untrusted Lab candidates.

    This is a third, independent gate: enabling attack-lab jobs does not consent
    to running generated code. Grants may never exceed these ceilings. Enabling
    it does not make an isolation runtime available; see aegis_core.lab_execution.
    """

    enabled: StrictBool = False
    compile_ceiling: CompileLimits = Field(default_factory=default_compile_ceiling)
    execute_ceiling: SandboxLimits = Field(default_factory=default_execute_ceiling)
    runtime: Literal["none", "firecracker"] = "none"
    """The isolation backend. "none" refuses every execution."""
    firecracker: FirecrackerConfig | None = None

    @model_validator(mode="after")
    def _runtime_section(self) -> CandidateExecutionConfig:
        if self.runtime == "firecracker" and self.firecracker is None:
            raise ValueError("runtime = 'firecracker' requires [attack_lab.candidate_execution.firecracker]")
        if self.runtime != "firecracker" and self.firecracker is not None:
            raise ValueError("a firecracker section requires runtime = 'firecracker'")
        return self


class AttackLabConfig(AegisModel):
    # Strict: a security gate opens only for a TOML boolean true, never "yes", "1" or 1.
    enabled: StrictBool = False
    candidate_execution: CandidateExecutionConfig = Field(default_factory=CandidateExecutionConfig)


class AdapterSpec(AegisModel):
    command: Annotated[list[str], Field(min_length=1)]
    """Argument array; executed without a shell."""
    tasks: Annotated[list[TaskKind], Field(min_length=1)] = [TaskKind.PROTECT]
    timeout_seconds: Annotated[int, Field(ge=1, le=86_400)] = 300
    env_passthrough: list[str] = Field(default_factory=list)
    """Names of environment variables forwarded to the adapter. Nothing else is."""
    max_stdout_bytes: Annotated[int, Field(ge=1024, le=64 * 1024 * 1024)] = 4 * 1024 * 1024

    @field_validator("command")
    @classmethod
    def _check_command(cls, value: list[str]) -> list[str]:
        for arg in value:
            if not arg or "\x00" in arg:
                raise ValueError("command arguments must be non-empty and contain no NUL bytes")
        return value

    @field_validator("env_passthrough")
    @classmethod
    def _check_env(cls, value: list[str]) -> list[str]:
        for name in value:
            if not re.match(ENV_NAME_PATTERN, name):
                raise ValueError(f"invalid environment variable name {name!r}")
        return value


SENTINEL_ACTIONS = ("execute", "analyze", "redistribute", "modify", "attack_evaluate")
SentinelAction = Literal["execute", "analyze", "redistribute", "modify", "attack_evaluate"]


class ProvenanceConfig(AegisModel):
    """Operator settings for signing job outputs with aegis-provenance (Ed25519).

    Data only: Core never loads keys or imports cryptography. The signing key is
    an operator-provided PKCS#8 PEM file; AEGIS never generates one. File checks
    (outside Git and the store, mode 0600, Ed25519) happen when aegis_provenance
    loads the settings, and failures stop the API/CLI with CONFIG_INVALID.
    """

    enabled: StrictBool = False
    signing_key_path: Path | None = None
    signing_key_password_env: Annotated[str, Field(pattern=ENV_NAME_PATTERN)] | None = None
    """Name of an environment variable holding the key password (never the password)."""
    trusted_public_keys: list[Path] = Field(default_factory=list, max_length=32)
    """Public keys (PEM) accepted when verifying. Signatures by any other key fail."""
    signer_name: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    signer_organization: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    build_repository: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    build_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{7,64}$")] | None = None

    @field_validator("signing_key_path")
    @classmethod
    def _key_path(cls, value: Path | None) -> Path | None:
        return None if value is None else _absolute(value)

    @field_validator("trusted_public_keys")
    @classmethod
    def _trusted_paths(cls, value: list[Path]) -> list[Path]:
        return [_absolute(p) for p in value]

    @model_validator(mode="after")
    def _complete(self) -> ProvenanceConfig:
        if not self.enabled:
            return self
        if self.signing_key_path is None and not self.trusted_public_keys:
            raise ValueError("enabled provenance needs signing_key_path and/or trusted_public_keys")
        if self.signing_key_path is not None:
            missing = [
                name
                for name in ("signer_name", "build_repository", "build_commit")
                if getattr(self, name) is None
            ]
            if missing:
                raise ValueError(f"signing_key_path requires {', '.join(missing)}")
        return self


class SentinelJobConfig(AegisModel):
    """Operator settings for attaching a Sentinel rights policy to every job output.

    Policies are cooperating metadata: they bind only tools that consult them
    (AEGIS's own artifact download does). They never open attack-lab gates.
    """

    enabled: StrictBool = False
    issuer: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    enforcement_mode: Literal["cooperating_enforced", "advisory_notice"] = "cooperating_enforced"
    allowed_actions: list[SentinelAction] | None = None
    """Actions written as allowed. Every other action is written as explicitly denied."""
    valid_days: Annotated[StrictInt, Field(ge=1, le=3650)] | None = None
    allowed_caller_ids: (
        Annotated[list[Annotated[str, Field(min_length=1, max_length=128)]], Field(min_length=1, max_length=64)]
        | None
    ) = None

    @model_validator(mode="after")
    def _complete(self) -> SentinelJobConfig:
        if self.allowed_actions is not None and len(set(self.allowed_actions)) != len(self.allowed_actions):
            raise ValueError("allowed_actions must not repeat an action")
        if self.enabled and (self.issuer is None or self.allowed_actions is None):
            raise ValueError("enabled sentinel needs issuer and an explicit allowed_actions list")
        return self


class AegisConfig(AegisModel):
    storage: StorageConfig = Field(default_factory=StorageConfig)
    attack_lab: AttackLabConfig = Field(default_factory=AttackLabConfig)
    provenance: ProvenanceConfig = Field(default_factory=ProvenanceConfig)
    sentinel: SentinelJobConfig = Field(default_factory=SentinelJobConfig)
    adapters: dict[str, AdapterSpec] = Field(default_factory=dict)
    source_path: Path | None = Field(default=None, exclude=True)

    @field_validator("adapters")
    @classmethod
    def _check_backend_names(cls, value: dict[str, AdapterSpec]) -> dict[str, AdapterSpec]:
        for name in value:
            if not re.match(BACKEND_PATTERN, name):
                raise ValueError(f"invalid backend name {name!r}")
        return value

    def supported_backends(self) -> list[str]:
        return sorted(self.adapters)


def resolve_config_path(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Explicit path, then $AEGIS_CONFIG, then ./aegis.toml."""
    if explicit:
        return Path(explicit)
    env = os.environ.get(CONFIG_ENV_VAR)
    if env:
        return Path(env)
    return Path.cwd() / DEFAULT_CONFIG_NAME


def load_config(path: str | os.PathLike[str]) -> AegisConfig:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise AegisError(
            ErrorCode.CONFIG_NOT_FOUND,
            f"No AEGIS configuration at {path}. Run `aegis init` to create one.",
            {"path": str(path)},
        ) from None
    except OSError as exc:
        raise AegisError(
            ErrorCode.CONFIG_INVALID, f"Cannot read configuration {path}: {exc.strerror}"
        ) from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise AegisError(
            ErrorCode.CONFIG_INVALID, f"Configuration {path} is not valid TOML: {exc}"
        ) from None
    return config_from_mapping(data, base_dir=path.parent, source_path=path)


def config_from_mapping(
    data: dict, *, base_dir: Path, source_path: Path | None = None
) -> AegisConfig:
    try:
        config = AegisConfig.model_validate(data)
    except ValidationError as exc:
        problems = [
            {"loc": ".".join(str(p) for p in err["loc"]), "msg": err["msg"]}
            for err in exc.errors(include_input=False, include_url=False)
        ]
        raise AegisError(
            ErrorCode.CONFIG_INVALID, "Configuration failed validation.", {"errors": problems}
        ) from None
    root = config.storage.root
    if not root.is_absolute():
        root = (base_dir / root).resolve()
    storage = config.storage.model_copy(update={"root": root})
    return config.model_copy(update={"storage": storage, "source_path": source_path})


def default_config_text() -> str:
    return DEFAULT_CONFIG_TEXT


DEFAULT_CONFIG_TEXT = """\
# AEGIS local configuration, generated by `aegis init`.
# Relative paths are resolved against the directory containing this file.

[storage]
root = ".aegis"
max_input_bytes = 67108864  # 64 MiB

[attack_lab]
# Attack-lab tasks run attacks against artifacts. They stay disabled unless an
# operator enables them here AND every request carries an authorization record.
enabled = false

# Compiling and running untrusted Lab candidates is a separate, third gate. It
# also needs an approved isolation runtime, which this version does not provide:
# candidate execution is refused with SANDBOX_UNAVAILABLE even when enabled.
# See docs/adr/0004-isolated-candidate-execution.md.
[attack_lab.candidate_execution]
enabled = false

# Signing job outputs (aegis-provenance, Ed25519) and attaching Sentinel rights
# policies are off by default. AEGIS never generates a signing key: create one
# outside any Git checkout with `aegis-provenance keygen`, then configure it.
# See docs/release/FINAL_API_CONTRACT.md.
[provenance]
enabled = false
# signing_key_path = "/home/me/.config/aegis/signing-key.pem"   # absolute, mode 0600
# trusted_public_keys = ["/home/me/.config/aegis/signing-key.pub.pem"]
# signer_name = "AEGIS operator"
# build_repository = "https://example.invalid/repo"
# build_commit = "0123456789abcdef0123456789abcdef01234567"

[sentinel]
enabled = false
# issuer = "AEGIS operator"
# enforcement_mode = "cooperating_enforced"
# allowed_actions = ["analyze"]                 # all other actions are denied

# Protection backends are registered as [adapters.<name>]. None is registered by
# default: requests for an unregistered backend fail with UNSUPPORTED_BACKEND.
# `command` is an argument array executed without a shell; AEGIS appends
# `--aegis-request <path>`. See core/docs/adapter-protocol.md.
#
# [adapters.example]
# command = ["/opt/aegis/bin/example-adapter"]
# tasks = ["protect"]          # add "attack_lab" only if the adapter supports it
# timeout_seconds = 300
# env_passthrough = []         # environment variables forwarded to the adapter
"""
