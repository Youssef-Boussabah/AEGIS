"""Typed contracts shared by the AEGIS orchestrator, API and CLI.

Every model forbids unknown fields so that malformed input fails loudly instead
of being silently ignored. Status/error invariants are enforced by validators:
a failed job or report always carries an error, and a successful one never does.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

SCHEMA_VERSION: Literal["1"] = "1"

ID_PATTERN = r"^[0-9a-f]{32}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
BACKEND_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,63}$"
ARTIFACT_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
OPTION_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"

MAX_OPTIONS = 64
MAX_OPTION_STRING = 4096

ObjectId = Annotated[str, Field(pattern=ID_PATTERN)]
Sha256 = Annotated[str, Field(pattern=SHA256_PATTERN)]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AegisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- enums


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in (JobStatus.SUCCEEDED, JobStatus.FAILED)


class TaskKind(StrEnum):
    PROTECT = "protect"
    ATTACK_LAB = "attack_lab"


class ErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    UNAUTHORIZED = "UNAUTHORIZED"
    CONFIG_NOT_FOUND = "CONFIG_NOT_FOUND"
    CONFIG_INVALID = "CONFIG_INVALID"
    CONFIG_EXISTS = "CONFIG_EXISTS"
    UNSUPPORTED_BACKEND = "UNSUPPORTED_BACKEND"
    UNSUPPORTED_TASK = "UNSUPPORTED_TASK"
    AUTHORIZATION_REQUIRED = "AUTHORIZATION_REQUIRED"
    INPUT_NOT_FOUND = "INPUT_NOT_FOUND"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    JOB_NOT_FOUND = "JOB_NOT_FOUND"
    JOB_CONFLICT = "JOB_CONFLICT"
    REPORT_NOT_READY = "REPORT_NOT_READY"
    ADAPTER_UNAVAILABLE = "ADAPTER_UNAVAILABLE"
    ADAPTER_TIMEOUT = "ADAPTER_TIMEOUT"
    ADAPTER_FAILED = "ADAPTER_FAILED"
    ADAPTER_INVALID_OUTPUT = "ADAPTER_INVALID_OUTPUT"
    ARTIFACT_INTEGRITY_ERROR = "ARTIFACT_INTEGRITY_ERROR"
    # No approved, verified isolation runtime: candidate code was not started.
    SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"
    # The isolation runtime failed (start, enforcement, protocol, cleanup). An
    # infrastructure failure, never a candidate outcome.
    SANDBOX_FAILED = "SANDBOX_FAILED"
    # A registered output artifact, or its signed manifest / Sentinel policy, does
    # not exist for this job (details.kind names which).
    ARTIFACT_NOT_FOUND = "ARTIFACT_NOT_FOUND"
    # A cooperating Sentinel policy denies the action, or the policy that should
    # govern it is missing, invalid or modified (fail closed).
    POLICY_DENIED = "POLICY_DENIED"
    STORAGE_ERROR = "STORAGE_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ArtifactRole(StrEnum):
    INPUT = "input"
    OUTPUT = "output"
    LOG = "log"


class EvidenceKind(StrEnum):
    ARTIFACT_HASH = "artifact_hash"
    ADAPTER_INVOCATION = "adapter_invocation"
    ADAPTER_CLAIM = "adapter_claim"
    AUTHORIZATION = "authorization"


class EvidenceSource(StrEnum):
    # Computed or observed by the orchestrator itself.
    ORCHESTRATOR = "orchestrator"
    # Reported by the adapter; recorded verbatim and not independently verified.
    ADAPTER = "adapter"


class AttackOutcome(StrEnum):
    RESISTED = "resisted"
    BYPASSED = "bypassed"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


# ------------------------------------------------------------------------- errors


class ErrorInfo(AegisModel):
    code: ErrorCode
    message: Annotated[str, Field(min_length=1, max_length=4000)]
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------- artifacts


class Artifact(AegisModel):
    artifact_id: ObjectId
    name: Annotated[str, Field(pattern=ARTIFACT_NAME_PATTERN)]
    role: ArtifactRole
    sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0)]
    storage_path: Annotated[str, Field(min_length=1)]
    """POSIX path relative to the local artifact store root."""
    created_at: AwareDatetime

    @field_validator("storage_path")
    @classmethod
    def _relative_path(cls, value: str) -> str:
        parts = value.split("/")
        if value.startswith("/") or "\\" in value or any(p in ("", ".", "..") for p in parts):
            raise ValueError("storage_path must be a normalized relative POSIX path")
        return value


# ----------------------------------------------------------------------- policies

OptionValue = (
    bool
    | int
    | Annotated[float, Field(allow_inf_nan=False)]
    | Annotated[str, Field(max_length=MAX_OPTION_STRING)]
)


class AttackLabAuthorization(AegisModel):
    """Explicit record that someone is permitted to attack the submitted artifact."""

    authorized_by: Annotated[str, Field(min_length=1, max_length=200)]
    reference: Annotated[str, Field(min_length=1, max_length=200)]
    """Engagement, ticket or approval identifier."""
    scope: Annotated[str, Field(min_length=1, max_length=2000)]
    attested_at: AwareDatetime = Field(default_factory=utcnow)
    expires_at: AwareDatetime | None = None

    @field_validator("authorized_by", "reference", "scope")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value


class ProtectionPolicy(AegisModel):
    name: Annotated[str, Field(pattern=ARTIFACT_NAME_PATTERN)] = "default"
    backend: Annotated[str, Field(pattern=BACKEND_PATTERN)]
    task: TaskKind = TaskKind.PROTECT
    options: dict[str, OptionValue] = Field(default_factory=dict)
    timeout_seconds: Annotated[int, Field(ge=1, le=86_400)] | None = None
    """Overrides the adapter's configured timeout when set."""
    authorization: AttackLabAuthorization | None = None
    """Required for attack-lab tasks; ignored otherwise."""

    @field_validator("options")
    @classmethod
    def _check_options(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > MAX_OPTIONS:
            raise ValueError(f"at most {MAX_OPTIONS} options are allowed")
        for key, item in value.items():
            if not re.match(OPTION_KEY_PATTERN, key):
                raise ValueError(f"invalid option key {key!r}")
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError(f"option {key!r} must be finite")
        return value


# --------------------------------------------------------------------------- jobs


def _check_status_invariants(status: JobStatus, error: ErrorInfo | None, finished_at: Any) -> None:
    if status is JobStatus.FAILED and error is None:
        raise ValueError("a failed job must carry an error")
    if status is not JobStatus.FAILED and error is not None:
        raise ValueError(f"a {status.value} job must not carry an error")
    if status.is_terminal and finished_at is None:
        raise ValueError("a terminal job must have finished_at")
    if not status.is_terminal and finished_at is not None:
        raise ValueError("a non-terminal job must not have finished_at")


class ProtectionJob(AegisModel):
    schema_version: Literal["1"] = SCHEMA_VERSION
    job_id: ObjectId
    status: JobStatus
    policy: ProtectionPolicy
    input_artifact: Artifact
    output_artifacts: list[Artifact] = Field(default_factory=list)
    error: ErrorInfo | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _invariants(self) -> ProtectionJob:
        _check_status_invariants(self.status, self.error, self.finished_at)
        if self.status is not JobStatus.PENDING and self.started_at is None:
            raise ValueError("a job that has left pending must have started_at")
        if self.output_artifacts and self.status is not JobStatus.SUCCEEDED:
            raise ValueError("only succeeded jobs may list output artifacts")
        if self.input_artifact.role is not ArtifactRole.INPUT:
            raise ValueError("input_artifact must have role 'input'")
        return self


# ----------------------------------------------------------------------- evidence


class EvidenceRecord(AegisModel):
    evidence_id: ObjectId
    job_id: ObjectId
    kind: EvidenceKind
    source: EvidenceSource
    summary: Annotated[str, Field(min_length=1, max_length=2000)]
    artifact_sha256: Sha256 | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: AwareDatetime


class AttackEvaluation(AegisModel):
    evaluation_id: ObjectId
    job_id: ObjectId
    attack: Annotated[str, Field(min_length=1, max_length=200)]
    outcome: AttackOutcome
    target_artifact_sha256: Sha256 | None = None
    details: Annotated[str, Field(max_length=4000)] = ""
    metrics: dict[str, OptionValue] = Field(default_factory=dict)
    source: EvidenceSource = EvidenceSource.ADAPTER
    evaluated_at: AwareDatetime


# ------------------------------------------------------------------------ reports

REPORT_LIMITATIONS: tuple[str, ...] = (
    "Artifact hashes and adapter exit status are verified by the orchestrator; "
    "all other adapter evidence is recorded as claimed and is not independently verified.",
    "Attack evaluations cover only the attacks listed; the absence of a successful "
    "attack does not prove an artifact is secure.",
)


class ProtectionReport(AegisModel):
    schema_version: Literal["1"] = SCHEMA_VERSION
    report_id: ObjectId
    job_id: ObjectId
    status: JobStatus
    generated_at: AwareDatetime
    policy: ProtectionPolicy
    input_artifact: Artifact
    output_artifacts: list[Artifact] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    attack_evaluations: list[AttackEvaluation] = Field(default_factory=list)
    error: ErrorInfo | None = None
    summary: Annotated[str, Field(min_length=1)]
    limitations: list[str] = Field(default_factory=lambda: list(REPORT_LIMITATIONS))

    @model_validator(mode="after")
    def _invariants(self) -> ProtectionReport:
        if not self.status.is_terminal:
            raise ValueError("reports can only be produced for terminal jobs")
        _check_status_invariants(self.status, self.error, self.generated_at)
        return self
