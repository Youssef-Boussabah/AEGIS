"""Data models for Sentinel rights, usage policies, and cooperating tool evaluation."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

SENTINEL_SCHEMA_VERSION: Literal["1"] = "1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[0-9a-f]{32}$"

Sha256 = Annotated[str, Field(pattern=SHA256_PATTERN)]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SentinelModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnforcementMode(StrEnum):
    ADVISORY_NOTICE = "advisory_notice"
    COOPERATING_ENFORCED = "cooperating_enforced"


class PermissionAction(StrEnum):
    EXECUTE = "execute"
    ANALYZE = "analyze"
    REDISTRIBUTE = "redistribute"
    MODIFY = "modify"
    ATTACK_EVALUATE = "attack_evaluate"


class PolicyPermission(SentinelModel):
    action: PermissionAction
    allowed: bool
    scope: str | None = Field(default=None, max_length=256)
    notes: str | None = Field(default=None, max_length=1024)


class PolicyConstraint(SentinelModel):
    not_before: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None
    environments: list[str] | None = None
    watermark_required: bool = False
    allowed_caller_ids: list[str] | None = None


class ArtifactLinkage(SentinelModel):
    artifact_name: str = Field(min_length=1, max_length=256)
    artifact_sha256: Sha256
    manifest_reference: Sha256 | None = None


class SentinelPolicy(SentinelModel):
    """Machine-readable rights and usage policy record."""
    schema_version: Literal["1"] = SENTINEL_SCHEMA_VERSION
    policy_id: str = Field(pattern=ID_PATTERN)
    issuer: str = Field(min_length=1, max_length=256)
    issued_at: AwareDatetime
    enforcement_mode: EnforcementMode = EnforcementMode.ADVISORY_NOTICE
    target_artifact: ArtifactLinkage
    permissions: list[PolicyPermission]
    constraints: PolicyConstraint = Field(default_factory=PolicyConstraint)
    disclaimer: str = (
        "Publishing this policy document conveys rights metadata; third-party tools are not bound "
        "unless cooperating with AEGIS enforcement."
    )


class ValidationResult(SentinelModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class EvaluationResult(SentinelModel):
    action: PermissionAction
    permitted: bool
    enforcement_mode: EnforcementMode
    reason: str
    evaluated_at: AwareDatetime = Field(default_factory=utcnow)

