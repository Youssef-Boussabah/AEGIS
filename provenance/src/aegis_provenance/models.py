"""Strict data models for signed artifact manifests, envelopes, and verification."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

PROVENANCE_SCHEMA_VERSION: Literal["1"] = "1"
ENVELOPE_SCHEMA_VERSION: Literal["1"] = "1"

SHA256_PATTERN = r"^[0-9a-f]{64}$"
KEY_ID_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[0-9a-f]{32}$"

Sha256 = Annotated[str, Field(pattern=SHA256_PATTERN)]
KeyId = Annotated[str, Field(pattern=KEY_ID_PATTERN)]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProvenanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VerificationErrorCode(StrEnum):
    ARTIFACT_NOT_FOUND = "ARTIFACT_NOT_FOUND"
    ARTIFACT_TAMPERED = "ARTIFACT_TAMPERED"
    MANIFEST_MALFORMED = "MANIFEST_MALFORMED"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    KEY_ID_MISMATCH = "KEY_ID_MISMATCH"
    UNTRUSTED_KEY = "UNTRUSTED_KEY"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    ABSENT_TRUSTED_KEYS = "ABSENT_TRUSTED_KEYS"


class BuildReference(ProvenanceModel):
    repository: str = Field(min_length=1, max_length=512)
    commit: str = Field(min_length=7, max_length=64)
    branch: str | None = Field(default=None, max_length=256)
    build_job_id: str | None = Field(default=None, max_length=64)


class ToolchainInfo(ProvenanceModel):
    compiler: str = Field(min_length=1, max_length=128)
    compiler_version: str = Field(min_length=1, max_length=128)
    platform: str = Field(min_length=1, max_length=128)
    target_triple: str | None = Field(default=None, max_length=128)


class ConfigurationIdentity(ProvenanceModel):
    profile: str = Field(min_length=1, max_length=64)
    backend: str | None = Field(default=None, max_length=64)
    options_digest: Sha256 | None = Field(default=None)


class SignerIdentity(ProvenanceModel):
    name: str = Field(min_length=1, max_length=128)
    organization: str | None = Field(default=None, max_length=128)
    contact: str | None = Field(default=None, max_length=128)


class ProvenanceManifest(ProvenanceModel):
    """The canonical signed payload covering artifact provenance."""
    schema_version: Literal["1"] = PROVENANCE_SCHEMA_VERSION
    manifest_id: str = Field(pattern=ID_PATTERN)
    created_at: AwareDatetime
    artifact_name: str = Field(min_length=1, max_length=256)
    artifact_sha256: Sha256
    artifact_size_bytes: int = Field(ge=0)
    build_reference: BuildReference
    toolchain: ToolchainInfo
    configuration: ConfigurationIdentity
    signer: SignerIdentity
    key_id: KeyId


class ManifestEnvelope(ProvenanceModel):
    """Cryptographic signature envelope containing manifest payload and signature."""
    envelope_version: Literal["1"] = ENVELOPE_SCHEMA_VERSION
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: KeyId
    public_key: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    payload: ProvenanceManifest


class VerificationResult(ProvenanceModel):
    """Outcome of offline verification against trusted keys."""
    valid: bool
    error_code: VerificationErrorCode | None = None
    message: str
    artifact_sha256: Sha256 | None = None
    manifest_sha256: Sha256 | None = None
    key_id: KeyId | None = None
    signer_name: str | None = None
    verified_at: AwareDatetime = Field(default_factory=utcnow)

