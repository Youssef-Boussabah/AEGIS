"""Signing and Sentinel policies for AEGIS Core job outputs.

This module connects Core's protection lifecycle to the existing Ed25519
provenance implementation and to Sentinel's policy creation, validation and
evaluation. Core stays free of cryptography: it only calls
``JobAttestor.attest`` as a post-success hook (see
``aegis_core.orchestrator.PostSuccessHook``).

Truthfulness rules implemented here:

* A signature is reported ``verified`` only after ``verify_artifact_manifest``
  succeeds against the operator's trusted keys **and** the manifest names the
  digest, file name and job id that Core recorded.
* Without a configured signing key nothing is signed and every output is
  ``unsigned``. No key is ever generated here.
* A broken signing configuration raises ``CONFIG_INVALID`` at load time; the
  API and CLI refuse to start rather than run unsigned silently.
* Sentinel policies are cooperating metadata. A missing, invalid or modified
  policy always evaluates as denied.

Layout under ``<store>/jobs/<job_id>/attestation/`` (0700, files 0600)::

    attestation.json                  JobAttestationRecord
    <artifact_id>.manifest.json       ManifestEnvelope for one output
    <artifact_id>.policy.json         SentinelPolicy for one output
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import stat
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import AwareDatetime, Field, ValidationError

from aegis_core import __version__ as core_version
from aegis_core.config import AegisConfig, ProvenanceConfig, SentinelJobConfig
from aegis_core.errors import AegisError
from aegis_core.models import (
    ID_PATTERN,
    AegisModel,
    Artifact,
    ErrorCode,
    JobStatus,
    ProtectionJob,
    Sha256,
    utcnow,
)
from aegis_core.storage import LocalArtifactStore
from aegis_provenance.canonical import canonical_json
from aegis_provenance.crypto import compute_key_id, load_public_key
from aegis_provenance.manifest import sign_artifact, verify_artifact_manifest
from aegis_provenance.models import (
    BuildReference,
    ConfigurationIdentity,
    ManifestEnvelope,
    SignerIdentity,
    ToolchainInfo,
)
from aegis_sentinel.evaluator import evaluate_action
from aegis_sentinel.models import (
    ArtifactLinkage,
    EnforcementMode,
    PermissionAction,
    PolicyConstraint,
    PolicyPermission,
    SentinelPolicy,
)
from aegis_sentinel.validator import validate_policy_data

logger = logging.getLogger(__name__)

RECORD_NAME = "attestation.json"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
API_CALLER_ID = "aegis-api"

LIMITATIONS: tuple[str, ...] = (
    "A verified signature shows that the holder of a trusted Ed25519 key attested to "
    "these exact bytes and the listed build metadata. It does not show that the "
    "artifact is protected, original, free of defects or resistant to any attack.",
    "Signatures are verified against the operator's configured trusted public keys "
    "only; the private key's custody is the operator's responsibility.",
    "Sentinel policies are cooperating rights metadata. They bind only tools that "
    "consult them (AEGIS's own artifact download does); they do not restrict "
    "third-party tools, decompilers or anyone holding a copy of the bytes.",
    "Sentinel caller and environment identifiers are asserted by the caller and are "
    "not authenticated.",
)

SignatureStatus = Literal["verified", "failed", "unsigned"]
SigningState = Literal["signed", "not_configured", "signing_failed"]
SentinelState = Literal["created", "not_configured", "creation_failed"]


# ----------------------------------------------------------------- records


class ArtifactAttestation(AegisModel):
    artifact_id: str = Field(pattern=ID_PATTERN)
    name: str
    sha256: Sha256
    manifest_file: str | None = None
    manifest_sha256: Sha256 | None = None
    policy_file: str | None = None
    policy_sha256: Sha256 | None = None
    policy_id: str | None = Field(default=None, pattern=ID_PATTERN)


class JobAttestationRecord(AegisModel):
    """Written once, inside the job run, before the job becomes terminal."""

    schema_: Literal["aegis.job-attestation-record.v1"] = Field(
        default="aegis.job-attestation-record.v1", alias="schema"
    )
    job_id: str = Field(pattern=ID_PATTERN)
    created_at: AwareDatetime
    signing_state: SigningState
    signing_message: str
    key_id: Sha256 | None = None
    signer_name: str | None = None
    configuration_digest: Sha256 | None = None
    configuration_preimage: dict | None = None
    sentinel_state: SentinelState
    sentinel_message: str
    enforcement_mode: EnforcementMode | None = None
    artifacts: list[ArtifactAttestation] = Field(default_factory=list)

    model_config = {"extra": "forbid", "populate_by_name": True}


# ------------------------------------------------------------ API responses


class SigningSummary(AegisModel):
    state: Literal["signed", "not_configured", "signing_failed", "not_applicable", "pending"]
    key_id: Sha256 | None = None
    signer_name: str | None = None
    message: str


class SentinelSummary(AegisModel):
    state: Literal["created", "not_configured", "creation_failed", "not_applicable", "pending"]
    enforcement_mode: EnforcementMode | None = None
    message: str


class SignatureVerification(AegisModel):
    status: SignatureStatus
    error_code: str | None = None
    message: str
    key_id: Sha256 | None = None
    signer_name: str | None = None
    manifest_sha256: Sha256 | None = None


class PermissionView(AegisModel):
    action: PermissionAction
    allowed: bool


class PolicyView(AegisModel):
    status: Literal["valid", "invalid", "absent"]
    policy_id: str | None = None
    policy_sha256: Sha256 | None = None
    enforcement_mode: EnforcementMode | None = None
    permissions: list[PermissionView] = Field(default_factory=list)
    not_before: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None
    disclaimer: str | None = None
    errors: list[str] = Field(default_factory=list)


class ArtifactStatus(AegisModel):
    artifact_id: str
    name: str
    sha256: Sha256
    size_bytes: int
    signature: SignatureVerification
    policy: PolicyView


class JobAttestationStatus(AegisModel):
    schema_: Literal["aegis.job-attestation.v1"] = Field(
        default="aegis.job-attestation.v1", alias="schema"
    )
    job_id: str
    job_status: JobStatus
    checked_at: AwareDatetime
    signing: SigningSummary
    sentinel: SentinelSummary
    artifacts: list[ArtifactStatus]
    limitations: list[str]

    model_config = {"extra": "forbid", "populate_by_name": True}

    @property
    def all_verified(self) -> bool:
        return (
            self.job_status is JobStatus.SUCCEEDED
            and bool(self.artifacts)
            and all(a.signature.status == "verified" for a in self.artifacts)
            and all(a.policy.status != "invalid" for a in self.artifacts)
        )


class SigningConfigView(AegisModel):
    state: Literal["configured", "not_configured"]
    key_id: Sha256 | None = None
    signer_name: str | None = None
    signer_trusted: bool = False


class VerificationConfigView(AegisModel):
    trusted_key_ids: list[Sha256]


class SentinelConfigView(AegisModel):
    state: Literal["configured", "not_configured"]
    issuer: str | None = None
    enforcement_mode: EnforcementMode | None = None
    allowed_actions: list[PermissionAction] = Field(default_factory=list)


class AttestationConfigView(AegisModel):
    schema_: Literal["aegis.attestation-config.v1"] = Field(
        default="aegis.attestation-config.v1", alias="schema"
    )
    signing: SigningConfigView
    verification: VerificationConfigView
    sentinel: SentinelConfigView

    model_config = {"extra": "forbid", "populate_by_name": True}


class SentinelDecision(AegisModel):
    schema_: Literal["aegis.sentinel-decision.v1"] = Field(
        default="aegis.sentinel-decision.v1", alias="schema"
    )
    job_id: str
    artifact_sha256: Sha256
    action: PermissionAction
    permitted: bool
    enforcement_mode: EnforcementMode
    reason: str
    policy_id: str | None = None
    caller_id_verified: Literal[False] = False
    evaluated_at: AwareDatetime

    model_config = {"extra": "forbid", "populate_by_name": True}


# ----------------------------------------------------------------- settings


@dataclass(frozen=True)
class SigningIdentity:
    private_key: ed25519.Ed25519PrivateKey
    key_id: str
    signer: SignerIdentity
    repository: str
    commit: str


@dataclass(frozen=True)
class AttestationSettings:
    signing: SigningIdentity | None
    trusted_keys: tuple[ed25519.Ed25519PublicKey, ...]
    trusted_key_ids: tuple[str, ...]
    sentinel: SentinelJobConfig | None


def _config_error(message: str, **details: object) -> AegisError:
    return AegisError(ErrorCode.CONFIG_INVALID, message, dict(details))


def is_git_marker(marker: Path) -> bool:
    """A real repository marker: a .git directory with HEAD, or a `gitdir:` file."""
    try:
        if marker.is_dir():
            return (marker / "HEAD").is_file()
        if marker.is_file():
            with marker.open("rb") as handle:
                return handle.read(8) == b"gitdir: "
    except OSError:
        return True  # cannot tell: refuse rather than risk a key in a repository
    return False


def inside_git_work_tree(path: Path) -> Path | None:
    for parent in path.absolute().parents:
        if is_git_marker(parent / ".git"):
            return parent
    return None


def _read_key_file(path: Path, what: str, *, private: bool) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise _config_error(f"The {what} does not exist.", path=str(path)) from None
    except OSError as exc:
        raise _config_error(
            f"The {what} cannot be opened ({exc.strerror}); symlinks are refused.", path=str(path)
        ) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise _config_error(f"The {what} is not a regular file.", path=str(path))
        if private and info.st_mode & 0o077:
            raise _config_error(
                f"The {what} is readable by group or others; restrict it to mode 0600.",
                path=str(path),
                mode=oct(stat.S_IMODE(info.st_mode)),
            )
        if info.st_size > MAX_KEY_BYTES:
            raise _config_error(f"The {what} is too large to be a key.", path=str(path))
        data = os.read(fd, MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    return data


def _load_signing_identity(cfg: ProvenanceConfig, store_root: Path) -> SigningIdentity:
    assert cfg.signing_key_path is not None
    path = cfg.signing_key_path
    # A parent-directory symlink can hide Git ancestry from the configured
    # spelling. Check both locations; _read_key_file still refuses a symlink
    # final component with O_NOFOLLOW.
    repo = inside_git_work_tree(path) or inside_git_work_tree(path.resolve())
    if repo is not None:
        raise _config_error(
            "The signing key is inside a Git work tree; keep private keys outside any "
            "repository.",
            path=str(path),
        )
    if path.resolve().is_relative_to(store_root.resolve()):
        raise _config_error("The signing key must not be inside the artifact store.", path=str(path))
    data = _read_key_file(path, "signing key", private=True)
    password: bytes | None = None
    if cfg.signing_key_password_env is not None:
        value = os.environ.get(cfg.signing_key_password_env)
        if not value:
            raise _config_error(
                "The signing key password environment variable is not set.",
                variable=cfg.signing_key_password_env,
            )
        password = value.encode("utf-8")
    try:
        key = serialization.load_pem_private_key(data, password=password)
    except TypeError:
        raise _config_error(
            "The signing key is encrypted but no password variable is configured, or it "
            "is not encrypted but one is.",
            path=str(path),
        ) from None
    except ValueError:
        # Wrong password, corrupt PEM or unsupported key type: never echo details.
        raise _config_error(
            "The signing key could not be loaded (wrong password or not a PEM private key).",
            path=str(path),
        ) from None
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise _config_error("The signing key is not an Ed25519 private key.", path=str(path))
    assert cfg.signer_name and cfg.build_repository and cfg.build_commit
    return SigningIdentity(
        private_key=key,
        key_id=compute_key_id(key.public_key()),
        signer=SignerIdentity(name=cfg.signer_name, organization=cfg.signer_organization),
        repository=cfg.build_repository,
        commit=cfg.build_commit,
    )


def load_attestation_settings(config: AegisConfig) -> AttestationSettings:
    """Load keys and policies from the operator configuration, or raise CONFIG_INVALID."""
    prov = config.provenance
    signing: SigningIdentity | None = None
    trusted: list[ed25519.Ed25519PublicKey] = []
    if prov.enabled:
        if prov.signing_key_path is not None:
            signing = _load_signing_identity(prov, config.storage.root)
        for path in prov.trusted_public_keys:
            raw = _read_key_file(path, "trusted public key", private=False)
            try:
                trusted.append(load_public_key(raw.decode("utf-8")))
            except (UnicodeDecodeError, ValueError):
                raise _config_error(
                    "A trusted public key is not an Ed25519 public key (PEM or raw base64).",
                    path=str(path),
                ) from None
    ids: list[str] = []
    for key in trusted:
        kid = compute_key_id(key)
        if kid not in ids:
            ids.append(kid)
    sentinel = config.sentinel if config.sentinel.enabled else None
    return AttestationSettings(
        signing=signing,
        trusted_keys=tuple(trusted),
        trusted_key_ids=tuple(ids),
        sentinel=sentinel,
    )


# ----------------------------------------------------------------- attestor


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class JobAttestor:
    """Signs outputs, writes Sentinel policies and reports verified status."""

    def __init__(
        self,
        settings: AttestationSettings,
        store: LocalArtifactStore,
        *,
        clock: Callable[[], datetime] = utcnow,
    ):
        self.settings = settings
        self.store = store
        self.clock = clock

    @classmethod
    def from_config(
        cls,
        config: AegisConfig,
        store: LocalArtifactStore,
        *,
        clock: Callable[[], datetime] = utcnow,
    ) -> JobAttestor:
        return cls(load_attestation_settings(config), store, clock=clock)

    # ------------------------------------------------------------ config view

    def config_view(self) -> AttestationConfigView:
        signing = self.settings.signing
        sentinel = self.settings.sentinel
        return AttestationConfigView(
            signing=SigningConfigView(
                state="configured" if signing else "not_configured",
                key_id=signing.key_id if signing else None,
                signer_name=signing.signer.name if signing else None,
                signer_trusted=bool(signing and signing.key_id in self.settings.trusted_key_ids),
            ),
            verification=VerificationConfigView(trusted_key_ids=list(self.settings.trusted_key_ids)),
            sentinel=SentinelConfigView(
                state="configured" if sentinel else "not_configured",
                issuer=sentinel.issuer if sentinel else None,
                enforcement_mode=EnforcementMode(sentinel.enforcement_mode) if sentinel else None,
                allowed_actions=[PermissionAction(a) for a in (sentinel.allowed_actions or [])]
                if sentinel
                else [],
            ),
        )

    # ----------------------------------------------------------------- attest

    def attest(self, job: ProtectionJob) -> None:
        """Post-success hook: never raises; always leaves an explicit record."""
        try:
            self._attest(job)
        except Exception as exc:
            logger.exception("attestation failed for job %s", job.job_id)
            try:
                self._write_record(
                    JobAttestationRecord(
                        job_id=job.job_id,
                        created_at=self.clock(),
                        signing_state="signing_failed" if self.settings.signing else "not_configured",
                        signing_message=f"Attestation failed unexpectedly ({type(exc).__name__}).",
                        sentinel_state="creation_failed" if self.settings.sentinel else "not_configured",
                        sentinel_message=f"Attestation failed unexpectedly ({type(exc).__name__}).",
                    )
                )
            except Exception:
                logger.exception("could not record attestation failure for job %s", job.job_id)

    def _configuration_preimage(self, job: ProtectionJob) -> dict:
        policy = job.policy
        return {
            "schema": "aegis.job-configuration.v1",
            "job_id": job.job_id,
            "backend": policy.backend,
            "task": policy.task.value,
            "policy_name": policy.name,
            "options": policy.options,
            "input_sha256": job.input_artifact.sha256,
        }

    def _attest(self, job: ProtectionJob) -> None:
        if job.status is not JobStatus.SUCCEEDED:
            return
        signing = self.settings.signing
        sentinel = self.settings.sentinel
        if signing is None and sentinel is None:
            # Nothing configured: write no files; status reports not_configured.
            return
        directory = self.store.ensure_attestation_dir(job.job_id)
        preimage = self._configuration_preimage(job)
        config_digest = _sha256(canonical_json(preimage))
        entries = [
            ArtifactAttestation(artifact_id=a.artifact_id, name=a.name, sha256=a.sha256)
            for a in job.output_artifacts
        ]

        signing_state: SigningState = "not_configured"
        signing_message = "No signing key is configured; outputs are unsigned."
        if signing is not None:
            try:
                for artifact, entry in zip(job.output_artifacts, entries):
                    self._sign_one(job, artifact, entry, directory, signing, config_digest)
                signing_state = "signed"
                signing_message = (
                    f"{len(entries)} output(s) signed with Ed25519 key {signing.key_id[:16]}…."
                )
            except AegisError as exc:
                signing_state = "signing_failed"
                signing_message = exc.message
                for entry in entries:
                    entry.manifest_file = entry.manifest_sha256 = None

        sentinel_state: SentinelState = "not_configured"
        sentinel_message = "Sentinel is not configured; no rights policy was attached."
        if sentinel is not None:
            try:
                for artifact, entry in zip(job.output_artifacts, entries):
                    self._policy_one(job, artifact, entry, directory, sentinel)
                sentinel_state = "created"
                sentinel_message = (
                    f"{len(entries)} {sentinel.enforcement_mode} policy record(s) created."
                )
            except AegisError as exc:
                sentinel_state = "creation_failed"
                sentinel_message = exc.message
                for entry in entries:
                    entry.policy_file = entry.policy_sha256 = entry.policy_id = None

        self._write_record(
            JobAttestationRecord(
                job_id=job.job_id,
                created_at=self.clock(),
                signing_state=signing_state,
                signing_message=signing_message,
                key_id=signing.key_id if signing_state == "signed" and signing else None,
                signer_name=signing.signer.name if signing_state == "signed" and signing else None,
                configuration_digest=config_digest if signing_state == "signed" else None,
                configuration_preimage=preimage if signing_state == "signed" else None,
                sentinel_state=sentinel_state,
                sentinel_message=sentinel_message,
                enforcement_mode=EnforcementMode(sentinel.enforcement_mode) if sentinel else None,
                artifacts=entries,
            )
        )

    def _sign_one(
        self,
        job: ProtectionJob,
        artifact: Artifact,
        entry: ArtifactAttestation,
        directory: Path,
        signing: SigningIdentity,
        config_digest: str,
    ) -> None:
        path = self.store.artifact_path(artifact)
        envelope = sign_artifact(
            artifact_path=path,
            private_key=signing.private_key,
            signer=signing.signer,
            build_reference=BuildReference(
                repository=signing.repository,
                commit=signing.commit,
                build_job_id=job.job_id,
            ),
            toolchain=ToolchainInfo(
                compiler=f"aegis-backend:{job.policy.backend}",
                compiler_version=f"aegis-core {core_version}",
                platform=f"{sys.platform}-{platform.machine() or 'unknown'}"[:128],
            ),
            configuration=ConfigurationIdentity(
                profile=job.policy.name[:64],
                backend=job.policy.backend,
                options_digest=config_digest,
            ),
        )
        # Sign only the bytes Core registered; refuse if they changed in between.
        if envelope.payload.artifact_sha256 != artifact.sha256:
            raise AegisError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                f"Output {artifact.name!r} changed after Core hashed it; it was not signed.",
            )
        data = envelope.model_dump_json(indent=2).encode("utf-8")
        name = f"{artifact.artifact_id}.manifest.json"
        self.store.write_atomic(directory / name, data)
        entry.manifest_file = name
        entry.manifest_sha256 = _sha256(data)

    def _policy_one(
        self,
        job: ProtectionJob,
        artifact: Artifact,
        entry: ArtifactAttestation,
        directory: Path,
        sentinel: SentinelJobConfig,
    ) -> None:
        now = self.clock()
        allowed = set(sentinel.allowed_actions or [])
        policy = SentinelPolicy(
            policy_id=uuid.uuid4().hex,
            issuer=sentinel.issuer or "",
            issued_at=now,
            enforcement_mode=EnforcementMode(sentinel.enforcement_mode),
            target_artifact=ArtifactLinkage(
                artifact_name=artifact.name,
                artifact_sha256=artifact.sha256,
                manifest_reference=entry.manifest_sha256,
            ),
            permissions=[
                PolicyPermission(
                    action=action,
                    allowed=action.value in allowed,
                    scope=f"AEGIS job {job.job_id}",
                )
                for action in PermissionAction
            ],
            constraints=PolicyConstraint(
                not_before=now,
                expires_at=now + timedelta(days=sentinel.valid_days) if sentinel.valid_days else None,
                allowed_caller_ids=list(sentinel.allowed_caller_ids)
                if sentinel.allowed_caller_ids
                else None,
            ),
        )
        # Run Sentinel's own validator on exactly what will be stored.
        data = policy.model_dump_json(indent=2).encode("utf-8")
        validated, result = validate_policy_data(data)
        if not result.valid or validated is None:
            raise AegisError(
                ErrorCode.INTERNAL_ERROR,
                "Generated Sentinel policy failed validation: " + "; ".join(result.errors),
            )
        name = f"{artifact.artifact_id}.policy.json"
        self.store.write_atomic(directory / name, data)
        entry.policy_file = name
        entry.policy_sha256 = _sha256(data)
        entry.policy_id = policy.policy_id

    def _write_record(self, record: JobAttestationRecord) -> None:
        directory = self.store.ensure_attestation_dir(record.job_id)
        self.store.write_atomic(
            directory / RECORD_NAME,
            record.model_dump_json(indent=2, by_alias=True).encode("utf-8"),
        )

    # ----------------------------------------------------------------- reads

    def load_record(self, job_id: str) -> JobAttestationRecord | None:
        path = self.store.attestation_dir(job_id) / RECORD_NAME
        try:
            raw = self.store.read_bounded(path, max_bytes=MAX_DOCUMENT_BYTES)
        except FileNotFoundError:
            return None
        except OSError:
            raise AegisError(ErrorCode.STORAGE_ERROR, "The attestation record cannot be read safely.") from None
        try:
            return JobAttestationRecord.model_validate_json(raw)
        except ValidationError:
            raise AegisError(
                ErrorCode.STORAGE_ERROR, f"The attestation record for job {job_id} is corrupt."
            ) from None

    def _read_document(self, job_id: str, name: str) -> bytes | None:
        try:
            return self.store.read_bounded(
                self.store.attestation_dir(job_id) / name, max_bytes=MAX_DOCUMENT_BYTES
            )
        except (FileNotFoundError, OSError):
            return None
        except AegisError:
            return None

    def _entry(self, record: JobAttestationRecord | None, artifact: Artifact) -> ArtifactAttestation | None:
        if record is None:
            return None
        for entry in record.artifacts:
            if entry.artifact_id == artifact.artifact_id and entry.sha256 == artifact.sha256:
                return entry
        return None

    # -------------------------------------------------------------- verify

    def _verify_signature(
        self,
        job: ProtectionJob,
        artifact: Artifact,
        record: JobAttestationRecord | None,
        entry: ArtifactAttestation | None,
    ) -> SignatureVerification:
        if record is None or record.signing_state != "signed":
            message = "Not signed: signing is not configured."
            if record is not None and record.signing_state == "signing_failed":
                message = f"Not signed: signing failed ({record.signing_message})."
            elif record is None and self.settings.signing is not None:
                message = "Not signed: no signing record exists for this job."
            return SignatureVerification(status="unsigned", message=message)
        if entry is None or entry.manifest_file is None or entry.manifest_sha256 is None:
            return SignatureVerification(
                status="failed",
                error_code="MANIFEST_MISSING",
                message="The signing record has no manifest for this output.",
            )
        raw = self._read_document(job.job_id, entry.manifest_file)
        if raw is None:
            return SignatureVerification(
                status="failed",
                error_code="MANIFEST_MISSING",
                message="The signed manifest for this output is missing or unreadable.",
                manifest_sha256=entry.manifest_sha256,
            )
        manifest_sha = _sha256(raw)
        result = verify_artifact_manifest(
            artifact_path=self.store.artifact_path(artifact),
            envelope_input=raw,
            trusted_keys=list(self.settings.trusted_keys),
        )
        if not result.valid:
            return SignatureVerification(
                status="failed",
                error_code=str(result.error_code.value if result.error_code else "VERIFICATION_FAILED"),
                message=result.message,
                key_id=result.key_id,
                signer_name=result.signer_name,
                manifest_sha256=manifest_sha,
            )
        envelope = ManifestEnvelope.model_validate_json(raw)
        payload = envelope.payload
        mismatch = []
        if payload.artifact_sha256 != artifact.sha256 or payload.artifact_size_bytes != artifact.size_bytes:
            mismatch.append("digest/size differs from Core's record")
        if payload.build_reference.build_job_id != job.job_id:
            mismatch.append("manifest belongs to another job")
        if payload.artifact_name != self.store.artifact_path(artifact).name:
            mismatch.append("artifact name differs")
        if manifest_sha != entry.manifest_sha256:
            mismatch.append("manifest file differs from the one recorded at signing")
        if mismatch:
            return SignatureVerification(
                status="failed",
                error_code="RECORD_MISMATCH",
                message="Valid signature, but " + "; ".join(mismatch) + ".",
                key_id=result.key_id,
                signer_name=result.signer_name,
                manifest_sha256=manifest_sha,
            )
        return SignatureVerification(
            status="verified",
            message="Ed25519 signature verified with a trusted key; bytes match Core's record.",
            key_id=result.key_id,
            signer_name=result.signer_name,
            manifest_sha256=manifest_sha,
        )

    def _load_policy(
        self, job: ProtectionJob, artifact: Artifact, entry: ArtifactAttestation | None
    ) -> tuple[SentinelPolicy | None, PolicyView]:
        if entry is None or entry.policy_file is None or entry.policy_sha256 is None:
            return None, PolicyView(status="absent")
        raw = self._read_document(job.job_id, entry.policy_file)
        if raw is None:
            return None, PolicyView(
                status="invalid",
                policy_id=entry.policy_id,
                errors=["The Sentinel policy file is missing or unreadable."],
            )
        sha = _sha256(raw)
        policy, result = validate_policy_data(raw)
        errors = list(result.errors)
        if sha != entry.policy_sha256:
            errors.append("The Sentinel policy file was modified after AEGIS created it.")
        if policy is not None and policy.target_artifact.artifact_sha256 != artifact.sha256:
            errors.append("The Sentinel policy targets a different artifact digest.")
        if policy is not None and policy.policy_id != entry.policy_id:
            errors.append("The Sentinel policy id differs from the recorded one.")
        if policy is None or errors:
            return None, PolicyView(
                status="invalid", policy_id=entry.policy_id, policy_sha256=sha, errors=errors
            )
        return policy, PolicyView(
            status="valid",
            policy_id=policy.policy_id,
            policy_sha256=sha,
            enforcement_mode=policy.enforcement_mode,
            permissions=[PermissionView(action=p.action, allowed=p.allowed) for p in policy.permissions],
            not_before=policy.constraints.not_before,
            expires_at=policy.constraints.expires_at,
            disclaimer=policy.disclaimer,
        )

    def status(self, job: ProtectionJob) -> JobAttestationStatus:
        now = self.clock()
        if not job.status.is_terminal:
            return JobAttestationStatus(
                job_id=job.job_id,
                job_status=job.status,
                checked_at=now,
                signing=SigningSummary(state="pending", message="The job has not finished."),
                sentinel=SentinelSummary(state="pending", message="The job has not finished."),
                artifacts=[],
                limitations=list(LIMITATIONS),
            )
        if job.status is JobStatus.FAILED:
            return JobAttestationStatus(
                job_id=job.job_id,
                job_status=job.status,
                checked_at=now,
                signing=SigningSummary(
                    state="not_applicable", message="Failed jobs have no outputs to sign."
                ),
                sentinel=SentinelSummary(
                    state="not_applicable", message="Failed jobs have no outputs to govern."
                ),
                artifacts=[],
                limitations=list(LIMITATIONS),
            )
        record = self.load_record(job.job_id)
        if record is None:
            signing = SigningSummary(
                state="signing_failed" if self.settings.signing else "not_configured",
                message="No attestation record exists for this job."
                if self.settings.signing
                else "No signing key is configured; outputs are unsigned.",
            )
            sentinel = SentinelSummary(
                state="creation_failed" if self.settings.sentinel else "not_configured",
                message="No Sentinel record exists for this job."
                if self.settings.sentinel
                else "Sentinel is not configured; no rights policy was attached.",
            )
        else:
            signing = SigningSummary(
                state=record.signing_state,
                key_id=record.key_id,
                signer_name=record.signer_name,
                message=record.signing_message,
            )
            sentinel = SentinelSummary(
                state=record.sentinel_state,
                enforcement_mode=record.enforcement_mode,
                message=record.sentinel_message,
            )
        artifacts = []
        for artifact in job.output_artifacts:
            entry = self._entry(record, artifact)
            _, policy_view = self._load_policy(job, artifact, entry)
            artifacts.append(
                ArtifactStatus(
                    artifact_id=artifact.artifact_id,
                    name=artifact.name,
                    sha256=artifact.sha256,
                    size_bytes=artifact.size_bytes,
                    signature=self._verify_signature(job, artifact, record, entry),
                    policy=policy_view,
                )
            )
        return JobAttestationStatus(
            job_id=job.job_id,
            job_status=job.status,
            checked_at=now,
            signing=signing,
            sentinel=sentinel,
            artifacts=artifacts,
            limitations=list(LIMITATIONS),
        )

    # ------------------------------------------------------------- documents

    def manifest_bytes(self, job: ProtectionJob, artifact: Artifact) -> bytes:
        record = self.load_record(job.job_id)
        entry = self._entry(record, artifact)
        raw = None
        if record is not None and record.signing_state == "signed" and entry and entry.manifest_file:
            raw = self._read_document(job.job_id, entry.manifest_file)
        if raw is None:
            raise AegisError(
                ErrorCode.ARTIFACT_NOT_FOUND,
                "No signed manifest exists for this output.",
                {"kind": "manifest"},
            )
        return raw

    def policy_bytes(self, job: ProtectionJob, artifact: Artifact) -> bytes:
        entry = self._entry(self.load_record(job.job_id), artifact)
        raw = None
        if entry is not None and entry.policy_file:
            raw = self._read_document(job.job_id, entry.policy_file)
        if raw is None:
            raise AegisError(
                ErrorCode.ARTIFACT_NOT_FOUND,
                "No Sentinel policy exists for this output.",
                {"kind": "policy"},
            )
        return raw

    # ------------------------------------------------------------ evaluation

    def evaluate(
        self,
        job: ProtectionJob,
        artifact: Artifact,
        action: PermissionAction,
        *,
        caller_id: str | None = None,
        environment: str | None = None,
    ) -> SentinelDecision:
        """Sentinel decision for an action on one output. Fails closed."""
        record = self.load_record(job.job_id)
        entry = self._entry(record, artifact)
        if record is None or entry is None or entry.policy_file is None:
            raise AegisError(
                ErrorCode.ARTIFACT_NOT_FOUND,
                "No Sentinel policy exists for this output.",
                {"kind": "policy"},
            )
        now = self.clock()
        mode = record.enforcement_mode or EnforcementMode.COOPERATING_ENFORCED
        policy, view = self._load_policy(job, artifact, entry)
        if policy is None:
            return SentinelDecision(
                job_id=job.job_id,
                artifact_sha256=artifact.sha256,
                action=action,
                permitted=False,
                enforcement_mode=mode,
                reason="Denied: the Sentinel policy is invalid ("
                + "; ".join(view.errors)
                + ").",
                policy_id=entry.policy_id,
                evaluated_at=now,
            )
        result = evaluate_action(
            policy=policy,
            action=action,
            artifact_path=self.store.artifact_path(artifact),
            caller_id=caller_id,
            environment=environment,
            watermark_present=False,
            at_time=now,
        )
        return SentinelDecision(
            job_id=job.job_id,
            artifact_sha256=artifact.sha256,
            action=action,
            permitted=result.permitted,
            enforcement_mode=result.enforcement_mode,
            reason=result.reason,
            policy_id=policy.policy_id,
            evaluated_at=now,
        )

    def authorize_release(self, job: ProtectionJob, artifact: Artifact, *, caller_id: str) -> str:
        """Gate AEGIS's own download of an output (Sentinel action ``redistribute``).

        Returns the decision header value (``permitted``, ``advisory`` or
        ``not_configured``) or raises POLICY_DENIED. Fails closed whenever a
        policy should exist but is missing, invalid or modified.
        """
        record = self.load_record(job.job_id)
        entry = self._entry(record, artifact)
        has_policy = entry is not None and entry.policy_file is not None
        expected = self.settings.sentinel is not None or (
            record is not None and record.sentinel_state != "not_configured"
        )
        if not has_policy:
            if expected:
                raise AegisError(
                    ErrorCode.POLICY_DENIED,
                    "Sentinel is configured but no valid policy governs this output.",
                    {"reason": "policy_missing", "action": "redistribute"},
                )
            return "not_configured"
        decision = self.evaluate(
            job, artifact, PermissionAction.REDISTRIBUTE, caller_id=caller_id
        )
        if decision.enforcement_mode is EnforcementMode.ADVISORY_NOTICE:
            # Advisory policies are notices; AEGIS reports, but does not enforce, them.
            return "advisory"
        if not decision.permitted:
            raise AegisError(
                ErrorCode.POLICY_DENIED,
                decision.reason,
                {"reason": "policy_denied", "action": "redistribute", "policy_id": decision.policy_id},
            )
        return "permitted"
