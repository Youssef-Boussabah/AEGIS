"""Creation, signing, and offline verification of artifact provenance manifests."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from aegis_provenance.canonical import canonical_json
from aegis_provenance.crypto import (
    compute_key_id,
    export_public_key_pem,
    load_public_key,
    sign_bytes,
    verify_signature,
)
from aegis_provenance.models import (
    BuildReference,
    ConfigurationIdentity,
    ManifestEnvelope,
    ProvenanceManifest,
    SignerIdentity,
    ToolchainInfo,
    VerificationErrorCode,
    VerificationResult,
    utcnow,
)
from cryptography.hazmat.primitives.asymmetric import ed25519


def compute_file_sha256(path: Path) -> tuple[str, int]:
    """Compute SHA-256 and byte length of a file streaming in chunks."""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def create_manifest(
    artifact_path: Path,
    key_id: str,
    signer: SignerIdentity,
    build_reference: BuildReference,
    toolchain: ToolchainInfo,
    configuration: ConfigurationIdentity,
    manifest_id: str | None = None,
) -> ProvenanceManifest:
    """Build a ProvenanceManifest for an artifact whose final bytes are fixed."""
    if not artifact_path.is_file():
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")

    sha256_hex, size_bytes = compute_file_sha256(artifact_path)
    mid = manifest_id or uuid.uuid4().hex

    return ProvenanceManifest(
        schema_version="1",
        manifest_id=mid,
        created_at=utcnow(),
        artifact_name=artifact_path.name,
        artifact_sha256=sha256_hex,
        artifact_size_bytes=size_bytes,
        build_reference=build_reference,
        toolchain=toolchain,
        configuration=configuration,
        signer=signer,
        key_id=key_id,
    )


def sign_artifact(
    artifact_path: Path,
    private_key: ed25519.Ed25519PrivateKey,
    signer: SignerIdentity,
    build_reference: BuildReference,
    toolchain: ToolchainInfo,
    configuration: ConfigurationIdentity,
    manifest_id: str | None = None,
) -> ManifestEnvelope:
    """Create a signed manifest envelope for an artifact."""
    pub = private_key.public_key()
    kid = compute_key_id(pub)
    manifest = create_manifest(
        artifact_path=artifact_path,
        key_id=kid,
        signer=signer,
        build_reference=build_reference,
        toolchain=toolchain,
        configuration=configuration,
        manifest_id=manifest_id,
    )
    canon_bytes = canonical_json(manifest)
    sig_b64 = sign_bytes(private_key, canon_bytes)
    pub_pem = export_public_key_pem(pub)

    return ManifestEnvelope(
        envelope_version="1",
        algorithm="Ed25519",
        key_id=kid,
        public_key=pub_pem,
        signature=sig_b64,
        payload=manifest,
    )


def verify_artifact_manifest(
    artifact_path: Path,
    envelope_input: str | bytes | dict | ManifestEnvelope,
    trusted_keys: Sequence[ed25519.Ed25519PublicKey | str],
) -> VerificationResult:
    """Verify an artifact against a signed manifest envelope and trusted public keys.

    Acceptance rules:
    - Altering an artifact fails with ARTIFACT_TAMPERED
    - Altering any covered manifest field fails with SIGNATURE_INVALID
    - Wrong or untrusted key fails with UNTRUSTED_KEY or SIGNATURE_INVALID
    - Malformed envelope fails with MANIFEST_MALFORMED
    - Unsupported schema versions fail with UNSUPPORTED_VERSION
    - Empty trusted keys list fails with ABSENT_TRUSTED_KEYS
    """
    if not trusted_keys:
        return VerificationResult(
            valid=False,
            error_code=VerificationErrorCode.ABSENT_TRUSTED_KEYS,
            message="No trusted public keys provided for verification.",
        )

    # 1. Parse and validate envelope structure
    if isinstance(envelope_input, ManifestEnvelope):
        envelope = envelope_input
    elif isinstance(envelope_input, dict):
        try:
            envelope = ManifestEnvelope.model_validate(envelope_input)
        except ValidationError as err:
            return VerificationResult(
                valid=False,
                error_code=VerificationErrorCode.MANIFEST_MALFORMED,
                message=f"Manifest envelope validation error: {err}",
            )
    elif isinstance(envelope_input, (str, bytes)):
        try:
            raw_dict = json.loads(envelope_input)
            if not isinstance(raw_dict, dict):
                return VerificationResult(
                    valid=False,
                    error_code=VerificationErrorCode.MANIFEST_MALFORMED,
                    message="Manifest JSON root must be an object.",
                )
            # Check version before Pydantic parsing for explicit version errors
            if raw_dict.get("envelope_version") != "1" or (
                isinstance(raw_dict.get("payload"), dict)
                and raw_dict["payload"].get("schema_version") != "1"
            ):
                return VerificationResult(
                    valid=False,
                    error_code=VerificationErrorCode.UNSUPPORTED_VERSION,
                    message="Unsupported envelope or manifest schema version.",
                )
            envelope = ManifestEnvelope.model_validate(raw_dict)
        except json.JSONDecodeError as err:
            return VerificationResult(
                valid=False,
                error_code=VerificationErrorCode.MANIFEST_MALFORMED,
                message=f"Malformed manifest JSON: {err}",
            )
        except ValidationError as err:
            return VerificationResult(
                valid=False,
                error_code=VerificationErrorCode.MANIFEST_MALFORMED,
                message=f"Manifest schema validation error: {err}",
            )
    else:
        return VerificationResult(
            valid=False,
            error_code=VerificationErrorCode.MANIFEST_MALFORMED,
            message="Unsupported envelope input type.",
        )

    # 2. Check public key in envelope matches key_id
    try:
        envelope_pub = load_public_key(envelope.public_key)
    except Exception as err:
        return VerificationResult(
            valid=False,
            error_code=VerificationErrorCode.MANIFEST_MALFORMED,
            message=f"Invalid public key encoding in envelope: {err}",
        )

    computed_kid = compute_key_id(envelope_pub)
    if computed_kid != envelope.key_id:
        return VerificationResult(
            valid=False,
            error_code=VerificationErrorCode.KEY_ID_MISMATCH,
            message=f"Key ID mismatch: envelope has {envelope.key_id}, computed {computed_kid}.",
            key_id=envelope.key_id,
        )

    # 3. Check public key against trusted keys
    trusted_pub_keys: list[ed25519.Ed25519PublicKey] = []
    for tk in trusted_keys:
        if isinstance(tk, ed25519.Ed25519PublicKey):
            trusted_pub_keys.append(tk)
        else:
            try:
                trusted_pub_keys.append(load_public_key(tk))
            except Exception:
                continue

    trusted_kids = {compute_key_id(k) for k in trusted_pub_keys}
    if computed_kid not in trusted_kids:
        return VerificationResult(
            valid=False,
            error_code=VerificationErrorCode.UNTRUSTED_KEY,
            message=f"Signing key {computed_kid} is not in the set of trusted public keys.",
            key_id=computed_kid,
            signer_name=envelope.payload.signer.name,
        )

    # 4. Verify cryptographic signature over canonical payload
    canon_bytes = canonical_json(envelope.payload)
    if not verify_signature(envelope_pub, envelope.signature, canon_bytes):
        return VerificationResult(
            valid=False,
            error_code=VerificationErrorCode.SIGNATURE_INVALID,
            message="Cryptographic signature verification failed over canonical payload.",
            key_id=computed_kid,
            signer_name=envelope.payload.signer.name,
        )

    # 5. Check artifact on disk
    if not artifact_path.is_file():
        return VerificationResult(
            valid=False,
            error_code=VerificationErrorCode.ARTIFACT_NOT_FOUND,
            message=f"Target artifact does not exist: {artifact_path}",
            key_id=computed_kid,
            signer_name=envelope.payload.signer.name,
        )

    actual_sha256, actual_size = compute_file_sha256(artifact_path)
    if actual_sha256 != envelope.payload.artifact_sha256:
        return VerificationResult(
            valid=False,
            error_code=VerificationErrorCode.ARTIFACT_TAMPERED,
            message=(
                f"Artifact digest mismatch: actual SHA-256 {actual_sha256} != "
                f"manifest {envelope.payload.artifact_sha256}."
            ),
            artifact_sha256=actual_sha256,
            manifest_sha256=envelope.payload.artifact_sha256,
            key_id=computed_kid,
            signer_name=envelope.payload.signer.name,
        )

    return VerificationResult(
        valid=True,
        error_code=None,
        message="Artifact and manifest successfully verified against trusted public key.",
        artifact_sha256=actual_sha256,
        manifest_sha256=envelope.payload.artifact_sha256,
        key_id=computed_kid,
        signer_name=envelope.payload.signer.name,
    )

