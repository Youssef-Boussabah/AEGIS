import json
from pathlib import Path

import pytest
from aegis_provenance.crypto import (
    compute_key_id,
    export_public_key_pem,
    generate_keypair,
)
from aegis_provenance.manifest import (
    create_manifest,
    sign_artifact,
    verify_artifact_manifest,
)
from aegis_provenance.models import (
    BuildReference,
    ConfigurationIdentity,
    SignerIdentity,
    ToolchainInfo,
    VerificationErrorCode,
)


@pytest.fixture
def sample_artifact(tmp_path: Path) -> Path:
    f = tmp_path / "protected_binary.bin"
    f.write_bytes(b"\x7fELF\x02\x01\x01\x00data-protected-binary-content")
    return f


@pytest.fixture
def sample_signer() -> SignerIdentity:
    return SignerIdentity(name="Build Engineering", organization="AEGIS Security", contact="security@aegis.local")


@pytest.fixture
def sample_build_ref() -> BuildReference:
    return BuildReference(
        repository="https://github.com/Youssef-Boussabah/AEGIS",
        commit="a5efcd6a7b7b1e7695995377c6b1332a14618721",
        branch="feat/signature-sentinel",
        build_job_id="job_4001e5aceb144882a21a2f6653e52fb3",
    )


@pytest.fixture
def sample_toolchain() -> ToolchainInfo:
    return ToolchainInfo(
        compiler="clang++",
        compiler_version="22.1.8",
        platform="linux-x86_64",
        target_triple="x86_64-unknown-linux-gnu",
    )


@pytest.fixture
def sample_config() -> ConfigurationIdentity:
    return ConfigurationIdentity(
        profile="release-shield",
        backend="llvm-shield",
        options_digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )


def test_sign_and_verify_success(
    sample_artifact, sample_signer, sample_build_ref, sample_toolchain, sample_config
):
    kp = generate_keypair()
    envelope = sign_artifact(
        artifact_path=sample_artifact,
        private_key=kp.private_key,
        signer=sample_signer,
        build_reference=sample_build_ref,
        toolchain=sample_toolchain,
        configuration=sample_config,
    )

    trusted_keys = [export_public_key_pem(kp.public_key)]
    result = verify_artifact_manifest(
        artifact_path=sample_artifact,
        envelope_input=envelope,
        trusted_keys=trusted_keys,
    )

    assert result.valid is True
    assert result.error_code is None
    assert result.artifact_sha256 == envelope.payload.artifact_sha256
    assert result.key_id == kp.key_id
    assert result.signer_name == sample_signer.name


def test_negative_artifact_tampered(
    sample_artifact, sample_signer, sample_build_ref, sample_toolchain, sample_config
):
    kp = generate_keypair()
    envelope = sign_artifact(
        artifact_path=sample_artifact,
        private_key=kp.private_key,
        signer=sample_signer,
        build_reference=sample_build_ref,
        toolchain=sample_toolchain,
        configuration=sample_config,
    )

    # Tamper with the artifact file
    sample_artifact.write_bytes(b"tampered content")

    trusted_keys = [export_public_key_pem(kp.public_key)]
    result = verify_artifact_manifest(
        artifact_path=sample_artifact,
        envelope_input=envelope,
        trusted_keys=trusted_keys,
    )

    assert result.valid is False
    assert result.error_code == VerificationErrorCode.ARTIFACT_TAMPERED
    assert "digest mismatch" in result.message


def test_negative_manifest_field_tampered(
    sample_artifact, sample_signer, sample_build_ref, sample_toolchain, sample_config
):
    kp = generate_keypair()
    envelope = sign_artifact(
        artifact_path=sample_artifact,
        private_key=kp.private_key,
        signer=sample_signer,
        build_reference=sample_build_ref,
        toolchain=sample_toolchain,
        configuration=sample_config,
    )

    envelope_dict = envelope.model_dump(mode="json")
    # Tamper with a covered field inside the payload
    envelope_dict["payload"]["build_reference"]["commit"] = "0000000000000000000000000000000000000000"

    trusted_keys = [export_public_key_pem(kp.public_key)]
    result = verify_artifact_manifest(
        artifact_path=sample_artifact,
        envelope_input=envelope_dict,
        trusted_keys=trusted_keys,
    )

    assert result.valid is False
    assert result.error_code == VerificationErrorCode.SIGNATURE_INVALID


def test_negative_untrusted_key(
    sample_artifact, sample_signer, sample_build_ref, sample_toolchain, sample_config
):
    signer_kp = generate_keypair()
    trusted_kp = generate_keypair()  # A different keypair

    envelope = sign_artifact(
        artifact_path=sample_artifact,
        private_key=signer_kp.private_key,
        signer=sample_signer,
        build_reference=sample_build_ref,
        toolchain=sample_toolchain,
        configuration=sample_config,
    )

    # Trust only trusted_kp, not signer_kp
    trusted_keys = [export_public_key_pem(trusted_kp.public_key)]
    result = verify_artifact_manifest(
        artifact_path=sample_artifact,
        envelope_input=envelope,
        trusted_keys=trusted_keys,
    )

    assert result.valid is False
    assert result.error_code == VerificationErrorCode.UNTRUSTED_KEY
    assert "not in the set of trusted public keys" in result.message


def test_negative_key_id_mismatch(
    sample_artifact, sample_signer, sample_build_ref, sample_toolchain, sample_config
):
    kp = generate_keypair()
    envelope = sign_artifact(
        artifact_path=sample_artifact,
        private_key=kp.private_key,
        signer=sample_signer,
        build_reference=sample_build_ref,
        toolchain=sample_toolchain,
        configuration=sample_config,
    )

    envelope_dict = envelope.model_dump(mode="json")
    # Forged key_id in envelope that doesn't match the embedded public key
    envelope_dict["key_id"] = "f" * 64

    trusted_keys = [export_public_key_pem(kp.public_key)]
    result = verify_artifact_manifest(
        artifact_path=sample_artifact,
        envelope_input=envelope_dict,
        trusted_keys=trusted_keys,
    )

    assert result.valid is False
    assert result.error_code == VerificationErrorCode.KEY_ID_MISMATCH


def test_negative_malformed_envelope_json(sample_artifact, sample_signer):
    kp = generate_keypair()
    trusted_keys = [export_public_key_pem(kp.public_key)]

    result = verify_artifact_manifest(
        artifact_path=sample_artifact,
        envelope_input=b"{malformed json...",
        trusted_keys=trusted_keys,
    )
    assert result.valid is False
    assert result.error_code == VerificationErrorCode.MANIFEST_MALFORMED


def test_negative_unsupported_version(
    sample_artifact, sample_signer, sample_build_ref, sample_toolchain, sample_config
):
    kp = generate_keypair()
    envelope = sign_artifact(
        artifact_path=sample_artifact,
        private_key=kp.private_key,
        signer=sample_signer,
        build_reference=sample_build_ref,
        toolchain=sample_toolchain,
        configuration=sample_config,
    )

    envelope_dict = envelope.model_dump(mode="json")
    envelope_dict["envelope_version"] = "99"

    trusted_keys = [export_public_key_pem(kp.public_key)]
    result = verify_artifact_manifest(
        artifact_path=sample_artifact,
        envelope_input=json.dumps(envelope_dict),
        trusted_keys=trusted_keys,
    )
    assert result.valid is False
    assert result.error_code == VerificationErrorCode.UNSUPPORTED_VERSION


def test_negative_absent_trusted_keys(
    sample_artifact, sample_signer, sample_build_ref, sample_toolchain, sample_config
):
    kp = generate_keypair()
    envelope = sign_artifact(
        artifact_path=sample_artifact,
        private_key=kp.private_key,
        signer=sample_signer,
        build_reference=sample_build_ref,
        toolchain=sample_toolchain,
        configuration=sample_config,
    )

    result = verify_artifact_manifest(
        artifact_path=sample_artifact,
        envelope_input=envelope,
        trusted_keys=[],
    )
    assert result.valid is False
    assert result.error_code == VerificationErrorCode.ABSENT_TRUSTED_KEYS


def test_negative_artifact_not_found(
    tmp_path, sample_signer, sample_build_ref, sample_toolchain, sample_config
):
    real_artifact = tmp_path / "orig.bin"
    real_artifact.write_bytes(b"content")
    kp = generate_keypair()
    envelope = sign_artifact(
        artifact_path=real_artifact,
        private_key=kp.private_key,
        signer=sample_signer,
        build_reference=sample_build_ref,
        toolchain=sample_toolchain,
        configuration=sample_config,
    )

    missing_artifact = tmp_path / "nonexistent.bin"
    trusted_keys = [export_public_key_pem(kp.public_key)]

    result = verify_artifact_manifest(
        artifact_path=missing_artifact,
        envelope_input=envelope,
        trusted_keys=trusted_keys,
    )
    assert result.valid is False
    assert result.error_code == VerificationErrorCode.ARTIFACT_NOT_FOUND
