"""Signed job outputs and Sentinel policies on real Core jobs.

Jobs run through Core with the protocol test double (aegis_core.testing), which
applies no protection: these tests exercise signing/verification and policy
handling only, never protection.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegis_core.config import load_config
from aegis_core.errors import AegisError
from aegis_core.models import ErrorCode, JobStatus, ProtectionPolicy, utcnow
from aegis_core.orchestrator import Orchestrator
from aegis_core.testing import write_test_config
from aegis_provenance.canonical import canonical_json
from aegis_provenance.crypto import export_private_key_pem, generate_keypair
from aegis_provenance.jobs import RECORD_NAME, JobAttestor
from aegis_provenance.manifest import verify_artifact_manifest
from aegis_provenance.testing import attestation_toml, make_test_keys
from aegis_sentinel.models import PermissionAction


@pytest.fixture
def keys(tmp_path: Path):
    return make_test_keys(tmp_path / "keys")


class Clock:
    def __init__(self):
        self.now = utcnow()

    def __call__(self):
        return self.now


@pytest.fixture
def make(tmp_path: Path):
    def factory(extra: str = "", clock=None):
        config = load_config(write_test_config(tmp_path, extra_toml=extra))
        kwargs = {"clock": clock} if clock else {}
        orchestrator = Orchestrator(config, **kwargs)
        attestor = JobAttestor.from_config(config, orchestrator.store, clock=orchestrator.clock)
        orchestrator.post_success_hooks.append(attestor.attest)
        return orchestrator, attestor

    return factory


@pytest.fixture
def input_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF fake binary for signing tests")
    return path


def run(orchestrator: Orchestrator, source: Path, mode: str = "ok"):
    job = orchestrator.submit(ProtectionPolicy(backend="fake", options={"mode": mode}), source=source)
    return orchestrator.run(job.job_id)


def signed(keys, **kw) -> str:
    return attestation_toml(signing_key=keys.signer_private, trusted=[keys.signer_public], **kw)


def manifest_path(orchestrator, job) -> Path:
    return orchestrator.store.attestation_dir(job.job_id) / f"{job.output_artifacts[0].artifact_id}.manifest.json"


def policy_path(orchestrator, job) -> Path:
    return orchestrator.store.attestation_dir(job.job_id) / f"{job.output_artifacts[0].artifact_id}.policy.json"


# --------------------------------------------------------------- signed path


def test_signed_output_verifies_against_trusted_key(make, keys, input_file):
    orchestrator, attestor = make(signed(keys, allowed_actions=["analyze", "redistribute"]))
    job = run(orchestrator, input_file)
    assert job.status is JobStatus.SUCCEEDED

    status = attestor.status(job)
    assert status.signing.state == "signed"
    assert status.signing.key_id == keys.signer.key_id
    [item] = status.artifacts
    assert item.sha256 == job.output_artifacts[0].sha256
    assert item.signature.status == "verified"
    assert item.signature.error_code is None
    assert item.signature.key_id == keys.signer.key_id
    assert item.policy.status == "valid"
    assert status.all_verified

    # Files are private and the manifest verifies offline with the public key alone.
    directory = orchestrator.store.attestation_dir(job.job_id)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for child in directory.iterdir():
        assert stat.S_IMODE(child.stat().st_mode) == 0o600
    raw = manifest_path(orchestrator, job).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == item.signature.manifest_sha256
    offline = verify_artifact_manifest(
        orchestrator.store.artifact_path(job.output_artifacts[0]), raw, [keys.signer_public.read_text()]
    )
    assert offline.valid

    # The signed configuration digest binds backend, options and the input digest.
    record = json.loads((directory / RECORD_NAME).read_text())
    payload = json.loads(raw)["payload"]
    assert payload["build_reference"]["build_job_id"] == job.job_id
    assert payload["configuration"]["options_digest"] == record["configuration_digest"]
    assert record["configuration_preimage"]["input_sha256"] == job.input_artifact.sha256
    assert (
        hashlib.sha256(canonical_json(record["configuration_preimage"])).hexdigest()
        == record["configuration_digest"]
    )
    # The Sentinel policy links to the exact signed manifest.
    policy = json.loads(policy_path(orchestrator, job).read_text())
    assert policy["target_artifact"]["manifest_reference"] == item.signature.manifest_sha256


def test_unconfigured_signer_is_never_reported_verified(make, input_file):
    orchestrator, attestor = make()
    job = run(orchestrator, input_file)
    status = attestor.status(job)
    assert status.signing.state == "not_configured"
    assert status.sentinel.state == "not_configured"
    [item] = status.artifacts
    assert item.signature.status == "unsigned"
    assert item.signature.error_code is None
    assert item.signature.manifest_sha256 is None
    assert item.policy.status == "absent"
    assert not status.all_verified
    assert not orchestrator.store.attestation_dir(job.job_id).exists()
    view = attestor.config_view()
    assert view.signing.state == "not_configured" and view.signing.key_id is None


# ------------------------------------------------------------ failure paths


def test_modified_artifact_fails_verification(make, keys, input_file):
    orchestrator, attestor = make(signed(keys))
    job = run(orchestrator, input_file)
    path = orchestrator.store.artifact_path(job.output_artifacts[0])
    path.write_bytes(path.read_bytes() + b"tampered")
    item = attestor.status(job).artifacts[0]
    assert item.signature.status == "failed"
    assert item.signature.error_code == "ARTIFACT_TAMPERED"
    with pytest.raises(AegisError) as err:
        orchestrator.read_output(job.job_id, job.output_artifacts[0].sha256)
    assert err.value.code is ErrorCode.ARTIFACT_INTEGRITY_ERROR


def test_modified_manifest_field_fails_signature(make, keys, input_file):
    orchestrator, attestor = make(signed(keys))
    job = run(orchestrator, input_file)
    path = manifest_path(orchestrator, job)
    envelope = json.loads(path.read_text())
    envelope["payload"]["build_reference"]["commit"] = "f" * 40
    path.write_text(json.dumps(envelope))
    item = attestor.status(job).artifacts[0]
    assert item.signature.status == "failed"
    assert item.signature.error_code == "SIGNATURE_INVALID"


def test_signature_by_untrusted_key_fails(make, keys, input_file):
    orchestrator, attestor = make(
        attestation_toml(signing_key=keys.signer_private, trusted=[keys.other_public])
    )
    assert attestor.config_view().signing.signer_trusted is False
    job = run(orchestrator, input_file)
    status = attestor.status(job)
    assert status.signing.state == "signed"  # signing happened ...
    assert status.artifacts[0].signature.status == "failed"  # ... but it is not trusted
    assert status.artifacts[0].signature.error_code == "UNTRUSTED_KEY"
    assert not status.all_verified


def test_no_trusted_keys_never_verifies(make, keys, input_file):
    orchestrator, attestor = make(attestation_toml(signing_key=keys.signer_private, trusted=[]))
    job = run(orchestrator, input_file)
    item = attestor.status(job).artifacts[0]
    assert item.signature.status == "failed"
    assert item.signature.error_code == "ABSENT_TRUSTED_KEYS"


def test_deleted_manifest_is_reported(make, keys, input_file):
    orchestrator, attestor = make(signed(keys))
    job = run(orchestrator, input_file)
    manifest_path(orchestrator, job).unlink()
    item = attestor.status(job).artifacts[0]
    assert item.signature.status == "failed"
    assert item.signature.error_code == "MANIFEST_MISSING"
    with pytest.raises(AegisError) as err:
        attestor.manifest_bytes(job, job.output_artifacts[0])
    assert err.value.code is ErrorCode.ARTIFACT_NOT_FOUND


def test_valid_manifest_from_another_job_is_a_record_mismatch(make, keys, input_file):
    orchestrator, attestor = make(signed(keys))
    first, second = run(orchestrator, input_file), run(orchestrator, input_file)
    assert first.output_artifacts[0].sha256 == second.output_artifacts[0].sha256
    manifest_path(orchestrator, first).write_bytes(manifest_path(orchestrator, second).read_bytes())
    item = attestor.status(first).artifacts[0]
    assert item.signature.status == "failed"
    assert item.signature.error_code == "RECORD_MISMATCH"


def test_failed_and_pending_jobs_have_no_attestation(make, keys, input_file):
    orchestrator, attestor = make(signed(keys, allowed_actions=["analyze"]))
    failed = run(orchestrator, input_file, mode="fail")
    status = attestor.status(failed)
    assert status.signing.state == "not_applicable" and status.sentinel.state == "not_applicable"
    assert status.artifacts == []
    assert not orchestrator.store.attestation_dir(failed.job_id).exists()
    pending = orchestrator.submit(ProtectionPolicy(backend="fake"), source=input_file)
    status = attestor.status(pending)
    assert status.signing.state == "pending" and status.artifacts == []


def test_output_changed_before_signing_is_not_signed(make, keys, input_file):
    orchestrator, attestor = make(signed(keys))

    def mutate(job):
        path = orchestrator.store.artifact_path(job.output_artifacts[0])
        path.write_bytes(b"changed after hashing")

    orchestrator.post_success_hooks.insert(0, mutate)
    job = run(orchestrator, input_file)
    assert job.status is JobStatus.SUCCEEDED
    status = attestor.status(job)
    assert status.signing.state == "signing_failed"
    assert "not signed" in status.signing.message
    assert status.artifacts[0].signature.status == "unsigned"


def test_unexpected_signing_error_is_recorded_not_hidden(make, keys, input_file, monkeypatch):
    orchestrator, attestor = make(signed(keys))

    def boom(**_):
        raise RuntimeError("hsm offline")

    monkeypatch.setattr("aegis_provenance.jobs.sign_artifact", boom)
    job = run(orchestrator, input_file)
    assert job.status is JobStatus.SUCCEEDED
    status = attestor.status(job)
    assert status.signing.state == "signing_failed"
    assert status.artifacts[0].signature.status == "unsigned"
    assert not status.all_verified


# ------------------------------------------------------ configuration refusal


def _config_error(make, extra: str) -> AegisError:
    with pytest.raises(AegisError) as err:
        make(extra)
    assert err.value.code is ErrorCode.CONFIG_INVALID
    return err.value


def test_key_inside_git_work_tree_is_refused(make, keys, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    inside = repo / "secrets" / "key.pem"
    inside.parent.mkdir()
    inside.write_bytes(keys.signer_private.read_bytes())
    inside.chmod(0o600)
    err = _config_error(make, attestation_toml(signing_key=inside, trusted=[keys.signer_public]))
    assert "Git" in err.message
    # A linked worktree / submodule marks itself with a `.git` file.
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / ".git").write_text("gitdir: /elsewhere/.git/worktrees/x\n")
    key = linked / "key.pem"
    key.write_bytes(keys.signer_private.read_bytes())
    key.chmod(0o600)
    _config_error(make, attestation_toml(signing_key=key, trusted=[keys.signer_public]))


def test_group_readable_key_is_refused(make, keys):
    keys.signer_private.chmod(0o640)
    err = _config_error(make, signed(keys))
    assert "0600" in err.message


@pytest.mark.parametrize("linked_worktree", [False, True])
def test_key_inside_git_through_symlinked_parent_is_refused(make, keys, tmp_path, linked_worktree):
    repo = tmp_path / "repo"
    repo.mkdir()
    if linked_worktree:
        (repo / ".git").write_text("gitdir: /elsewhere/.git/worktrees/test\n")
    else:
        (repo / ".git").mkdir()
        (repo / ".git/HEAD").write_text("ref: refs/heads/main\n")
    private_dir = repo / "keys"
    private_dir.mkdir()
    private_key = private_dir / "key.pem"
    private_key.write_bytes(keys.signer_private.read_bytes())
    private_key.chmod(0o600)
    alias = tmp_path / "outside-alias"
    alias.symlink_to(private_dir, target_is_directory=True)
    err = _config_error(make, attestation_toml(signing_key=alias / "key.pem", trusted=[keys.signer_public]))
    assert "Git" in err.message


def test_safe_parent_alias_outside_git_preserves_signing(make, keys, tmp_path, input_file):
    alias = tmp_path / "safe-key-alias"
    alias.symlink_to(keys.signer_private.parent, target_is_directory=True)
    orchestrator, attestor = make(attestation_toml(
        signing_key=alias / keys.signer_private.name, trusted=[keys.signer_public]))
    job = run(orchestrator, input_file)
    assert attestor.status(job).all_verified


def test_missing_symlinked_and_store_keys_are_refused(make, keys, tmp_path):
    _config_error(make, attestation_toml(signing_key=tmp_path / "nope.pem", trusted=[keys.signer_public]))
    link = tmp_path / "keys" / "link.pem"
    link.symlink_to(keys.signer_private)
    _config_error(make, attestation_toml(signing_key=link, trusted=[keys.signer_public]))
    store_key = tmp_path / ".aegis" / "key.pem"
    store_key.parent.mkdir()
    store_key.write_bytes(keys.signer_private.read_bytes())
    store_key.chmod(0o600)
    _config_error(make, attestation_toml(signing_key=store_key, trusted=[keys.signer_public]))


def test_encrypted_key_needs_the_right_password(make, keys, tmp_path, monkeypatch, input_file):
    pair = generate_keypair()
    path = tmp_path / "keys" / "encrypted.pem"
    path.write_text(export_private_key_pem(pair.private_key, password="correct horse"))
    path.chmod(0o600)
    pub = tmp_path / "keys" / "encrypted.pub.pem"
    pub.write_bytes(
        pair.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    no_env = attestation_toml(signing_key=path, trusted=[pub])
    _config_error(make, no_env)
    with_env = attestation_toml(signing_key=path, trusted=[pub], password_env="AEGIS_TEST_KEY_PW")
    monkeypatch.delenv("AEGIS_TEST_KEY_PW", raising=False)
    _config_error(make, with_env)
    monkeypatch.setenv("AEGIS_TEST_KEY_PW", "wrong")
    err = _config_error(make, with_env)
    assert "wrong" not in json.dumps(err.details)  # never echo the password
    monkeypatch.setenv("AEGIS_TEST_KEY_PW", "correct horse")
    orchestrator, attestor = make(with_env)
    job = run(orchestrator, input_file)
    assert attestor.status(job).artifacts[0].signature.status == "verified"


def test_non_ed25519_keys_are_refused(make, keys, tmp_path):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "keys" / "ec.pem"
    path.write_bytes(
        ec_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    path.chmod(0o600)
    _config_error(make, attestation_toml(signing_key=path, trusted=[keys.signer_public]))
    bad_pub = tmp_path / "keys" / "garbage.pub.pem"
    bad_pub.write_text("not a key")
    _config_error(make, attestation_toml(signing_key=keys.signer_private, trusted=[bad_pub]))


def test_keygen_writes_private_key_0600_without_a_window(tmp_path):
    keys = make_test_keys(tmp_path / "fresh")
    assert stat.S_IMODE(keys.signer_private.stat().st_mode) == 0o600
    # Replacing an existing key keeps 0600 even with a permissive umask.
    old = os.umask(0)
    try:
        make_test_keys(tmp_path / "fresh")
    finally:
        os.umask(old)
    assert stat.S_IMODE(keys.signer_private.stat().st_mode) == 0o600


# --------------------------------------------------------------- Sentinel


def test_policy_allows_only_listed_actions(make, keys, input_file):
    orchestrator, attestor = make(signed(keys, allowed_actions=["analyze", "redistribute"]))
    job = run(orchestrator, input_file)
    artifact = job.output_artifacts[0]
    view = attestor.status(job).artifacts[0].policy
    assert {p.action.value: p.allowed for p in view.permissions} == {
        "execute": False,
        "analyze": True,
        "redistribute": True,
        "modify": False,
        "attack_evaluate": False,
    }
    assert view.enforcement_mode.value == "cooperating_enforced"
    assert "not bound" in view.disclaimer
    assert attestor.evaluate(job, artifact, PermissionAction.ANALYZE).permitted
    denied = attestor.evaluate(job, artifact, PermissionAction.EXECUTE)
    assert not denied.permitted and "explicitly denied" in denied.reason
    assert not attestor.evaluate(job, artifact, PermissionAction.ATTACK_EVALUATE).permitted
    assert attestor.authorize_release(job, artifact, caller_id="aegis-api") == "permitted"


def test_release_denied_when_redistribute_not_allowed(make, keys, input_file):
    orchestrator, attestor = make(signed(keys, allowed_actions=["analyze"]))
    job = run(orchestrator, input_file)
    with pytest.raises(AegisError) as err:
        attestor.authorize_release(job, job.output_artifacts[0], caller_id="aegis-api")
    assert err.value.code is ErrorCode.POLICY_DENIED
    assert err.value.details["reason"] == "policy_denied"


def test_advisory_policy_is_reported_not_enforced(make, input_file):
    orchestrator, attestor = make(
        attestation_toml(allowed_actions=["analyze"], enforcement_mode="advisory_notice")
    )
    job = run(orchestrator, input_file)
    artifact = job.output_artifacts[0]
    assert attestor.status(job).artifacts[0].signature.status == "unsigned"
    decision = attestor.evaluate(job, artifact, PermissionAction.REDISTRIBUTE)
    assert not decision.permitted and decision.enforcement_mode.value == "advisory_notice"
    assert attestor.authorize_release(job, artifact, caller_id="aegis-api") == "advisory"


def test_modified_or_deleted_policy_denies_everything(make, keys, input_file):
    orchestrator, attestor = make(signed(keys, allowed_actions=["analyze", "redistribute"]))
    job = run(orchestrator, input_file)
    artifact = job.output_artifacts[0]
    path = policy_path(orchestrator, job)
    policy = json.loads(path.read_text())
    for perm in policy["permissions"]:
        perm["allowed"] = True  # a holder tries to grant themselves execute
    path.write_text(json.dumps(policy))
    view = attestor.status(job).artifacts[0].policy
    assert view.status == "invalid" and any("modified" in e for e in view.errors)
    assert not attestor.evaluate(job, artifact, PermissionAction.EXECUTE).permitted
    assert not attestor.evaluate(job, artifact, PermissionAction.ANALYZE).permitted
    with pytest.raises(AegisError) as err:
        attestor.authorize_release(job, artifact, caller_id="aegis-api")
    assert err.value.code is ErrorCode.POLICY_DENIED
    assert not attestor.status(job).all_verified
    path.unlink()
    assert attestor.status(job).artifacts[0].policy.status == "invalid"
    assert not attestor.evaluate(job, artifact, PermissionAction.ANALYZE).permitted


def test_sentinel_enabled_after_job_fails_closed(make, keys, input_file, tmp_path):
    orchestrator, _ = make()
    job = run(orchestrator, input_file)
    _, attestor = make(attestation_toml(allowed_actions=["redistribute"]))
    with pytest.raises(AegisError) as err:
        attestor.authorize_release(job, job.output_artifacts[0], caller_id="aegis-api")
    assert err.value.code is ErrorCode.POLICY_DENIED
    assert err.value.details["reason"] == "policy_missing"
    with pytest.raises(AegisError) as err:
        attestor.evaluate(job, job.output_artifacts[0], PermissionAction.ANALYZE)
    assert err.value.code is ErrorCode.ARTIFACT_NOT_FOUND


def test_caller_restriction_and_expiry(make, input_file):
    clock = Clock()
    orchestrator, attestor = make(
        attestation_toml(
            allowed_actions=["analyze", "redistribute"], valid_days=1, allowed_caller_ids=["aegis-cli"]
        ),
        clock=clock,
    )
    job = run(orchestrator, input_file)
    artifact = job.output_artifacts[0]
    assert not attestor.evaluate(job, artifact, PermissionAction.ANALYZE).permitted  # no caller
    assert not attestor.evaluate(job, artifact, PermissionAction.ANALYZE, caller_id="other").permitted
    assert attestor.evaluate(job, artifact, PermissionAction.ANALYZE, caller_id="aegis-cli").permitted
    with pytest.raises(AegisError):
        attestor.authorize_release(job, artifact, caller_id="aegis-api")
    clock.now += timedelta(days=2)
    expired = attestor.evaluate(job, artifact, PermissionAction.ANALYZE, caller_id="aegis-cli")
    assert not expired.permitted and "expired" in expired.reason
