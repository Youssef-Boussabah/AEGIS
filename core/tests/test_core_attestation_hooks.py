"""Core's side of output signing: config sections, post-success hooks, verified reads.

Core never imports cryptography; these tests need none.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aegis_core.config import config_from_mapping
from aegis_core.errors import AegisError
from aegis_core.models import ErrorCode, JobStatus


def test_provenance_and_sentinel_are_off_by_default(tmp_path: Path):
    config = config_from_mapping({}, base_dir=tmp_path)
    assert config.provenance.enabled is False
    assert config.sentinel.enabled is False


@pytest.mark.parametrize(
    "data",
    [
        {"provenance": {"enabled": "yes"}},
        {"provenance": {"enabled": True}},  # neither key nor trusted keys
        {"provenance": {"enabled": True, "signing_key_path": "/k.pem", "trusted_public_keys": ["/p.pem"]}},
        {"provenance": {"enabled": True, "signing_key_path": "relative/k.pem", "signer_name": "x",
                        "build_repository": "r", "build_commit": "abcdef1"}},
        {"provenance": {"enabled": True, "trusted_public_keys": ["/a/../p.pem"]}},
        {"provenance": {"enabled": True, "trusted_public_keys": ["/p.pem"], "build_commit": "HEAD"}},
        {"provenance": {"enabled": True, "trusted_public_keys": ["/p.pem"], "signing_key_password_env": "BAD NAME"}},
        {"provenance": {"enabled": True, "trusted_public_keys": ["/p.pem"], "private_key": "inline"}},
        {"sentinel": {"enabled": True, "issuer": "x"}},  # allowed_actions must be explicit
        {"sentinel": {"enabled": True, "allowed_actions": ["analyze"]}},  # issuer required
        {"sentinel": {"enabled": True, "issuer": "x", "allowed_actions": ["analyze", "analyze"]}},
        {"sentinel": {"enabled": True, "issuer": "x", "allowed_actions": ["teleport"]}},
        {"sentinel": {"enabled": True, "issuer": "x", "allowed_actions": [], "enforcement_mode": "drm"}},
        {"sentinel": {"enabled": 1, "issuer": "x", "allowed_actions": []}},
    ],
)
def test_invalid_attestation_config_is_rejected(tmp_path: Path, data):
    with pytest.raises(AegisError) as err:
        config_from_mapping(data, base_dir=tmp_path)
    assert err.value.code is ErrorCode.CONFIG_INVALID


def test_valid_attestation_config(tmp_path: Path):
    config = config_from_mapping(
        {
            "provenance": {
                "enabled": True,
                "signing_key_path": "/keys/k.pem",
                "trusted_public_keys": ["/keys/k.pub.pem"],
                "signer_name": "op",
                "build_repository": "https://example.invalid/r",
                "build_commit": "abcdef1",
            },
            "sentinel": {"enabled": True, "issuer": "op", "allowed_actions": []},
        },
        base_dir=tmp_path,
    )
    assert config.provenance.signing_key_path == Path("/keys/k.pem")
    assert config.sentinel.enforcement_mode == "cooperating_enforced"
    assert config.sentinel.allowed_actions == []


def test_hooks_run_only_for_succeeded_jobs_before_terminal_state(orchestrator, input_file, policy):
    seen = []

    def hook(job):
        # The job is succeeded in memory but job.json is not terminal yet.
        assert job.status is JobStatus.SUCCEEDED
        stored = orchestrator.store.load_job(job.job_id)
        assert stored.status is JobStatus.RUNNING
        assert orchestrator.store.load_report(job.job_id) is None
        seen.append(job.job_id)

    orchestrator.post_success_hooks.append(hook)
    ok = orchestrator.run(orchestrator.submit(policy(), source=input_file).job_id)
    failed = orchestrator.run(orchestrator.submit(policy("fail"), source=input_file).job_id)
    assert seen == [ok.job_id]
    assert failed.status is JobStatus.FAILED


def test_hook_exception_never_fails_or_hides_the_job(orchestrator, input_file, policy):
    def boom(job):
        raise RuntimeError("hook crashed")

    orchestrator.post_success_hooks.append(boom)
    job = orchestrator.run(orchestrator.submit(policy(), source=input_file).job_id)
    assert job.status is JobStatus.SUCCEEDED
    assert orchestrator.get_report(job.job_id).status is JobStatus.SUCCEEDED


def test_read_output_returns_verified_bytes(orchestrator, input_file, policy):
    job = orchestrator.run(orchestrator.submit(policy(), source=input_file).job_id)
    artifact = job.output_artifacts[0]
    _, found, data = orchestrator.read_output(job.job_id, artifact.sha256)
    assert found == artifact
    assert data == orchestrator.store.artifact_path(artifact).read_bytes()


def test_read_output_rejects_unknown_digest_inputs_and_failed_jobs(orchestrator, input_file, policy):
    job = orchestrator.run(orchestrator.submit(policy(), source=input_file).job_id)
    for digest in ("0" * 64, job.input_artifact.sha256):
        with pytest.raises(AegisError) as err:
            orchestrator.read_output(job.job_id, digest)
        assert err.value.code is ErrorCode.ARTIFACT_NOT_FOUND
        assert err.value.details["kind"] == "artifact"
    failed = orchestrator.run(orchestrator.submit(policy("fail"), source=input_file).job_id)
    with pytest.raises(AegisError) as err:
        orchestrator.read_output(failed.job_id, "0" * 64)
    assert err.value.code is ErrorCode.ARTIFACT_NOT_FOUND


def test_read_output_fails_on_changed_missing_or_symlinked_bytes(orchestrator, input_file, policy, tmp_path):
    job = orchestrator.run(orchestrator.submit(policy(), source=input_file).job_id)
    artifact = job.output_artifacts[0]
    path = orchestrator.store.artifact_path(artifact)
    original = path.read_bytes()

    path.write_bytes(original + b"!")
    with pytest.raises(AegisError) as err:
        orchestrator.read_output(job.job_id, artifact.sha256)
    assert err.value.code is ErrorCode.ARTIFACT_INTEGRITY_ERROR

    # A symlink to identical bytes is still refused: only the registered file is served.
    twin = tmp_path / "twin.bin"
    twin.write_bytes(original)
    path.unlink()
    os.symlink(twin, path)
    with pytest.raises(AegisError) as err:
        orchestrator.read_output(job.job_id, artifact.sha256)
    assert err.value.code is ErrorCode.ARTIFACT_INTEGRITY_ERROR

    path.unlink()
    with pytest.raises(AegisError) as err:
        orchestrator.read_output(job.job_id, artifact.sha256)
    assert err.value.code is ErrorCode.ARTIFACT_INTEGRITY_ERROR
