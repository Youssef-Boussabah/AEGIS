"""`aegis protect` signing, `aegis verify` and `aegis evaluate` (protocol test double only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_cli.main import EXIT_CONFIG, EXIT_FAILED, EXIT_NOT_FOUND, EXIT_OK, main
from aegis_core.testing import write_test_config
from aegis_provenance.testing import attestation_toml, make_test_keys


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG", raising=False)
    (tmp_path / "sample.bin").write_bytes(b"\x7fELF cli attestation payload")
    return tmp_path


@pytest.fixture
def keys(workspace: Path):
    return make_test_keys(workspace / "keys")


def _protect(capsys) -> dict:
    assert main(["protect", "sample.bin", "--backend", "fake", "--json"]) == EXIT_OK
    return json.loads(capsys.readouterr().out)


def test_signed_protect_then_verify(workspace, keys, capsys):
    write_test_config(
        workspace,
        extra_toml=attestation_toml(
            signing_key=keys.signer_private, trusted=[keys.signer_public], allowed_actions=["analyze"]
        ),
    )
    assert main(["protect", "sample.bin", "--backend", "fake"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "signature: VERIFIED" in out
    job = _protect(capsys)
    assert "attestation" not in job  # JSON job output is the unchanged ProtectionJob

    assert main(["verify", job["job_id"]]) == EXIT_OK
    out = capsys.readouterr().out
    assert "ALL OUTPUTS VERIFIED" in out and "limitations:" in out
    assert main(["verify", job["job_id"], "--json"]) == EXIT_OK
    status = json.loads(capsys.readouterr().out)
    assert status["schema"] == "aegis.job-attestation.v1"
    assert status["artifacts"][0]["signature"]["status"] == "verified"

    sha = job["output_artifacts"][0]["sha256"]
    assert main(["evaluate", job["job_id"], sha, "--action", "analyze"]) == EXIT_OK
    assert "PERMITTED" in capsys.readouterr().out
    assert main(["evaluate", job["job_id"], sha, "--action", "execute", "--json"]) == EXIT_FAILED
    assert json.loads(capsys.readouterr().out)["permitted"] is False

    # Modify the output: verification fails with a nonzero exit.
    store = workspace / ".aegis"
    (store / job["output_artifacts"][0]["storage_path"]).write_bytes(b"tampered")
    assert main(["verify", job["job_id"]]) == EXIT_FAILED
    assert "ARTIFACT_TAMPERED" in capsys.readouterr().out


def test_unsigned_job_never_verifies(workspace, capsys):
    write_test_config(workspace)
    job = _protect(capsys)
    assert main(["verify", job["job_id"]]) == EXIT_FAILED
    out = capsys.readouterr().out
    assert "UNSIGNED" in out and "NOT VERIFIED" in out
    sha = job["output_artifacts"][0]["sha256"]
    assert main(["evaluate", job["job_id"], sha, "--action", "analyze"]) == EXIT_NOT_FOUND


def test_broken_signing_config_fails_before_running(workspace, keys, capsys):
    keys.signer_private.chmod(0o644)
    write_test_config(
        workspace,
        extra_toml=attestation_toml(signing_key=keys.signer_private, trusted=[keys.signer_public]),
    )
    assert main(["protect", "sample.bin", "--backend", "fake"]) == EXIT_CONFIG
    assert "CONFIG_INVALID" in capsys.readouterr().err
    assert not (workspace / ".aegis" / "jobs").exists() or not any((workspace / ".aegis" / "jobs").iterdir())
