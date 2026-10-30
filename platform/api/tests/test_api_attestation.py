"""Signature and Sentinel routes. Jobs use the protocol test double (no protection)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_api import create_app
from aegis_core.config import load_config
from aegis_core.errors import AegisError
from aegis_core.models import ErrorCode
from aegis_core.testing import write_test_config
from aegis_provenance.testing import attestation_toml, make_test_keys

PAYLOAD = b"\x7fELF api attestation payload"


@pytest.fixture(autouse=True)
def _no_token(monkeypatch):
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)


@pytest.fixture
def keys(tmp_path: Path):
    return make_test_keys(tmp_path / "keys")


@pytest.fixture
def make_client(tmp_path: Path):
    def factory(extra: str = "", token: str | None = None):
        config = load_config(write_test_config(tmp_path, extra_toml=extra))
        app = create_app(config, api_token=token)
        return TestClient(app), app

    return factory


def _submit(client: TestClient, headers: dict | None = None) -> dict:
    body = {
        "policy": {"backend": "fake", "options": {"mode": "ok"}},
        "input": {"name": "sample.bin", "content_base64": base64.b64encode(PAYLOAD).decode()},
    }
    response = client.post("/v1/jobs", json=body, headers=headers or {})
    assert response.status_code == 202
    job = client.get(f"/v1/jobs/{response.json()['job_id']}", headers=headers or {}).json()
    assert job["status"] == "succeeded"
    return job


def _signed(keys, actions=("analyze", "redistribute"), **kw) -> str:
    return attestation_toml(
        signing_key=keys.signer_private, trusted=[keys.signer_public], allowed_actions=list(actions), **kw
    )


def test_unconfigured_api_reports_unsigned_and_serves_downloads(make_client):
    client, _ = make_client()
    config = client.get("/v1/attestation").json()
    assert config["schema"] == "aegis.attestation-config.v1"
    assert config["signing"] == {
        "state": "not_configured", "key_id": None, "signer_name": None, "signer_trusted": False,
    }
    job = _submit(client)
    status = client.get(f"/v1/jobs/{job['job_id']}/attestation").json()
    assert status["schema"] == "aegis.job-attestation.v1"
    assert status["signing"]["state"] == "not_configured"
    [item] = status["artifacts"]
    assert item["signature"]["status"] == "unsigned"
    assert item["signature"]["error_code"] is None
    assert item["policy"]["status"] == "absent"

    sha = job["output_artifacts"][0]["sha256"]
    response = client.get(f"/v1/jobs/{job['job_id']}/artifacts/{sha}")
    assert response.status_code == 200
    assert hashlib.sha256(response.content).hexdigest() == sha
    assert response.headers["x-aegis-sentinel-decision"] == "not_configured"
    assert response.headers["x-aegis-artifact-sha256"] == sha
    assert response.headers["content-type"] == "application/octet-stream"
    assert 'filename="protected.bin"' in response.headers["content-disposition"]
    for doc in ("manifest", "policy"):
        missing = client.get(f"/v1/jobs/{job['job_id']}/artifacts/{sha}/{doc}")
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "ARTIFACT_NOT_FOUND"
        assert missing.json()["error"]["details"]["kind"] == doc


def test_signed_job_verifies_and_documents_are_served(make_client, keys, tmp_path):
    client, app = make_client(_signed(keys))
    config = client.get("/v1/attestation").json()
    assert config["signing"]["state"] == "configured"
    assert config["signing"]["key_id"] == keys.signer.key_id
    assert config["signing"]["signer_trusted"] is True
    assert config["verification"]["trusted_key_ids"] == [keys.signer.key_id]
    assert config["sentinel"]["allowed_actions"] == ["analyze", "redistribute"]
    assert "PRIVATE" not in json.dumps(config) and str(tmp_path) not in json.dumps(config)

    job = _submit(client)
    job_id, sha = job["job_id"], job["output_artifacts"][0]["sha256"]
    status = client.get(f"/v1/jobs/{job_id}/attestation").json()
    assert status["job_status"] == "succeeded"
    assert status["signing"]["state"] == "signed"
    assert status["sentinel"]["state"] == "created"
    [item] = status["artifacts"]
    assert item["signature"]["status"] == "verified"
    assert item["signature"]["key_id"] == keys.signer.key_id
    assert item["policy"]["status"] == "valid"
    assert status["limitations"]
    # Existing contracts are unchanged: job and report carry no attestation fields.
    assert set(job) == {
        "schema_version", "job_id", "status", "policy", "input_artifact", "output_artifacts",
        "error", "created_at", "updated_at", "started_at", "finished_at",
    }

    manifest = client.get(f"/v1/jobs/{job_id}/artifacts/{sha}/manifest")
    assert manifest.status_code == 200
    assert hashlib.sha256(manifest.content).hexdigest() == item["signature"]["manifest_sha256"]
    assert manifest.json()["payload"]["artifact_sha256"] == sha
    policy = client.get(f"/v1/jobs/{job_id}/artifacts/{sha}/policy")
    assert policy.json()["policy_id"] == item["policy"]["policy_id"]

    download = client.get(f"/v1/jobs/{job_id}/artifacts/{sha}")
    assert download.status_code == 200
    assert download.headers["x-aegis-sentinel-decision"] == "permitted"


def test_modified_output_fails_verification_and_download(make_client, keys):
    client, app = make_client(_signed(keys))
    job = _submit(client)
    job_id, artifact = job["job_id"], job["output_artifacts"][0]
    path = app.state.orchestrator.store.root / artifact["storage_path"]
    path.write_bytes(b"swapped")
    item = client.get(f"/v1/jobs/{job_id}/attestation").json()["artifacts"][0]
    assert item["signature"] == {
        **item["signature"], "status": "failed", "error_code": "ARTIFACT_TAMPERED",
    }
    response = client.get(f"/v1/jobs/{job_id}/artifacts/{artifact['sha256']}")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ARTIFACT_INTEGRITY_ERROR"
    assert b"swapped" not in response.content


def test_untrusted_signer_is_reported_as_failed(make_client, keys):
    client, _ = make_client(
        attestation_toml(signing_key=keys.signer_private, trusted=[keys.other_public])
    )
    assert client.get("/v1/attestation").json()["signing"]["signer_trusted"] is False
    job = _submit(client)
    item = client.get(f"/v1/jobs/{job['job_id']}/attestation").json()["artifacts"][0]
    assert item["signature"]["status"] == "failed"
    assert item["signature"]["error_code"] == "UNTRUSTED_KEY"


def test_denied_action_and_denied_download(make_client, keys):
    client, _ = make_client(_signed(keys, actions=("analyze",)))
    job = _submit(client)
    job_id, sha = job["job_id"], job["output_artifacts"][0]["sha256"]
    url = f"/v1/jobs/{job_id}/artifacts/{sha}/evaluate"

    denied = client.post(url, json={"action": "execute"})
    assert denied.status_code == 200
    body = denied.json()
    assert body["schema"] == "aegis.sentinel-decision.v1"
    assert body["permitted"] is False
    assert body["caller_id_verified"] is False
    assert body["enforcement_mode"] == "cooperating_enforced"
    assert client.post(url, json={"action": "analyze", "caller_id": "ui"}).json()["permitted"] is True

    download = client.get(f"/v1/jobs/{job_id}/artifacts/{sha}")
    assert download.status_code == 403
    assert download.json()["error"]["code"] == "POLICY_DENIED"
    assert download.content.find(PAYLOAD) == -1


def test_evaluate_rejects_bad_requests(make_client, keys):
    client, _ = make_client(_signed(keys))
    job = _submit(client)
    url = f"/v1/jobs/{job['job_id']}/artifacts/{job['output_artifacts'][0]['sha256']}/evaluate"
    for body in ({"action": "teleport"}, {"action": "analyze", "watermark_present": True},
                 {"action": "analyze", "caller_id": "x" * 129}):
        response = client.post(url, json=body)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "INVALID_REQUEST"
    other = client.post(f"/v1/jobs/{job['job_id']}/artifacts/{'0' * 64}/evaluate", json={"action": "analyze"})
    assert other.status_code == 404 and other.json()["error"]["code"] == "ARTIFACT_NOT_FOUND"
    # The input artifact is not an output and is never served.
    inp = client.get(f"/v1/jobs/{job['job_id']}/artifacts/{job['input_artifact']['sha256']}")
    assert inp.status_code == 404


@pytest.mark.parametrize("bad", ["ABC", "0" * 63, "../" + "0" * 61, "g" * 64])
def test_malformed_digests_are_rejected(make_client, bad):
    client, _ = make_client()
    job = _submit(client)
    response = client.get(f"/v1/jobs/{job['job_id']}/artifacts/{bad}")
    assert response.status_code in (404, 422)
    if response.status_code == 422:
        assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_new_routes_require_the_bearer_token(make_client, keys):
    client, _ = make_client(_signed(keys), token="s3cret")
    headers = {"Authorization": "Bearer s3cret"}
    job = _submit(client, headers)
    job_id, sha = job["job_id"], job["output_artifacts"][0]["sha256"]
    routes = [
        ("get", "/v1/attestation"),
        ("get", f"/v1/jobs/{job_id}/attestation"),
        ("get", f"/v1/jobs/{job_id}/artifacts/{sha}"),
        ("get", f"/v1/jobs/{job_id}/artifacts/{sha}/manifest"),
        ("get", f"/v1/jobs/{job_id}/artifacts/{sha}/policy"),
        ("post", f"/v1/jobs/{job_id}/artifacts/{sha}/evaluate"),
    ]
    for method, url in routes:
        kwargs = {"json": {"action": "analyze"}} if method == "post" else {}
        response = getattr(client, method)(url, **kwargs)
        assert response.status_code == 401, url
        assert getattr(client, method)(url, headers=headers, **kwargs).status_code == 200, url


def test_broken_signing_configuration_stops_the_api(tmp_path, keys):
    keys.signer_private.chmod(0o644)
    config = load_config(write_test_config(tmp_path, extra_toml=_signed(keys)))
    with pytest.raises(AegisError) as err:
        create_app(config)
    assert err.value.code is ErrorCode.CONFIG_INVALID
