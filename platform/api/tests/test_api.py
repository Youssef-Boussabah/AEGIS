from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_api import create_app
from aegis_core.config import AdapterSpec, load_config
from aegis_core.models import ProtectionPolicy
from aegis_core.testing import write_test_config

PAYLOAD = b"\x7fELF api test payload"


@pytest.fixture
def config(tmp_path: Path):
    return load_config(write_test_config(tmp_path, attack_lab_enabled=True))


@pytest.fixture
def client(config, monkeypatch) -> TestClient:
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    return TestClient(create_app(config))


def _body(mode: str = "ok", backend: str = "fake", data: bytes = PAYLOAD, **policy) -> dict:
    return {
        "policy": {"backend": backend, "options": {"mode": mode}, **policy},
        "input": {"name": "sample.bin", "content_base64": base64.b64encode(data).decode()},
    }


AUTH = {"authorized_by": "security-lead", "reference": "ENG-42", "scope": "sample.bin"}


def test_health_ok(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["storage_writable"] is True
    assert body["storage_root"] is None  # filesystem paths are not exposed over HTTP
    assert [b["name"] for b in body["backends"]] == ["fake"]


def test_health_degraded_when_adapter_missing(config, monkeypatch):
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    config.adapters["ghost"] = AdapterSpec(command=["/nonexistent/adapter"])
    response = TestClient(create_app(config)).get("/healthz")
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"


def test_create_job_then_status_then_report(client):
    response = client.post("/v1/jobs", json=_body())
    assert response.status_code == 202
    created = response.json()
    assert created["status"] == "pending"
    job_id = created["job_id"]
    assert response.headers["location"] == f"/v1/jobs/{job_id}"
    assert created["input_artifact"]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()

    # TestClient runs background tasks before returning, so the job is finished.
    job = client.get(f"/v1/jobs/{job_id}").json()
    assert job["status"] == "succeeded"
    assert job["error"] is None
    assert len(job["output_artifacts"]) == 1

    report = client.get(f"/v1/jobs/{job_id}/report")
    assert report.status_code == 200
    body = report.json()
    assert body["status"] == "succeeded"
    assert body["output_artifacts"] == job["output_artifacts"]
    assert body["limitations"]


def test_failed_job_reports_explicit_error(client):
    job_id = client.post("/v1/jobs", json=_body(mode="crash")).json()["job_id"]
    job = client.get(f"/v1/jobs/{job_id}").json()
    assert job["status"] == "failed"
    assert job["error"]["code"] == "ADAPTER_FAILED"
    report = client.get(f"/v1/jobs/{job_id}/report").json()
    assert report["status"] == "failed"
    assert report["error"]["code"] == "ADAPTER_FAILED"


def test_unsupported_backend_is_rejected(client, config):
    response = client.post("/v1/jobs", json=_body(backend="llvm-obfuscator"))
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "UNSUPPORTED_BACKEND"
    assert error["details"]["supported_backends"] == ["fake"]
    assert not any((config.storage.root / "jobs").iterdir())


def test_attack_lab_without_authorization_is_forbidden(client):
    response = client.post("/v1/jobs", json=_body(mode="attack", task="attack_lab"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_REQUIRED"


def test_attack_lab_disabled_in_config_is_forbidden(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    client = TestClient(create_app(load_config(write_test_config(tmp_path))))
    body = _body(mode="attack", task="attack_lab", authorization=AUTH)
    response = client.post("/v1/jobs", json=body)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_REQUIRED"


def test_authorized_attack_lab_job(client):
    body = _body(mode="attack", task="attack_lab", authorization=AUTH)
    job_id = client.post("/v1/jobs", json=body).json()["job_id"]
    report = client.get(f"/v1/jobs/{job_id}/report").json()
    assert report["status"] == "succeeded"
    assert report["attack_evaluations"][0]["outcome"] == "resisted"


def test_report_not_ready_for_pending_job(client):
    orchestrator = client.app.state.orchestrator
    job = orchestrator.submit(
        ProtectionPolicy(backend="fake"), data=b"x", name="pending.bin"
    )
    response = client.get(f"/v1/jobs/{job.job_id}/report")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "REPORT_NOT_READY"
    assert client.get(f"/v1/jobs/{job.job_id}").json()["status"] == "pending"


def test_unknown_job_is_404(client):
    response = client.get(f"/v1/jobs/{'f' * 32}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "JOB_NOT_FOUND"


@pytest.mark.parametrize("job_id", ["not-a-job", "F" * 32, "..%2F..%2Fetc"])
def test_malformed_job_id_is_rejected(client, job_id):
    response = client.get(f"/v1/jobs/{job_id}")
    assert response.status_code in (404, 422)


def test_invalid_base64_is_rejected(client):
    body = _body()
    body["input"]["content_base64"] = "!!!not base64!!!"
    response = client.post("/v1/jobs", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_validation_errors_do_not_echo_input(client):
    secret = "s3cr3t-value-that-must-not-echo"
    body = _body()
    body["policy"]["options"] = {"bad key!": secret}
    response = client.post("/v1/jobs", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert secret not in response.text


def test_oversized_input_is_rejected(client):
    response = client.post("/v1/jobs", json=_body(data=b"x" * (1024 * 1024 + 10)))
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "INPUT_TOO_LARGE"


def test_bearer_token_is_enforced_when_configured(config):
    client = TestClient(create_app(config, api_token="test-token"))
    assert client.get("/healthz").status_code == 200
    unauthorized = client.post("/v1/jobs", json=_body())
    assert unauthorized.status_code == 401
    assert unauthorized.json()["error"]["code"] == "UNAUTHORIZED"
    wrong = client.get(f"/v1/jobs/{'f' * 32}", headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401
    ok = client.post(
        "/v1/jobs", json=_body(), headers={"Authorization": "Bearer test-token"}
    )
    assert ok.status_code == 202
