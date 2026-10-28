from __future__ import annotations

import hashlib
import json
import time
from datetime import timedelta
from pathlib import Path

import pytest
from conftest import attack_policy, policy

from aegis_core.config import AdapterSpec
from aegis_core.errors import AegisError
from aegis_core.models import (
    AttackLabAuthorization,
    AttackOutcome,
    ErrorCode,
    EvidenceKind,
    EvidenceSource,
    JobStatus,
    utcnow,
)
from aegis_core.orchestrator import Orchestrator


def _run(orch: Orchestrator, pol, source: Path):
    job = orch.submit(pol, source=source)
    assert job.status is JobStatus.PENDING
    return orch.run(job.job_id)


def test_successful_protection_records_hashes_and_report(orchestrator, input_file):
    job = _run(orchestrator, policy(), input_file)
    assert job.status is JobStatus.SUCCEEDED
    assert job.error is None
    assert job.input_artifact.sha256 == hashlib.sha256(input_file.read_bytes()).hexdigest()

    [output] = job.output_artifacts
    out_path = orchestrator.store.artifact_path(output)
    assert output.sha256 == hashlib.sha256(out_path.read_bytes()).hexdigest()

    report = orchestrator.get_report(job.job_id)
    assert report.status is JobStatus.SUCCEEDED
    assert report.output_artifacts == job.output_artifacts
    kinds = {(e.kind, e.source) for e in report.evidence}
    assert (EvidenceKind.ARTIFACT_HASH, EvidenceSource.ORCHESTRATOR) in kinds
    assert (EvidenceKind.ADAPTER_INVOCATION, EvidenceSource.ORCHESTRATOR) in kinds
    assert (EvidenceKind.ADAPTER_CLAIM, EvidenceSource.ADAPTER) in kinds
    assert report.limitations


def test_unsupported_backend_fails_before_creating_a_job(orchestrator, input_file):
    with pytest.raises(AegisError) as info:
        orchestrator.submit(policy(backend="llvm-obfuscator"), source=input_file)
    assert info.value.code is ErrorCode.UNSUPPORTED_BACKEND
    assert info.value.details["supported_backends"] == ["fake"]
    assert orchestrator.list_jobs() == []


def test_unsupported_task_is_explicit(make_orchestrator, input_file):
    orch = make_orchestrator(attack_lab_enabled=True, tasks=("protect",))
    with pytest.raises(AegisError) as info:
        orch.submit(attack_policy(), source=input_file)
    assert info.value.code is ErrorCode.UNSUPPORTED_TASK


def test_missing_input_is_explicit(orchestrator, tmp_path):
    with pytest.raises(AegisError) as info:
        orchestrator.submit(policy(), source=tmp_path / "missing.bin")
    assert info.value.code is ErrorCode.INPUT_NOT_FOUND
    assert orchestrator.list_jobs() == []


# ------------------------------------------------------------- attack lab


def test_attack_lab_disabled_by_config(orchestrator, input_file):
    with pytest.raises(AegisError) as info:
        orchestrator.submit(attack_policy(), source=input_file)
    assert info.value.code is ErrorCode.AUTHORIZATION_REQUIRED


def test_attack_lab_requires_authorization_record(make_orchestrator, input_file):
    orch = make_orchestrator(attack_lab_enabled=True)
    with pytest.raises(AegisError) as info:
        orch.submit(attack_policy(authorization=None), source=input_file)
    assert info.value.code is ErrorCode.AUTHORIZATION_REQUIRED


def test_attack_lab_rejects_expired_authorization(make_orchestrator, input_file):
    orch = make_orchestrator(attack_lab_enabled=True)
    expired = AttackLabAuthorization(
        authorized_by="lead",
        reference="ENG-1",
        scope="all",
        expires_at=utcnow() - timedelta(minutes=1),
    )
    with pytest.raises(AegisError) as info:
        orch.submit(attack_policy(authorization=expired), source=input_file)
    assert info.value.code is ErrorCode.AUTHORIZATION_REQUIRED


def test_authorized_attack_lab_records_evaluations(make_orchestrator, input_file):
    orch = make_orchestrator(attack_lab_enabled=True)
    job = _run(orch, attack_policy(), input_file)
    assert job.status is JobStatus.SUCCEEDED
    report = orch.get_report(job.job_id)
    [evaluation] = report.attack_evaluations
    assert evaluation.outcome is AttackOutcome.RESISTED
    assert evaluation.target_artifact_sha256 == job.output_artifacts[0].sha256
    assert any(e.kind is EvidenceKind.AUTHORIZATION for e in report.evidence)
    request = json.loads((orch.store.adapter_dir(job.job_id) / "request.json").read_text())
    assert request["authorization"]["reference"] == "ENG-42"


def test_attack_lab_without_evaluations_fails(make_orchestrator, input_file):
    orch = make_orchestrator(attack_lab_enabled=True)
    job = _run(orch, attack_policy(mode="ok"), input_file)
    assert job.status is JobStatus.FAILED
    assert job.error.code is ErrorCode.ADAPTER_INVALID_OUTPUT


def test_protect_task_rejects_attack_evaluations(orchestrator, input_file):
    job = _run(orchestrator, policy("attack"), input_file)
    assert job.status is JobStatus.FAILED
    assert job.error.code is ErrorCode.ADAPTER_INVALID_OUTPUT


# -------------------------------------------------------- adapter failures


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("fail", ErrorCode.ADAPTER_FAILED),
        ("crash", ErrorCode.ADAPTER_FAILED),
        ("garbage", ErrorCode.ADAPTER_INVALID_OUTPUT),
        ("escape", ErrorCode.ADAPTER_INVALID_OUTPUT),
        ("no-output", ErrorCode.ADAPTER_INVALID_OUTPUT),
        ("mutate-input", ErrorCode.ARTIFACT_INTEGRITY_ERROR),
    ],
)
def test_adapter_failures_are_never_reported_as_success(orchestrator, input_file, mode, code):
    job = _run(orchestrator, policy(mode), input_file)
    assert job.status is JobStatus.FAILED
    assert job.error.code is code
    assert job.output_artifacts == []
    report = orchestrator.get_report(job.job_id)
    assert report.status is JobStatus.FAILED
    assert report.error == job.error
    assert report.summary.startswith("Job failed")


def test_crash_captures_stderr_as_evidence(orchestrator, input_file):
    job = _run(orchestrator, policy("crash"), input_file)
    assert "crashed on purpose" in job.error.details["stderr_tail"]
    report = orchestrator.get_report(job.job_id)
    [inv] = [e for e in report.evidence if e.kind is EvidenceKind.ADAPTER_INVOCATION]
    assert inv.data["exit_code"] == 3
    log = orchestrator.store.resolve_storage_path(inv.data["stderr_log"])
    assert hashlib.sha256(log.read_bytes()).hexdigest() == inv.data["stderr_sha256"]


def test_timeout_kills_adapter(orchestrator, input_file):
    started = time.monotonic()
    job = _run(orchestrator, policy("sleep", options={"seconds": 30}, timeout_seconds=1), input_file)
    assert time.monotonic() - started < 15
    assert job.status is JobStatus.FAILED
    assert job.error.code is ErrorCode.ADAPTER_TIMEOUT


def test_missing_executable_is_explicit(orchestrator, input_file):
    orchestrator.config.adapters["fake"] = AdapterSpec(command=["/nonexistent/adapter-bin"])
    job = _run(orchestrator, policy(), input_file)
    assert job.status is JobStatus.FAILED
    assert job.error.code is ErrorCode.ADAPTER_UNAVAILABLE


def test_backend_removed_after_submit_fails_job(orchestrator, input_file):
    job = orchestrator.submit(policy(), source=input_file)
    orchestrator.config.adapters.clear()
    job = orchestrator.run(job.job_id)
    assert job.status is JobStatus.FAILED
    assert job.error.code is ErrorCode.UNSUPPORTED_BACKEND


def test_job_cannot_run_twice(orchestrator, input_file):
    job = _run(orchestrator, policy(), input_file)
    with pytest.raises(AegisError) as info:
        orchestrator.run(job.job_id)
    assert info.value.code is ErrorCode.JOB_CONFLICT


def test_report_not_ready_for_pending_job(orchestrator, input_file):
    job = orchestrator.submit(policy(), source=input_file)
    with pytest.raises(AegisError) as info:
        orchestrator.get_report(job.job_id)
    assert info.value.code is ErrorCode.REPORT_NOT_READY


def test_unknown_job(orchestrator):
    with pytest.raises(AegisError) as info:
        orchestrator.get_job("f" * 32)
    assert info.value.code is ErrorCode.JOB_NOT_FOUND


# ---------------------------------------------------------------- safety


def test_adapter_does_not_inherit_secrets(orchestrator, input_file, monkeypatch):
    monkeypatch.setenv("AEGIS_TEST_SECRET_TOKEN", "do-not-leak")
    job = _run(orchestrator, policy("env"), input_file)
    names = orchestrator.store.artifact_path(job.output_artifacts[0]).read_text().split()
    assert "AEGIS_TEST_SECRET_TOKEN" not in names
    assert "PATH" in names


def test_env_passthrough_is_opt_in(orchestrator, input_file, monkeypatch):
    monkeypatch.setenv("AEGIS_TEST_ALLOWED", "1")
    spec = orchestrator.config.adapters["fake"]
    orchestrator.config.adapters["fake"] = spec.model_copy(
        update={"env_passthrough": ["AEGIS_TEST_ALLOWED"]}
    )
    job = _run(orchestrator, policy("env"), input_file)
    names = orchestrator.store.artifact_path(job.output_artifacts[0]).read_text().split()
    assert "AEGIS_TEST_ALLOWED" in names


def test_untrusted_values_never_reach_a_shell(orchestrator, tmp_path):
    hostile = tmp_path / "x; touch pwned; $(touch pwned) `touch pwned`.bin"
    hostile.write_bytes(b"data")
    job = _run(
        orchestrator, policy("argv", options={"note": "$(touch pwned); touch pwned"}), hostile
    )
    assert job.status is JobStatus.SUCCEEDED
    # A shell would have created "pwned" in the adapter's working directory (or ours).
    assert not [p for p in tmp_path.rglob("*pwned*") if p.name == "pwned"]
    assert not Path("pwned").exists()
    argv = json.loads(orchestrator.store.artifact_path(job.output_artifacts[0]).read_text())
    # The adapter receives exactly one extra argument pair: the request flag and path.
    assert argv[-2] == "--aegis-request"
    assert argv[-1].endswith("adapter/request.json")
