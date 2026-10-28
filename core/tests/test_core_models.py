from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis_core.adapter import AdapterResult
from aegis_core.models import (
    Artifact,
    ArtifactRole,
    ErrorCode,
    ErrorInfo,
    JobStatus,
    ProtectionJob,
    ProtectionPolicy,
    ProtectionReport,
    utcnow,
)

SHA = "a" * 64


def _artifact(**overrides) -> Artifact:
    data = dict(
        artifact_id="0" * 32,
        name="in.bin",
        role=ArtifactRole.INPUT,
        sha256=SHA,
        size_bytes=1,
        storage_path="jobs/x/inputs/in.bin",
        created_at=utcnow(),
    )
    data.update(overrides)
    return Artifact(**data)


def _job(**overrides) -> dict:
    now = utcnow()
    data = dict(
        job_id="1" * 32,
        status=JobStatus.PENDING,
        policy=ProtectionPolicy(backend="fake"),
        input_artifact=_artifact(),
        created_at=now,
        updated_at=now,
    )
    data.update(overrides)
    return data


def test_pending_job_is_valid():
    assert ProtectionJob(**_job()).status is JobStatus.PENDING


def test_failed_job_requires_error():
    now = utcnow()
    with pytest.raises(ValidationError, match="must carry an error"):
        ProtectionJob(**_job(status=JobStatus.FAILED, started_at=now, finished_at=now))


def test_succeeded_job_rejects_error():
    now = utcnow()
    err = ErrorInfo(code=ErrorCode.ADAPTER_FAILED, message="x")
    with pytest.raises(ValidationError, match="must not carry an error"):
        ProtectionJob(
            **_job(status=JobStatus.SUCCEEDED, started_at=now, finished_at=now, error=err)
        )


def test_terminal_job_requires_finished_at():
    with pytest.raises(ValidationError, match="finished_at"):
        ProtectionJob(**_job(status=JobStatus.SUCCEEDED, started_at=utcnow()))


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        ProtectionPolicy(backend="fake", surprise=True)


@pytest.mark.parametrize("backend", ["", "Has Space", "../etc", "UPPER", "x" * 65])
def test_backend_name_is_constrained(backend):
    with pytest.raises(ValidationError):
        ProtectionPolicy(backend=backend)


@pytest.mark.parametrize(
    "options",
    [{"bad key": 1}, {"k": float("nan")}, {"k": "x" * 5000}, {f"k{i}": i for i in range(65)}],
)
def test_policy_options_are_constrained(options):
    with pytest.raises(ValidationError):
        ProtectionPolicy(backend="fake", options=options)


def test_policy_option_types_are_preserved():
    policy = ProtectionPolicy(backend="fake", options={"a": True, "b": 3, "c": 1.5, "d": "s"})
    assert policy.options == {"a": True, "b": 3, "c": 1.5, "d": "s"}
    assert type(policy.options["a"]) is bool and type(policy.options["b"]) is int


@pytest.mark.parametrize("path", ["/abs/path", "../x", "a/../b", "a//b", "a\\b"])
def test_artifact_storage_path_must_be_relative(path):
    with pytest.raises(ValidationError):
        _artifact(storage_path=path)


def test_report_requires_terminal_status():
    with pytest.raises(ValidationError, match="terminal"):
        ProtectionReport(
            report_id="2" * 32,
            job_id="1" * 32,
            status=JobStatus.RUNNING,
            generated_at=utcnow(),
            policy=ProtectionPolicy(backend="fake"),
            input_artifact=_artifact(),
            summary="x",
        )


def test_adapter_result_failed_requires_error():
    with pytest.raises(ValidationError):
        AdapterResult.model_validate({"protocol": "aegis.adapter.v1", "status": "failed"})


def test_adapter_result_rejects_unknown_protocol():
    with pytest.raises(ValidationError):
        AdapterResult.model_validate({"protocol": "v0", "status": "succeeded"})
