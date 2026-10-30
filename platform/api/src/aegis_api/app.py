"""FastAPI application exposing jobs, reports, health, signatures and Sentinel policies.

Signing and Sentinel policy creation run inside the job (a Core post-success
hook from aegis_provenance.jobs). The routes below only read and verify; they
never sign. See docs/release/FINAL_API_CONTRACT.md.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import os
from typing import Annotated

from fastapi import BackgroundTasks, Depends, FastAPI, Path, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import Field

from aegis_core import __version__
from aegis_core.config import AegisConfig, load_config, resolve_config_path
from aegis_core.errors import AegisError
from aegis_core.health import HealthReport, check_health
from aegis_core.models import (
    ID_PATTERN,
    SHA256_PATTERN,
    AegisModel,
    ErrorCode,
    ErrorInfo,
    ProtectionJob,
    ProtectionPolicy,
    ProtectionReport,
)
from aegis_core.orchestrator import Orchestrator
from aegis_provenance.jobs import (
    API_CALLER_ID,
    AttestationConfigView,
    JobAttestationStatus,
    JobAttestor,
    SentinelDecision,
)
from aegis_sentinel.models import PermissionAction

logger = logging.getLogger(__name__)

TOKEN_ENV_VAR = "AEGIS_API_TOKEN"

STATUS_BY_CODE: dict[ErrorCode, int] = {
    ErrorCode.INVALID_REQUEST: 422,
    ErrorCode.UNAUTHORIZED: 401,
    ErrorCode.UNSUPPORTED_BACKEND: 400,
    ErrorCode.UNSUPPORTED_TASK: 400,
    ErrorCode.AUTHORIZATION_REQUIRED: 403,
    ErrorCode.INPUT_NOT_FOUND: 400,
    ErrorCode.INPUT_TOO_LARGE: 413,
    ErrorCode.JOB_NOT_FOUND: 404,
    ErrorCode.JOB_CONFLICT: 409,
    ErrorCode.REPORT_NOT_READY: 409,
    ErrorCode.ARTIFACT_NOT_FOUND: 404,
    ErrorCode.POLICY_DENIED: 403,
    ErrorCode.ARTIFACT_INTEGRITY_ERROR: 409,
}

JobId = Annotated[str, Path(pattern=ID_PATTERN, description="32-char lowercase hex job id")]
ArtifactSha = Annotated[
    str, Path(pattern=SHA256_PATTERN, description="SHA-256 of a registered output artifact")
]


class InlineInput(AegisModel):
    name: Annotated[str, Field(min_length=1, max_length=255)]
    content_base64: str


class CreateJobRequest(AegisModel):
    policy: ProtectionPolicy
    input: InlineInput


class ErrorResponse(AegisModel):
    error: ErrorInfo


class EvaluateRequest(AegisModel):
    action: PermissionAction
    caller_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    """Asserted by the caller; not authenticated."""
    environment: Annotated[str, Field(min_length=1, max_length=128)] | None = None


def _error_response(info: ErrorInfo, status_code: int | None = None) -> JSONResponse:
    status = status_code or STATUS_BY_CODE.get(info.code, 500)
    return JSONResponse(status_code=status, content={"error": info.model_dump(mode="json")})


def _decode_input(item: InlineInput, max_bytes: int) -> bytes:
    # Reject oversized payloads before decoding them.
    if len(item.content_base64) > (max_bytes + 2) // 3 * 4 + 4:
        raise AegisError(
            ErrorCode.INPUT_TOO_LARGE,
            f"Input exceeds the configured limit of {max_bytes} bytes.",
            {"max_input_bytes": max_bytes},
        )
    try:
        return base64.b64decode(item.content_base64, validate=True)
    except (binascii.Error, ValueError):
        raise AegisError(
            ErrorCode.INVALID_REQUEST, "input.content_base64 is not valid base64."
        ) from None


def create_app(config: AegisConfig | None = None, *, api_token: str | None = None) -> FastAPI:
    """Build the app. Without `config`, loads it from $AEGIS_CONFIG or ./aegis.toml.

    When a token is given (or $AEGIS_API_TOKEN is set), every /v1 route requires
    `Authorization: Bearer <token>`. /healthz stays open.
    """
    if config is None:
        config = load_config(resolve_config_path())
    if api_token is None:
        api_token = os.environ.get(TOKEN_ENV_VAR) or None
    orchestrator = Orchestrator(config)
    orchestrator.store.initialize()
    # Loads the operator's signing key and trusted keys; a broken signing
    # configuration raises CONFIG_INVALID here, so the API never starts unsigned
    # by accident.
    attestor = JobAttestor.from_config(config, orchestrator.store, clock=orchestrator.clock)
    orchestrator.post_success_hooks.append(attestor.attest)

    app = FastAPI(
        title="AEGIS API",
        version=__version__,
        responses={
            400: {"model": ErrorResponse},
            401: {"model": ErrorResponse},
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
            409: {"model": ErrorResponse},
            413: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
        },
    )
    app.state.orchestrator = orchestrator
    app.state.attestor = attestor

    @app.exception_handler(AegisError)
    async def _aegis_error(_: Request, exc: AegisError) -> JSONResponse:
        return _error_response(exc.to_info())

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo request input back (it may be large or sensitive).
        problems = [
            {"loc": ".".join(str(p) for p in err.get("loc", ())), "msg": err.get("msg", "")}
            for err in exc.errors()[:50]
        ]
        info = ErrorInfo(
            code=ErrorCode.INVALID_REQUEST,
            message="Request failed validation.",
            details={"errors": problems},
        )
        return _error_response(info, 422)

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled API error")
        info = ErrorInfo(code=ErrorCode.INTERNAL_ERROR, message="Internal server error.")
        return _error_response(info, 500)

    def require_token(request: Request) -> None:
        if api_token is None:
            return
        header = request.headers.get("authorization", "")
        scheme, _, supplied = header.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            supplied.strip().encode(), api_token.encode()
        ):
            raise AegisError(ErrorCode.UNAUTHORIZED, "A valid bearer token is required.")

    auth = [Depends(require_token)]

    @app.get("/healthz", response_model=HealthReport, tags=["health"])
    def healthz(response: Response) -> HealthReport:
        report = check_health(config, include_paths=False)
        if report.status != "ok":
            response.status_code = 503
        return report

    @app.post(
        "/v1/jobs",
        status_code=202,
        response_model=ProtectionJob,
        dependencies=auth,
        tags=["jobs"],
    )
    def create_job(
        body: CreateJobRequest, background: BackgroundTasks, response: Response
    ) -> ProtectionJob:
        """Store the input, record a pending job and run it in the background."""
        orchestrator.validate_policy(body.policy)
        data = _decode_input(body.input, config.storage.max_input_bytes)
        job = orchestrator.submit(body.policy, data=data, name=body.input.name)
        background.add_task(orchestrator.run_safely, job.job_id)
        response.headers["Location"] = f"/v1/jobs/{job.job_id}"
        return job

    @app.get("/v1/jobs/{job_id}", response_model=ProtectionJob, dependencies=auth, tags=["jobs"])
    def get_job(job_id: JobId) -> ProtectionJob:
        return orchestrator.get_job(job_id)

    @app.get(
        "/v1/jobs/{job_id}/report",
        response_model=ProtectionReport,
        dependencies=auth,
        tags=["jobs"],
    )
    def get_report(job_id: JobId) -> ProtectionReport:
        return orchestrator.get_report(job_id)

    # ------------------------------------------------- signatures and policies

    @app.get(
        "/v1/attestation",
        response_model=AttestationConfigView,
        dependencies=auth,
        tags=["attestation"],
    )
    def attestation_config() -> AttestationConfigView:
        """Signing and Sentinel configuration: key ids only, never key material or paths."""
        return attestor.config_view()

    @app.get(
        "/v1/jobs/{job_id}/attestation",
        response_model=JobAttestationStatus,
        dependencies=auth,
        tags=["attestation"],
    )
    def job_attestation(job_id: JobId) -> JobAttestationStatus:
        """Signature verification and policy status, recomputed on every request."""
        return attestor.status(orchestrator.get_job(job_id))

    @app.get(
        "/v1/jobs/{job_id}/artifacts/{sha256}",
        response_class=Response,
        dependencies=auth,
        tags=["attestation"],
        responses={200: {"content": {"application/octet-stream": {}}}},
    )
    def download_artifact(job_id: JobId, sha256: ArtifactSha) -> Response:
        """Exact bytes of a registered output, hash-checked before anything is sent."""
        job, artifact, data = orchestrator.read_output(job_id, sha256)
        decision = attestor.authorize_release(job, artifact, caller_id=API_CALLER_ID)
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{artifact.name}"',
                "X-AEGIS-Artifact-SHA256": artifact.sha256,
                "X-AEGIS-Sentinel-Decision": decision,
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    @app.get(
        "/v1/jobs/{job_id}/artifacts/{sha256}/manifest",
        response_class=Response,
        dependencies=auth,
        tags=["attestation"],
        responses={200: {"content": {"application/json": {}}}},
    )
    def artifact_manifest(job_id: JobId, sha256: ArtifactSha) -> Response:
        job, artifact = orchestrator.find_output(job_id, sha256)
        return Response(
            content=attestor.manifest_bytes(job, artifact),
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    @app.get(
        "/v1/jobs/{job_id}/artifacts/{sha256}/policy",
        response_class=Response,
        dependencies=auth,
        tags=["attestation"],
        responses={200: {"content": {"application/json": {}}}},
    )
    def artifact_policy(job_id: JobId, sha256: ArtifactSha) -> Response:
        job, artifact = orchestrator.find_output(job_id, sha256)
        return Response(
            content=attestor.policy_bytes(job, artifact),
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    @app.post(
        "/v1/jobs/{job_id}/artifacts/{sha256}/evaluate",
        response_model=SentinelDecision,
        dependencies=auth,
        tags=["attestation"],
    )
    def evaluate_artifact_action(
        job_id: JobId, sha256: ArtifactSha, body: EvaluateRequest
    ) -> SentinelDecision:
        """Sentinel decision for a cooperating tool. A denial is a 200 decision."""
        job, artifact = orchestrator.find_output(job_id, sha256)
        return attestor.evaluate(
            job, artifact, body.action, caller_id=body.caller_id, environment=body.environment
        )

    return app
