"""FastAPI application exposing job creation, job status, reports and health."""

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
    AegisModel,
    ErrorCode,
    ErrorInfo,
    ProtectionJob,
    ProtectionPolicy,
    ProtectionReport,
)
from aegis_core.orchestrator import Orchestrator

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
}

JobId = Annotated[str, Path(pattern=ID_PATTERN, description="32-char lowercase hex job id")]


class InlineInput(AegisModel):
    name: Annotated[str, Field(min_length=1, max_length=255)]
    content_base64: str


class CreateJobRequest(AegisModel):
    policy: ProtectionPolicy
    input: InlineInput


class ErrorResponse(AegisModel):
    error: ErrorInfo


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

    return app
