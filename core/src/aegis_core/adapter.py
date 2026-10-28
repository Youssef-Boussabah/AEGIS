"""Subprocess adapter protocol (`aegis.adapter.v1`) and runner.

An adapter is an executable registered in `aegis.toml`. The orchestrator runs it as
``[*command, "--aegis-request", <request.json>]`` with ``shell=False``, a minimal
environment, a timeout and its own process group. The adapter reads the request
file and prints exactly one JSON `AdapterResult` on stdout. See
core/docs/adapter-protocol.md.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, ValidationError, model_validator

from .config import AdapterSpec
from .models import (
    AegisModel,
    AttackLabAuthorization,
    AttackOutcome,
    ErrorCode,
    ErrorInfo,
    OptionValue,
    TaskKind,
)

PROTOCOL = "aegis.adapter.v1"
REQUEST_FLAG = "--aegis-request"
STDERR_TAIL_CHARS = 4000
MAX_STDERR_BYTES = 1024 * 1024
_KILL_GRACE_SECONDS = 5


class AdapterRequest(AegisModel):
    protocol: Literal["aegis.adapter.v1"] = PROTOCOL
    job_id: str
    task: TaskKind
    backend: str
    policy_name: str
    input_path: str
    input_sha256: str
    output_dir: str
    options: dict[str, OptionValue] = Field(default_factory=dict)
    authorization: AttackLabAuthorization | None = None


class AdapterOutput(AegisModel):
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    """Path relative to the request's output_dir."""


class AdapterEvidence(AegisModel):
    summary: Annotated[str, Field(min_length=1, max_length=2000)]
    data: dict[str, Any] = Field(default_factory=dict)


class AdapterAttackEvaluation(AegisModel):
    attack: Annotated[str, Field(min_length=1, max_length=200)]
    outcome: AttackOutcome
    target: str | None = None
    """"input", an output path, or null."""
    details: Annotated[str, Field(max_length=4000)] = ""
    metrics: dict[str, OptionValue] = Field(default_factory=dict)


class AdapterError(AegisModel):
    code: Annotated[str, Field(min_length=1, max_length=100)]
    message: Annotated[str, Field(min_length=1, max_length=4000)]


class AdapterResult(AegisModel):
    protocol: Literal["aegis.adapter.v1"]
    status: Literal["succeeded", "failed"]
    outputs: Annotated[list[AdapterOutput], Field(max_length=256)] = Field(default_factory=list)
    evidence: Annotated[list[AdapterEvidence], Field(max_length=256)] = Field(default_factory=list)
    attack_evaluations: Annotated[list[AdapterAttackEvaluation], Field(max_length=256)] = Field(
        default_factory=list
    )
    error: AdapterError | None = None

    @model_validator(mode="after")
    def _status_error(self) -> AdapterResult:
        if self.status == "failed" and self.error is None:
            raise ValueError("a failed result must include an error")
        if self.status == "succeeded" and self.error is not None:
            raise ValueError("a succeeded result must not include an error")
        return self


@dataclass
class AdapterInvocation:
    argv: list[str]
    exit_code: int | None = None
    timed_out: bool = False
    duration_seconds: float = 0.0
    stdout_sha256: str | None = None
    stdout_bytes: int = 0
    stderr: bytes = b""
    result: AdapterResult | None = None
    error: ErrorInfo | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def stderr_tail(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")[-STDERR_TAIL_CHARS:]


def resolve_executable(program: str, path_env: str | None = None) -> str | None:
    """Absolute path of an executable, or None when it cannot be run."""
    if os.sep in program or (os.altsep and os.altsep in program):
        candidate = Path(program)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            # absolute(), not resolve(): following symlinks would change what runs
            # (e.g. a venv's bin/python would become the base interpreter).
            return str(candidate.absolute())
        return None
    return shutil.which(program, path=path_env)


def adapter_environment(spec: AdapterSpec, work_dir: Path) -> dict[str, str]:
    """Minimal environment: the parent's secrets are never inherited implicitly."""
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(work_dir),
        "TMPDIR": str(work_dir),
    }
    for name in spec.env_passthrough:
        if name in os.environ:
            env[name] = os.environ[name]
    return env


class SubprocessAdapterRunner:
    def invoke(
        self,
        spec: AdapterSpec,
        request_path: Path,
        *,
        work_dir: Path,
        timeout_seconds: int,
    ) -> AdapterInvocation:
        env = adapter_environment(spec, work_dir)
        program = resolve_executable(spec.command[0], env["PATH"])
        argv = [program or spec.command[0], *spec.command[1:], REQUEST_FLAG, str(request_path)]
        invocation = AdapterInvocation(argv=argv)
        if program is None:
            invocation.error = ErrorInfo(
                code=ErrorCode.ADAPTER_UNAVAILABLE,
                message=f"Adapter executable {spec.command[0]!r} was not found or is not executable.",
            )
            return invocation

        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=work_dir,
                env=env,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            invocation.error = ErrorInfo(
                code=ErrorCode.ADAPTER_UNAVAILABLE,
                message=f"Adapter could not be started: {exc.strerror or exc}",
            )
            return invocation

        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            invocation.timed_out = True
            _kill_process_group(proc)
            try:
                stdout, stderr = proc.communicate(timeout=_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                stdout, stderr = b"", b""
        invocation.duration_seconds = round(time.monotonic() - started, 3)
        invocation.exit_code = proc.returncode
        invocation.stderr = stderr[-MAX_STDERR_BYTES:]
        invocation.stdout_bytes = len(stdout)
        invocation.stdout_sha256 = hashlib.sha256(stdout).hexdigest()

        if invocation.timed_out:
            invocation.error = ErrorInfo(
                code=ErrorCode.ADAPTER_TIMEOUT,
                message=f"Adapter did not finish within {timeout_seconds}s and was killed.",
                details={"timeout_seconds": timeout_seconds},
            )
            return invocation

        parsed, parse_error = _parse_result(stdout, spec.max_stdout_bytes)
        invocation.result = parsed

        if proc.returncode != 0:
            details: dict[str, Any] = {
                "exit_code": proc.returncode,
                "stderr_tail": invocation.stderr_tail,
            }
            if parsed is not None and parsed.error is not None:
                details["adapter_error"] = parsed.error.model_dump()
            invocation.error = ErrorInfo(
                code=ErrorCode.ADAPTER_FAILED,
                message=f"Adapter exited with status {proc.returncode}.",
                details=details,
            )
        elif parse_error is not None:
            invocation.error = parse_error
        elif parsed is not None and parsed.status == "failed":
            assert parsed.error is not None
            invocation.error = ErrorInfo(
                code=ErrorCode.ADAPTER_FAILED,
                message=f"Adapter reported failure: {parsed.error.message}",
                details={"adapter_error": parsed.error.model_dump()},
            )
        return invocation


def _parse_result(stdout: bytes, limit: int) -> tuple[AdapterResult | None, ErrorInfo | None]:
    if len(stdout) > limit:
        return None, ErrorInfo(
            code=ErrorCode.ADAPTER_INVALID_OUTPUT,
            message=f"Adapter stdout exceeded {limit} bytes.",
        )
    if not stdout.strip():
        return None, ErrorInfo(
            code=ErrorCode.ADAPTER_INVALID_OUTPUT, message="Adapter produced no result on stdout."
        )
    try:
        return AdapterResult.model_validate_json(stdout), None
    except ValidationError as exc:
        problems = [
            {"loc": ".".join(str(p) for p in err["loc"]), "msg": err["msg"]}
            for err in exc.errors(include_input=False, include_url=False)[:20]
        ]
        return None, ErrorInfo(
            code=ErrorCode.ADAPTER_INVALID_OUTPUT,
            message=f"Adapter stdout is not a valid {PROTOCOL} result.",
            details={"errors": problems},
        )


def _kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        proc.kill()
