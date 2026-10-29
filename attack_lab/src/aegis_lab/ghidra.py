"""Bounded headless Ghidra evidence exporter for locally authorized artifacts.

Not an AEGIS attack_lab adapter. A real attack adapter must be gated by both
Core authorization controls; this module never compiles or executes the input.
Ghidra parses arbitrary binary formats and is NOT executed in a sandbox here.

Report invariants (``report_violations``) are defined once here. The worker
applies them before publication, and every ``AnalysisReport`` enforces them
when it is constructed or parsed, so the evidence binder applies the same rules.
"""

from __future__ import annotations

import errno
import hashlib
import os
import pwd
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import IO, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, ValidationError, model_validator
from pydantic_core import PydanticCustomError

from .diagnostics import SafeArgumentParser, model_field_names, terminal_text, validation_issues
from .safe_io import LoadError, hash_regular_file, parse_strict_json, read_regular_file

SCHEMA = "aegis.lab.ghidra.v1"
EXPORTER_NAME = "AegisExportFunctions.java"
RESULT_NAME = "ghidra-analysis.json"
VALIDATED_GHIDRA_VERSIONS = ("12.1.4",)
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_EXPORT_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 128 * 1024
MAX_PROPERTIES_BYTES = 64 * 1024
MAX_LAUNCHER_BYTES = 1024 * 1024
MAX_EXPORTER_BYTES = 1024 * 1024
# Bound on decompiler messages and failure reasons, in UTF-16 code units (the
# exporter truncates in Java). Pydantic counts code points, which never exceed that.
MAX_DECOMPILER_MESSAGE_CHARS = 2000
KILL_GRACE_SECONDS = 5
SHA = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
# Versions are echoed in error messages, so only a conservative alphabet is accepted.
_VERSION_PATTERN = r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$"
_VERSION_RE = re.compile(_VERSION_PATTERN)
Version = Annotated[str, Field(pattern=_VERSION_PATTERN)]
# Log markers Ghidra 12.1.x emits when a step failed but the process still exits 0.
_FAILURE_MARKERS = {
    b"REPORT SCRIPT ERROR": "Ghidra reported a post-script error",
    b"REPORT: Analysis timed out": "Ghidra auto-analysis timed out; analysis is incomplete",
}

WORKER_ERROR_CATEGORIES = frozenset({
    "invalid_request",       # options or selector rejected before anything runs
    "invalid_input",         # input binary missing, not regular, too large or changed
    "invalid_installation",  # launcher, application.properties or exporter rejected
    "staging_failed",        # private scratch copy could not be created
    "output_failed",         # output directory unusable, replaced, or result exists
    "ghidra_start_failed",
    "ghidra_timeout",
    "ghidra_failed",         # non-zero exit, failure marker, or no export
    "invalid_ghidra_output",  # raw export unreadable, malformed or schema-invalid
    "analysis_rejected",     # export valid but violates the report invariants
    "integrity_failed",      # private input or exporter changed during analysis
})


class WorkerError(RuntimeError):
    """An analysis did not complete and must never count as a successful trial.

    The message is built only from fixed text, integers, the caller's own
    validated selector and pattern-checked version strings. It never contains a
    path, an operating-system message, Ghidra output or a rejected value.
    ``log_tail`` (redacted, bounded) and ``violations`` (fixed codes) are kept as
    attributes for programmatic diagnostics and are not part of the message.
    """

    def __init__(
        self, message: str, *, category: str, log_tail: str = "", violations: tuple[tuple[str, str], ...] = ()
    ) -> None:
        if category not in WORKER_ERROR_CATEGORIES:
            raise AssertionError(f"unregistered worker error category {category!r}")
        self.category = category
        self.log_tail = log_tail
        self.violations = violations
        super().__init__(message)


class ReportInvariantError(ValueError):
    """A schema-valid report violates the ``aegis.lab.ghidra.v1`` invariants.

    ``violations`` are ``(field path, reason)`` pairs of fixed strings and list
    indices only; they are safe to show.
    """

    def __init__(self, violations: tuple[tuple[str, str], ...]) -> None:
        self.violations = violations
        self.fields = tuple(path for path, _ in violations)
        super().__init__("invalid Ghidra report: " + ", ".join(f"{p}: {r}" for p, r in violations))


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# Exporter outcome per function. "completed_with_warnings" is a success whose
# decompiler message (DecompileResults.getErrorMessage()) was not empty.
DecompileStatus = Literal["completed", "completed_with_warnings", "timed_out", "cancelled", "failed_to_start", "failed"]
SUCCESS_STATUSES = frozenset({"completed", "completed_with_warnings"})
_FAILURE_TEXT = {
    "timed_out": "decompiler timed out",
    "cancelled": "decompilation cancelled",
    "failed_to_start": "decompiler failed to start",
    "failed": "decompiler error",
}
BoundedMessage = Annotated[str, Field(max_length=MAX_DECOMPILER_MESSAGE_CHARS)]


class FunctionEvidence(StrictRecord):
    name: Annotated[str, Field(min_length=1)]
    qualified_name: Annotated[str, Field(min_length=1)]
    entry_point: Annotated[str, Field(min_length=1)]
    is_thunk: StrictBool
    signature: str
    decompiler_signature: str
    decompile_success: StrictBool
    decompile_status: DecompileStatus
    decompiled_c: str
    decompiled_c_truncated: StrictBool
    decompiler_message: BoundedMessage
    decompiler_message_truncated: StrictBool
    error: BoundedMessage

    @model_validator(mode="after")
    def _check_outcome(self) -> FunctionEvidence:
        if self.decompile_success != (self.decompile_status in SUCCESS_STATUSES):
            raise ValueError("decompile_success inconsistent with decompile_status")
        if self.decompile_success and (not self.decompiled_c or self.error):
            raise ValueError("successful decompilation needs code and no error")
        if not self.decompile_success and (self.decompiled_c or not self.error):
            raise ValueError("failed decompilation must have an error and no code")
        if self.decompiled_c_truncated and not self.decompile_success:
            raise ValueError("truncation flag on a failed decompilation")
        if self.decompile_status == "completed" and self.decompiler_message:
            raise ValueError("decompiler message on a decompilation without warnings")
        if self.decompile_status == "completed_with_warnings" and not self.decompiler_message:
            raise ValueError("decompilation with warnings has no message")
        if self.decompiler_message_truncated and not self.decompiler_message:
            raise ValueError("message truncation flag without a message")
        return self


class RawAnalysis(StrictRecord):
    schema_version: Literal["aegis.lab.ghidra.v1"]
    ghidra_version: Version
    ghidra_release_name: Annotated[str, Field(min_length=1, max_length=64)]
    ghidra_build_date: Annotated[str, Field(min_length=1, max_length=64)]
    java_version: Annotated[str, Field(min_length=1, max_length=64)]
    analysis_timed_out: StrictBool
    program_name: Annotated[str, Field(min_length=1)]
    executable_sha256: SHA  # Ghidra's own digest of the bytes it imported
    executable_format: Annotated[str, Field(min_length=1)]
    language_id: Annotated[str, Field(min_length=1)]
    functions: Annotated[list[FunctionEvidence], Field(max_length=512)]
    matching_function_count: Annotated[StrictInt, Field(ge=0)]
    functions_limited: StrictBool

    @model_validator(mode="after")
    def _check_counts(self) -> RawAnalysis:
        if len(self.functions) > self.matching_function_count:
            raise ValueError("function count exceeds matching count")
        if self.functions_limited != (len(self.functions) < self.matching_function_count):
            raise ValueError("function limit flag inconsistent with count")
        return self


class BinaryIdentity(StrictRecord):
    name: Annotated[str, Field(min_length=1)]
    sha256: SHA
    size_bytes: Annotated[int, Field(ge=1)]


class ExportIdentity(StrictRecord):
    ghidra_version: Version
    ghidra_release_name: Annotated[str, Field(min_length=1)]
    ghidra_build_date: Annotated[str, Field(min_length=1)]
    ghidra_revision: str
    java_version: Annotated[str, Field(min_length=1)]
    ghidra_launcher_sha256: SHA
    ghidra_application_properties_sha256: SHA
    exporter_name: Literal["AegisExportFunctions.java"] = EXPORTER_NAME
    exporter_script_sha256: SHA
    selected_function: Annotated[str, Field(min_length=1, max_length=200)]
    max_functions: Annotated[int, Field(ge=1, le=512)]
    max_c_chars: Annotated[int, Field(ge=100, le=20000)]
    decompile_timeout_seconds: Annotated[int, Field(ge=1, le=120)]
    analysis_timeout_seconds: Annotated[int, Field(ge=1, le=600)]
    wall_timeout_seconds: Annotated[int, Field(ge=1, le=3600)]


REPORT_INVARIANT_ERROR = "aegis_ghidra_report_invalid"
OBSERVED_RUNTIME_FIELDS = ("ghidra_release_name", "ghidra_build_date", "java_version")


class AnalysisReport(StrictRecord):
    """The published record. Construction or parsing enforces ``report_violations``."""

    schema_version: Literal["aegis.lab.ghidra.v1"] = SCHEMA
    binary: BinaryIdentity
    export: ExportIdentity
    analysis: RawAnalysis
    decompiled_ok_count: Annotated[int, Field(ge=1)]
    decompile_failed_count: Annotated[int, Field(ge=0)]
    duration_seconds: Annotated[float, Field(ge=0)]
    warnings_and_logs: str
    log_bytes_total: Annotated[int, Field(ge=0)]
    log_truncated: StrictBool
    limitations: list[str]

    @model_validator(mode="after")
    def _check_invariants(self) -> AnalysisReport:
        violations = report_violations(self)
        if violations:
            raise PydanticCustomError(
                REPORT_INVARIANT_ERROR, "report violates the aegis.lab.ghidra.v1 invariants", {"violations": violations}
            )
        return self


RAW_FIELDS = model_field_names(RawAnalysis)
REPORT_FIELDS = model_field_names(AnalysisReport)


def _utf16_units(text: str) -> int:
    """Length as the Java exporter measures it."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def analysis_violations(
    analysis: RawAnalysis,
    *,
    selector: str,
    max_functions: int,
    max_c_chars: int,
    program_name: str,
    executable_sha256: str,
) -> tuple[tuple[str, str], ...]:
    """Every rule an exporter result must satisfy for the request that produced it.

    Returns ``(field path, reason)`` pairs; empty means acceptable. Wildcard
    selections may contain failed decompilations as long as one succeeded; an
    exact selector must identify one function that decompiled successfully.
    Decompiler warnings and truncation are permitted and reported, not rejected.
    """
    found: list[tuple[str, str]] = []
    functions = analysis.functions
    if analysis.analysis_timed_out:
        found.append(("analysis.analysis_timed_out", "analysis_incomplete"))
    if analysis.program_name != program_name:
        found.append(("analysis.program_name", "not_analyzed_input"))
    if analysis.executable_sha256 != executable_sha256:
        found.append(("analysis.executable_sha256", "not_analyzed_input"))
    if len(functions) > max_functions:
        found.append(("analysis.functions", "exceeds_max_functions"))
    elif len(functions) != min(analysis.matching_function_count, max_functions):
        found.append(("analysis.functions", "count_inconsistent"))
    entries: set[str] = set()
    for index, fn in enumerate(functions):
        if selector != "*" and selector not in (fn.name, fn.qualified_name):
            found.append((f"analysis.functions.{index}.name", "not_selected"))
        units = _utf16_units(fn.decompiled_c)
        if units > max_c_chars:
            found.append((f"analysis.functions.{index}.decompiled_c", "exceeds_max_c_chars"))
        elif fn.decompiled_c_truncated and units < max_c_chars - 1:
            # The exporter cuts at max_c_chars, or one unit earlier to keep a surrogate pair.
            found.append((f"analysis.functions.{index}.decompiled_c_truncated", "truncation_inconsistent"))
        if fn.entry_point in entries:
            found.append((f"analysis.functions.{index}.entry_point", "duplicate"))
        entries.add(fn.entry_point)
    if not functions:
        found.append(("analysis.functions", "no_matching_function"))
    elif selector != "*":
        if analysis.matching_function_count != 1 or len(functions) != 1:
            found.append(("analysis.matching_function_count", "ambiguous_selector"))
        elif not functions[0].decompile_success:
            found.append(("analysis.functions.0.decompile_status", "selected_function_failed"))
    if functions and not any(fn.decompile_success for fn in functions):
        found.append(("analysis.functions", "none_decompiled"))
    return tuple(found)


def report_violations(report: AnalysisReport) -> tuple[tuple[str, str], ...]:
    """``analysis_violations`` for the request recorded in the report, plus internal consistency."""
    found = list(analysis_violations(
        report.analysis,
        selector=report.export.selected_function,
        max_functions=report.export.max_functions,
        max_c_chars=report.export.max_c_chars,
        program_name=report.binary.name,
        executable_sha256=report.binary.sha256,
    ))
    if report.analysis.ghidra_version != report.export.ghidra_version:
        found.append(("analysis.ghidra_version", "mismatch"))
    for name in OBSERVED_RUNTIME_FIELDS:
        if getattr(report.analysis, name) != getattr(report.export, name):
            found.append((f"analysis.{name}", "mismatch"))
    succeeded = sum(1 for fn in report.analysis.functions if fn.decompile_success)
    if (report.decompiled_ok_count, report.decompile_failed_count) != (succeeded, len(report.analysis.functions) - succeeded):
        found.append(("decompiled_ok_count", "inconsistent"))
    if report.log_truncated != (report.log_bytes_total > MAX_LOG_BYTES):
        found.append(("log_truncated", "inconsistent"))
    return tuple(found)


def _invariant_violations(exc: ValidationError) -> tuple[tuple[str, str], ...]:
    for error in exc.errors(include_url=False, include_input=False):
        if error["type"] == REPORT_INVARIANT_ERROR:
            return tuple(error["ctx"]["violations"])
    return ()


def parse_raw_analysis(data: bytes) -> RawAnalysis:
    """Parse the exporter's raw JSON. Raises LoadError or pydantic.ValidationError.

    Strict JSON first: duplicate keys, NaN/Infinity, overflowing numbers and
    invalid UTF-8 are rejected before schema validation.
    """
    parse_strict_json(data)
    return RawAnalysis.model_validate_json(data)


def parse_analysis_report(data: bytes) -> AnalysisReport:
    """Parse a published report. Raises LoadError, pydantic.ValidationError or ReportInvariantError.

    The same strict JSON and invariant rules the worker applied before publication.
    """
    parse_strict_json(data)
    try:
        return AnalysisReport.model_validate_json(data)
    except ValidationError as exc:
        violations = _invariant_violations(exc)
        if violations:
            raise ReportInvariantError(violations) from None
        raise


# --- Local files --------------------------------------------------------------------------------
# Policy (see safe_io): the final path component must not be a symlink; parent
# directories are resolved normally. Only regular files are opened, without
# blocking (a FIFO or device is rejected, never waited on), and reads are bounded.

def _load_failure(role: str, exc: LoadError, maximum: int, category: str) -> WorkerError:
    if exc.category in ("too_large", "empty"):
        return WorkerError(f"{role} size is zero or exceeds {maximum} bytes", category=category)
    if exc.category in ("not_found", "symlink_rejected", "not_regular_file"):
        return WorkerError(f"{role} must be an existing regular file, not a symlink", category=category)
    if exc.category == "file_changed":
        return WorkerError(f"{role} changed while it was being read", category=category)
    return WorkerError(f"{role} could not be read ({exc.category})", category=category)


def sha256_file(path: Path, maximum: int, *, role: str = "file", category: str = "invalid_input") -> str:
    try:
        return hash_regular_file(path, maximum)[0]
    except LoadError as exc:
        raise _load_failure(role, exc, maximum, category) from None


def _verify_regular_file(path: Path, role: str, *, maximum: int | None = None, category: str = "invalid_input") -> Path:
    """Early check by ``lstat`` (never opens, so it cannot block). Opening is re-checked later."""
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        raise WorkerError(f"{role} must be an existing regular file, not a symlink", category=category) from None
    if not stat.S_ISREG(st.st_mode):
        raise WorkerError(f"{role} must be an existing regular file, not a symlink", category=category)
    if maximum is not None and (st.st_size == 0 or st.st_size > maximum):
        raise WorkerError(f"{role} size is zero or exceeds {maximum} bytes", category=category)
    return path.absolute()


def _private_copy(source: Path, destination: Path, role: str, maximum: int, category: str) -> tuple[str, int]:
    """Copy under the safe_io policy, hashing exactly the bytes that were copied.

    Ghidra then reads only the private copy, so a later change or swap of the
    caller's file cannot alter what is analyzed after it was hashed.
    """
    try:
        out_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(out_fd, "wb") as dst:
            digest, size = hash_regular_file(source, maximum, dst.write)
        os.chmod(destination, 0o400)
    except LoadError as exc:
        raise _load_failure(role, exc, maximum, category) from None
    except OSError:
        raise WorkerError(f"cannot stage a private copy of the {role}", category="staging_failed") from None
    return digest, size


def _read_application_properties(headless: Path) -> tuple[dict[str, str], str]:
    """Read the version declared by the Ghidra installation that owns the launcher."""
    path = headless.parent.parent / "Ghidra" / "application.properties"
    try:
        data = read_regular_file(path, MAX_PROPERTIES_BYTES)
    except LoadError as exc:
        if exc.category == "too_large":
            raise WorkerError("Ghidra application.properties exceeds size limit", category="invalid_installation") from None
        raise WorkerError(
            "launcher is not inside a Ghidra installation (Ghidra/application.properties missing or not a regular file)",
            category="invalid_installation",
        ) from None
    values: dict[str, str] = {}
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")) and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    if not _VERSION_RE.fullmatch(values.get("application.version", "")):
        raise WorkerError("Ghidra application.properties declares no valid application.version", category="invalid_installation")
    return values, hashlib.sha256(data).hexdigest()


# --- Process control ---------------------------------------------------------------------------

class _LogCollector(threading.Thread):
    """Drain the analyzer's combined output, keeping only a bounded tail in memory.

    Failure markers are detected over the full stream, so truncation cannot
    hide them.
    """

    def __init__(self, stream: IO[bytes]) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._tail = bytearray()
        self._carry = b""
        self._overlap = max(len(m) for m in _FAILURE_MARKERS) - 1
        self.total = 0
        self.markers: set[bytes] = set()

    def run(self) -> None:
        read = getattr(self._stream, "read1", self._stream.read)
        while chunk := read(65536):
            self.total += len(chunk)
            window = self._carry + chunk
            self.markers.update(m for m in _FAILURE_MARKERS if m in window)
            self._carry = window[-self._overlap:]
            self._tail += chunk
            if len(self._tail) > MAX_LOG_BYTES:
                del self._tail[: len(self._tail) - MAX_LOG_BYTES]

    def tail(self) -> str:
        return bytes(self._tail).decode("utf-8", "replace")


def _wait_unreaped(process: subprocess.Popen[bytes], timeout: float) -> bool:
    """Wait for exit without reaping, so the process-group id cannot be reused yet."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                return True
        except ChildProcessError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        process.kill()


def _redactor(scratch: Path, ghidra_root: Path):
    """Replace local paths and the account name in tool logs before they are shared."""
    pairs: dict[str, str] = {}
    for path, label in ((scratch, "<scratch>"), (ghidra_root, "<ghidra>"), (Path.home(), "~")):
        for variant in {str(path), os.path.realpath(path)}:
            if len(variant) > 1:
                pairs[variant] = label
    ordered = sorted(pairs.items(), key=lambda item: len(item[0]), reverse=True)
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        user = ""
    user_re = re.compile(rf"(?<![A-Za-z0-9_.]){re.escape(user)}(?![A-Za-z0-9_.])") if len(user) >= 3 else None

    def redact(text: str) -> str:
        for original, label in ordered:
            text = text.replace(original, label)
        return user_re.sub("<user>", text) if user_re else text

    return redact


def _errno_name(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, "unknown")


def _violation_error(violations: tuple[tuple[str, str], ...], selector: str, analysis: RawAnalysis, tail: str) -> WorkerError:
    """Describe the first violation with fixed text; never echo exporter-controlled strings."""
    path, reason = violations[0]
    if reason == "ambiguous_selector":
        message = (f"ambiguous selector {selector!r}: {analysis.matching_function_count} functions match; "
                   "use a namespace-qualified name")
    elif reason == "selected_function_failed":
        message = f"decompilation of {selector!r} failed: {_FAILURE_TEXT[analysis.functions[0].decompile_status]}"
    elif reason == "no_matching_function":
        message = f"no matching analyzed functions for selector {selector!r}"
    else:
        message = {
            "analysis_incomplete": "Ghidra auto-analysis timed out; analysis is incomplete",
            "not_analyzed_input": "exported program is not the analyzed input",
            "exceeds_max_functions": "exporter returned more functions than requested",
            "count_inconsistent": "exporter function counts are inconsistent",
            "not_selected": "exporter returned a non-matching function",
            "exceeds_max_c_chars": "exporter exceeded the decompiled source length limit",
            "truncation_inconsistent": "exporter truncation flag is inconsistent with the source length",
            "duplicate": "exporter returned duplicate function entry points",
            "none_decompiled": "no exported function decompiled successfully",
        }.get(reason, "exporter output violates the report invariants")
    return WorkerError(f"{message} ({path})", category="analysis_rejected", log_tail=tail, violations=violations)


def _publish(dir_fd: int, output_dir: Path, data: bytes) -> None:
    """Atomically publish ``data`` as RESULT_NAME inside the directory opened as ``dir_fd``.

    All names are resolved relative to the descriptor, so replacing the output
    path with a symlink cannot redirect the write. Publication is refused if the
    path no longer names that directory, and an existing result is never replaced.
    """
    try:
        opened, current = os.fstat(dir_fd), os.lstat(output_dir)
    except OSError:
        raise WorkerError("output directory was removed during analysis", category="output_failed") from None
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino) or not stat.S_ISDIR(current.st_mode):
        raise WorkerError("output directory was replaced during analysis", category="output_failed")
    partial = f".ghidra-analysis.{secrets.token_hex(8)}.partial"
    try:
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
    except OSError as exc:
        raise WorkerError(f"cannot write to output directory ({_errno_name(exc)})", category="output_failed") from None
    try:
        with os.fdopen(fd, "wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        os.link(partial, RESULT_NAME, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
        os.fsync(dir_fd)
    except FileExistsError:
        raise WorkerError("analysis result already exists; use a new output directory", category="output_failed") from None
    except OSError as exc:
        raise WorkerError(f"cannot publish analysis result ({_errno_name(exc)})", category="output_failed") from None
    finally:
        try:
            os.unlink(partial, dir_fd=dir_fd)
        except FileNotFoundError:
            pass


def analyze(
    binary: Path,
    output_dir: Path,
    headless: Path,
    *,
    expected_sha256: str | None = None,
    expected_ghidra_version: str | None = None,
    function: str = "*",
    max_functions: int = 64,
    max_c_chars: int = 12000,
    decompile_timeout_seconds: int = 30,
    analysis_timeout_seconds: int = 120,
    wall_timeout_seconds: int = 300,
    script_path: Path | None = None,
) -> Path:
    """Analyze a trusted local test binary and atomically publish one JSON report.

    Does not follow symlinks for the input, execute target code, call a model,
    or bypass the Core attack authorization gate; it is not a Core adapter.
    """
    if not (1 <= max_functions <= 512 and 100 <= max_c_chars <= 20000):
        raise WorkerError("invalid function count or source length limit", category="invalid_request")
    if not (1 <= decompile_timeout_seconds <= 120 and 1 <= analysis_timeout_seconds <= 600):
        raise WorkerError("invalid analysis/decompiler timeout", category="invalid_request")
    if not (1 <= wall_timeout_seconds <= 3600):
        raise WorkerError("invalid wall timeout", category="invalid_request")
    if not function or len(function) > 200:
        raise WorkerError("function selector must contain 1–200 characters", category="invalid_request")
    if function.startswith("-") or any(ord(c) < 0x20 or ord(c) == 0x7F for c in function):
        # Ghidra would parse a leading '-' as an option rather than a script argument.
        raise WorkerError("function selector must not start with '-' or contain control characters", category="invalid_request")
    if expected_sha256 is not None and not _SHA_RE.fullmatch(expected_sha256):
        raise WorkerError("expected SHA-256 must be 64 lowercase hexadecimal characters", category="invalid_request")
    if expected_ghidra_version is not None and not _VERSION_RE.fullmatch(expected_ghidra_version):
        raise WorkerError("expected Ghidra version has an invalid format", category="invalid_request")

    binary = _verify_regular_file(Path(binary), "input binary", maximum=MAX_BINARY_BYTES)
    headless = _verify_regular_file(Path(headless), "headless launcher", category="invalid_installation")
    if not os.access(headless, os.X_OK):
        raise WorkerError("headless launcher is not executable", category="invalid_installation")
    exporter = Path(script_path) if script_path is not None else Path(__file__).resolve().parents[2] / "scripts" / EXPORTER_NAME
    exporter = _verify_regular_file(exporter, "Ghidra exporter", category="invalid_installation")
    if exporter.name != EXPORTER_NAME:
        raise WorkerError("unexpected exporter script name", category="invalid_installation")
    properties, properties_sha256 = _read_application_properties(headless)
    declared_version = properties["application.version"]
    if expected_ghidra_version is not None and declared_version != expected_ghidra_version:
        raise WorkerError(
            f"Ghidra installation is {declared_version}, expected {expected_ghidra_version}", category="invalid_installation"
        )
    # The launcher is executed by path after this; see the README limitations.
    launcher_sha256 = sha256_file(headless, MAX_LAUNCHER_BYTES, role="headless launcher", category="invalid_installation")

    output_dir = Path(output_dir)
    if output_dir.is_symlink():
        raise WorkerError("output directory must not be a symlink", category="output_failed")
    result_path = output_dir.absolute() / RESULT_NAME
    if result_path.exists() or result_path.is_symlink():
        raise WorkerError("analysis result already exists; use a new output directory", category="output_failed")

    with tempfile.TemporaryDirectory(prefix="aegis-ghidra-") as scratch_name:
        scratch = Path(scratch_name)
        if any(c.isspace() for c in str(scratch)):
            # The launcher splits GHIDRA_HEADLESS_JAVA_OPTIONS on whitespace.
            raise WorkerError("temporary directory path must not contain whitespace", category="staging_failed")
        redact = _redactor(scratch, headless.parent.parent)
        for sub in ("input", "scripts", "project", "config", "cache", "jtmp"):
            (scratch / sub).mkdir(mode=0o700)
        private_binary = scratch / "input" / binary.name
        expected, size = _private_copy(binary, private_binary, "input binary", MAX_BINARY_BYTES, "invalid_input")
        if expected_sha256 is not None and expected != expected_sha256:
            raise WorkerError("binary SHA-256 does not match the expected digest", category="invalid_input")
        private_exporter = scratch / "scripts" / EXPORTER_NAME
        exporter_sha256, _ = _private_copy(
            exporter, private_exporter, "Ghidra exporter", MAX_EXPORTER_BYTES, "invalid_installation"
        )

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WorkerError(f"cannot create output directory ({_errno_name(exc)})", category="output_failed") from None
        output_dir = output_dir.absolute()
        try:
            dir_fd = os.open(output_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise WorkerError("invalid output directory (must be a directory, not a symlink)", category="output_failed") from None
        try:
            report = _run_and_build(
                headless=headless, scratch=scratch, redact=redact, private_binary=private_binary,
                private_exporter=private_exporter, binary_name=binary.name, expected=expected, size=size,
                exporter_sha256=exporter_sha256, launcher_sha256=launcher_sha256, properties=properties,
                properties_sha256=properties_sha256, declared_version=declared_version, function=function,
                max_functions=max_functions, max_c_chars=max_c_chars,
                decompile_timeout_seconds=decompile_timeout_seconds,
                analysis_timeout_seconds=analysis_timeout_seconds, wall_timeout_seconds=wall_timeout_seconds,
            )
            data = report.model_dump_json(indent=2).encode("utf-8")
            # Publish only bytes that the evidence binder's own parser accepts.
            try:
                parse_analysis_report(data)
            except (LoadError, ValidationError, ReportInvariantError):
                raise WorkerError("report failed its own validation before publication", category="analysis_rejected") from None
            _publish(dir_fd, output_dir, data)
        finally:
            os.close(dir_fd)
    return result_path


def _run_and_build(
    *, headless: Path, scratch: Path, redact, private_binary: Path, private_exporter: Path, binary_name: str,
    expected: str, size: int, exporter_sha256: str, launcher_sha256: str, properties: dict[str, str],
    properties_sha256: str, declared_version: str, function: str, max_functions: int, max_c_chars: int,
    decompile_timeout_seconds: int, analysis_timeout_seconds: int, wall_timeout_seconds: int,
) -> AnalysisReport:
    raw_report = scratch / "ghidra-raw.json"
    command = [
        str(headless), str(scratch / "project"), "aegis_analysis",
        "-scriptPath", str(private_exporter.parent),
        "-import", str(private_binary),
        "-postScript", EXPORTER_NAME, str(raw_report), function,
        str(max_functions), str(max_c_chars), str(decompile_timeout_seconds),
        "-analysisTimeoutPerFile", str(analysis_timeout_seconds),
        "-deleteProject",
    ]
    # Ghidra itself is a trusted developer tool. Deliberately do not forward
    # arbitrary token/provider variables into its process environment, and
    # keep its settings, cache and temporary files inside the scratch tree.
    env = {k: os.environ[k] for k in ("PATH", "JAVA_HOME", "LANG", "LC_ALL") if k in os.environ}
    env["HOME"] = str(scratch)
    env["TMPDIR"] = str(scratch / "jtmp")
    env["XDG_CONFIG_HOME"] = str(scratch / "config")
    env["XDG_CACHE_HOME"] = str(scratch / "cache")
    env["GHIDRA_HEADLESS_JAVA_OPTIONS"] = f"-Djava.io.tmpdir={scratch / 'jtmp'} -XX:-UsePerfData"
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=str(scratch), env=env, start_new_session=True,
        )
    except OSError as exc:
        raise WorkerError(f"failed to start Ghidra ({_errno_name(exc)})", category="ghidra_start_failed") from None
    collector = _LogCollector(process.stdout)
    collector.start()
    try:
        exited = _wait_unreaped(process, wall_timeout_seconds)
    finally:
        # Always kill the whole group: on timeout, on interrupt, and after a
        # normal exit to remove any stragglers (e.g. decompiler processes).
        _terminate_group(process)
        try:
            process.wait(timeout=KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        collector.join(timeout=KILL_GRACE_SECONDS)
        if not collector.is_alive() and process.stdout is not None:
            process.stdout.close()
    elapsed = round(time.monotonic() - started, 3)
    returncode = process.returncode
    tail = redact(collector.tail())
    if not exited:
        raise WorkerError(f"Ghidra exceeded {wall_timeout_seconds}s wall time", category="ghidra_timeout", log_tail=tail)
    if collector.is_alive():
        raise WorkerError("Ghidra output stream stayed open after its process group was killed",
                          category="ghidra_timeout", log_tail=tail)
    if returncode != 0:
        raise WorkerError(f"Ghidra exited {returncode}", category="ghidra_failed", log_tail=tail)
    for marker, message in _FAILURE_MARKERS.items():
        if marker in collector.markers:
            raise WorkerError(message, category="ghidra_failed", log_tail=tail)
    try:
        raw_bytes = read_regular_file(raw_report, MAX_EXPORT_BYTES)
        parsed = parse_raw_analysis(raw_bytes)
    except LoadError as exc:
        if exc.category == "not_found":
            raise WorkerError("Ghidra exited without exporting structured evidence",
                              category="ghidra_failed", log_tail=tail) from None
        if exc.category == "too_large":
            raise WorkerError("Ghidra report exceeds bounded export limit",
                              category="invalid_ghidra_output", log_tail=tail) from None
        raise WorkerError(f"invalid Ghidra structured output: {exc.category}",
                          category="invalid_ghidra_output", log_tail=tail) from None
    except ValidationError as exc:
        issues = "; ".join(validation_issues(exc, RAW_FIELDS)[:5])
        raise WorkerError(f"invalid Ghidra structured output: {issues}",
                          category="invalid_ghidra_output", log_tail=tail) from None
    if parsed.ghidra_version != declared_version:
        raise WorkerError(
            f"running Ghidra reported version {parsed.ghidra_version}, installation declares {declared_version}",
            category="invalid_ghidra_output", log_tail=tail,
        )
    violations = analysis_violations(
        parsed, selector=function, max_functions=max_functions, max_c_chars=max_c_chars,
        program_name=private_binary.name, executable_sha256=expected,
    )
    if violations:
        raise _violation_error(violations, function, parsed, tail)
    if sha256_file(private_binary, MAX_BINARY_BYTES, category="integrity_failed") != expected:
        raise WorkerError("input binary changed during analysis", category="integrity_failed")
    if sha256_file(private_exporter, MAX_EXPORTER_BYTES, category="integrity_failed") != exporter_sha256:
        raise WorkerError("exporter script changed during analysis", category="integrity_failed")

    ok = sum(1 for f in parsed.functions if f.decompile_success)
    limitations = [
        "Ghidra decompilation is an analyst hypothesis, not behavioral reconstruction.",
        "This tool runs Ghidra outside a hardened binary-analysis sandbox and is limited to authorized local inputs.",
        "This is not an AEGIS attack_lab adapter and does not establish a reconstruction outcome.",
        "Function names, signatures and decompiled code reveal program internals; treat this report as a build artifact.",
        "Local paths and the account name in the log tail are redacted on a best-effort basis.",
        "This report is not signed; its fields do not authenticate which process produced it.",
    ]
    if parsed.ghidra_version not in VALIDATED_GHIDRA_VERSIONS:
        limitations.append(
            f"The exporter was validated with Ghidra {', '.join(VALIDATED_GHIDRA_VERSIONS)} only; "
            f"this run used {parsed.ghidra_version}."
        )
    if parsed.functions_limited:
        limitations.append("More functions matched than were exported (max_functions limit).")
    if any(f.decompiled_c_truncated for f in parsed.functions):
        limitations.append("At least one decompiled function was truncated at max_c_chars.")
    if any(f.decompile_status == "completed_with_warnings" for f in parsed.functions):
        limitations.append("The decompiler reported warnings for at least one function; see decompiler_message.")
    if any(f.decompiler_message_truncated for f in parsed.functions):
        limitations.append("At least one decompiler message was truncated.")
    if ok != len(parsed.functions):
        limitations.append("Decompilation failed for some exported functions; see per-function errors.")

    try:
        return AnalysisReport(
            binary=BinaryIdentity(name=binary_name, sha256=expected, size_bytes=size),
            export=ExportIdentity(
                ghidra_version=parsed.ghidra_version,
                ghidra_release_name=parsed.ghidra_release_name,
                ghidra_build_date=parsed.ghidra_build_date,
                ghidra_revision=properties.get("application.revision.ghidra", ""),
                java_version=parsed.java_version,
                ghidra_launcher_sha256=launcher_sha256,
                ghidra_application_properties_sha256=properties_sha256,
                exporter_script_sha256=exporter_sha256,
                selected_function=function, max_functions=max_functions, max_c_chars=max_c_chars,
                decompile_timeout_seconds=decompile_timeout_seconds,
                analysis_timeout_seconds=analysis_timeout_seconds,
                wall_timeout_seconds=wall_timeout_seconds,
            ),
            analysis=parsed,
            decompiled_ok_count=ok,
            decompile_failed_count=len(parsed.functions) - ok,
            duration_seconds=elapsed,
            warnings_and_logs=tail,
            log_bytes_total=collector.total,
            log_truncated=collector.total > MAX_LOG_BYTES,
            limitations=limitations,
        )
    except ValidationError as exc:
        violations = _invariant_violations(exc)
        if violations:
            raise _violation_error(violations, function, parsed, tail) from None
        issues = "; ".join(validation_issues(exc, REPORT_FIELDS)[:5])
        raise WorkerError(f"invalid Ghidra structured output: {issues}",
                          category="invalid_ghidra_output", log_tail=tail) from None


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(
        prog="python -m aegis_lab.ghidra",
        description="Export structured Ghidra analysis for an authorized local artifact",
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--headless", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--expected-ghidra-version", help="fail unless the installation declares this version")
    parser.add_argument("--function", default="*", help="exact function name, namespace-qualified name, or *")
    parser.add_argument("--max-functions", type=int, default=64)
    parser.add_argument("--max-c-chars", type=int, default=12000)
    parser.add_argument("--decompile-timeout", type=int, default=30, help="seconds per function (1-120)")
    parser.add_argument("--analysis-timeout", type=int, default=120, help="Ghidra auto-analysis seconds (1-600)")
    parser.add_argument("--wall-timeout", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        result = analyze(args.binary, args.output_dir, args.headless,
                         expected_sha256=args.expected_sha256,
                         expected_ghidra_version=args.expected_ghidra_version, function=args.function,
                         max_functions=args.max_functions, max_c_chars=args.max_c_chars,
                         decompile_timeout_seconds=args.decompile_timeout,
                         analysis_timeout_seconds=args.analysis_timeout,
                         wall_timeout_seconds=args.wall_timeout)
    except WorkerError as exc:
        print(f"AEGIS Ghidra analysis failed [{exc.category}]: {terminal_text(str(exc))}", file=sys.stderr)
        return 1
    except Exception as exc:  # never let an unexpected message reach the terminal
        print(f"AEGIS Ghidra analysis failed [internal_error]: {type(exc).__name__}", file=sys.stderr)
        return 3
    print(terminal_text(str(result), limit=4096))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
