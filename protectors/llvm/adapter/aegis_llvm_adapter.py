"""LLVM Shield bridge for aegis.adapter.v1 (POSIX, Python >= 3.11).

Run through aegis_core: its process group and timeout cover this process and
every LLVM child. Children deliberately inherit that group; starting a new
session here would let them outlive the orchestrator's timeout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from report import InvalidReport, strict_json, validate_report

PROTOCOL = "aegis.adapter.v1"
CHUNK = 65536
LOG_LIMIT = 65536
REQUEST_LIMIT = 512 * 1024
UINT64_MAX = 2**64 - 1


class Failure(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message


def fail(code, message):
    raise Failure(code, message)


def regular(path, limit, *, nonempty=True, too_large="OUTPUT_TOO_LARGE"):
    """Reject links (including hardlinks), special files and oversized files."""
    try:
        info = path.lstat()
    except OSError:
        fail("INVALID_ARTIFACT", "A required artifact is missing or unreadable.")
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or path.resolve() != path.absolute()):
        fail("UNSAFE_PATH", "Artifact must be a regular, unlinked file at a safe path.")
    if info.st_size > limit:
        fail(too_large, "An artifact exceeds its configured byte limit.")
    if nonempty and not info.st_size:
        fail("EMPTY_ARTIFACT", "A required artifact is empty.")
    return info


def bounded_read(path, limit):
    regular(path, limit)
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        fail("OUTPUT_TOO_LARGE", "An artifact exceeds its configured byte limit.")
    return raw


def safe_directory(path):
    if (not path.is_absolute() or path.resolve() != path or not path.is_dir()):
        fail("UNSAFE_PATH", "Job directories must be absolute and contain no symlinks.")


def read_request(path, work):
    try:
        request = strict_json(bounded_read(path, REQUEST_LIMIT))
    except (ValueError, RecursionError):
        fail("INVALID_REQUEST", "Request is not valid JSON.")
    fields = {"protocol", "job_id", "task", "backend", "policy_name", "input_path",
              "input_sha256", "output_dir", "options", "authorization"}
    required = fields - {"options", "authorization"}
    if type(request) is not dict or request.keys() - fields or required - request.keys():
        fail("INVALID_REQUEST", "Request fields do not match aegis.adapter.v1.")
    if request["protocol"] != PROTOCOL:
        fail("INVALID_REQUEST", "Unsupported adapter protocol.")
    if request["task"] != "protect" or request.get("authorization") is not None:
        fail("UNSUPPORTED_TASK", "LLVM Shield accepts protection jobs only.")
    for key, pattern in (("job_id", r"[0-9a-f]{32}"),
                         ("input_sha256", r"[0-9a-f]{64}"),
                         ("backend", r"[a-z0-9][a-z0-9_-]{0,63}"),
                         ("policy_name", r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")):
        if type(request[key]) is not str or not re.fullmatch(pattern, request[key]):
            fail("INVALID_REQUEST", "Invalid request identifier.")
    safe_directory(work)
    job = work.parent
    if work.name != "work" or job.name != request["job_id"]:
        fail("UNSAFE_PATH", "Adapter must run in the core job work directory.")
    if path != job / "adapter/request.json":
        fail("UNSAFE_PATH", "Request must be the core job's adapter/request.json.")
    if any(type(request[key]) is not str or "\x00" in request[key]
           for key in ("input_path", "output_dir")):
        fail("INVALID_REQUEST", "Invalid artifact paths.")
    source, output = Path(request["input_path"]), Path(request["output_dir"])
    if (not source.is_absolute() or source.parent != job / "inputs"
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", source.name)
            or output != job / "outputs"):
        fail("UNSAFE_PATH", "Artifact paths do not belong to this job.")
    safe_directory(source.parent)
    safe_directory(output)
    if any(output.iterdir()):
        fail("UNSAFE_PATH", "Output directory must be empty before invocation.")
    return request, source, output


def shield_config(options):
    if type(options) is not dict or options.keys() - {"seed", "max-sites", "enabled"}:
        fail("INVALID_OPTIONS", "Only seed, max-sites and enabled options are supported.")
    seed = options.get("seed", "0")
    if (type(seed) is not str or not re.fullmatch(r"[0-9]{1,20}", seed)
            or int(seed) > UINT64_MAX):
        fail("INVALID_OPTIONS", "seed must be a decimal uint64 string (at most 20 digits).")
    budget = options.get("max-sites", 16)
    enabled = options.get("enabled", True)
    if type(budget) is not int or not 0 <= budget <= 1_000_000:
        fail("INVALID_OPTIONS", "max-sites must be an integer from 0 to 1000000.")
    if type(enabled) is not bool:
        fail("INVALID_OPTIONS", "enabled must be a boolean.")
    # Explicit conversion to urn:aegis-shield-llvm:config:1. No schema changes.
    return {"schema_version": 1, "seed": str(int(seed)),
            "max_sites_per_function": budget, "enabled": enabled}


def tool_path(raw):
    # These are operator configuration, never request options. Paths containing
    # slashes must be absolute because the core runs us in a job work directory.
    if "/" in raw and not Path(raw).is_absolute():
        fail("INVALID_CONFIGURATION", "Tool paths with slashes must be absolute.")
    found = shutil.which(raw)
    if not found or not Path(found).is_file():
        fail("TOOL_UNAVAILABLE", "The configured opt executable is unavailable.")
    return str(Path(found).absolute())


def tool_environment(work):
    return {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "HOME": str(work), "TMPDIR": str(work)}


def run_tool(argv, scratch, watched, file_cap):
    """Spool bounded diagnostics, preserving the core-owned process group.

    RLIMIT_FSIZE provides a hard per-file ceiling, including temporary reports.
    Polling also enforces the smaller individual report/IR/log limits. The core
    owns the wall timeout and kills the entire inherited group, including LLVM.
    """
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_cap, file_cap))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    stdout_path, stderr_path = scratch / "tool.stdout", scratch / "tool.stderr"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            proc = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, cwd=scratch,
                                    env=tool_environment(scratch), close_fds=True)
        except OSError:
            fail("TOOL_UNAVAILABLE", "LLVM could not be started.")
        exceeded = False
        try:
            while proc.poll() is None:
                if any(p.exists() and p.lstat().st_size > limit
                       for p, limit in [*watched, (stdout_path, LOG_LIMIT), (stderr_path, LOG_LIMIT)]):
                    exceeded = True
                    break
                time.sleep(0.02)
        finally:
            # Reap LLVM even if a filesystem/monitoring error interrupts us.
            # Core's hard timeout still covers this whole inherited group.
            if proc.poll() is None:
                proc.kill()
            proc.wait()
    for path, limit in [*watched, (stdout_path, LOG_LIMIT), (stderr_path, LOG_LIMIT)]:
        if path.exists() and path.lstat().st_size > limit:
            exceeded = True
    if exceeded or proc.returncode == -signal.SIGXFSZ:
        fail("OUTPUT_TOO_LARGE", "LLVM exceeded an output or diagnostic byte limit.")
    if proc.returncode:
        # Diagnostics can contain source text and function names: bounded,
        # private job stderr only, never copy them into user-facing errors.
        sys.stderr.buffer.write(stderr_path.read_bytes()[:LOG_LIMIT])
        fail("LLVM_FAILED", "LLVM rejected the input, plugin or configuration.")
    return stdout_path.read_bytes()[:LOG_LIMIT]


def stage_input(source, dest, expected_hash, limit):
    regular(source, limit, too_large="INPUT_TOO_LARGE")
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as src, dest.open("xb") as out:
        while chunk := src.read(CHUNK):
            size += len(chunk)
            if size > limit:
                fail("INPUT_TOO_LARGE", "Input exceeds the adapter byte limit.")
            if b"\x00" in chunk:
                fail("UNSUPPORTED_FORMAT", "Only textual LLVM IR is accepted; no native binaries or bitcode.")
            # LLVM's parser is the final format validator; extension alone is
            # never trusted. No input or produced artifact is ever executed.
            if size == len(chunk) and chunk.startswith((b"\x7fELF", b"MZ", b"BC\xc0\xde",
                                                      b"\xde\xc0\x17\x0b", b"\xcf\xfa\xed\xfe")):
                fail("UNSUPPORTED_FORMAT", "Input is a binary, not textual LLVM IR.")
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != expected_hash:
        fail("ARTIFACT_INTEGRITY_ERROR", "Input does not match the orchestrator's SHA-256.")


def publish(source, dest, limit):
    regular(source, limit)
    # Exclusive creation refuses stale files, links, or collisions. No user
    # names are used for published artifacts. Core computes the final hashes.
    with source.open("rb") as src, dest.open("xb") as out:
        shutil.copyfileobj(src, out, CHUNK)
    regular(dest, limit)


def digest_file(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").digest()


def execute(args):
    work = Path.cwd()
    request, source, output = read_request(Path(args.aegis_request), work)
    config = shield_config(request.get("options", {}))
    opt = tool_path(args.opt)
    plugin = Path(args.plugin)
    if not plugin.is_absolute() or not plugin.is_file() or not os.access(plugin, os.R_OK):
        fail("PLUGIN_UNAVAILABLE", "Plugin must be an absolute readable regular file.")
    # Private work area and fixed filenames prevent pipeline injection even
    # when the store root contains ';', ',' or other pipeline metacharacters.
    with tempfile.TemporaryDirectory(prefix="shield-", dir=work) as temporary:
        scratch = Path(temporary)
        stage_input(source, scratch / "shield-input.ll", request["input_sha256"], args.max_input_bytes)
        (scratch / "shield-config.json").write_text(json.dumps(config), encoding="utf-8")
        file_cap = max(args.max_output_bytes, args.max_report_bytes, LOG_LIMIT)
        version_raw = run_tool([opt, "--version"], scratch, [], file_cap)
        version = re.search(rb"LLVM version (22\.[0-9]+\.[0-9]+)(?:\s|$)", version_raw)
        if version is None:
            fail("UNSUPPORTED_LLVM", "The adapter requires opt from LLVM 22.x.")
        llvm_version = version.group(1).decode("ascii")
        ir, report_path = scratch / "protected.ll", scratch / "shield-report.json"
        watched = [(ir, args.max_output_bytes), (report_path, args.max_report_bytes)]
        run_tool([opt, "-load-pass-plugin", str(plugin),
                  "-passes=aegis-shield<config=shield-config.json;report=shield-report.json>,verify",
                  "-S", "shield-input.ll", "-o", "protected.ll"], scratch, watched, file_cap)
        regular(ir, args.max_output_bytes)
        try:
            report = validate_report(bounded_read(report_path, args.max_report_bytes), config, llvm_version)
        except InvalidReport:
            fail("INVALID_SHIELD_REPORT", "Shield report failed schema or invocation consistency validation.")
        if not report["transformed_sites"]:
            fail("NO_TRANSFORMATIONS_APPLIED", "Shield reported zero transformed sites; no protection success is claimed.")
        # Independently parse/verify the emitted IR, without loading the plugin.
        # Neither compilation nor execution of native artifacts is performed.
        run_tool([opt, "-passes=verify", "-disable-output", "protected.ll"],
                 scratch, watched, file_cap)
        if digest_file(ir) == digest_file(scratch / "shield-input.ll"):
            fail("INVALID_ARTIFACT", "Shield reported transformations but the output is unchanged.")
        publish(ir, output / "protected.ll", args.max_output_bytes)
        publish(report_path, output / "shield-report.json", args.max_report_bytes)
        reasons = {}
        for row in report["functions"]:
            reasons[row["reason"]] = reasons.get(row["reason"], 0) + 1
        return {"protocol": PROTOCOL, "status": "succeeded",
                "outputs": [{"path": "protected.ll"}, {"path": "shield-report.json"}],
                "evidence": [{"summary": "Shield reports arithmetic transformations; no established security property.",
                              "data": {"llvm_version": report["llvm_version"],
                                       "transformed_sites": report["transformed_sites"],
                                       "function_reasons": reasons, "config": report["config"],
                                       "report_schema": "urn:aegis-shield-llvm:report:1",
                                       "limitations": "No attack resistance or native runtime equivalence evaluated."}}],
                "attack_evaluations": [], "error": None}


def positive(raw):
    value = int(raw)
    if not 1 <= value <= 4 * 1024**3:
        raise argparse.ArgumentTypeError("byte limits must be in 1..4294967296")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opt", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--aegis-request", required=True)
    parser.add_argument("--max-input-bytes", type=positive, default=64 * 1024**2)
    parser.add_argument("--max-output-bytes", type=positive, default=128 * 1024**2)
    parser.add_argument("--max-report-bytes", type=positive, default=4 * 1024**2)
    args = parser.parse_args()
    try:
        result = execute(args)
    except Failure as exc:
        result = {"protocol": PROTOCOL, "status": "failed", "outputs": [], "evidence": [],
                  "attack_evaluations": [], "error": {"code": exc.code, "message": exc.message}}
    except (OSError, ValueError, RecursionError):
        result = {"protocol": PROTOCOL, "status": "failed", "outputs": [], "evidence": [],
                  "attack_evaluations": [], "error": {"code": "ADAPTER_IO_ERROR",
                                                        "message": "Adapter could not safely process job files."}}
    print(json.dumps(result, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
