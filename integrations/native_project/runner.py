"""Bounded host execution for trusted compilers, adapters and owned programs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import time


class Failure(Exception):
    def __init__(self, code, message, **details):
        super().__init__(message)
        self.code, self.message, self.details = code, message, details

    def record(self):
        return {"code": self.code, "message": self.message, "details": self.details}


def regular(path: Path, limit: int, *, empty=False, code="OUTPUT_TOO_LARGE"):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.resolve() != path.absolute():
        raise Failure("UNSAFE_PATH", "Expected a regular file without symlinks or hardlinks.")
    if info.st_size > limit:
        raise Failure(code, "File exceeds its byte limit.", limit=limit)
    if not empty and not info.st_size:
        raise Failure("EMPTY_ARTIFACT", "Required file is empty.")
    return info


def digest(path: Path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path, limit=1024 * 1024):
    regular(path, limit, code="INPUT_TOO_LARGE")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("Nonfinite JSON constant")

    return json.loads(path.read_bytes(), object_pairs_hook=unique, parse_constant=invalid)


def write_json(path, value):
    # All paths are fixed beneath a new private output directory.
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


class Runner:
    def __init__(self, root: Path, timeout=60, file_limit=128 * 1024**2, log_limit=65536):
        self.root, self.timeout = root, timeout
        self.file_limit, self.log_limit = file_limit, log_limit
        self.commands = []
        (root / "commands").mkdir(mode=0o700)

    def run(self, argv, cwd, *, watched=(), expected=(0,), stage="tool"):
        argv = [str(arg) for arg in argv]
        index = len(self.commands)
        directory = self.root / "commands" / f"{index:04d}"
        directory.mkdir(mode=0o700)
        stdout_path, stderr_path = directory / "stdout", directory / "stderr"
        entry = {"argv": argv, "cwd": str(cwd), "stage": stage,
                 "timeout_seconds": self.timeout,
                 "stdout": str(stdout_path.relative_to(self.root)),
                 "stderr": str(stderr_path.relative_to(self.root))}
        self.commands.append(entry)
        write_json(directory / "command.json", entry)

        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (self.file_limit, self.file_limit))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        start = time.monotonic()
        proc = None
        try:
            with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
                proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                        stdout=out, stderr=err, shell=False, close_fds=True,
                                        start_new_session=True, preexec_fn=limits,
                                        env={"PATH": os.defpath, "LANG": "C.UTF-8",
                                             "LC_ALL": "C.UTF-8", "HOME": str(directory),
                                             "TMPDIR": str(directory)})
                while True:
                    for path, limit in [*watched, (stdout_path, self.log_limit),
                                         (stderr_path, self.log_limit)]:
                        if path.exists():
                            regular(path, limit, empty=True)
                    if time.monotonic() - start > self.timeout:
                        raise Failure("ADAPTER_TIMEOUT" if stage == "adapter" else "TIMEOUT",
                                      "Process group exceeded the wall timeout.", stage=stage)
                    if proc.poll() is not None:
                        break
                    time.sleep(0.01)
                entry["returncode"] = proc.returncode
                if proc.returncode == -signal.SIGXFSZ:
                    raise Failure("OUTPUT_TOO_LARGE", "Process exceeded its hard file limit.", stage=stage)
                if proc.returncode not in expected:
                    raise Failure("TOOL_FAILED", "Command failed; see private bounded diagnostics.",
                                  stage=stage, returncode=proc.returncode, command=index)
        except OSError as exc:
            raise Failure("TOOL_UNAVAILABLE", "Command or working directory is unavailable.", stage=stage) from exc
        finally:
            if proc is not None:
                # Kill descendants even when the leader has exited successfully.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                entry["returncode"] = proc.returncode
            entry["elapsed_seconds"] = round(time.monotonic() - start, 6)
        return stdout_path.read_bytes(), stderr_path.read_bytes(), proc.returncode
