"""Standalone LLVM side-module transformer. Never runs its input or output.

The compiler's used+retain attributes keep decoy code through optimization and
ELF section garbage collection. Decoys have no callers or initializers, touch
no state and use defined unsigned arithmetic. There is no security claim.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024


class MirageError(ValueError):
    pass


@dataclass(frozen=True)
class MirageConfig:
    seed: int
    enabled: bool = True
    count: int = 3

    def __post_init__(self):
        if type(self.seed) is not int or not 0 <= self.seed < 2**63:
            raise MirageError("seed_out_of_range")
        if type(self.enabled) is not bool or type(self.count) is not int or not 1 <= self.count <= 32:
            raise MirageError("invalid_configuration")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path, limit: int = MAX_BYTES) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise MirageError("invalid_regular_input")
        chunks = []
        total = 0
        while total <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        if total > limit or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise MirageError("input_changed_or_oversized")
        return b"".join(chunks)
    finally:
        os.close(fd)


def publish(path: Path, data: bytes):
    if len(data) > MAX_BYTES:
        raise MirageError("output_too_large")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def run(argv: list[str], cwd: Path, timeout: float = 60) -> bytes:
    """Trusted tool argv, bounded files/time, minimal environment and group kill."""
    import resource

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BYTES, MAX_BYTES))

    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    start_new_session=True, preexec_fn=limits,
                                    env={"PATH": "/usr/bin:/bin", "HOME": str(cwd), "TMPDIR": str(cwd), "LANG": "C"})
        except OSError:
            raise MirageError("tool_unavailable") from None
        try:
            proc.wait(timeout=timeout)
        except BaseException:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise MirageError("tool_timeout_or_interruption") from None
        # A trusted backend may spawn children: terminate its process group on every path.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if proc.returncode:
            raise MirageError("tool_failed")
        out.seek(0)
        data = out.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise MirageError("tool_output_too_large")
        return data


def decoy_source(config: MirageConfig) -> tuple[bytes, tuple[str, ...]]:
    names = []
    lines = ['#include <stdint.h>', '#if !defined(__ELF__) || !__has_attribute(retain)',
             '#error "Mirage requires ELF retain support"', '#endif']
    prefixes = ("validate_entitlement", "derive_policy_key", "decode_access_state")
    for index in range(config.count if config.enabled else 0):
        material = hashlib.sha256(f"aegis.mirage.v1:{config.seed}:{index}".encode()).digest()
        name = f"{prefixes[index % len(prefixes)]}_{material[:6].hex()}"
        names.append(name)
        constants = [int.from_bytes(material[i:i + 4], "little") | 1 for i in (8, 12, 16, 20)]
        a, b, c, d = constants
        lines.extend([
            '__attribute__((used,retain,noinline,visibility("hidden")))',
            f'uint32_t {name}(uint32_t token, uint32_t salt) {{',
            f'  uint32_t state = (token ^ {a}u) + salt * {b}u;',
            f'  state = (state << 7) | (state >> 25);',
            f'  state ^= (state >> 11) + {c}u;',
            f'  return (state * {d}u) ^ (salt + {a}u);',
            '}',
        ])
    return ("\n".join(lines) + "\n").encode(), tuple(names)


def transform(input_ir: Path, output_dir: Path, config: MirageConfig, *, clang="/usr/bin/clang",
              llvm_link="/usr/bin/llvm-link", opt="/usr/bin/opt") -> dict:
    """Produce module.ll and report.json in a new private directory; no code execution."""
    data = read(Path(input_ir))
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise MirageError("textual_ir_required") from None
    if "define " not in text or "target triple = " not in text:
        raise MirageError("llvm_module_required")
    source, names = decoy_source(config)
    if any(re.search(r"@" + re.escape(name) + r"\b", text) for name in names):
        raise MirageError("decoy_symbol_collision")
    toolchain = {}
    with tempfile.TemporaryDirectory(prefix="aegis-mirage-") as scratch:
        work = Path(scratch)
        for key, executable in (("clang", clang), ("llvm_link", llvm_link), ("opt", opt)):
            path = Path(executable)
            if not path.is_absolute():
                raise MirageError("absolute_tool_path_required")
            version = run([str(path), "--version"], work).decode("utf-8")
            match = re.search(r"(?:clang|LLVM) version (\d+\.\d+\.\d+)", version)
            if not match or int(match.group(1).split(".")[0]) != 22:
                raise MirageError("matching_llvm22_required")
            toolchain[key] = {"version": match.group(1), "sha256": digest(read(path.resolve(), 256 * 1024 * 1024))}
        if len({t["version"] for t in toolchain.values()}) != 1:
            raise MirageError("toolchain_version_mismatch")
        (work / "input.ll").write_bytes(data)
        run([opt, "-passes=verify", "-disable-output", "input.ll"], work)
        if config.enabled:
            (work / "decoys.c").write_bytes(source)
            run([clang, "-std=c11", "-O1", "-S", "-emit-llvm", "decoys.c", "-o", "decoys.ll"], work)
            sidecar = read(work / "decoys.ll").decode()
            triple = re.compile(r'^target triple = "([^"]+)"', re.M)
            if triple.search(text).group(1) != triple.search(sidecar).group(1):
                raise MirageError("target_triple_mismatch")
            run([llvm_link, "-S", "input.ll", "decoys.ll", "-o", "module.ll"], work)
            run([opt, "-passes=verify", "-disable-output", "module.ll"], work)
            output = read(work / "module.ll")
            for name in names:
                if not re.search(rb"define [^\n]+@" + name.encode() + rb"\(", output):
                    raise MirageError("decoy_insertion_failed")
            if b"@llvm.used" not in output:
                raise MirageError("retention_metadata_missing")
        else:
            output = data  # byte-identical no-decoy control
    report = {
        "schema_version": "aegis.mirage.report.v1", "mechanism": "retained_unreachable_arithmetic_functions",
        "configuration": asdict(config), "input_sha256": digest(data), "output_sha256": digest(output),
        "decoy_source_sha256": digest(source), "inserted_functions": list(names), "inserted_count": len(names),
        "toolchain": toolchain, "runtime_side_effects": "no_callers_or_initializers_inserted",
        "final_artifact_retention": "requires_independent_check", "security_property": "not_established",
    }
    output_dir = Path(output_dir)
    output_dir.mkdir(mode=0o700)
    publish(output_dir / "module.ll", output)
    publish(output_dir / "report.json", (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    return report


def restore(original_ir: Path, report: dict, output: Path):
    """Reproduce the no-decoy input from an operator-retained original, checked by digest."""
    data = read(original_ir)
    if digest(data) != report["input_sha256"]:
        raise MirageError("original_digest_mismatch")
    publish(output, data)
