#!/usr/bin/env python3
"""Optional Rust library-test component workflow; consumes the existing Core adapters.

No root registration, toolchain changes, package installation, or backend imports.
This is a trusted developer build tool, not a sandbox for hostile crates or LLVM IR.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time

from capture import COMPILE_ENV

REPO = Path(__file__).resolve().parents[2]
MIRAGE_LIMIT = 64 * 1024**2
LOG_LIMIT = 8 * 1024**2
SCHEMA = "aegis.rust.component-run.v1"  # private integration record, not a Core contract


class WorkflowError(Exception):
    def __init__(self, code: str, message: str, **details):
        super().__init__(message)
        self.code, self.details = code, details


def require(condition, code, message, **details):
    if not condition:
        raise WorkflowError(code, message, **details)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular(path: Path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1,
            "UNSAFE_PATH", "Expected a regular, unlinked private file.", path=str(path))


def artifact(path: Path) -> dict:
    regular(path)
    require(path.stat().st_size > 0, "EMPTY_ARTIFACT", "An artifact is empty.", path=str(path))
    return {"path": str(path), "sha256": digest(path), "size_bytes": path.stat().st_size}


def write_json(path: Path, data):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")


class Runner:
    """Bound each trusted local stage, kill its process group, retain bounded logs."""
    def __init__(self, root: Path, timeout: int):
        self.root, self.timeout = root, timeout
        self.steps: list[dict] = []
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                    "HOME": str(root), "TMPDIR": str(root)}

    def run(self, argv, *, cwd=None, env=None, allow_failure=False, code="TOOL_FAILED"):
        argv = list(map(str, argv))
        index = len(self.steps)
        out, err = self.root / f"step-{index:03d}.stdout", self.root / f"step-{index:03d}.stderr"
        entry = {"argv": argv, "cwd": str(cwd or self.root),
                 "stdout": str(out), "stderr": str(err)}
        self.steps.append(entry)
        start = time.monotonic()
        process = None
        try:
            with out.open("xb") as stdout, err.open("xb") as stderr:
                process = subprocess.Popen(argv, cwd=cwd or self.root,
                                           env={**self.env, **(env or {})}, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                while process.poll() is None:
                    require(time.monotonic() - start < self.timeout, "STAGE_TIMEOUT",
                            "Stage exceeded its wall timeout.", step=index)
                    require(max(out.stat().st_size, err.stat().st_size) <= LOG_LIMIT,
                            "OUTPUT_TOO_LARGE", "Stage diagnostics exceeded 8 MiB.", step=index)
                    try:
                        process.wait(timeout=0.05)
                    except subprocess.TimeoutExpired:
                        pass
                entry["returncode"] = process.returncode
            require(max(out.stat().st_size, err.stat().st_size) <= LOG_LIMIT,
                    "OUTPUT_TOO_LARGE", "Stage diagnostics exceeded 8 MiB.", step=index)
            require(allow_failure or process.returncode == 0, code,
                    "Stage returned a nonzero exit code; see its private stderr log.", step=index,
                    returncode=process.returncode)
            return entry
        except OSError as exc:
            raise WorkflowError("TOOL_UNAVAILABLE", "Could not start or capture a stage.",
                                step=index, reason=exc.strerror) from None
        finally:
            entry["wall_seconds"] = time.monotonic() - start
            if process is not None:
                # Also clean up descendants after a leader exits or an exception occurs.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()

    @staticmethod
    def stdout(entry):
        return Path(entry["stdout"]).read_text(encoding="utf-8", errors="replace")


def tool_path(raw: str) -> str:
    # Preserve argv[0] for rustup's rustc proxy; resolving symlinks changes its behavior.
    found = shutil.which(raw)
    require(found is not None, "TOOL_UNAVAILABLE", "A required tool is unavailable.", tool=raw)
    return os.path.abspath(found)


def check_versions(runner: Runner, invocation: dict, tools: dict) -> dict:
    rust = runner.stdout(runner.run([invocation["rustc"], "-vV"], cwd=invocation["cwd"]))
    version = re.search(r"^LLVM version: (\d+\.\d+\.\d+)$", rust, re.M)
    host = re.search(r"^host: (.+)$", rust, re.M)
    require(version is not None and host is not None, "UNSUPPORTED_RUST",
            "rustc must report its LLVM version and host.")
    require(host[1] == "x86_64-unknown-linux-gnu" and sys.platform == "linux",
            "UNSUPPORTED_RUST", "Only native Linux x86-64 GNU library-test components are supported.")
    require(version[1].startswith("22."), "UNSUPPORTED_LLVM", "The existing adapters require LLVM 22.")
    versions = {"rustc": rust.strip(), "llvm_version": version[1], "host": host[1]}
    for name, tool in tools.items():
        output = runner.stdout(runner.run([tool, "--version"]))
        match = re.search(r"(?:LLVM|clang) version (\d+\.\d+\.\d+)", output, re.I)
        require(match is not None and match[1] == version[1], "UNSUPPORTED_LLVM",
                "rustc and every LLVM stage must use the same exact LLVM version.", tool=name)
        versions[name] = {"path": tool, "version": match[1]}
    return versions


def load_invocation(path: Path) -> dict:
    regular(path)
    require(path.stat().st_size <= 1024**2, "INVALID_INVOCATION", "Invocation record exceeds 1 MiB.")
    try:
        record = json.loads(path.read_text())
    except (ValueError, UnicodeError):
        raise WorkflowError("INVALID_INVOCATION", "Invocation record is not UTF-8 JSON.") from None
    require(type(record) is dict and set(record) == {"schema_version", "rustc", "cwd", "argv", "compile_env"}
            and type(record["schema_version"]) is int and record["schema_version"] == 1,
            "INVALID_INVOCATION", "Unsupported invocation record fields or version.")
    for key in ("rustc", "cwd"):
        require(type(record[key]) is str and Path(record[key]).is_absolute() and "\0" not in record[key],
                "INVALID_INVOCATION", "Compiler and working directory must be absolute paths.")
    require(Path(record["cwd"]).is_dir(), "INVALID_INVOCATION", "Compiler working directory is absent.")
    require(type(record["argv"]) is list and record["argv"]
            and all(type(a) is str and a and "\0" not in a for a in record["argv"]),
            "INVALID_INVOCATION", "Compiler argv must contain nonempty strings.")
    env = record["compile_env"]
    require(type(env) is dict and not env.keys() - COMPILE_ENV
            and all(type(v) is str and "\0" not in v for v in env.values()),
            "INVALID_INVOCATION", "Only captured Cargo compile-time metadata may be forwarded.")
    return record


def prepare_args(args: list[str], out: Path) -> list[str]:
    """Normalize only the documented release test pipeline; refuse other codegen modes."""
    require("--test" in args and "--crate-name" in args, "UNSUPPORTED_RUST",
            "Capture a Cargo --release --lib unit-test compiler invocation.")
    require(args.index("--crate-name") + 1 < len(args), "INVALID_INVOCATION", "Missing crate name.")
    result, settings = [], {}
    i = 0
    replaced = {"opt-level", "lto", "codegen-units", "save-temps", "incremental", "embed-bitcode"}
    allowed_codegen = replaced | {"metadata", "extra-filename", "strip", "debuginfo",
                                 "overflow-checks", "debug-assertions", "panic"}
    while i < len(args):
        arg = args[i]
        if arg in {"-o", "--out-dir", "--emit", "--target", "--crate-type"}:
            require(i + 1 < len(args), "INVALID_INVOCATION", "Missing compiler option value.")
            value = args[i + 1]
            i += 2
        elif any(arg.startswith(key + "=") for key in ("--out-dir", "--emit", "--target", "--crate-type")):
            arg, value = arg.split("=", 1)
            i += 1
        else:
            value = None
        if value is not None:
            require(arg in {"--out-dir", "--emit"}, "UNSUPPORTED_RUST",
                    "Custom targets, crate types and explicit -o outputs are unsupported.", option=arg)
            if arg == "--emit":
                require("link" in value.split(","), "UNSUPPORTED_RUST", "Invocation must link a test binary.")
            continue
        if arg == "-C" or arg.startswith("-C"):
            if arg == "-C":
                require(i + 1 < len(args), "INVALID_INVOCATION", "Missing codegen option.")
                value = args[i + 1]
                i += 2
            else:
                value = arg[2:]
                i += 1
            key, _, setting = value.partition("=")
            require(key in allowed_codegen, "UNSUPPORTED_RUST",
                    "This codegen option has not been validated by the component workflow.", option=key)
            settings[key] = setting
            if key not in replaced:
                result += ["-C", value]
            continue
        require(not arg.startswith(("-Z", "--print", "@", "--codegen", "--sysroot")),
                "UNSUPPORTED_RUST", "Unvalidated compiler stage override.", option=arg)
        result.append(arg)
        i += 1
    require(settings.get("opt-level") == "3", "UNSUPPORTED_RUST",
            "Only release opt-level=3 captures are supported; debug/optnone is not supported.")
    require(settings.get("panic", "unwind") == "unwind", "UNSUPPORTED_RUST", "panic=abort is unsupported.")
    return result + ["--out-dir", str(out), "--emit=llvm-ir,link", "-C", "lto=off",
                     "-C", "opt-level=3", "-C", "codegen-units=1", "-C", "save-temps", "--print=link-args"]


def captured_binary(args: list[str], cwd: Path) -> Path:
    """Find the ordinary Cargo test binary without running Cargo or guessing by glob."""
    crate = args[args.index("--crate-name") + 1]
    out, suffix = None, ""
    for i, arg in enumerate(args):
        if arg == "--out-dir":
            out = args[i + 1]
        elif arg.startswith("--out-dir="):
            out = arg.split("=", 1)[1]
        elif arg == "-C" and args[i + 1].startswith("extra-filename="):
            suffix = args[i + 1].split("=", 1)[1]
        elif arg.startswith("-Cextra-filename="):
            suffix = arg.split("=", 1)[1]
    require(out is not None and re.fullmatch(r"[A-Za-z0-9_]+", crate) is not None
            and re.fullmatch(r"[-A-Za-z0-9_]*", suffix) is not None,
            "INVALID_INVOCATION", "Expected a Cargo crate name, output directory and safe extra-filename.")
    path = Path(out) / (crate + suffix)
    return path if path.is_absolute() else cwd / path


def integer_signature(line: str, groups: dict[str, str]) -> tuple[bool, int]:
    """Conservative selector for canonical llvm-dis headers; never matches by symbol name."""
    match = re.search(r' @((?:"(?:[^"\\]|\\.)*"|[^\s(]+))\(', line)
    require(match is not None and line.rstrip().endswith("{"), "UNSUPPORTED_IR",
            "Expected canonical single-line llvm-dis function definitions.")
    opening = match.end() - 1
    depth, closing = 1, opening + 1
    while closing < len(line) and depth:
        depth += {"(": 1, ")": -1}.get(line[closing], 0)
        closing += 1
    require(depth == 0, "UNSUPPORTED_IR", "Unbalanced function parameter list.")
    # Strip nested return-attribute arguments such as range(i32 0, 64).
    head = line[:match.start()]
    while re.search(r"\([^()]*\)", head):
        head = re.sub(r"\([^()]*\)", "", head)
    ret = re.search(r"(?:^|\s)i[1-9][0-9]*\s*$", head)
    params = line[opening + 1:closing - 1]
    parts, level, begin = [], 0, 0
    for pos, char in enumerate(params):
        if char in "([{<":
            level += 1
        elif char in ")]}>" :
            level -= 1
        elif char == "," and level == 0:
            parts.append(params[begin:pos].strip())
            begin = pos + 1
    if params.strip():
        parts.append(params[begin:].strip())
    tail = line[closing:]
    attributes = tail + " " + " ".join(groups.get(n, "") for n in re.findall(r"#([0-9]+)", tail))
    eligible = (bool(ret) and all(re.match(r"i[1-9][0-9]*(?:\s|$)", p) for p in parts)
                and not re.search(r"\boptnone\b", attributes))
    # Function attrs go after optional unnamed_addr, before #group/section/personality.
    prefix = re.match(r"\s*(?:(?:local_)?unnamed_addr\s*)?", tail)
    return eligible, closing + prefix.end()


def mark_ir(source: Path, destination: Path) -> dict:
    groups = {}
    with source.open() as stream:
        for line in stream:
            match = re.match(r"attributes #([0-9]+) = \{(.*)\}", line)
            if match:
                groups[match[1]] = match[2]
    definitions = marked = 0
    with source.open() as stream, destination.open("x") as output:
        for line in stream:
            if line.startswith("define "):
                definitions += 1
                eligible, pos = integer_signature(line, groups)
                if eligible:
                    require('"aegis.protect"' not in line, "UNSUPPORTED_IR", "Input is already marked.")
                    line = line[:pos] + ' "aegis.protect" ' + line[pos:]
                    marked += 1
            output.write(line)
    return {"definitions": definitions, "marked_integer_signatures": marked,
            "selection": "all scalar-integer return/parameter definitions without optnone; includes instantiated dependencies"}


def parse_link_command(text: str, rustc_dir: Path) -> tuple[list[str], dict, Path]:
    # rustc --print=link-args is shell-quoted *data*. shlex parses it; no shell executes it.
    import shlex
    lines = [line for line in text.splitlines() if line.strip()]
    require(len(lines) == 1, "UNSUPPORTED_LINK", "Expected exactly one printed linker command.")
    try:
        tokens = shlex.split(lines[0])
    except ValueError:
        raise WorkflowError("UNSUPPORTED_LINK", "Malformed linker command quoting.") from None
    env = {}
    while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
        key, value = tokens.pop(0).split("=", 1)
        require(key in {"PATH", "LC_ALL", "VSLANG"}, "UNSUPPORTED_LINK",
                "Printed linker command requires an unvalidated environment variable.", variable=key)
        env[key] = value
    require(tokens and Path(tokens[0]).name in {"cc", "gcc", "clang", "clang-22"},
            "UNSUPPORTED_LINK", "Only rustc's native C-driver linker command is supported.")
    require(not any(a.startswith("@") for a in tokens), "UNSUPPORTED_LINK", "Linker response files unsupported.")
    hits = [Path(a) for a in tokens if a.endswith("-cgu.0.rcgu.o")]
    all_cgus = [a for a in tokens if re.search(r"-cgu\.[0-9]+\.rcgu\.o$", a)]
    require(len(hits) == len(all_cgus) == 1 and tokens.count("-o") == 1,
            "UNSUPPORTED_LINK", "Expected one primary codegen-unit object and one linker output.")
    obj = hits[0]
    require(obj.is_absolute() and obj.parent.resolve() == rustc_dir.resolve(),
            "UNSAFE_PATH", "Primary object must be in this run's private compiler directory.")
    regular(obj)
    executable = shutil.which(tokens[0], path=env.get("PATH", "/usr/bin:/bin"))
    require(executable is not None, "TOOL_UNAVAILABLE", "rustc's linker driver is unavailable.")
    tokens[0] = os.path.abspath(executable)
    return tokens, env, obj


def test_outcome(text: str, returncode: int) -> dict:
    cases = re.findall(r"^test (.+) \.\.\. (ok|FAILED|ignored(?:,.*)?)$", text, re.M)
    summaries = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                           r"(\d+) measured; (\d+) filtered out;", text, re.M)
    require(len(summaries) == 1, "INVALID_TEST_OUTPUT", "Expected one Rust libtest summary.")
    status, passed, failed, ignored, measured, filtered = summaries[0]
    counts = dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"),
                      map(int, (passed, failed, ignored, measured, filtered))))
    outcomes = {name: ("ignored" if value.startswith("ignored") else value) for name, value in cases}
    require(len(outcomes) == len(cases) == counts["passed"] + counts["failed"] + counts["ignored"]
            and counts["measured"] == 0 and len(cases) > 0,
            "INVALID_TEST_OUTPUT", "Per-test outcomes do not match the libtest summary.")
    require(returncode == (0 if status == "ok" else 101) and (status == "ok") == (counts["failed"] == 0),
            "INVALID_TEST_OUTPUT", "Test exit code and summary disagree.")
    return {"returncode": returncode, "counts": counts, "tests": outcomes}


def compare_tests(runner: Runner, binaries: dict[str, Path], cwd: Path, samples: int, record: dict):
    observations = {name: [] for name in binaries}
    record["tests"] = {"samples_per_variant": samples, "order": "alternating forward/reverse",
                       "observations": observations, "equivalent": False}
    reference = None
    for sample in range(samples):
        order = list(binaries) if sample % 2 == 0 else list(reversed(binaries))
        for name in order:
            step = runner.run([binaries[name], "--test-threads=1", "--format=pretty", "--color=never"],
                              cwd=cwd, allow_failure=True)
            outcome = test_outcome(runner.stdout(step), step["returncode"])
            observations[name].append({**outcome, "wall_seconds": step["wall_seconds"],
                                       "stdout": step["stdout"], "stderr": step["stderr"]})
            # The original rustc pipeline may differ from matched Clang O3. Preserve
            # that distinction; only matched baseline vs protected defines equivalence.
            if name == "baseline":
                if reference is None:
                    reference = outcome
                require(outcome == reference, "NONDETERMINISTIC_BASELINE",
                        "Matched baseline per-test outcomes varied across samples.")
    for item in observations["protected"]:
        outcome = {k: item[k] for k in ("returncode", "counts", "tests")}
        require(outcome == reference, "BEHAVIOR_MISMATCH",
                "Protected and matched baseline per-test outcomes differ.")
    record["tests"]["equivalent"] = True
    record["tests"]["baseline_passed"] = reference["returncode"] == 0
    record["tests"]["original_matches_baseline"] = all(
        {k: item[k] for k in ("returncode", "counts", "tests")} == reference
        for item in observations["original"])
    record["tests"]["original_passed"] = all(item["returncode"] == 0 for item in observations["original"])
    record["performance"] = {
        name: {"wall_seconds": [x["wall_seconds"] for x in runs],
               "median_wall_seconds": statistics.median(x["wall_seconds"] for x in runs)}
        for name, runs in observations.items()}


def protect_ir(args, runner: Runner, marked: Path, record: dict) -> Path:
    # Lazy imports: unit tests and --help do not require an installed Core.
    from aegis_core.config import AdapterSpec, AegisConfig, StorageConfig
    from aegis_core.errors import AegisError
    from aegis_core.models import JobStatus, ProtectionPolicy
    from aegis_core.orchestrator import Orchestrator

    command = [sys.executable, str(REPO / "protectors/llvm/adapter" /
               ("aegis_llvm_adapter.py" if args.backend == "llvm-shield" else "aegis_shield_mirage_adapter.py")),
               "--opt", args.opt, "--plugin", str(args.plugin.absolute()),
               "--max-input-bytes", str(args.max_input_bytes),
               "--max-output-bytes", str(min(4 * 1024**3, args.max_input_bytes * 2)),
               "--max-report-bytes", str(32 * 1024**2)]
    if args.backend == "llvm-shield-mirage":
        command += ["--clang", args.clang, "--llvm-link", args.llvm_link]
    config = AegisConfig(storage=StorageConfig(root=runner.root / "store", max_input_bytes=args.max_input_bytes),
                        adapters={args.backend: AdapterSpec(command=command, timeout_seconds=args.timeout,
                                                            max_stdout_bytes=65536)})
    orchestrator = Orchestrator(config)
    try:
        job = orchestrator.submit(ProtectionPolicy(backend=args.backend, options={"seed": args.seed, "max-sites": 16}),
                                  source=marked)
        job = orchestrator.run(job.job_id)
    except AegisError as exc:
        raise WorkflowError(exc.code.value, exc.message, core_details=exc.details) from None
    record["adapter_job"] = job.model_dump(mode="json")
    require(job.status == JobStatus.SUCCEEDED, "ADAPTER_FAILED", "Core protection job failed.",
            core_error=job.error.model_dump(mode="json") if job.error else None)
    outputs = {}
    for item in job.output_artifacts:
        path = runner.root / "store" / item.storage_path
        observed = artifact(path)
        require(observed["sha256"] == item.sha256 and observed["size_bytes"] == item.size_bytes,
                "ARTIFACT_INTEGRITY_ERROR", "Adapter artifact differs from Core's hash.")
        outputs[item.name] = observed
    record["adapter_outputs"] = outputs
    report = json.loads(Path(outputs["shield-report.json"]["path"]).read_text())
    record["shield"] = {"source": "adapter", "transformed_sites": report["transformed_sites"],
                        "transformed_functions": sum(f["status"] == "transformed" for f in report["functions"])}
    if "mirage-report.json" in outputs:
        mirage = json.loads(Path(outputs["mirage-report.json"]["path"]).read_text())
        record["mirage"] = {"source": "adapter", "inserted_count": mirage["inserted_count"],
                            "inserted_functions": mirage["inserted_functions"]}
    return Path(outputs["protected.ll"]["path"])


def pipeline(args, runner: Runner, record: dict):
    invocation = load_invocation(args.invocation)
    require(not runner.root.is_relative_to(Path(invocation["cwd"]).resolve()), "UNSAFE_PATH",
            "Output must be outside the captured crate's source directory.")
    args.opt, args.clang = tool_path(args.opt), tool_path(args.clang)
    args.llvm_dis = tool_path(args.llvm_dis)
    if args.backend == "llvm-shield-mirage":
        args.llvm_link = tool_path(args.llvm_link)
        args.llvm_nm = tool_path(args.llvm_nm)
    regular(args.plugin)
    record["invocation"] = artifact(args.invocation)
    record["compiler_cwd"] = invocation["cwd"]
    compiler_dir = runner.root / "rustc"
    compiler_dir.mkdir(mode=0o700)
    argv = prepare_args(invocation["argv"], compiler_dir)
    cargo_binary = captured_binary(invocation["argv"], Path(invocation["cwd"]))
    cargo_snapshot = runner.root / "cargo-original.tests"
    record["cargo_original"] = artifact(cargo_binary)
    shutil.copyfile(cargo_binary, cargo_snapshot)
    cargo_snapshot.chmod(0o700)
    require(digest(cargo_snapshot) == record["cargo_original"]["sha256"], "ARTIFACT_INTEGRITY_ERROR",
            "Original Cargo binary changed while being snapshotted.")
    tools = {"opt": args.opt, "clang": args.clang, "llvm-dis": args.llvm_dis}
    if args.backend == "llvm-shield-mirage":
        tools["llvm-link"] = args.llvm_link
        tools["llvm-nm"] = args.llvm_nm
    record["toolchain"] = check_versions(runner, invocation, tools)
    step = runner.run([invocation["rustc"], *argv], cwd=invocation["cwd"],
                      env=invocation["compile_env"], code="RUSTC_FAILED")
    link, link_env, original_object = parse_link_command(runner.stdout(step), compiler_dir)
    bitcode = original_object.with_suffix(".no-opt.bc")
    regular(bitcode)
    require(len(list(compiler_dir.glob("*-cgu.*.rcgu.no-opt.bc"))) == 1,
            "UNSUPPORTED_RUST", "Expected exactly one pre-optimization codegen module.")
    record["artifacts"] = {"preopt_bitcode": artifact(bitcode), "rustc_object": artifact(original_object)}
    original_binary = Path(link[link.index("-o") + 1])
    require(original_binary.is_absolute() and original_binary.parent == compiler_dir,
            "UNSAFE_PATH", "Original binary must be in this run's compiler directory.")
    record["artifacts"]["rustc_replay_binary"] = artifact(original_binary)
    record["artifacts"]["original_binary"] = artifact(cargo_snapshot)
    raw, marked = runner.root / "preopt.ll", runner.root / "marked.ll"
    runner.run([args.llvm_dis, bitcode, "-o", raw], code="LLVM_FAILED")
    require(raw.stat().st_size <= args.max_input_bytes, "INPUT_TOO_LARGE",
            "Pre-opt IR exceeds the configured Rust input limit.", size_bytes=raw.stat().st_size)
    record["selection"] = mark_ir(raw, marked)
    record["artifacts"].update(preopt_ir=artifact(raw), marked_ir=artifact(marked))
    require(marked.stat().st_size <= args.max_input_bytes, "INPUT_TOO_LARGE", "Marked IR exceeds input limit.")
    require(args.backend != "llvm-shield-mirage" or marked.stat().st_size <= MIRAGE_LIMIT,
            "MIRAGE_INPUT_TOO_LARGE", "Mirage has a fixed 64 MiB module limit; choose Shield for large components.")
    runner.run([args.opt, "-passes=verify", "-disable-output", marked], code="LLVM_FAILED")
    require(record["selection"]["marked_integer_signatures"] > 0, "NO_ELIGIBLE_FUNCTIONS",
            "No scalar-integer signatures were marked; no protection job was run.")
    protected = protect_ir(args, runner, marked, record)
    binaries = {"original": cargo_snapshot}
    for name, ir in (("baseline", raw), ("protected", protected)):
        obj, binary = runner.root / f"{name}.o", runner.root / f"{name}.tests"
        runner.run([args.clang, "-O3", "-fPIC", "-c", ir, "-o", obj], code="LLVM_FAILED")
        argv = [str(obj) if token == str(original_object) else token for token in link]
        argv[argv.index("-o") + 1] = str(binary)
        runner.run(argv, cwd=invocation["cwd"], env=link_env, code="LINK_FAILED")
        record["artifacts"].update({f"{name}_object": artifact(obj), f"{name}_binary": artifact(binary)})
        binaries[name] = binary
    if "mirage" in record:
        step = runner.run([args.llvm_nm, "--defined-only", "--format=posix", binaries["protected"]])
        symbols = {line.split()[0] for line in runner.stdout(step).splitlines() if line.strip()}
        expected = set(record["mirage"]["inserted_functions"])
        record["mirage_retention"] = {"source": "local_symbol_observation",
                                       "expected": len(expected), "retained": len(expected & symbols)}
        require(expected <= symbols, "DECOYS_NOT_RETAINED",
                "Some Mirage symbols were not retained after Clang O3 and final linking.")
    compare_tests(runner, binaries, Path(invocation["cwd"]), args.samples, record)
    for name, binary in binaries.items():
        require(digest(binary) == record["artifacts"][f"{name}_binary"]["sha256"],
                "ARTIFACT_INTEGRITY_ERROR", "A test executable changed during execution.", variant=name)
    # A matching failure remains a failure; equivalence is recorded independently.
    require(record["tests"]["baseline_passed"], "BASELINE_TEST_FAILURE",
            "Matched baseline and protected tests agree but contain failing tests.")
    require(record["tests"]["original_passed"], "ORIGINAL_TEST_FAILURE",
            "The original Cargo test binary contains failing tests.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--invocation", type=Path, required=True, help="Private capture.py JSON")
    parser.add_argument("--output", type=Path, required=True, help="New scratch directory, outside source tree")
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--backend", choices=("llvm-shield", "llvm-shield-mirage"), default="llvm-shield")
    for name in ("opt", "clang", "llvm-dis", "llvm-link", "llvm-nm"):
        parser.add_argument("--" + name, default=name)
    parser.add_argument("--seed", default="42")
    parser.add_argument("--max-input-bytes", type=int, default=MIRAGE_LIMIT)
    parser.add_argument("--timeout", type=int, default=300, help="Wall seconds per stage")
    parser.add_argument("--samples", type=int, default=3, help="Alternating test runs per variant; 1-20")
    args = parser.parse_args(argv)
    root = args.output.absolute()
    record = {"schema": SCHEMA, "status": "failed", "backend": args.backend,
              "started_at": datetime.now(timezone.utc).isoformat(),
              "host": {"system": list(os.uname()) if hasattr(os, "uname") else [sys.platform],
                       "logical_cpus": os.cpu_count(), "python": sys.version},
              "limitations": ["No established security property; tests cover only the selected crate's test harness.",
                              "Dependencies/std are linked unchanged; instantiated generics may be selected.",
                              "Test wall times include process launch and are noisy, not kernel benchmarks.",
                              "Trusted native builds only; no parser/compiler/runtime sandbox.",
                              "No signing or Sentinel policy is configured by this optional workflow."]}
    runner = None
    created = False
    try:
        require(re.fullmatch(r"[0-9]{1,20}", args.seed) is not None and int(args.seed) < 2**64,
                "INVALID_OPTIONS", "seed must be a uint64 decimal string.")
        require(1 <= args.samples <= 20 and 1 <= args.timeout <= 3600
                and 1 <= args.max_input_bytes <= 4 * 1024**3,
                "INVALID_OPTIONS", "Invalid samples, timeout or input limit.")
        require(not root.is_relative_to(REPO) and not root.exists()
                and root.parent.is_dir() and root.parent.resolve() == root.parent,
                "UNSAFE_PATH", "Output must be a new directory outside the repository with no symlink ancestors.")
        root.mkdir(mode=0o700)
        created = True
        runner = Runner(root, args.timeout)
        pipeline(args, runner, record)
        record["status"] = "succeeded"
    except WorkflowError as exc:
        record["error"] = {"code": exc.code, "message": str(exc), "details": exc.details}
    except ImportError:
        record["error"] = {"code": "DEPENDENCY_UNAVAILABLE", "message": "Use the repository .venv with aegis-core installed."}
    except (OSError, ValueError, KeyError) as exc:
        record["error"] = {"code": "WORKFLOW_ERROR", "message": f"{type(exc).__name__}; inspect private stage logs."}
    finally:
        record["finished_at"] = datetime.now(timezone.utc).isoformat()
        record["steps"] = runner.steps if runner else []
        if created:
            write_json(root / "run.json", record)
    print(json.dumps({"status": record["status"], "report": str(root / "run.json") if created else None,
                      "error": record.get("error")}))
    return 0 if record["status"] == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
