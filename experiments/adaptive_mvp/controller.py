#!/usr/bin/env python3
"""Bounded experiment over one fixed, trusted AEGIS native fixture.

Run with the repository .venv Python. All generated artifacts belong in a new
directory outside the repository. No imported source or model output is executed.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import math
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
if __name__ == "__main__":
    sys.modules.setdefault("experiments.adaptive_mvp.controller", sys.modules[__name__])

from experiments.adaptive_mvp.evidence import (  # noqa: E402
    EvidenceError, digest, load_index, resistance_for,
)
from experiments.adaptive_mvp.policy import (  # noqa: E402
    Configuration, Constraints, next_configuration, rejection_reasons, select,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TARGET_SHA256 = "72c5204be63165e63311ea47456f2145410ed399f3bb44fc0007336707bd8f83"
MAX_CAPTURE = 8 * 1024 * 1024
SCHEMA = "aegis.adaptive.experiment.v1"
LIMITATIONS = [
    "No established security property; final code changes and retained decoys do not prove resistance.",
    "One fixed AEGIS-owned unsigned-arithmetic fixture; one million input tuples per execution, aggregated to a 32-bit checksum.",
    "Independent Python reference and checksum equality are finite regression evidence, not a formal equivalence proof.",
    "Process wall timings include startup, supervision and log I/O on an unpinned shared host; ratios are observations, not guarantees.",
    "Only the fixed hash-pinned trusted fixture is executed on the host; no reconstruction source, evidence file or AI-generated native code is compiled or run.",
    "External evidence receipts are operator-pinned attestations, not signatures; independent verification and validated isolation remain the external verifier's responsibility.",
]


class ExperimentError(RuntimeError):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        super().__init__(message or code)


class BudgetExhausted(ExperimentError):
    pass


@dataclass(frozen=True)
class Budgets:
    max_candidates: int = 4
    wall_seconds: float = 180.0
    command_seconds: float = 30.0
    max_native_runs: int = 100
    samples: int = 9

    def __post_init__(self):
        if type(self.max_candidates) is not int or not 0 <= self.max_candidates <= 5:
            raise ValueError("max_candidates_must_be_0_to_5")
        for value in (self.wall_seconds, self.command_seconds):
            if type(value) not in (float, int) or not math.isfinite(value) or value <= 0:
                raise ValueError("time_budget_must_be_positive_and_finite")
        if type(self.max_native_runs) is not int or not 0 <= self.max_native_runs <= 1000:
            raise ValueError("native_run_budget_must_be_0_to_1000")
        if type(self.samples) is not int or not 1 <= self.samples <= 31:
            raise ValueError("samples_must_be_1_to_31")


class Budget:
    def __init__(self, limits: Budgets, clock=time.monotonic):
        self.limits = limits
        self.clock = clock
        self.started = clock()
        self.native_runs = 0

    def remaining(self):
        remaining = self.limits.wall_seconds - (self.clock() - self.started)
        if remaining <= 0:
            raise BudgetExhausted("WALL_BUDGET_EXHAUSTED")
        return remaining

    def native(self):
        self.remaining()
        if self.native_runs >= self.limits.max_native_runs:
            raise BudgetExhausted("NATIVE_RUN_BUDGET_EXHAUSTED")
        self.native_runs += 1

    def usage(self):
        return {"wall_seconds": self.clock() - self.started, "native_runs": self.native_runs}


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value):
    import json
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def contained(root: Path, path: Path) -> Path:
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ExperimentError("UNSAFE_PATH")
    return path


def artifact(root: Path, path: Path) -> dict:
    contained(root, path)
    if not path.is_file() or path.stat().st_size == 0:
        raise ExperimentError("INVALID_ARTIFACT")
    return {"path": str(path.relative_to(root)), "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size}


def reference_checksum() -> str:
    """Independent scalar Python oracle for every tuple in the trusted fixture."""
    state, checksum = 42, 0
    mask = (1 << 32) - 1
    for index in range(1_000_000):
        state = (state * 1664525 + 1013904223) & mask
        checksum ^= (3 * state + (index ^ (state >> 16)) + 0x9E3779B9) & mask
    return f"{checksum:08x}\n"


class Runner:
    def __init__(self, root: Path, budget: Budget):
        self.root, self.budget = root, budget
        self.commands = []
        (root / "logs").mkdir(mode=0o700)

    def run(self, argv, cwd: Path | None = None, *, timeout_seconds: float | None = None) -> bytes:
        argv = list(map(str, argv))
        cwd = cwd or self.root
        contained(self.root, cwd)
        timeout = min(self.budget.remaining(), self.budget.limits.command_seconds)
        if timeout_seconds is not None:
            timeout = min(timeout, timeout_seconds)
        entry = {"argv": argv, "cwd": str(cwd.relative_to(self.root)),
                 "timeout_seconds": timeout, "exit_code": None, "timed_out": False}
        self.commands.append(entry)
        index = len(self.commands)
        output = self.root / "logs" / f"{index:04d}.stdout"
        errors = self.root / "logs" / f"{index:04d}.stderr"

        def limits():
            # Match the production adapter's default maximum output cap. A lower
            # inherited hard limit prevents its own per-tool limit from being set.
            resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        started = time.monotonic()
        with output.open("wb") as out, errors.open("wb") as err:
            try:
                proc = subprocess.Popen(
                    argv, cwd=cwd, shell=False, stdin=subprocess.DEVNULL,
                    stdout=out, stderr=err, start_new_session=True,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                         "HOME": str(cwd), "TMPDIR": str(cwd)}, preexec_fn=limits,
                )
            except OSError as exc:
                entry["error"] = "TOOL_UNAVAILABLE"
                raise ExperimentError("TOOL_UNAVAILABLE") from exc
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                entry["timed_out"] = True
            finally:
                # Kill descendants even when the immediate tool has exited.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                entry["exit_code"] = proc.returncode
                entry["duration_seconds"] = time.monotonic() - started
        entry["stdout"] = {"path": str(output.relative_to(self.root)), "sha256": sha256_file(output)}
        entry["stderr"] = {"path": str(errors.relative_to(self.root)), "sha256": sha256_file(errors)}
        if entry["timed_out"]:
            self.budget.remaining()  # Global exhaustion has priority over per-tool timeout.
            raise ExperimentError("COMMAND_TIMEOUT")
        if proc.returncode:
            raise ExperimentError("COMMAND_FAILED", f"Command {index} failed; inspect its private log.")
        if output.stat().st_size > MAX_CAPTURE or errors.stat().st_size > MAX_CAPTURE:
            raise ExperimentError("OUTPUT_TOO_LARGE")
        return output.read_bytes()


def elf_function_bytes(path: Path, names: list[str]) -> dict[str, bytes]:
    """Inspect actual defined executable symbol bytes in little-endian ELF64.

    No target is run. Symbol extents and executable sections are checked instead
    of treating a report's list of names as final-artifact retention evidence.
    """
    data = path.read_bytes()
    try:
        if data[:6] != b"\x7fELF\x02\x01":
            raise ValueError("ELF64 little endian required")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        section_offset, entry_size, count = header[6], header[11], header[12]
        if entry_size != 64 or count == 0 or section_offset + count * entry_size > len(data):
            raise ValueError("invalid section table")
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, section_offset + i * entry_size)
                    for i in range(count)]

        def section_bytes(section):
            offset, size = section[4], section[5]
            if offset + size > len(data):
                raise ValueError("section bounds")
            return data[offset:offset + size]

        result = {}
        for section in sections:
            if section[1] != 2:  # SHT_SYMTAB; use full symbol table, not just dynamic exports.
                continue
            if section[9] != 24 or section[5] % 24:
                raise ValueError("symbol table shape")
            strings = section_bytes(sections[section[6]])
            symbols = section_bytes(section)
            for offset in range(0, len(symbols), 24):
                name_offset, info, _, section_index, value, size = struct.unpack_from("<IBBHQQ", symbols, offset)
                if name_offset >= len(strings):
                    raise ValueError("symbol name bounds")
                end = strings.find(b"\0", name_offset)
                if end < 0:
                    raise ValueError("symbol string terminator")
                name = strings[name_offset:end].decode("utf-8")
                if name not in names or info & 15 != 2 or section_index == 0:
                    continue
                target = sections[section_index]
                relative = value - target[3]
                if not target[2] & 4 or size <= 0 or relative < 0 or relative + size > target[5]:
                    raise ValueError("function not in executable bytes")
                if name in result:
                    raise ValueError("ambiguous function")
                result[name] = section_bytes(target)[relative:relative + size]
        return result
    except (ValueError, IndexError, struct.error, UnicodeError) as exc:
        raise ExperimentError("INVALID_ELF") from exc


def retention(final: Path, baseline: Path, decoys: list[str]) -> dict:
    native = elf_function_bytes(final, ["signal_mix", *decoys])
    reference = elf_function_bytes(baseline, ["signal_mix", *decoys])
    if "signal_mix" not in native or "signal_mix" not in reference:
        raise ExperimentError("TARGET_SYMBOL_MISSING")
    if len(set(decoys)) != len(decoys) or any(name in reference for name in decoys):
        raise ExperimentError("DECOY_BASELINE_COLLISION")
    retained = [name for name in decoys if name in native]
    changed = native["signal_mix"] != reference["signal_mix"]
    return {"shield_final_observation": "MACHINE_CODE_CHANGED" if changed else "NOT_OBSERVED",
            "baseline_target_code_sha256": digest(reference["signal_mix"]),
            "final_target_code_sha256": digest(native["signal_mix"]),
            "mirage_expected_count": len(decoys), "mirage_retained_count": len(retained),
            "mirage_code": {name: {"sha256": digest(native[name]), "size_bytes": len(native[name])}
                            for name in retained},
            "mirage_all_retained": len(retained) == len(decoys),
            "any_observed": changed or bool(retained),
            "meaning": "Observed final function bytes and decoy definitions; no security inference and no proof of the exact Shield identity surviving optimization."}


class NativeEngine:
    def __init__(self, root: Path, runner: Runner, tools: dict, plugin: Path):
        self.root, self.runner, self.tools, self.plugin = root, runner, tools, plugin
        self.expected = reference_checksum().encode()
        self.baseline_path = root / "baseline.elf"
        self.source_ir = root / "inputs/input.ll"
        self.core = None
        self.oracle = {"method": "independent_python_u32_reference", "input_tuples": 1_000_000,
                       "expected_stdout": self.expected.decode(), "aggregate_bits": 32}

    def snapshot(self) -> dict:
        inputs = self.root / "inputs"
        inputs.mkdir(mode=0o700)
        source = (HERE / "target/signal.c").read_bytes()
        if digest(source) != TARGET_SHA256:
            raise ExperimentError("TARGET_SOURCE_NOT_TRUSTED")
        (inputs / "target.c").write_bytes(source)
        snapshot = inputs / "repository"
        paths = list((ROOT / "core/src/aegis_core").rglob("*.py"))
        paths += list((ROOT / "protectors/mirage/src/aegis_mirage").rglob("*.py"))
        paths += list((ROOT / "protectors/llvm/adapter").glob("*.py"))
        paths += list((ROOT / "protectors/llvm/schemas").glob("*.json"))
        paths += list(HERE.glob("*.py"))
        paths.append(HERE / "target/signal.c")
        inventory = []
        for path in sorted(paths):
            relative = path.relative_to(ROOT)
            dest = snapshot / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dest)
            inventory.append({"repository_path": str(relative), "sha256": sha256_file(dest)})
        pinned_plugin = inputs / "AegisShield.so"
        if not self.plugin.is_file():
            raise ExperimentError("PLUGIN_UNAVAILABLE")
        shutil.copyfile(self.plugin, pinned_plugin)
        self.plugin = pinned_plugin
        # The Core import and both adapter subprocesses use the captured source,
        # insulating this experiment from concurrent edits in other workstreams.
        self.snapshot_root = snapshot
        versions = {}
        for name, path in self.tools.items():
            version = self.runner.run([path, "--version"]).decode()
            if "version 22." not in version:
                raise ExperimentError("UNSUPPORTED_LLVM")
            versions[name] = {"path": path, "sha256": sha256_file(Path(path).resolve()),
                              "version": version.strip()}
        cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                    if line.startswith("model name")), "unknown")
        import importlib.metadata
        return {"target": artifact(self.root, inputs / "target.c"), "dependency_sources": inventory,
                "plugin": artifact(self.root, pinned_plugin), "tools": versions,
                "python": {"version": sys.version, "executable": sys.executable,
                           "sha256": sha256_file(Path(sys.executable).resolve())},
                "python_dependencies": {name: importlib.metadata.version(name) for name in ("pydantic", "pydantic-core")},
                "platform": platform.platform(), "cpu": cpu, "oracle": self.oracle,
                "compile_flags": ["-O1", "-g0", "-S", "-emit-llvm"],
                "final_flags": ["-O2", "-g0", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections", "-Wl,--build-id=none"]}

    def link(self, ir: Path, output: Path):
        self.runner.run([self.tools["clang"], "-O2", "-g0", "-ffunction-sections", "-fdata-sections",
                         "-Wl,--gc-sections", "-Wl,--build-id=none", ir, "-o", output])

    def execute_owned(self, path: Path, expected_hash: str):
        contained(self.root, path)
        if sha256_file(path) != expected_hash:
            raise ExperimentError("ARTIFACT_INTEGRITY_ERROR")
        self.runner.budget.native()
        start = time.perf_counter_ns()
        output = self.runner.run([path])
        elapsed = time.perf_counter_ns() - start
        if output != self.expected:
            raise ExperimentError("CORRECTNESS_FAILED")
        if sha256_file(path) != expected_hash:
            raise ExperimentError("ARTIFACT_INTEGRITY_ERROR")
        return elapsed

    def baseline(self) -> dict:
        self.runner.run([self.tools["clang"], "-O1", "-g0", "-S", "-emit-llvm",
                         "target.c", "-o", "input.ll"], self.root / "inputs")
        self.runner.run([self.tools["opt"], "-passes=verify", "-disable-output", self.source_ir])
        self.link(self.source_ir, self.baseline_path)
        value = artifact(self.root, self.baseline_path)
        self.baseline_hash = value["sha256"]
        self.execute_owned(self.baseline_path, self.baseline_hash)
        samples = [self.execute_owned(self.baseline_path, self.baseline_hash)
                   for _ in range(self.runner.budget.limits.samples)]
        if "signal_mix" not in elf_function_bytes(self.baseline_path, ["signal_mix"]):
            raise ExperimentError("TARGET_SYMBOL_MISSING")
        return {"status": "VERIFIED", "artifact": value,
                "input_ir": artifact(self.root, self.source_ir), "correctness": {"status": "passed", **self.oracle},
                "performance": {"process_wall_ns": samples, "median_ns": statistics.median(samples), "warmups": 1}}

    def _orchestrator(self):
        if self.core is not None:
            return self.core
        sys.path.insert(0, str(self.snapshot_root / "core/src"))
        from aegis_core.adapter import AdapterInvocation, _parse_result
        from aegis_core.config import config_from_mapping
        from aegis_core.orchestrator import Orchestrator
        from aegis_core.models import ErrorCode, ErrorInfo
        import aegis_core
        if not Path(aegis_core.__file__).resolve().is_relative_to(self.snapshot_root):
            raise ExperimentError("CORE_SOURCE_NOT_PINNED")
        budget = self.runner.budget
        supervisor = self.runner

        class DeadlineRunner:
            """Keep Core's protocol validation, using this experiment's supervisor.

            File-backed capture, group cleanup on interruption, and the same
            monotonic deadline cover adapters and native/compiler invocations.
            No production runner or gate is modified.
            """
            def invoke(self, spec, request_path, *, work_dir, timeout_seconds):
                argv = [*spec.command, "--aegis-request", str(request_path)]
                invocation = AdapterInvocation(argv=argv)
                before = len(supervisor.commands)
                try:
                    stdout = supervisor.run(argv, work_dir, timeout_seconds=timeout_seconds)
                    invocation.result, invocation.error = _parse_result(stdout, spec.max_stdout_bytes)
                    invocation.stdout_sha256 = digest(stdout)
                    invocation.stdout_bytes = len(stdout)
                    if invocation.result is not None and invocation.result.status == "failed":
                        invocation.error = ErrorInfo(
                            code=ErrorCode.ADAPTER_FAILED, message="Production adapter reported failure.",
                            details={"adapter_error": invocation.result.error.model_dump()})
                except ExperimentError as exc:
                    timeout = isinstance(exc, BudgetExhausted) or exc.code == "COMMAND_TIMEOUT"
                    invocation.timed_out = timeout
                    invocation.error = ErrorInfo(
                        code=ErrorCode.ADAPTER_TIMEOUT if timeout else ErrorCode.ADAPTER_FAILED,
                        message=exc.code)
                if len(supervisor.commands) > before:
                    command = supervisor.commands[-1]
                    invocation.duration_seconds = command.get("duration_seconds", 0.0)
                    invocation.exit_code = command["exit_code"]
                    if "stderr" in command:
                        invocation.stderr = (self_root / command["stderr"]["path"]).read_bytes()[-65536:]
                return invocation

        self_root = self.root

        adapters = {}
        for backend, script in (("llvm-shield", "aegis_llvm_adapter.py"),
                                ("llvm-shield-mirage", "aegis_shield_mirage_adapter.py")):
            argv = [sys.executable, str(self.snapshot_root / "protectors/llvm/adapter" / script),
                    "--opt", self.tools["opt"], "--plugin", str(self.plugin)]
            if backend.endswith("mirage"):
                argv += ["--clang", self.tools["clang"], "--llvm-link", self.tools["llvm-link"]]
            adapters[backend] = {"command": argv, "tasks": ["protect"], "env_passthrough": [],
                                 "max_stdout_bytes": 65536,
                                 "timeout_seconds": max(1, math.ceil(budget.limits.command_seconds))}
        mapping = {"storage": {"root": str(self.root / "store")}, "adapters": adapters}
        config = config_from_mapping(mapping, base_dir=self.root)
        write_json(self.root / "core-config.json", mapping)
        self.core = Orchestrator(config, runner=DeadlineRunner())
        return self.core

    def candidate(self, configuration: Configuration, candidate_id: str, baseline: dict, *, progress: dict) -> dict:
        from experiments.adaptive_mvp.evidence import strict_json
        core = self._orchestrator()
        from aegis_core.models import JobStatus, ProtectionPolicy
        budget = self.runner.budget
        budget.remaining()
        progress.update({"phase": "adapter", "build_status": "not_built"})
        job = core.submit(ProtectionPolicy(backend=configuration.backend, options=configuration.options()),
                          source=self.source_ir)
        progress["job_id"] = job.job_id
        job = core.run(job.job_id)
        budget.remaining()
        details = {"job_id": job.job_id, "core_report": str(
            (self.root / "store/jobs" / job.job_id / "report.json").relative_to(self.root)),
                   "adapter_status": job.status.value,
                   "core_report_artifact": artifact(self.root, self.root / "store/jobs" / job.job_id / "report.json")}
        progress.update(details)
        if job.status != JobStatus.SUCCEEDED:
            error = job.error.model_dump(mode="json") if job.error else {"code": "ADAPTER_FAILED"}
            return {**details, "status": "FAILED", "build_status": "adapter_failed", "error": error}
        files = {item.name: core.store.artifact_path(item) for item in job.output_artifacts}
        # Recompute every output digest independently of adapter claims and Core's metadata.
        for item in job.output_artifacts:
            if sha256_file(contained(self.root, files[item.name])) != item.sha256:
                raise ExperimentError("ARTIFACT_INTEGRITY_ERROR")
        progress["protection_artifacts"] = {name: artifact(self.root, path) for name, path in files.items()}
        progress["phase"] = "verify_ir"
        protected = files["protected.ll"]
        self.runner.run([self.tools["opt"], "-passes=verify", "-disable-output", protected])
        report = strict_json(files["shield-report.json"].read_bytes())
        decoys = []
        if configuration.decoys:
            mirage = strict_json(files["mirage-report.json"].read_bytes())
            if (mirage["input_sha256"] != sha256_file(files["shield-stage.ll"])
                    or mirage["output_sha256"] != sha256_file(protected)):
                raise ExperimentError("PROTECTION_CHAIN_MISMATCH")
            decoys = mirage["inserted_functions"]
            if len(decoys) != configuration.decoys:
                raise ExperimentError("DECOY_COUNT_MISMATCH")
        directory = self.root / "candidates" / candidate_id
        directory.mkdir(parents=True, mode=0o700)
        executable = directory / "target.elf"
        progress.update({"phase": "native_build", "build_status": "running"})
        self.link(protected, executable)
        final = artifact(self.root, executable)
        progress.update({"artifact": final, "build_status": "succeeded", "phase": "correctness"})
        self.execute_owned(executable, final["sha256"])
        progress["correctness"] = {"status": "passed", **self.oracle, "checked_runs": 1}
        progress["phase"] = "retention"
        observation = retention(executable, self.baseline_path, decoys)
        progress["retention"] = observation
        if not observation["mirage_all_retained"]:
            raise ExperimentError("DECOY_RETENTION_FAILED")
        progress["phase"] = "measurement"
        samples, controls = [], []
        # Alternating order and fresh baseline controls reduce systematic drift.
        for index in range(budget.limits.samples):
            pair = [(self.baseline_path, self.baseline_hash, controls), (executable, final["sha256"], samples)]
            for path, expected_hash, destination in pair[::1 if index % 2 == 0 else -1]:
                destination.append(self.execute_owned(path, expected_hash))
        median = statistics.median(samples)
        return {**details, "status": "VERIFIED", "phase": "verified", "build_status": "succeeded", "artifact": final,
                "protection_artifacts": {name: artifact(self.root, path) for name, path in files.items()},
                "adapter_claims": {"shield_transformed_sites": report["transformed_sites"], "source": "adapter"},
                "correctness": {"status": "passed", **self.oracle, "checked_runs": 1 + len(samples)},
                "retention": observation, "size_ratio": final["size_bytes"] / baseline["artifact"]["size_bytes"],
                "performance": {"process_wall_ns": samples, "paired_baseline_wall_ns": controls,
                                "median_ns": median, "median_ratio": median / statistics.median(controls),
                                "warmups": 1, "sample_order": "alternating_baseline_candidate"}}


def run_experiment(engine, budget: Budget, constraints: Constraints, receipts: list[dict], report: dict, save):
    """Controller separated from native execution so failure policy can be tested."""
    report.update({"candidates": [], "baseline": None, "selection": select([], constraints),
                   "stop_reason": None})
    try:
        budget.remaining()
        report["inputs"] = engine.snapshot()
        report["baseline"] = engine.baseline()
        save()
        while True:
            budget.remaining()
            config, decision = next_configuration(report["candidates"], constraints)
            if config is None:
                report["stop_reason"] = "FEEDBACK_PLAN_COMPLETE"
                report["terminal_decision"] = decision
                break
            if len(report["candidates"]) >= budget.limits.max_candidates:
                report["stop_reason"] = "CANDIDATE_BUDGET_EXHAUSTED"
                report["deferred_decision"] = {**decision, "configuration": asdict(config)}
                break
            candidate_id = f"c{len(report['candidates']) + 1:03d}"
            previous = report["candidates"][-1]["candidate_id"] if report["candidates"] else "baseline"
            entry = {"candidate_id": candidate_id, "parent_candidate_id": previous,
                     "configuration": asdict(config), "options": config.options(), "decision": decision,
                     "status": "RUNNING", "resistance": resistance_for("", [])}
            report["candidates"].append(entry)
            save()  # Preserve intended lineage before attempting any adapter/build.
            try:
                entry.update(engine.candidate(config, candidate_id, report["baseline"], progress=entry))
                if entry["status"] == "VERIFIED":
                    entry["resistance"] = resistance_for(entry["artifact"]["sha256"], receipts)
            except ExperimentError as exc:
                if entry.get("phase") == "native_build":
                    entry["build_status"] = "failed"
                entry.update({"status": "FAILED", "verification_status": "incomplete" if isinstance(exc, BudgetExhausted) else "failed",
                              "error": {"code": exc.code, "message": str(exc)}})
                if isinstance(exc, BudgetExhausted):
                    raise
            entry["constraint_rejections"] = rejection_reasons(entry, constraints)
            report["selection"] = select(report["candidates"], constraints)
            entry["selection_after_measurement"] = report["selection"]["selected_candidate_id"]
            save()
    except BudgetExhausted as exc:
        report["stop_reason"] = exc.code
    except ExperimentError as exc:
        report["stop_reason"] = "EXPERIMENT_FAILED"
        report["error"] = {"code": exc.code, "message": str(exc)}
    except KeyboardInterrupt:
        report["stop_reason"] = "INTERRUPTED"
        for candidate in report["candidates"]:
            if candidate["status"] == "RUNNING":
                candidate.update({"status": "FAILED", "build_status": "interrupted",
                                  "error": {"code": "INTERRUPTED"}})
    except Exception as exc:
        # Unexpected defects are explicit failures, with private traceback-free
        # diagnostics. Preserve already verified candidates for inspection.
        report["stop_reason"] = "EXPERIMENT_FAILED"
        report["error"] = {"code": "INTERNAL_ERROR", "exception_type": type(exc).__name__}
        for candidate in report["candidates"]:
            if candidate["status"] == "RUNNING":
                candidate.update({"status": "FAILED", "error": report["error"]})
    finally:
        report["selection"] = select(report["candidates"], constraints)
        targets = {item["artifact"]["sha256"] for item in report["candidates"] if "artifact" in item}
        if report["baseline"] and "artifact" in report["baseline"]:
            targets.add(report["baseline"]["artifact"]["sha256"])
        report["evidence_bindings"] = [
            {"receipt_sha256": item["receipt_sha256"], "artifact_sha256": item["artifact_sha256"],
             "binding": "matched_final_artifact" if item["artifact_sha256"] in targets else "unmatched_target_hash"}
            for item in receipts
        ]
        report["usage"] = budget.usage()
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        save()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--clang", default="/usr/bin/clang")
    parser.add_argument("--opt", default="/usr/bin/opt")
    parser.add_argument("--llvm-link", default="/usr/bin/llvm-link")
    parser.add_argument("--max-candidates", type=int, default=4)
    parser.add_argument("--wall-seconds", type=float, default=180)
    parser.add_argument("--command-seconds", type=float, default=30)
    parser.add_argument("--max-native-runs", type=int, default=100)
    parser.add_argument("--samples", type=int, default=9)
    parser.add_argument("--max-size-ratio", type=float, default=1.10)
    parser.add_argument("--max-time-ratio", type=float, default=3.0)
    parser.add_argument("--require-attack-evidence", action="store_true")
    parser.add_argument("--evidence-index", type=Path)
    args = parser.parse_args(argv)
    try:
        limits = Budgets(args.max_candidates, args.wall_seconds, args.command_seconds,
                         args.max_native_runs, args.samples)
        constraints = Constraints(args.max_size_ratio, args.max_time_ratio,
                                  require_attack_evidence=args.require_attack_evidence)
        root = args.output_dir.absolute()
        if root.resolve().is_relative_to(ROOT):
            raise ExperimentError("OUTPUT_MUST_BE_OUTSIDE_SOURCE_TREE")
        root.mkdir(mode=0o700)  # Refuse overwrites, resume ambiguity and reused stores.
        budget = Budget(limits)
        runner = Runner(root, budget)
        receipts = load_index(args.evidence_index, root / "external-evidence")
        tools = {"clang": str(Path(args.clang).absolute()), "opt": str(Path(args.opt).absolute()),
                 "llvm-link": str(Path(args.llvm_link).absolute())}
        engine = NativeEngine(root, runner, tools, args.plugin.absolute())
        report = {"schema_version": SCHEMA, "started_at": datetime.now(timezone.utc).isoformat(),
                  "budgets": asdict(limits), "constraints": asdict(constraints),
                  "limitations": LIMITATIONS, "external_evidence": receipts,
                  "invocation": [sys.executable, str(Path(__file__).absolute()), *(argv if argv is not None else sys.argv[1:])],
                  "commands": runner.commands}

        def save():
            report["usage"] = budget.usage()
            write_json(root / "report.json", report)

        run_experiment(engine, budget, constraints, receipts, report, save)
        from experiments.adaptive_mvp.verify import verify_report
        try:
            verification = verify_report(root / "report.json")
            verification.pop("report_sha256")  # The report changes when this summary is embedded.
            report["final_verification"] = verification
        except (ExperimentError, EvidenceError, OSError, ValueError, KeyError, TypeError) as exc:
            report["stop_reason"] = "FINAL_VERIFICATION_FAILED"
            report["final_verification"] = {"status": "failed", "error": str(exc)}
            report["selection"]["selected_candidate_id"] = None
            report["selection"]["status"] = "final_verification_failed"
        save()
        print(f"report={root / 'report.json'} stop={report['stop_reason']} selected={report['selection']['selected_candidate_id']} resistance={report['selection']['resistance']}")
        return 0 if (report["selection"]["selected_candidate_id"] and report["stop_reason"] not in (
            "EXPERIMENT_FAILED", "INTERRUPTED", "FINAL_VERIFICATION_FAILED")) else 2
    except (ValueError, OSError, ExperimentError, EvidenceError) as exc:
        print(f"Experiment refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
