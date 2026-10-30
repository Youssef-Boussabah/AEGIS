"""Containment validation for the Firecracker backend (ADR 0004: F1-F5, V1-V11).

The driver boots real microVMs **only** when run with ``--approve-vm-launch``;
``plan`` never starts anything. It uses a validation-mode ``FirecrackerRuntime``,
which compiles only the pinned canary sources and can never serve a session.

The result is ``aegis.core.containment-report.v1``. Execution is enabled only by
a report that (a) is pinned by SHA-256 in the operator config, (b) targets the
candidate guest, (c) passed every required check and (d) is bound to exactly the
running configuration (``config_identity``). Any failed, missing, erroneous or
not-run check, a smoke-fixture target or any later change to a pinned artifact
or host control leaves real candidate execution disabled.

    python -m aegis_core.lab_containment plan --config aegis.toml --target smoke_fixture
    python -m aegis_core.lab_containment run  --config aegis.toml --target smoke_fixture \\
        --report /path/report.json --approve-vm-launch
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import socket
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, Field, ValidationError, model_validator

from . import lab_vm_protocol as proto
from .config import FirecrackerConfig, load_config
from .errors import AegisError
from .lab_execution import CompileJob, ExecuteJob, PreflightRequest, SourceFile
from .lab_firecracker import (
    BOOT_ARGS,
    JAIL_FIRECRACKER,
    FIRECRACKER_VERSION,
    MAX_PINNED_ASSET_BYTES,
    FirecrackerRuntime,
    VmContext,
    config_identity,
    plan_vm,
    scope_unit,
)
from .lab_limits import CompileLimits, SandboxLimits
from .models import AegisModel, ErrorCode, Sha256, utcnow

REPORT_SCHEMA = "aegis.core.containment-report.v1"
MANIFEST_SCHEMA = "aegis.core.canary-manifest.v1"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_CANARY_BYTES = 64 * 1024
# The smoke fixture keeps its own init and console; it is inert and never runs canaries.
SMOKE_BOOT_ARGS = "console=ttyS0 reboot=k panic=1 pci=off ro"
SMOKE_LIMITS = SandboxLimits(
    wall_ms=30_000, cpu_ms=30_000, memory_bytes=192 * 1024 * 1024, max_processes=1,
    scratch_bytes=1024 * 1024, stdout_bytes=1, stderr_bytes=1,
)
BACKSTOP_SECONDS = 20

CHECKS: dict[str, tuple[str, tuple[str, ...]]] = {
    "C0": ("positive control: a trusted canary compiles and runs", ("control",)),
    "V1": ("no network path out of the guest", ("net",)),
    "V2": ("no host file visibility; no device, mount or namespace escape", ("fs",)),
    "V3": ("read-only system image; nothing written to the host image", ("fs", "rootfs_unchanged")),
    "V4": ("process limit contains a fork bomb", ("forkbomb",)),
    "V5": ("memory and scratch limits", ("memory", "scratch")),
    "V6": ("CPU and wall-clock limits", ("spin", "sleeper")),
    "V7": ("stdout, stderr and binary limits", ("flood_stdout", "flood_stderr", "bigbinary")),
    "V8": ("unprivileged, capability-free, no_new_privs job", ("identity",)),
    "V9": ("kill and cleanup; RuntimeMaxSec backstop; nothing left behind",
           ("teardown_verified", "backstop", "no_leftovers")),
    "V10": ("fail closed: read-back mismatch, pin mismatch, report enforcement",
            ("readback_mismatch", "pin_mismatch", "report_enforcement")),
    "V11": ("a detached background process dies with the job and VM", ("orphan", "teardown_verified")),
    "F1": ("the VMM sees only its jail", ("jail_view",)),
    "F2": ("no API socket, no network device", ("host_sockets_and_netns", "net")),
    "F3": ("VMM seccomp, no_new_privs, no capabilities on every thread", ("vmm_seccomp",)),
    "F4": ("guest memory bounded; the host scope never OOM-killed the VMM", ("memory",)),
    "F5": ("malformed vsock traffic is refused and the guest powers off",
           ("fuzz_garbage", "fuzz_hello_bad_tag", "fuzz_oversized", "fuzz_job_bad_tag", "fuzz_truncated")),
}
REQUIRED_CHECKS = tuple(CHECKS)
HOST_CASES = ("rootfs_unchanged", "teardown_verified", "backstop", "no_leftovers", "readback_mismatch",
              "pin_mismatch", "report_enforcement", "jail_view", "host_sockets_and_netns", "vmm_seccomp")
FUZZ_CASES = CHECKS["F5"][1]

CaseStatus = Literal["passed", "failed", "error", "not_run"]


# ---------------------------------------------------------------- report


class CaseResult(AegisModel):
    case: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    status: CaseStatus
    observed: dict[str, Any] = Field(default_factory=dict)
    failures: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> CaseResult:
        if self.status in ("passed", "not_run") and self.failures:
            raise ValueError("a passed or not-run case has no failures")
        if self.status in ("failed", "error") and not self.failures:
            raise ValueError("a failed or erroneous case states why")
        return self


class CheckResult(AegisModel):
    check: str
    title: str
    status: Literal["passed", "failed", "not_run"]
    cases: list[str]


class ContainmentReport(AegisModel):
    schema_version: Literal["aegis.core.containment-report.v1"] = REPORT_SCHEMA
    target: Literal["candidate_guest", "smoke_fixture"]
    started_at: AwareDatetime
    finished_at: AwareDatetime
    host: dict[str, str]
    identity: dict[str, Any]
    canary_manifest_sha256: Sha256
    cases: list[CaseResult]
    checks: list[CheckResult]
    overall: Literal["passed", "failed", "incomplete"]

    @model_validator(mode="after")
    def _derived(self) -> ContainmentReport:
        """Checks and the overall verdict are recomputed from the cases: a report
        cannot claim more than its case results support."""
        if self.checks != derive_checks(self.cases):
            raise ValueError("checks do not follow from the case results")
        if self.overall != derive_overall(self.target, self.checks):
            raise ValueError("overall does not follow from the checks")
        return self


def derive_checks(cases: list[CaseResult]) -> list[CheckResult]:
    by_case = {c.case: c.status for c in cases}
    out = []
    for check, (title, names) in CHECKS.items():
        statuses = [by_case.get(n, "not_run") for n in names]
        if any(s in ("failed", "error") for s in statuses):
            status = "failed"
        elif all(s == "passed" for s in statuses):
            status = "passed"
        else:
            status = "not_run"
        out.append(CheckResult(check=check, title=title, status=status, cases=list(names)))
    return out


def derive_overall(target: str, checks: list[CheckResult]) -> str:
    if any(c.status == "failed" for c in checks):
        return "failed"
    if target == "candidate_guest" and all(c.status == "passed" for c in checks):
        return "passed"
    return "incomplete"


def report_bytes(report: ContainmentReport) -> bytes:
    return (json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2) + "\n").encode("utf-8")


def report_permits_execution(data: bytes, identity: dict[str, Any]) -> bool:
    """True only for a strictly valid, passed, candidate-guest report bound to ``identity``."""
    try:
        proto.loads_strict(data)
        report = ContainmentReport.model_validate_json(data, strict=False)
    except (proto.ProtocolError, ValidationError, ValueError):
        return False
    passed = {c.check for c in report.checks if c.status == "passed"}
    return (
        report.target == "candidate_guest"
        and report.overall == "passed"
        and set(REQUIRED_CHECKS) <= passed
        and report.identity == json.loads(json.dumps(identity))
    )


# ------------------------------------------------------------ expectations


def parse_canary_line(stdout: bytes) -> tuple[str | None, dict[str, str]]:
    for line in stdout.decode("ascii", errors="replace").splitlines():
        if line.startswith("AEGIS-CANARY "):
            parts = line.split()
            fields = dict(p.split("=", 1) for p in parts[2:] if "=" in p)
            return (parts[1] if len(parts) > 1 else None), fields
    return None, {}


def _check_field(name: str, value: str | None, rule: dict[str, Any]) -> list[str]:
    failures = []
    if value is None:
        return [f"field {name} missing"]
    for op, expected in rule.items():
        ok = {
            "eq": lambda: value == expected,
            "ne": lambda: value != expected,
            "in": lambda: value in expected,
            "le": lambda: value.isdigit() and int(value) <= expected,
        }.get(op, lambda: False)()
        if not ok:
            failures.append(f"field {name}={value} fails {op} {expected}")
    return failures


def evaluate(expect: dict[str, Any], obs: Any) -> tuple[list[str], dict[str, Any]]:
    """Compare one stage observation with its expectation. Returns (failures, observed summary)."""
    name, fields = parse_canary_line(obs.stdout)
    observed: dict[str, Any] = {
        "status": obs.status, "exit_code": obs.exit_code, "signal": obs.signal, "limit": obs.limit,
        "stdout_bytes": len(obs.stdout), "stderr_bytes": len(obs.stderr), "duration_ms": obs.duration_ms,
        "canary": name, "fields": fields,
    }
    if obs.host_enforcement is not None:
        observed["host_enforcement"] = obs.host_enforcement.model_dump()
    failures = []
    for key in ("status", "limit", "exit_code"):
        if key in expect and getattr(obs, key) != expect[key]:
            failures.append(f"{key}={getattr(obs, key)} expected {expect[key]}")
    for field, rule in expect.get("fields", {}).items():
        failures += _check_field(field, fields.get(field), rule)
    if "stdout_len_le" in expect and len(obs.stdout) > expect["stdout_len_le"]:
        failures.append("stdout longer than its limit")
    if "stderr_len_le" in expect and len(obs.stderr) > expect["stderr_len_le"]:
        failures.append("stderr longer than its limit")
    host = expect.get("host", {})
    if host:
        he = obs.host_enforcement
        if he is None:
            failures.append("no host enforcement record")
        else:
            if "oom_kills_eq" in host and he.host_oom_kills != host["oom_kills_eq"]:
                failures.append(f"host_oom_kills={he.host_oom_kills}")
            if host.get("peak_le_memory_max") and (
                he.host_memory_peak_bytes is None or he.host_memory_peak_bytes > he.memory_max_bytes
            ):
                failures.append("host memory peak above the scope limit or unknown")
    return failures, observed


# --------------------------------------------------------------- manifest


@dataclass(frozen=True)
class CanaryCase:
    case: str
    source: str
    args: tuple[str, ...]
    compile_limits: CompileLimits
    execute_limits: SandboxLimits
    expect: dict[str, Any]


@dataclass(frozen=True)
class CanaryManifest:
    directory: Path
    sha256: str
    flags: tuple[str, ...]
    support: tuple[SourceFile, ...]
    sources: dict[str, bytes]
    cases: tuple[CanaryCase, ...]

    @property
    def digests(self) -> frozenset[str]:
        return frozenset(hashlib.sha256(data).hexdigest() for data in self.sources.values())


def load_manifest(directory: Path) -> CanaryManifest:
    """Strictly load the manifest and every file it names. Its digest covers all of them."""
    from .lab_firecracker import read_bounded

    directory = Path(directory)
    raw = read_bounded(directory / "manifest.json", MAX_MANIFEST_BYTES)
    doc = proto.loads_strict(raw)
    if not isinstance(doc, dict) or doc.get("schema_version") != MANIFEST_SCHEMA:
        raise ValueError("unsupported canary manifest")
    files: dict[str, bytes] = {}

    def file(name: str) -> bytes:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,40}\.[ch]", name):
            raise ValueError("bad canary file name")
        if name not in files:
            files[name] = read_bounded(directory / name, MAX_CANARY_BYTES)
        return files[name]

    support = tuple(SourceFile(name=n, data=file(n)) for n in doc["support_files"])
    base_compile, base_execute = doc["compile_limits"], doc["execute_limits"]
    cases = []
    for item in doc["cases"]:
        file(item["source"])
        cases.append(CanaryCase(
            case=item["case"], source=item["source"], args=tuple(item.get("args", ())),
            compile_limits=CompileLimits.model_validate({**base_compile, **item.get("compile_limits", {})}),
            execute_limits=SandboxLimits.model_validate({**base_execute, **item.get("execute_limits", {})}),
            expect=item["expect"],
        ))
    if len({c.case for c in cases}) != len(cases):
        raise ValueError("duplicate canary case")
    digest = hashlib.sha256(json.dumps(
        {"manifest": hashlib.sha256(raw).hexdigest(),
         "files": {n: hashlib.sha256(d).hexdigest() for n, d in sorted(files.items())}},
        sort_keys=True).encode()).hexdigest()
    sources = {c.source: files[c.source] for c in cases}
    return CanaryManifest(directory, digest, tuple(doc["compile_flags"]), support, sources, tuple(cases))


# ------------------------------------------------------- host inspection


def _status_fields(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        key, _, value = line.partition(":")
        out[key] = value.strip()
    return out


def _is_vmm(proc_root: Path, pid: int | str) -> bool:
    """The jailed VMM: argv[0] is the fixed jail path (cmdline is world-readable even for
    non-dumpable processes); the thread name is only a fallback, since Firecracker renames threads."""
    cmdline = _read_bytes(proc_root / str(pid) / "cmdline")
    if cmdline:
        return cmdline.split(b"\0", 1)[0] == JAIL_FIRECRACKER.encode()
    return _read(proc_root / str(pid) / "comm").strip() == "firecracker"


def find_vmm_pid(ctx: VmContext, proc_root: Path, timeout: float) -> int:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with contextlib.suppress(OSError):
            for pid in (ctx.scope.path / "cgroup.procs").read_text().split():
                if _is_vmm(proc_root, pid):
                    return int(pid)
        time.sleep(0.05)
    raise TimeoutError("no firecracker process in the scope")


def _readable_root_pid(pid: int, proc_root: Path) -> int:
    """Firecracker may be non-dumpable; its jail parent shares the same mount and net namespaces."""
    try:
        os.listdir(proc_root / str(pid) / "root")
        return pid
    except PermissionError:
        return int(_status_fields(proc_root / str(pid) / "status")["PPid"])


ALLOWED_MOUNTS = {"/", "/proc", "/tmp", "/run", "/vm/firecracker", "/vm/vmlinux", "/vm/rootfs.ext4",
                  "/vm/config.json"}


def inspect_jail(ctx: VmContext, proc_root: Path, timeout: float) -> dict[str, CaseResult]:
    """F1, F2 (host side) and F3 on a running microVM."""
    pid = find_vmm_pid(ctx, proc_root, timeout)
    view_pid = _readable_root_pid(pid, proc_root)
    entries = sorted(os.listdir(proc_root / str(view_pid) / "root"))
    mounts = sorted({line.split()[4] for line in (proc_root / str(view_pid) / "mountinfo").read_text().splitlines()})
    bad_mounts = [m for m in mounts if m not in ALLOWED_MOUNTS and not (m == "/dev" or m.startswith("/dev/"))]
    jail_fail = []
    if entries != ["dev", "proc", "run", "tmp", "vm"]:
        jail_fail.append(f"unexpected root entries {entries}")
    if bad_mounts:
        jail_fail.append(f"unexpected mounts {bad_mounts}")

    tasks = {}
    for task in sorted(os.listdir(proc_root / str(pid) / "task")):
        f = _status_fields(proc_root / str(pid) / "task" / task / "status")
        tasks[task] = {"Seccomp": f.get("Seccomp"), "NoNewPrivs": f.get("NoNewPrivs"), "CapEff": f.get("CapEff")}
    sec_fail = [f"task {t} {v}" for t, v in tasks.items()
                if v != {"Seccomp": "2", "NoNewPrivs": "1", "CapEff": "0000000000000000"}]
    if not tasks:
        sec_fail.append("no tasks")

    ifaces = sorted(line.split(":")[0].strip()
                    for line in (proc_root / str(view_pid) / "net" / "dev").read_text().splitlines()[2:] if ":" in line)
    sockets = sorted(os.listdir(ctx.sock_dir))
    run_entries = sorted(os.listdir(proc_root / str(view_pid) / "root" / "run"))
    net_fail = []
    if ifaces != ["lo"]:
        net_fail.append(f"network interfaces {ifaces}")
    if sockets != ["vsock.sock"] or run_entries != ["vsock.sock"]:
        net_fail.append(f"unexpected sockets {sockets} / {run_entries}")

    def result(case: str, failures: list[str], observed: dict) -> CaseResult:
        return CaseResult(case=case, status="failed" if failures else "passed", observed=observed, failures=failures)

    return {
        "jail_view": result("jail_view", jail_fail, {"vmm_pid_used": view_pid == pid, "root": entries, "mounts": mounts}),
        "vmm_seccomp": result("vmm_seccomp", sec_fail, {"tasks": tasks}),
        "host_sockets_and_netns": result("host_sockets_and_netns", net_fail,
                                         {"ifaces": ifaces, "socket_dir": sockets, "jail_run": run_entries}),
        "_pid": pid,  # type: ignore[dict-item]
    }


# ------------------------------------------------------------------ driver


RuntimeFactory = Callable[..., FirecrackerRuntime]


def default_runtime_factory(cfg: FirecrackerConfig, **kw: Any) -> FirecrackerRuntime:
    return FirecrackerRuntime(cfg, **kw)


class ContainmentDriver:
    def __init__(
        self,
        cfg: FirecrackerConfig,
        manifest: CanaryManifest,
        *,
        target: Literal["candidate_guest", "smoke_fixture"],
        runtime_factory: RuntimeFactory = default_runtime_factory,
        proc_root: Path = Path("/proc"),
        cgroup_root: Path = Path("/sys/fs/cgroup"),
        uid: int | None = None,
        clock: Callable[[], datetime] = utcnow,
        inspect_timeout: float = 15.0,
        backstop_seconds: int = BACKSTOP_SECONDS,
    ):
        self.cfg = cfg
        self.manifest = manifest
        self.target = target
        self.factory = runtime_factory
        self.proc_root = proc_root
        self.cgroup_root = cgroup_root
        self.uid = os.getuid() if uid is None else uid
        self.clock = clock
        self.inspect_timeout = inspect_timeout
        self.backstop_seconds = backstop_seconds
        self.results: dict[str, CaseResult] = {}

    # ---------------------------------------------------------------- plan

    def plan(self) -> dict[str, Any]:
        """What ``run`` would do. Starts nothing."""
        vms = []
        host_limits = SMOKE_LIMITS if self.target == "smoke_fixture" else self.manifest.cases[0].execute_limits
        for case in ("jail_view+vmm_seccomp+host_sockets_and_netns+teardown_verified", "backstop", "readback_mismatch"):
            vms.append(self._vm_entry(case, "host", host_limits,
                                      extra_s=self.backstop_seconds if case == "backstop" else 0))
        if self.target == "candidate_guest":
            for c in self.manifest.cases:
                vms.append(self._vm_entry(c.case, "compile", c.compile_limits))
                if "execute" in c.expect:
                    vms.append(self._vm_entry(c.case, "execute", c.execute_limits))
            for case in FUZZ_CASES:
                vms.append(self._vm_entry(case, "fuzz", host_limits))
        return {
            "target": self.target,
            "starts_vms": len(vms),
            "concurrent_vms": 1,
            "peak_scope_memory_bytes": max(v["scope_memory_max_bytes"] for v in vms),
            "pinned_asset_snapshot_max_bytes": MAX_PINNED_ASSET_BYTES,
            "snapshot_accounting": "Additional host memory held by Core, outside each VM scope; released on verified close.",
            "upper_bound_seconds": sum(v["upper_bound_seconds"] for v in vms),
            "privileges": "operator uid only: systemd user scopes, unprivileged user namespaces, /dev/kvm; no sudo",
            "files_created": [f"{self.cfg.state_dir}/<vm id>/ (config.json, sock/vsock.sock); removed per VM",
                              "the report file given with --report"],
            "vms": vms,
            "identity": config_identity(self.cfg),
            "canary_manifest_sha256": self.manifest.sha256,
        }

    def _vm_entry(self, case: str, stage: str, limits: SandboxLimits, extra_s: int = 0) -> dict[str, Any]:
        plan = plan_vm(self.cfg, limits)
        return {"case": case, "stage": stage, "vm_memory_mib": plan.vm_memory_mib,
                "scope_memory_max_bytes": plan.scope_memory_max_bytes, "tasks_max": plan.tasks_max,
                "upper_bound_seconds": plan.runtime_max_sec + extra_s}

    # ----------------------------------------------------------------- run

    def _record(self, result: CaseResult) -> None:
        self.results[result.case] = result

    def _guard(self, case: str, fn: Callable[[], CaseResult]) -> None:
        try:
            self._record(fn())
        except AegisError as exc:
            detail = exc.details.get("failure") or exc.details.get("blockers") or exc.details.get("reason")
            self._record(CaseResult(case=case, status="error", observed={"code": exc.code.value, "detail": detail},
                                    failures=[f"{exc.code.value}: {detail}"]))
        except Exception as exc:  # any surprise is an error, never a pass
            self._record(CaseResult(case=case, status="error", failures=[f"{type(exc).__name__}"]))

    def _runtime(self, *, boot_args: str | None = None, cfg: FirecrackerConfig | None = None) -> FirecrackerRuntime:
        args = boot_args or (SMOKE_BOOT_ARGS if self.target == "smoke_fixture" else BOOT_ARGS)
        return self.factory(cfg or self.cfg, validation_digests=self.manifest.digests, boot_args=args)

    def run(self) -> ContainmentReport:
        started = self.clock()
        before = _sha256_file(self.cfg.rootfs_path)
        runtime = self._runtime()
        limits = SMOKE_LIMITS if self.target == "smoke_fixture" else self.manifest.cases[0].execute_limits
        runtime.validation_preflight(PreflightRequest(
            compile_limits=self.manifest.cases[0].compile_limits, execute_limits=limits))

        self._guard("teardown_verified", lambda: self._host_inspection(runtime, limits))
        for name in ("jail_view", "vmm_seccomp", "host_sockets_and_netns"):
            if name not in self.results:  # the inspection VM failed before inspecting
                failed = self.results["teardown_verified"]
                self._record(CaseResult(case=name, status="error", observed=failed.observed,
                                        failures=failed.failures or ["inspection did not run"]))
        self._guard("backstop", lambda: self._backstop(runtime, limits))
        self._guard("readback_mismatch", lambda: self._readback_mismatch(runtime, limits))
        self._guard("pin_mismatch", self._pin_mismatch)
        self._guard("report_enforcement", self._report_enforcement)
        if self.target == "candidate_guest":
            for case in self.manifest.cases:
                self._guard(case.case, lambda c=case: self._canary(runtime, c))
            for case in FUZZ_CASES:
                self._guard(case, lambda c=case: self._fuzz(runtime, c, limits))
        self._guard("no_leftovers", lambda: self._no_leftovers(runtime))
        after = _sha256_file(self.cfg.rootfs_path)
        self._record(CaseResult(
            case="rootfs_unchanged", status="passed" if before == after else "failed",
            observed={"before": before, "after": after},
            failures=[] if before == after else ["the system image changed"]))

        cases = [self.results[name] for name in sorted(self.results)]
        checks = derive_checks(cases)
        return ContainmentReport(
            target=self.target, started_at=started, finished_at=self.clock(),
            host={"kernel": platform.release(), "machine": platform.machine(),
                  "firecracker": FIRECRACKER_VERSION, "python": platform.python_version()},
            identity=config_identity(self.cfg), canary_manifest_sha256=self.manifest.sha256,
            cases=cases, checks=checks, overall=derive_overall(self.target, checks),
        )

    # --------------------------------------------------------------- cases

    def _host_inspection(self, runtime: FirecrackerRuntime, limits: SandboxLimits) -> CaseResult:
        seen: dict[str, Any] = {}

        def inspect(ctx: VmContext) -> None:
            seen.update(inspect_jail(ctx, self.proc_root, self.inspect_timeout))
            seen["_scope"] = ctx.scope.path
            seen["_rundir"] = ctx.rundir

        runtime.boot_only(limits, inspect)
        pid = seen.pop("_pid")
        scope, rundir = seen.pop("_scope"), seen.pop("_rundir")
        for result in seen.values():
            self._record(result)
        failures = []
        if _is_firecracker(self.proc_root, pid):
            failures.append("the VMM process survived teardown")
        if scope.exists() and "populated 1" in _read(scope / "cgroup.events"):
            failures.append("the scope still has processes")
        if os.path.lexists(rundir):
            failures.append("the per-VM directory remains")
        return CaseResult(case="teardown_verified", status="failed" if failures else "passed",
                          observed={"vmm_pid_gone": not _is_firecracker(self.proc_root, pid)}, failures=failures)

    def _backstop(self, runtime: FirecrackerRuntime, limits: SandboxLimits) -> CaseResult:
        _, facts = runtime.boot_only(limits, lambda ctx: find_vmm_pid(ctx, self.proc_root, self.inspect_timeout),
                                     backstop_seconds=self.backstop_seconds)
        ok = facts.get("backstop_stopped_scope") is True
        return CaseResult(case="backstop", status="passed" if ok else "failed", observed=facts,
                          failures=[] if ok else ["RuntimeMaxSec did not stop the scope"])

    def _readback_mismatch(self, runtime: FirecrackerRuntime, limits: SandboxLimits) -> CaseResult:
        wrong = {"memory.max": "1", "memory.swap.max": "0", "pids.max": "1", "cpu.max": "1000 100000"}
        try:
            runtime.boot_only(limits, lambda ctx: None, expected_override=wrong)
        except AegisError as exc:
            ok = exc.code is ErrorCode.SANDBOX_FAILED and exc.details.get("failure") == "resource_enforcement_failed"
            return CaseResult(case="readback_mismatch", status="passed" if ok else "failed",
                              observed={"code": exc.code.value, "failure": exc.details.get("failure")},
                              failures=[] if ok else ["wrong refusal"])
        return CaseResult(case="readback_mismatch", status="failed", failures=["a read-back mismatch was accepted"])

    def _pin_mismatch(self) -> CaseResult:
        wrong = self.cfg.model_copy(update={"kernel_sha256": "0" * 64})
        runtime = self._runtime(cfg=wrong)
        try:
            runtime.validation_preflight(PreflightRequest(compile_limits=None, execute_limits=None))
        except AegisError as exc:
            ok = exc.code is ErrorCode.SANDBOX_UNAVAILABLE and exc.details.get("blockers") == ["kernel_digest_mismatch"]
            return CaseResult(case="pin_mismatch", status="passed" if ok else "failed",
                              observed={"blockers": exc.details.get("blockers")},
                              failures=[] if ok else ["wrong refusal"])
        return CaseResult(case="pin_mismatch", status="failed", failures=["a wrong kernel pin was accepted"])

    def _report_enforcement(self) -> CaseResult:
        """Normal-mode preflight refuses without a report and with a failed or foreign report."""
        observed, failures = {}, []
        with tempfile.TemporaryDirectory(prefix="aegis-report-") as tmp:
            failed = _synthetic_report("candidate_guest", config_identity(self.cfg), passed=False)
            foreign = _synthetic_report("candidate_guest", {**config_identity(self.cfg), "rootfs_sha256": "0" * 64},
                                        passed=True)
            smoke = _synthetic_report("smoke_fixture", config_identity(self.cfg), passed=True)
            for name, data, expected in (("none", None, "containment_unverified"),
                                         ("failed", failed, "containment_report_rejected"),
                                         ("foreign_identity", foreign, "containment_report_rejected"),
                                         ("smoke_target", smoke, "containment_report_rejected"),
                                         ("digest_mismatch", failed, "containment_report_mismatch")):
                update: dict[str, Any] = {"containment_verification_sha256": None, "containment_report_path": None}
                if data is not None:
                    path = Path(tmp) / f"{name}.json"
                    path.write_bytes(data)
                    digest = "f" * 64 if name == "digest_mismatch" else hashlib.sha256(data).hexdigest()
                    update = {"containment_verification_sha256": digest, "containment_report_path": path}
                runtime = self.factory(self.cfg.model_copy(update=update))
                try:
                    runtime.preflight(PreflightRequest(compile_limits=None, execute_limits=None))
                    observed[name] = "accepted"
                    failures.append(f"{name} report was accepted")
                except AegisError as exc:
                    blockers = exc.details.get("blockers")
                    observed[name] = blockers
                    if blockers != [expected]:
                        failures.append(f"{name}: {blockers}")
        return CaseResult(case="report_enforcement", status="failed" if failures else "passed",
                          observed=observed, failures=failures)

    def _canary(self, runtime: FirecrackerRuntime, case: CanaryCase) -> CaseResult:
        m = self.manifest
        job = CompileJob(
            candidate=SourceFile(name="candidate.c", data=m.sources[case.source]),
            support_files=list(m.support), translation_units=["candidate.c"], flags=list(m.flags),
            limits=case.compile_limits,
        )
        compiled = runtime.compile(job)
        if "compile" in case.expect:
            failures, observed = evaluate(case.expect["compile"], compiled)
            return CaseResult(case=case.case, status="failed" if failures else "passed",
                              observed={"compile": observed}, failures=failures)
        if not (compiled.status == "exited" and compiled.exit_code == 0 and compiled.binary):
            return CaseResult(case=case.case, status="error", observed={"compile_status": compiled.status},
                              failures=["the trusted canary did not compile"])
        ran = runtime.execute(ExecuteJob(binary=compiled.binary, args=list(case.args), limits=case.execute_limits))
        failures, observed = evaluate(case.expect["execute"], ran)
        return CaseResult(case=case.case, status="failed" if failures else "passed",
                          observed={"execute": observed}, failures=failures)

    def _fuzz(self, runtime: FirecrackerRuntime, case: str, limits: SandboxLimits) -> CaseResult:
        key, wrong = os.urandom(32), b"w" * 32

        def action(ctx: VmContext, conn: socket.socket) -> dict[str, Any]:
            got_ready = False
            try:
                send(ctx, conn)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the agent already dropped the connection: that is the expected refusal
            got_ready = bool(state.get("ready"))
            conn.settimeout(10)
            try:
                reply = conn.recv(1)
            except (ConnectionResetError, BrokenPipeError):
                reply = b""  # closed with our unread bytes pending: a refusal, not an answer
            except (TimeoutError, socket.timeout, OSError):
                reply = b"?"  # still open after 10 s: treated as not refused
            return {"got_ready": got_ready, "connection_closed": reply == b"", "further_reply": reply != b""}

        state: dict[str, bool] = {}

        def send(ctx: VmContext, conn: socket.socket) -> None:
            if case == "fuzz_garbage":
                conn.sendall(b"\x00GARBAGE" * 64)
            elif case == "fuzz_hello_bad_tag":
                conn.sendall(proto.encode_frame(wrong, proto.HELLO, 0, proto.hello_payload(ctx.vm_id, key)))
            elif case == "fuzz_oversized":
                conn.sendall(proto.HEADER.pack(proto.MAGIC, proto.HELLO, 0, 0x7FFFFFFF))
            elif case == "fuzz_truncated":
                conn.sendall(proto.encode_frame(key, proto.HELLO, 0, proto.hello_payload(ctx.vm_id, key))[:20])
                conn.shutdown(socket.SHUT_WR)
            elif case == "fuzz_job_bad_tag":
                channel = proto.Channel(conn, key)
                channel.send(proto.HELLO, proto.hello_payload(ctx.vm_id, key), proto.Deadline(30))
                channel.recv({proto.READY}, 4096, proto.Deadline(30))
                state["ready"] = True
                conn.sendall(proto.encode_frame(wrong, proto.JOB, 1, proto.pack({"stage": "execute"})))

        result, self_exited = runtime.raw_session(limits, action)
        failures = []
        if result["further_reply"]:
            failures.append("the agent answered malformed traffic")
        if not self_exited:
            failures.append("the guest did not power off by itself")
        if case == "fuzz_job_bad_tag" and not result["got_ready"]:
            failures.append("no READY before the bad JOB")
        return CaseResult(case=case, status="failed" if failures else "passed",
                          observed={**result, "guest_powered_off": self_exited}, failures=failures)

    def _no_leftovers(self, runtime: FirecrackerRuntime) -> CaseResult:
        runtime.close()
        base = self.cgroup_root / "user.slice" / f"user-{self.uid}.slice" / f"user@{self.uid}.service"
        scopes = sorted(p.name for p in base.rglob(f"{scope_unit('')}*.scope")) if base.exists() else []
        leftovers = sorted(os.listdir(self.cfg.state_dir)) if self.cfg.state_dir.exists() else []
        failures = ([f"scopes {scopes}"] if scopes else []) + ([f"state {leftovers}"] if leftovers else [])
        return CaseResult(case="no_leftovers", status="failed" if failures else "passed",
                          observed={"scopes": scopes, "state_entries": leftovers}, failures=failures)


def _synthetic_report(target: str, identity: dict[str, Any], *, passed: bool) -> bytes:
    """A structurally valid report used only to test that preflight rejects it."""
    now = utcnow()
    cases = [CaseResult(case=n, status="passed" if passed else "failed",
                        failures=[] if passed else ["synthetic"])
             for n in sorted({n for _, names in CHECKS.values() for n in names})]
    checks = derive_checks(cases)
    report = ContainmentReport(target=target, started_at=now, finished_at=now, host={}, identity=identity,
                               canary_manifest_sha256="0" * 64, cases=cases, checks=checks,
                               overall=derive_overall(target, checks))
    return report_bytes(report)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def _is_firecracker(proc_root: Path, pid: int) -> bool:
    return _is_vmm(proc_root, pid)


# --------------------------------------------------------------------- CLI


def _firecracker_section(config_path: Path) -> FirecrackerConfig:
    config = load_config(config_path)
    fc = config.attack_lab.candidate_execution.firecracker
    if fc is None:
        raise SystemExit("the configuration has no [attack_lab.candidate_execution.firecracker] section")
    return fc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis_core.lab_containment")
    parser.add_argument("command", choices=["plan", "run"])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=["candidate_guest", "smoke_fixture"])
    parser.add_argument("--canaries", type=Path, default=Path(__file__).resolve().parents[2] / "guest" / "canaries")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--approve-vm-launch", action="store_true",
                        help="required for 'run': boots real microVMs with trusted canaries only")
    args = parser.parse_args(argv)
    try:
        driver = ContainmentDriver(_firecracker_section(args.config), load_manifest(args.canaries),
                                   target=args.target)
    except (OSError, ValueError, AegisError) as exc:
        sys.stderr.write(f"cannot prepare validation: {type(exc).__name__}\n")
        return 2
    if args.command == "plan":
        sys.stdout.write(json.dumps(driver.plan(), indent=2, default=str) + "\n")
        return 0
    if not args.approve_vm_launch or args.report is None:
        sys.stderr.write("run needs --approve-vm-launch and --report; use 'plan' to see what it would do\n")
        return 2
    if args.report.exists():
        sys.stderr.write("refusing to overwrite an existing report\n")
        return 2
    try:
        report = driver.run()
    except AegisError as exc:
        sys.stderr.write(f"validation could not start: {exc.code.value} {exc.details}\n")
        return 1
    data = report_bytes(report)
    fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    sys.stdout.write(json.dumps({"overall": report.overall, "report": str(args.report),
                                 "report_sha256": hashlib.sha256(data).hexdigest()}) + "\n")
    # 0 passed; 1 a check failed or errored; 3 incomplete (the smoke fixture always ends here).
    return {"passed": 0, "failed": 1}.get(report.overall, 3)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
