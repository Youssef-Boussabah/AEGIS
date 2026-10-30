"""Firecracker backend (lab_firecracker): config, planning, preflight and the full host lifecycle.

``FakeLauncher`` replaces systemd-run/bwrap/firecracker. It creates a fake scope
cgroup and /proc entry, listens on the per-VM vsock Unix socket, answers
Firecracker's CONNECT handshake and runs the real guest-agent ``serve`` loop
with a scripted executor. No VM starts and nothing is compiled or executed.
"""

from __future__ import annotations

import hashlib
import fcntl
import itertools
import json
import os
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from aegis_core import lab_guest_agent as agent
from aegis_core import lab_vm_protocol as proto
from aegis_core.config import FirecrackerConfig, config_from_mapping
from aegis_core.errors import AegisError
from aegis_core.lab_authorization import LabBindings
from aegis_core.lab_execution import (
    CompileJob,
    ExecuteJob,
    PreflightRequest,
    SourceFile,
    UnavailableRuntime,
    configured_runtime,
    open_session,
)
from aegis_core.lab_firecracker import (
    BOOT_ARGS,
    JAIL_CONFIG,
    FirecrackerRuntime,
    bwrap_argv,
    expected_cgroup_limits,
    firecracker_config,
    host_environment,
    plan_vm,
    scope_argv,
)
from aegis_core.lab_limits import MIB, CompileLimits, SandboxLimits
from aegis_core.models import ErrorCode
from lab_fixtures import CANDIDATE_A, ID_A, LAB_NOW, compile_limits_data, execute_limits_data, lab_bindings_data, bind_bundle

FLAGS = ["-std=c11", "-O2", "-static"]
UNIT = SourceFile(name="aegis_candidate_unit.c", data=b'#include "candidate.c"\n')
HARNESS = SourceFile(name="aegis_harness.c", data=b"int main(void){return 0;}\n")
FAKE_BINARY = b"\x7fELF scripted bytes, never executed"
_pids = itertools.count(40000)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------- environment


class Env:
    def __init__(self, root: Path):
        self.root = root
        self.cgroup = root / "cg"
        self.proc = root / "proc"
        self.cgroup.mkdir()
        self.proc.mkdir()
        files = root / "files"
        files.mkdir()
        self.files = {}
        for name, data, mode in (
            ("firecracker", b"firecracker v1.17.0 stand-in", 0o700),
            ("bwrap", b"bwrap stand-in", 0o700),
            ("vmlinux", b"kernel stand-in", 0o600),
            ("rootfs.ext4", b"read-only image stand-in", 0o600),
            ("systemd-run", b"systemd-run stand-in", 0o700),
        ):
            path = files / name
            path.write_bytes(data)
            path.chmod(mode)
            self.files[name] = path

    def cfg(self, **over) -> FirecrackerConfig:
        data = {
            "firecracker_path": str(self.files["firecracker"]),
            "firecracker_sha256": sha(self.files["firecracker"].read_bytes()),
            "bwrap_path": str(self.files["bwrap"]),
            "bwrap_sha256": sha(self.files["bwrap"].read_bytes()),
            "systemd_run_path": str(self.files["systemd-run"]),
            "kernel_path": str(self.files["vmlinux"]),
            "kernel_sha256": sha(self.files["vmlinux"].read_bytes()),
            "rootfs_path": str(self.files["rootfs.ext4"]),
            "rootfs_sha256": sha(self.files["rootfs.ext4"].read_bytes()),
            "guest_agent_sha256": "a" * 64,
            "compiler_name": "gcc",
            "compiler_version": "14.2.0",
            "compiler_sha256": "c" * 64,
            "state_dir": str(self.root / "state"),
            "boot_timeout_ms": 2000,
            "teardown_timeout_ms": 500,
            "host_grace_ms": 100,
        }
        data.update(over)
        if "containment_verification_sha256" not in over:
            # A genuine passing report bound to exactly this configuration.
            from aegis_core.lab_containment import _synthetic_report
            from aegis_core.lab_firecracker import config_identity

            report = _synthetic_report(
                "candidate_guest", config_identity(FirecrackerConfig.model_validate(data)), passed=True
            )
            path = self.root / f"report-{sha(report)[:12]}.json"
            path.write_bytes(report)
            data["containment_verification_sha256"] = sha(report)
            data["containment_report_path"] = str(path)
        return FirecrackerConfig.model_validate(data)


@pytest.fixture
def env():
    # Short root: <state>/<vm id>/sock/vsock.sock must fit a Unix socket path.
    root = Path(tempfile.mkdtemp(prefix="afc", dir="/tmp"))
    try:
        yield Env(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def identity_for(cfg: FirecrackerConfig) -> agent.AgentIdentity:
    return agent.AgentIdentity(
        agent_sha256=cfg.guest_agent_sha256,
        compiler={"name": cfg.compiler_name, "version": cfg.compiler_version, "sha256": cfg.compiler_sha256},
    )


class Scripted:
    def __init__(self, result=None, delay=0.0):
        self.result = result
        self.delay = delay
        self.jobs: list[agent.GuestJob] = []

    def run(self, job):
        self.jobs.append(job)
        time.sleep(self.delay)
        if self.result is not None:
            return self.result
        if job.stage == "compile":
            return agent.GuestResult("exited", exit_code=0, duration_ms=5, binary=FAKE_BINARY)
        return agent.GuestResult("exited", exit_code=0, stdout=b"AEGIS-RESULT 1\n", duration_ms=2)


class FakeProcess:
    def __init__(self, pid: int, scope: Path, *, exit_code=None, stuck=False):
        self.pid = pid
        self.scope = scope
        self.exit_code = exit_code
        self.stuck = stuck
        self.killed = False

    def _kill_requested(self) -> bool:
        path = self.scope / "cgroup.kill"
        return self.killed or (path.exists() and path.read_text() == "1")

    def poll(self):
        if self._kill_requested() and not self.stuck:
            (self.scope / "cgroup.events").write_text("populated 0\nfrozen 0\n")
            return self.exit_code if self.exit_code is not None else -9
        if self.exit_code is not None:
            return self.exit_code
        return None

    def wait(self, timeout):
        result = self.poll()
        if result is None:
            time.sleep(min(timeout, 0.05))
            result = self.poll()
        return result

    def kill(self):
        self.killed = True

    def stderr_tail(self):
        return b""


class FakeLauncher:
    """Plays systemd-run + bwrap + firecracker for one VM per start()."""

    def __init__(self, env: Env, cfg: FirecrackerConfig, *, executor=None, guest=None, refusals=0,
                 readback=None, scope_unit_override=None, exit_code=None, stuck=False, oom_kills=0,
                 start_error=None, no_socket=False):
        self.env, self.cfg = env, cfg
        self.executor = executor or Scripted()
        self.guest = guest
        self.refusals = refusals
        self.readback = readback or {}
        self.scope_unit_override = scope_unit_override
        self.exit_code, self.stuck, self.oom_kills = exit_code, stuck, oom_kills
        self.start_error = start_error
        self.no_socket = no_socket
        self.starts: list[dict] = []
        self.threads: list[threading.Thread] = []
        self.hello_keys: list[bytes] = []

    def start(self, argv, env):
        if self.start_error is not None:
            raise self.start_error
        unit = next(a.split("=", 1)[1] for a in argv if a.startswith("--unit="))
        props = dict(argv[i + 1].split("=", 1) for i, a in enumerate(argv) if a == "-p")
        bind = argv.index("--bind")
        sock_dir = Path(argv[bind + 1])
        config = Path(argv[argv.index(JAIL_CONFIG) - 1])
        self.starts.append({"argv": argv, "env": env, "unit": unit, "props": props,
                            "vm_config": json.loads(config.read_text())})
        scope_name = self.scope_unit_override or unit
        relative = f"user.slice/user-1000.slice/user@1000.service/app.slice/{scope_name}.scope"
        scope = self.env.cgroup / relative
        scope.mkdir(parents=True)
        values = {
            "memory.max": props["MemoryMax"],
            "memory.swap.max": props["MemorySwapMax"],
            "pids.max": props["TasksMax"],
            "cpu.max": f"{int(props['CPUQuota'].rstrip('%')) * 1000} 100000",
            **self.readback,
        }
        for name, value in values.items():
            (scope / name).write_text(value + "\n")
        (scope / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        (scope / "memory.events").write_text(f"low 0\nhigh 0\nmax 0\noom 0\noom_kill {self.oom_kills}\n")
        (scope / "cpu.stat").write_text("usage_usec 4321\nuser_usec 4000\nsystem_usec 321\n")
        (scope / "memory.peak").write_text("12345678\n")
        pid = next(_pids)
        (self.env.proc / str(pid)).mkdir()
        (self.env.proc / str(pid) / "cgroup").write_text(f"0::/{relative}\n")
        if not self.no_socket:
            thread = threading.Thread(target=self._vmm, args=(sock_dir / "vsock.sock",), daemon=True)
            thread.start()
            self.threads.append(thread)
        return FakeProcess(pid, scope, exit_code=self.exit_code, stuck=self.stuck)

    def _vmm(self, path: Path):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(path))
        except OSError:  # the runtime already failed and removed the VM directory
            server.close()
            return
        server.listen(8)
        server.settimeout(5)
        refusals = self.refusals
        try:
            while True:
                conn, _ = server.accept()
                line = b""
                while not line.endswith(b"\n"):
                    chunk = conn.recv(1)
                    if not chunk:
                        break
                    line += chunk
                if refusals:
                    refusals -= 1
                    conn.close()
                    continue
                conn.sendall(b"OK 1073741824\n")
                try:
                    if self.guest is not None:
                        self.guest(conn, self)
                    else:
                        agent.serve(conn, self.executor, identity_for(self.cfg))
                except Exception:
                    pass
                finally:
                    conn.close()
                return
        except OSError:
            return
        finally:
            server.close()


def runtime_for(env: Env, launcher: FakeLauncher, cfg: FirecrackerConfig, **kw) -> FirecrackerRuntime:
    return FirecrackerRuntime(
        cfg, launcher=launcher, cgroup_root=env.cgroup, proc_root=env.proc, kvm_path=Path("/dev/null"), **kw
    )


def climits(**kw) -> CompileLimits:
    return CompileLimits.model_validate(compile_limits_data(**kw))


def elimits(**kw) -> SandboxLimits:
    return SandboxLimits.model_validate(execute_limits_data(**kw))


def preflighted(env, launcher=None, cfg=None, **kw):
    cfg = cfg or env.cfg()
    launcher = launcher or FakeLauncher(env, cfg)
    rt = runtime_for(env, launcher, cfg, **kw)
    rt.preflight(PreflightRequest(compile_limits=climits(), execute_limits=elimits()))
    return rt, launcher


def compile_job(**kw) -> CompileJob:
    return CompileJob(
        candidate=SourceFile(name="candidate.c", data=CANDIDATE_A),
        support_files=[HARNESS, UNIT],
        translation_units=[HARNESS.name, UNIT.name],
        flags=FLAGS,
        limits=kw.pop("limits", climits()),
    )


def execute_job(limits=None, args=("41",)) -> ExecuteJob:
    return ExecuteJob(binary=FAKE_BINARY, args=list(args), limits=limits or elimits())


def failure(info) -> str:
    assert info.value.code is ErrorCode.SANDBOX_FAILED, info.value
    return info.value.details["failure"]


def assert_clean(env: Env, rt: FirecrackerRuntime):
    state = Path(rt.cfg.state_dir)
    assert list(state.iterdir()) == []
    rt.close()


# --------------------------------------------------------------------- config


def test_config_selects_firecracker_and_validates_the_section(env, tmp_path):
    section = json.loads(env.cfg().model_dump_json())
    config = config_from_mapping(
        {"attack_lab": {"candidate_execution": {"runtime": "firecracker", "firecracker": section}}}, base_dir=tmp_path
    )
    assert config.attack_lab.candidate_execution.runtime == "firecracker"
    assert config_from_mapping({}, base_dir=tmp_path).attack_lab.candidate_execution.runtime == "none"
    bad = [
        {"runtime": "firecracker"},
        {"firecracker": section},
        {"runtime": "gvisor", "firecracker": section},
        {"runtime": "firecracker", "firecracker": {**section, "kernel_path": "relative/vmlinux"}},
        {"runtime": "firecracker", "firecracker": {**section, "rootfs_path": "/a/../b"}},
        {"runtime": "firecracker", "firecracker": {**section, "rootfs_sha256": "x"}},
        {"runtime": "firecracker", "firecracker": {**section, "vcpu_count": 3}},
        {"runtime": "firecracker", "firecracker": {**section, "boot_timeout_ms": "15000"}},
        {"runtime": "firecracker", "firecracker": {**section, "network": "tap0"}},
    ]
    for candidate_execution in bad:
        with pytest.raises(AegisError) as info:
            config_from_mapping({"attack_lab": {"candidate_execution": candidate_execution}}, base_dir=tmp_path)
        assert info.value.code is ErrorCode.CONFIG_INVALID


def _fc_config(env, tmp_path, **over):
    section = json.loads(env.cfg(**over).model_dump_json())
    return config_from_mapping(
        {"attack_lab": {"enabled": True, "candidate_execution": {
            "enabled": True, "runtime": "firecracker", "firecracker": section}}},
        base_dir=tmp_path,
    )


def test_configured_runtime_refuses_until_adr_verification_and_host_are_ready(env, tmp_path):
    config = _fc_config(env, tmp_path, containment_verification_sha256=None)
    runtime = configured_runtime(config, host_blockers=lambda: ("kvm_unavailable",))
    assert isinstance(runtime, UnavailableRuntime)
    assert runtime.blockers == ("isolation_adr_not_accepted", "containment_unverified", "kvm_unavailable")
    # ADR not accepted in this revision: refused even when everything else is ready.
    ready = _fc_config(env, tmp_path)
    assert configured_runtime(ready, host_blockers=lambda: ()).blockers == ("isolation_adr_not_accepted",)
    assert isinstance(configured_runtime(ready, host_blockers=lambda: (), adr_accepted=True), FirecrackerRuntime)


# ------------------------------------------------------------------- planning


def test_vm_plan_sizes_guest_and_scope():
    cfg_mib = (512 * MIB + 64 * MIB) // MIB
    from aegis_core.lab_limits import default_compile_ceiling

    del default_compile_ceiling
    plan = plan_vm(FirecrackerConfig.model_validate({**_minimal(), "guest_overhead_mib": 128}), climits())
    assert plan.vm_memory_mib == cfg_mib + 128
    assert plan.scope_memory_max_bytes == (cfg_mib + 128 + 64) * MIB
    assert plan.cpu_quota_percent == 100 and plan.tasks_max == 16
    assert plan.job_seconds == pytest.approx(30 + 2)
    assert plan.runtime_max_sec >= plan.boot_seconds + plan.job_seconds
    assert expected_cgroup_limits(plan) == {
        "memory.max": str(plan.scope_memory_max_bytes),
        "memory.swap.max": "0",
        "pids.max": "16",
        "cpu.max": "100000 100000",
    }


def _minimal() -> dict:
    return {
        "firecracker_path": "/opt/fc/firecracker", "firecracker_sha256": "1" * 64,
        "bwrap_sha256": "2" * 64, "kernel_path": "/opt/fc/vmlinux", "kernel_sha256": "3" * 64,
        "rootfs_path": "/opt/fc/rootfs.ext4", "rootfs_sha256": "4" * 64, "guest_agent_sha256": "5" * 64,
        "compiler_name": "gcc", "compiler_version": "14", "compiler_sha256": "6" * 64, "state_dir": "/run/afc",
    }


# The FullVmConfiguration top-level keys of the Firecracker v1.17.0 API spec.
V117_TOP_LEVEL = {"balloon", "drives", "boot-source", "cpu-config", "logger", "machine-config", "metrics",
                  "memory-hotplug", "mmds-config", "network-interfaces", "pmem", "vsock", "entropy"}


def test_vm_config_has_no_network_no_sharing_and_a_read_only_rate_limited_root():
    cfg = FirecrackerConfig.model_validate(_minimal())
    doc = firecracker_config(cfg, plan_vm(cfg, elimits()))
    assert set(doc) <= V117_TOP_LEVEL
    assert doc["network-interfaces"] == []
    for absent in ("balloon", "mmds-config", "pmem", "memory-hotplug", "logger", "metrics"):
        assert absent not in doc
    [drive] = doc["drives"]
    assert drive["is_read_only"] is True and drive["is_root_device"] is True
    assert drive["rate_limiter"]["bandwidth"] == {"size": 64 * MIB, "refill_time": 1000}
    assert drive["rate_limiter"]["ops"] == {"size": 2000, "refill_time": 1000}
    assert doc["vsock"] == {"guest_cid": 3, "uds_path": "/run/vsock.sock"}
    assert doc["machine-config"]["vcpu_count"] == 1 and doc["machine-config"]["smt"] is False
    assert " ro " in f" {BOOT_ARGS} " and "8250.nr_uarts=0" in BOOT_ARGS and "console=" not in BOOT_ARGS
    assert doc["boot-source"]["boot_args"] == BOOT_ARGS


def test_bwrap_jail_exposes_only_the_pinned_files_and_the_socket_dir():
    cfg = FirecrackerConfig.model_validate(_minimal())
    argv = bwrap_argv(cfg, config_file=Path("/s/v/config.json"), sock_dir=Path("/s/v/sock"), vm_id="9" * 32)
    for flag in ("--unshare-all", "--die-with-parent", "--new-session", "--clearenv"):
        assert flag in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--share-net" not in argv and "--no-seccomp" not in argv and "--seccomp-filter" not in argv
    ro = [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == "--ro-bind"]
    assert ro == [("/opt/fc/firecracker", "/vm/firecracker"), ("/opt/fc/vmlinux", "/vm/vmlinux"),
                  ("/opt/fc/rootfs.ext4", "/vm/rootfs.ext4"), ("/s/v/config.json", "/vm/config.json")]
    assert [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == "--bind"] == [("/s/v/sock", "/run")]
    assert [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == "--dev-bind"] == [("/dev/kvm", "/dev/kvm")]
    assert not any("/home" in a for a in argv)
    tail = argv[argv.index("--") + 1 :]
    assert tail[:4] == ["/vm/firecracker", "--no-api", "--config-file", "/vm/config.json"]


def test_scope_properties_and_environment(monkeypatch):
    cfg = FirecrackerConfig.model_validate(_minimal())
    plan = plan_vm(cfg, elimits())
    argv = scope_argv(cfg, vm_id="9" * 32, plan=plan, inner=["bwrap"])
    assert argv[:5] == ["/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--collect"]
    assert "--unit=aegis-fc-" + "9" * 32 in argv
    props = [argv[i + 1] for i, a in enumerate(argv) if a == "-p"]
    assert props == [f"MemoryMax={plan.scope_memory_max_bytes}", "MemorySwapMax=0", "TasksMax=16",
                     "CPUQuota=100%", f"RuntimeMaxSec={plan.runtime_max_sec}"]
    monkeypatch.setenv("AEGIS_API_TOKEN", "secret")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    env = host_environment()
    assert set(env) <= {"PATH", "LANG", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"}
    assert "secret" not in env.values()


# ------------------------------------------------------------------ preflight


def test_preflight_attests_pinned_identities(env):
    rt, _ = preflighted(env)
    a = rt._attestation
    cfg = rt.cfg
    assert (a.runtime, a.platform, a.rootless, a.network) == ("firecracker", "kvm", True, "none")
    assert (a.runtime_sha256, a.rootfs_sha256, a.guest_kernel_sha256) == (
        cfg.firecracker_sha256, cfg.rootfs_sha256, cfg.kernel_sha256)
    assert a.containment_verification_sha256 == cfg.containment_verification_sha256 and a.isolation_verified


def _blocker(info) -> list[str]:
    assert info.value.code is ErrorCode.SANDBOX_UNAVAILABLE, info.value
    return info.value.details["blockers"]


@pytest.mark.parametrize(
    ("mutate", "blocker"),
    [
        (lambda e: e.files["rootfs.ext4"].write_bytes(b"swapped image"), "rootfs_digest_mismatch"),
        (lambda e: e.files["vmlinux"].chmod(0o666), "kernel_unsafe_permissions"),
        (lambda e: e.files["firecracker"].unlink(), "firecracker_missing"),
        (lambda e: (e.files["bwrap"].unlink(), e.files["bwrap"].symlink_to("/usr/bin/true")), "bwrap_not_regular_file"),
        (lambda e: e.files["systemd-run"].chmod(0o600), "systemd_run_missing"),
    ],
)
def test_preflight_fails_closed_on_any_identity_problem(env, mutate, blocker):
    cfg = env.cfg()
    mutate(env)
    rt = runtime_for(env, FakeLauncher(env, cfg), cfg)
    with pytest.raises(AegisError) as info:
        rt.preflight(PreflightRequest(compile_limits=None, execute_limits=elimits()))
    assert _blocker(info) == [blocker]


def test_preflight_requires_kvm_verification_and_a_safe_state_dir(env, tmp_path):
    cfg = env.cfg(containment_verification_sha256=None)
    with pytest.raises(AegisError) as info:
        runtime_for(env, FakeLauncher(env, cfg), cfg).preflight(PreflightRequest(compile_limits=None, execute_limits=None))
    assert _blocker(info) == ["containment_unverified"]

    cfg = env.cfg()
    rt = FirecrackerRuntime(cfg, launcher=FakeLauncher(env, cfg), kvm_path=env.files["vmlinux"])
    with pytest.raises(AegisError) as info:
        rt.preflight(PreflightRequest(compile_limits=None, execute_limits=None))
    assert _blocker(info) == ["kvm_unavailable"]

    unsafe = env.root / "unsafe"
    unsafe.mkdir(mode=0o755)
    unsafe.chmod(0o755)
    for state, blocker in ((unsafe, "state_dir_unsafe"), (env.root / ("x" * 80), "state_dir_path_too_long")):
        cfg = env.cfg(state_dir=str(state))
        with pytest.raises(AegisError) as info:
            runtime_for(env, FakeLauncher(env, cfg), cfg).preflight(PreflightRequest(compile_limits=None, execute_limits=None))
        assert _blocker(info) == [blocker]
    link = env.root / "link"
    link.symlink_to(env.root / "files")
    cfg = env.cfg(state_dir=str(link))
    with pytest.raises(AegisError) as info:
        runtime_for(env, FakeLauncher(env, cfg), cfg).preflight(PreflightRequest(compile_limits=None, execute_limits=None))
    assert _blocker(info) == ["state_dir_unsafe"]


def test_unpreflighted_or_closed_runtime_refuses(env):
    cfg = env.cfg()
    launcher = FakeLauncher(env, cfg)
    rt = runtime_for(env, launcher, cfg)
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == "sandbox_start_failed"
    rt, launcher = preflighted(env)
    rt.close()
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == "sandbox_start_failed"
    assert launcher.starts == []


# ------------------------------------------------------------------ lifecycle


def test_compile_runs_one_fresh_vm_and_cleans_up(env):
    rt, launcher = preflighted(env)
    obs = rt.compile(compile_job())
    assert obs.status == "exited" and obs.exit_code == 0 and obs.binary == FAKE_BINARY
    [start] = launcher.starts
    [job] = launcher.executor.jobs
    # The guest received exactly the authorized inputs; candidate.c is staged, not a unit.
    assert dict(job.files) == {"candidate.c": CANDIDATE_A, HARNESS.name: HARNESS.data, UNIT.name: UNIT.data}
    assert job.translation_units == (HARNESS.name, UNIT.name) and job.flags == tuple(FLAGS)
    he = obs.host_enforcement
    assert he.memory_max_bytes == int(start["props"]["MemoryMax"]) and he.memory_swap_max_bytes == 0
    assert (he.pids_max, he.cpu_quota_us, he.cpu_period_us, he.vcpu_count) == (16, 100_000, 100_000, 1)
    assert (he.host_cpu_usec, he.host_memory_peak_bytes, he.host_oom_kills) == (4321, 12345678, 0)
    assert start["vm_config"]["network-interfaces"] == []
    scope = env.cgroup / f"user.slice/user-1000.slice/user@1000.service/app.slice/{start['unit']}.scope"
    assert (scope / "cgroup.kill").read_text() == "1"
    assert_clean(env, rt)


def test_execute_sends_only_the_binary_and_case_arguments(env):
    rt, launcher = preflighted(env)
    obs = rt.execute(execute_job(args=("7", "9")))
    assert obs.stdout == b"AEGIS-RESULT 1\n" and obs.host_enforcement is not None
    [job] = launcher.executor.jobs
    assert (job.stage, job.binary, job.args) == ("execute", FAKE_BINARY, ("7", "9"))
    assert_clean(env, rt)


def test_every_stage_gets_a_new_vm_id_key_and_scope(env):
    keys = iter([bytes([1]) * 32, bytes([2]) * 32])
    rt, launcher = preflighted(env, key_factory=lambda: next(keys))
    rt.execute(execute_job())
    rt.execute(execute_job())
    units = [s["unit"] for s in launcher.starts]
    assert len(set(units)) == 2 and rt.vm_runs == 2
    assert_clean(env, rt)


def test_connect_retries_until_the_agent_listens(env):
    cfg = env.cfg()
    rt, launcher = preflighted(env, FakeLauncher(env, cfg, refusals=3), cfg)
    assert rt.execute(execute_job()).status == "exited"
    assert_clean(env, rt)


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"readback": {"memory.max": "max"}}, "resource_enforcement_failed"),
        ({"readback": {"memory.swap.max": "max"}}, "resource_enforcement_failed"),
        ({"readback": {"pids.max": "max"}}, "resource_enforcement_failed"),
        ({"readback": {"cpu.max": "max 100000"}}, "resource_enforcement_failed"),
        ({"scope_unit_override": "someone-else"}, "resource_enforcement_failed"),
    ],
)
def test_job_is_never_sent_unless_cgroup_limits_read_back(env, kw, expected):
    cfg = env.cfg(boot_timeout_ms=500)
    launcher = FakeLauncher(env, cfg, **kw)
    rt, _ = preflighted(env, launcher, cfg)
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == expected
    assert launcher.executor.jobs == []
    assert_clean(env, rt)


@pytest.mark.parametrize(
    "identity_change",
    [{"agent_sha256": "b" * 64}, {"compiler": {"name": "clang", "version": "14.2.0", "sha256": "c" * 64}}],
)
def test_job_is_never_sent_to_an_unexpected_guest(env, identity_change):
    cfg = env.cfg()

    def guest(conn, launcher):
        base = identity_for(cfg)
        ident = agent.AgentIdentity(
            agent_sha256=identity_change.get("agent_sha256", base.agent_sha256),
            compiler=identity_change.get("compiler", base.compiler),
        )
        agent.serve(conn, launcher.executor, ident)

    launcher = FakeLauncher(env, cfg, guest=guest)
    rt, _ = preflighted(env, launcher, cfg)
    with pytest.raises(AegisError) as info:
        rt.compile(compile_job())
    assert failure(info) == "sandbox_start_failed"
    assert launcher.executor.jobs == []
    assert_clean(env, rt)


@pytest.mark.parametrize(
    "kw", [{"refusals": 10_000}, {"no_socket": True}, {"no_socket": True, "exit_code": 1}]
)
def test_boot_failures_are_start_failures(env, kw):
    cfg = env.cfg(boot_timeout_ms=500)
    rt, launcher = preflighted(env, FakeLauncher(env, cfg, **kw), cfg)
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == "sandbox_start_failed"
    assert_clean(env, rt)


def test_launch_errors_and_interrupts_clean_up(env):
    cfg = env.cfg()
    rt, _ = preflighted(env, FakeLauncher(env, cfg, start_error=OSError("no systemd-run")), cfg)
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == "sandbox_start_failed"
    assert_clean(env, rt)
    rt, _ = preflighted(env, FakeLauncher(env, cfg, start_error=KeyboardInterrupt()), cfg)
    with pytest.raises(KeyboardInterrupt):
        rt.execute(execute_job())
    assert_clean(env, rt)


def test_host_kills_a_guest_that_does_not_report_in_time(env):
    cfg = env.cfg(host_grace_ms=100)
    launcher = FakeLauncher(env, cfg, executor=Scripted(delay=1.0))
    rt, _ = preflighted(env, launcher, cfg)
    began = time.monotonic()
    obs = rt.execute(execute_job(limits=elimits(wall_ms=50)))
    assert time.monotonic() - began < 1.0
    assert obs.status == "timeout" and obs.host_enforcement is not None  # host-observed
    assert_clean(env, rt)


def _malicious(action):
    """A guest that completes the handshake, receives the job, then misbehaves."""

    def guest(conn, launcher):
        channel = proto.Channel(conn)
        _, hello = channel.recv({proto.HELLO}, 4096, proto.Deadline(2))
        vm_id = proto.unpack(hello)[0]["vm_id"]
        base = identity_for(launcher.cfg)
        ready = {"protocol": proto.PROTOCOL, "vm_id": vm_id, "agent_version": "x",
                 "agent_sha256": base.agent_sha256, "compiler": base.compiler}
        channel.send(proto.READY, proto.pack(ready), proto.Deadline(2))
        channel.recv({proto.JOB}, 1 << 26, proto.Deadline(2))
        action(channel, conn)

    return guest


def _result(**over):
    header = {"status": "exited", "exit_code": 0, "signal": None, "limit": None, "stdout_truncated": False,
              "stderr_truncated": False, "duration_ms": 1, "cpu_ms": 1, "peak_memory_bytes": 1, "has_binary": False}
    header.update(over)
    return header


def _send(header, blobs=(b"", b"")):
    return lambda ch, conn: ch.send(proto.RESULT, proto.pack(header, list(blobs)), proto.Deadline(2))


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        (_send(_result(), (b"x" * 4097, b"")), "protocol_violation"),  # stdout over the limit
        (_send(_result(has_binary=True), (b"", b"", b"bin")), "protocol_violation"),  # binary on execute
        (_send(_result(status="signaled")), "protocol_violation"),  # inconsistent fields
        (_send({**_result(), "verdict": "pass"}), "protocol_violation"),  # extra field
        (_send(_result(), (b"",)), "protocol_violation"),  # blob count
        (lambda ch, conn: conn.sendall(proto.encode_frame(b"z" * 32, proto.RESULT, 1, b"{}")), "protocol_violation"),
        (lambda ch, conn: conn.sendall(proto.encode_frame(ch.key, proto.RESULT, 5, b"{}")), "protocol_violation"),
        (lambda ch, conn: conn.sendall(proto.HEADER.pack(proto.MAGIC, proto.RESULT, 1, 1 << 30)),
         "protocol_violation"),
        (lambda ch, conn: ch.send(proto.ERROR, proto.pack({"code": "setup_failed"}), proto.Deadline(2)),
         "sandbox_failed"),
        (lambda ch, conn: None, "sandbox_failed"),  # VM went away without a result
    ],
)
def test_misbehaving_guests_are_infrastructure_failures(env, action, expected):
    cfg = env.cfg()
    rt, _ = preflighted(env, FakeLauncher(env, cfg, guest=_malicious(action)), cfg)
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == expected
    assert_clean(env, rt)


def test_vm_lost_after_host_oom_is_a_memory_limit(env):
    cfg = env.cfg()
    rt, _ = preflighted(env, FakeLauncher(env, cfg, guest=_malicious(lambda ch, conn: None), oom_kills=1), cfg)
    obs = rt.execute(execute_job())
    assert (obs.status, obs.limit, obs.host_enforcement.host_oom_kills) == ("limit_exceeded", "memory", 1)
    assert_clean(env, rt)


def test_compile_binary_limit_is_enforced_by_the_host(env):
    cfg = env.cfg()
    big = agent.GuestResult("exited", exit_code=0, duration_ms=1, binary=b"x" * 2048)
    rt, _ = preflighted(env, FakeLauncher(env, cfg, executor=Scripted(big)), cfg)
    with pytest.raises(AegisError) as info:
        rt.compile(compile_job(limits=climits(binary_bytes=1024)))
    assert failure(info) == "protocol_violation"
    assert_clean(env, rt)


def test_unverifiable_cleanup_fails_even_after_a_good_result(env):
    cfg = env.cfg(teardown_timeout_ms=100)
    rt, _ = preflighted(env, FakeLauncher(env, cfg, stuck=True), cfg)
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == "cleanup_failed"
    assert rt._pending_cleanup and rt._live_dirs
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == "sandbox_start_failed"
    with pytest.raises(AegisError) as info:
        rt.close()
    assert failure(info) == "cleanup_failed"
    for process, _ in rt._pending_cleanup.values():
        process.stuck = False
    rt.close()
    assert not rt._pending_cleanup and not rt._live_dirs and not rt._asset_fds


def test_pinned_file_changed_after_preflight_is_refused(env):
    rt, launcher = preflighted(env)
    env.files["rootfs.ext4"].write_bytes(b"different and longer image bytes")
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == "sandbox_start_failed"
    assert launcher.starts == []


def test_launch_uses_sealed_bytes_even_when_original_paths_are_replaced(env):
    cfg = env.cfg()
    original = {name: path.read_bytes() for name, path in env.files.items()}

    class RacingLauncher(FakeLauncher):
        def start(self, argv, environment):
            for name, destination in (("firecracker", "/vm/firecracker"), ("bwrap", None),
                                      ("vmlinux", "/vm/vmlinux"), ("rootfs.ext4", "/vm/rootfs.ext4")):
                path = env.files[name]
                # Replacement occurs after the final metadata check at launch.
                path.unlink()
                path.write_bytes(b"replacement")
                source = Path(argv[argv.index(destination) - 1]) if destination else Path(next(
                    a for a in argv if a.startswith(f"/proc/{os.getpid()}/fd/")))
                assert source.read_bytes() == original[name]
                fd = int(source.name)
                seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
                assert seals & fcntl.F_SEAL_WRITE and seals & fcntl.F_SEAL_GROW and seals & fcntl.F_SEAL_SHRINK
                with pytest.raises(OSError):
                    os.pwrite(fd, b"tampered", 0)
            return super().start(argv, environment)

    rt, _ = preflighted(env, RacingLauncher(env, cfg), cfg)
    assert rt.execute(execute_job()).status == "exited"
    assert_clean(env, rt)


def test_snapshot_rejects_in_place_mutation_and_preserves_original_bytes(env):
    rt, _ = preflighted(env)
    aliases = [Path(f"/proc/{os.getpid()}/fd/{fd}") for fd in rt._asset_fds]
    before = [path.read_bytes() for path in aliases]
    for name in ("firecracker", "bwrap", "vmlinux", "rootfs.ext4"):
        path = env.files[name]
        info = path.stat()
        path.write_bytes(b"x" * info.st_size)
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    assert [path.read_bytes() for path in aliases] == before
    rt.close()
    assert all(not path.exists() for path in aliases)


def test_snapshot_hashes_the_copy_and_refuses_a_swap_during_preflight(env, monkeypatch):
    from aegis_core import lab_firecracker as fc

    copy = fc.sealed_asset

    def racing(identity):
        if identity.path == env.files["rootfs.ext4"]:
            identity.path.write_bytes(b"x" * identity.size)
        return copy(identity)

    monkeypatch.setattr(fc, "sealed_asset", racing)
    cfg = env.cfg()
    rt = runtime_for(env, FakeLauncher(env, cfg), cfg)
    with pytest.raises(AegisError) as info:
        rt.preflight(PreflightRequest(compile_limits=None, execute_limits=elimits()))
    assert _blocker(info) == ["pinned_asset_changed"]
    assert rt._asset_fds == []


@pytest.mark.parametrize("stage", ["compile", "execute"])
def test_guest_success_cannot_override_a_host_oom(env, stage):
    cfg = env.cfg()
    rt, _ = preflighted(env, FakeLauncher(env, cfg, oom_kills=1), cfg)
    obs = rt.compile(compile_job()) if stage == "compile" else rt.execute(execute_job())
    assert obs.status == "limit_exceeded" and obs.limit == "memory"
    assert obs.exit_code is None and obs.host_enforcement.host_oom_kills == 1
    if stage == "compile":
        assert obs.binary is None
    assert_clean(env, rt)


def test_cleanup_exceptions_retain_tracking_and_can_be_retried(env, monkeypatch):
    from aegis_core.lab_firecracker import ScopeCgroup

    cfg = env.cfg()
    rt, _ = preflighted(env, cfg=cfg)
    original = ScopeCgroup.populated

    def unavailable(self):
        raise OSError("cannot verify cleanup")

    monkeypatch.setattr(ScopeCgroup, "populated", unavailable)
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == "cleanup_failed"
    assert rt._pending_cleanup and all(p.exists() for p in rt._live_dirs)
    monkeypatch.setattr(ScopeCgroup, "populated", original)
    rt.close()
    assert not rt._pending_cleanup and not rt._live_dirs


def test_preexisting_vm_directory_is_never_removed(env):
    rt, _ = preflighted(env, id_factory=lambda: "0" * 32)
    path = rt.cfg.state_dir / ("0" * 32)
    path.mkdir()
    marker = path / "existing"
    marker.write_bytes(b"preserve")
    with pytest.raises(AegisError) as info:
        rt.execute(execute_job())
    assert failure(info) == "sandbox_start_failed"
    assert marker.read_bytes() == b"preserve"
    rt.close()


# ------------------------------------------------------ through Core's session


def _session(env, lab_config, make_grant, launcher=None, cfg=None, **grant_over):
    cfg = cfg or env.cfg()
    launcher = launcher or FakeLauncher(env, cfg)
    rt = runtime_for(env, launcher, cfg)
    session = open_session(
        lab_config(), bind_bundle(make_grant(**grant_over),
                                  {"candidate.c": CANDIDATE_A, HARNESS.name: HARNESS.data, UNIT.name: UNIT.data},
                                  [HARNESS.name, UNIT.name]), lab_bindings=LabBindings.model_validate(lab_bindings_data()),
        runtime=rt, clock=lambda: LAB_NOW,
    )
    return session, launcher, rt


def test_session_records_firecracker_attestation_and_host_enforcement(env, lab_config, make_grant):
    session, launcher, rt = _session(env, lab_config, make_grant)
    result = session.compile(ID_A, SourceFile(name="candidate.c", data=CANDIDATE_A), support_files=[HARNESS, UNIT],
                             translation_units=[HARNESS.name, UNIT.name], flags=FLAGS, limits=climits())
    record = result.record
    assert record.runtime.runtime == "firecracker"
    assert record.runtime.containment_verification_sha256 == rt.cfg.containment_verification_sha256
    assert record.observation.host_enforcement.host_cpu_usec == 4321
    assert record.binary_sha256 == sha(FAKE_BINARY)
    run = session.execute(ID_A, result.binary, args=["3"], limits=elimits())
    assert run.observation.stdout == b"AEGIS-RESULT 1\n" and len(launcher.starts) == 2
    session.close()
    assert list(Path(rt.cfg.state_dir).iterdir()) == []


def test_ledger_and_gates_still_apply_before_any_vm_starts(env, lab_config, make_grant):
    session, launcher, _ = _session(env, lab_config, make_grant)
    compile_a = lambda: session.compile(  # noqa: E731
        ID_A, SourceFile(name="candidate.c", data=CANDIDATE_A), support_files=[HARNESS, UNIT],
        translation_units=[HARNESS.name, UNIT.name], flags=FLAGS, limits=climits())
    compile_a()
    with pytest.raises(AegisError) as info:
        compile_a()
    assert info.value.details["reason"] == "compilation_budget_exhausted"
    assert len(launcher.starts) == 1  # the refused compile never launched a VM

    cfg = env.cfg()
    gated = FakeLauncher(env, cfg)
    with pytest.raises(AegisError) as info:
        open_session(lab_config(candidate_execution=False), make_grant(grant_id="9" * 32),
                     lab_bindings=LabBindings.model_validate(lab_bindings_data()),
                     runtime=runtime_for(env, gated, cfg), clock=lambda: LAB_NOW)
    assert info.value.details["reason"] == "candidate_execution_disabled"
    assert gated.starts == []
