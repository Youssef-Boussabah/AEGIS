"""Containment validation: expectations, the report and its enforcement, the driver end to end.

The driver runs against FakeLauncher (no VM): a fake firecracker process appears in a
fake /proc with a jail root, mounts, task status and network namespace; a scripted
guest returns what each trusted canary would print. Nothing is compiled or executed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from aegis_core import lab_guest_agent as agent
from aegis_core.errors import AegisError
from aegis_core.lab_containment import (
    CHECKS,
    REQUIRED_CHECKS,
    CaseResult,
    ContainmentDriver,
    ContainmentReport,
    _synthetic_report,
    derive_checks,
    derive_overall,
    evaluate,
    load_manifest,
    main,
    parse_canary_line,
    report_bytes,
    report_permits_execution,
)
from aegis_core.lab_execution import CompileJob, ExecuteJob, ExecuteObservation, PreflightRequest, SourceFile
from aegis_core.lab_firecracker import FirecrackerRuntime, config_identity
from aegis_core.models import ErrorCode
from test_lab_firecracker import FakeLauncher, climits, elimits, env, sha  # noqa: F401  (env is a fixture)

CANARIES = Path(__file__).resolve().parents[1] / "guest" / "canaries"


# ------------------------------------------------------------ expectations


def obs(status="exited", exit_code=0, stdout=b"", **kw):
    return ExecuteObservation(status=status, exit_code=exit_code if status == "exited" else None,
                              stdout=stdout, duration_ms=1, **kw)


def test_canary_line_parsing():
    assert parse_canary_line(b"noise\nAEGIS-CANARY net inet=EAFNOSUPPORT ifaces=lo\n") == (
        "net", {"inet": "EAFNOSUPPORT", "ifaces": "lo"})
    assert parse_canary_line(b"nothing here") == (None, {})


def test_expectation_operators():
    expect = {"status": "exited", "exit_code": 0,
              "fields": {"a": {"eq": "1"}, "b": {"ne": "OK"}, "c": {"in": ["x", "y"]}, "d": {"le": 10}}}
    good = obs(stdout=b"AEGIS-CANARY t a=1 b=EPERM c=y d=10\n")
    assert evaluate(expect, good)[0] == []
    bad = obs(stdout=b"AEGIS-CANARY t a=2 b=OK c=z d=11\n")
    assert len(evaluate(expect, bad)[0]) == 4
    assert evaluate(expect, obs(stdout=b""))[0][0] == "field a missing"
    assert evaluate({"status": "limit_exceeded", "limit": "memory"}, obs())[0]


# ------------------------------------------------------------------ report


def _cases(status="passed"):
    names = sorted({n for _, ns in CHECKS.values() for n in ns})
    return [CaseResult(case=n, status=status, failures=[] if status in ("passed", "not_run") else ["x"])
            for n in names]


def test_report_verdict_is_derived_from_cases():
    checks = derive_checks(_cases())
    assert {c.status for c in checks} == {"passed"}
    assert derive_overall("candidate_guest", checks) == "passed"
    assert derive_overall("smoke_fixture", checks) == "incomplete"  # smoke never passes
    one_failed = _cases()
    one_failed[0] = CaseResult(case=one_failed[0].case, status="failed", failures=["boom"])
    assert derive_overall("candidate_guest", derive_checks(one_failed)) == "failed"
    missing = [c for c in _cases() if c.case != "net"]
    assert derive_overall("candidate_guest", derive_checks(missing)) == "incomplete"


def test_report_cannot_claim_more_than_its_cases():
    data = json.loads(_synthetic_report("candidate_guest", {"x": 1}, passed=False))
    data["overall"] = "passed"
    with pytest.raises(ValueError):
        ContainmentReport.model_validate(data)
    data = json.loads(_synthetic_report("candidate_guest", {"x": 1}, passed=False))
    data["checks"][0]["status"] = "passed"
    with pytest.raises(ValueError):
        ContainmentReport.model_validate(data)
    with pytest.raises(ValueError):
        CaseResult(case="net", status="passed", failures=["contradiction"])
    with pytest.raises(ValueError):
        CaseResult(case="net", status="failed")


def test_only_a_passed_bound_candidate_report_permits_execution():
    identity = {"rootfs_sha256": "1" * 64, "vcpu_count": 1}
    good = _synthetic_report("candidate_guest", identity, passed=True)
    assert report_permits_execution(good, identity)
    assert not report_permits_execution(good, {**identity, "vcpu_count": 2})
    assert not report_permits_execution(_synthetic_report("candidate_guest", identity, passed=False), identity)
    assert not report_permits_execution(_synthetic_report("smoke_fixture", identity, passed=True), identity)
    assert not report_permits_execution(good[:-10], identity)
    duplicated = good.replace(b'"overall": "passed"', b'"overall": "failed", "overall": "passed"')
    assert not report_permits_execution(duplicated, identity)


# ------------------------------------------- runtime enforcement of reports


def _blockers(info):
    assert info.value.code is ErrorCode.SANDBOX_UNAVAILABLE, info.value
    return info.value.details["blockers"]


def test_runtime_refuses_without_a_matching_passed_report(env, tmp_path):
    def preflight(cfg):
        rt = FirecrackerRuntime(cfg, launcher=FakeLauncher(env, cfg), cgroup_root=env.cgroup,
                                proc_root=env.proc, kvm_path=Path("/dev/null"))
        return rt.preflight(PreflightRequest(compile_limits=None, execute_limits=None))

    good = env.cfg()
    assert preflight(good).runtime == "firecracker"
    identity = config_identity(good)
    cases = {
        "failed": (_synthetic_report("candidate_guest", identity, passed=False), "containment_report_rejected"),
        "smoke": (_synthetic_report("smoke_fixture", identity, passed=True), "containment_report_rejected"),
        "other_config": (_synthetic_report("candidate_guest", {**identity, "vcpu_count": 2}, passed=True),
                         "containment_report_rejected"),
    }
    for name, (data, blocker) in cases.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(data)
        cfg = good.model_copy(update={"containment_report_path": path, "containment_verification_sha256": sha(data)})
        with pytest.raises(AegisError) as info:
            preflight(cfg)
        assert _blockers(info) == [blocker], name
    with pytest.raises(AegisError) as info:
        preflight(good.model_copy(update={"containment_verification_sha256": "0" * 64}))
    assert _blockers(info) == ["containment_report_mismatch"]
    link = tmp_path / "link.json"
    link.symlink_to(good.containment_report_path)
    with pytest.raises(AegisError) as info:
        preflight(good.model_copy(update={"containment_report_path": link}))
    assert _blockers(info) == ["containment_report_unreadable"]
    # A pinned artifact changing (here the agent) invalidates the report too.
    with pytest.raises(AegisError) as info:
        preflight(good.model_copy(update={"guest_agent_sha256": "9" * 64}))
    assert _blockers(info) == ["containment_report_rejected"]


def test_validation_runtime_is_restricted(env):
    manifest = load_manifest(CANARIES)
    cfg = env.cfg()
    launcher = FakeLauncher(env, cfg)
    rt = FirecrackerRuntime(cfg, launcher=launcher, cgroup_root=env.cgroup, proc_root=env.proc,
                            kvm_path=Path("/dev/null"), validation_digests=manifest.digests)
    with pytest.raises(AegisError) as info:
        rt.preflight(PreflightRequest(compile_limits=None, execute_limits=None))
    assert _blockers(info) == ["validation_runtime_cannot_serve_sessions"]
    rt.validation_preflight(PreflightRequest(compile_limits=climits(), execute_limits=elimits()))
    job = CompileJob(candidate=SourceFile(name="candidate.c", data=b"int main(void){return 0;}\n"),
                     support_files=[], translation_units=["candidate.c"], flags=["-std=c11"], limits=climits())
    with pytest.raises(AegisError) as info:
        rt.compile(job)  # not a pinned canary
    assert info.value.details["failure"] == "sandbox_start_failed"
    with pytest.raises(AegisError):
        rt.execute(ExecuteJob(binary=b"\x7fELF anything", args=[], limits=elimits()))
    assert launcher.starts == []
    with pytest.raises(ValueError):
        FirecrackerRuntime(cfg, boot_args="init=/bin/sh")  # only validation runtimes may change boot args
    normal = FirecrackerRuntime(cfg, launcher=launcher)
    with pytest.raises(AegisError) as info:
        normal.validation_preflight(PreflightRequest(compile_limits=None, execute_limits=None))
    assert _blockers(info) == ["not_a_validation_runtime"]
    for probe in (lambda: normal.boot_only(elimits(), lambda ctx: None),
                  lambda: normal.raw_session(elimits(), lambda ctx, conn: None)):
        with pytest.raises(AegisError):
            probe()


# ------------------------------------------------------------ the driver


def _canary_results(manifest, broken: set[str]):
    by_digest = {hashlib.sha256(d).hexdigest(): name for name, d in manifest.sources.items()}
    lines = {
        "control.c": b"AEGIS-CANARY control value=42 uid=1000\n",
        "net.c": b"AEGIS-CANARY net inet=EAFNOSUPPORT udp=EAFNOSUPPORT inet6=EAFNOSUPPORT vsock_host=ECONNRESET "
                 b"vsock_host_agent_port=ECONNRESET vsock_self_agent=ECONNREFUSED packet=EAFNOSUPPORT ifaces=lo\n",
        "fs.c": b"AEGIS-CANARY fs home=absent host_root=absent kvm=absent write_root=EROFS write_usr=EROFS "
                b"write_etc=EROFS vda_rw=EACCES vda_ro=EACCES proc1_environ=EACCES proc1_mem=EACCES mount=EPERM "
                b"chroot=EPERM userns=EINVAL setid=0 scratch=OK\n",
        "identity.c": b"AEGIS-CANARY identity uid=1000 euid=1000 gid=1000 egid=1000 groups=0 "
                      b"capeff=0000000000000000 nnp=1\n",
        "scratch.c": b"AEGIS-CANARY scratch written=8388608 errno=ENOSPC\n",
        "orphan.c": b"AEGIS-CANARY orphan spawned=yes\n",
    }
    if "net" in broken:
        lines["net.c"] = lines["net.c"].replace(b"inet=EAFNOSUPPORT", b"inet=OK")

    class Executor:
        def run(self, job: agent.GuestJob) -> agent.GuestResult:
            if job.stage == "compile":
                name = by_digest[hashlib.sha256(dict(job.files)["candidate.c"]).hexdigest()]
                assert dict(job.files)["canary.h"] and job.translation_units == ("candidate.c",)
                if name == "bigbinary.c":
                    return agent.GuestResult("limit_exceeded", limit="binary", duration_ms=1)
                return agent.GuestResult("exited", exit_code=0, duration_ms=1, binary=f"BIN:{name}".encode())
            name = job.binary.decode().split(":", 1)[1]
            if name in lines:
                code = 4 if name == "scratch.c" else 0
                return agent.GuestResult("exited", exit_code=code, stdout=lines[name], duration_ms=1)
            limit = {"forkbomb.c": "processes", "memory.c": "memory", "spin.c": "cpu",
                     "flood.c": "stdout" if job.args == ("1",) else "stderr"}.get(name)
            if limit:
                return agent.GuestResult("limit_exceeded", limit=limit, duration_ms=1)
            return agent.GuestResult("timeout", duration_ms=2000)  # sleeper

    return Executor()


class JailedLauncher(FakeLauncher):
    """Adds the firecracker process (jail view, task status, netns), RuntimeMaxSec and self power-off."""

    def __init__(self, env, cfg, *, jail_extra=(), seccomp="2", ifaces=("lo",), **kw):
        super().__init__(env, cfg, **kw)
        self.jail_extra, self.seccomp, self.ifaces = jail_extra, seccomp, ifaces
        self.current = None
        guest = self.guest

        def serve_then_power_off(conn, launcher):
            try:
                if guest is not None:
                    guest(conn, launcher)
                else:
                    agent.serve(conn, launcher.executor, _identity(launcher.cfg))
            finally:
                if launcher.current is not None:
                    launcher.current.exit_code = 0  # the agent powers the VM off

        self.guest = serve_then_power_off

    def start(self, argv, env_vars):
        process = super().start(argv, env_vars)
        self.current = process
        scope = process.scope
        fc = process.pid + 50000
        (scope / "cgroup.procs").write_text(f"{process.pid}\n{fc}\n")
        proc = self.env.proc / str(fc)
        (proc / "task" / str(fc)).mkdir(parents=True)
        (proc / "task" / str(fc + 1)).mkdir()
        (proc / "comm").write_text("fc_main\n")  # thread names are not relied on
        (proc / "cmdline").write_bytes(b"/vm/firecracker\0--no-api\0--config-file\0/vm/config.json\0")
        (proc / "status").write_text(f"Name:\tfirecracker\nPPid:\t{process.pid}\n")
        for tid in (fc, fc + 1):
            (proc / "task" / str(tid) / "status").write_text(
                f"Seccomp:\t{self.seccomp}\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\n")
        root = proc / "root"
        for entry in ("dev", "proc", "run", "tmp", "vm", *self.jail_extra):
            (root / entry).mkdir(parents=True)
        (root / "run" / "vsock.sock").write_text("")
        mounts = ["/", "/dev", "/dev/kvm", "/dev/null", "/proc", "/tmp", "/vm/firecracker", "/vm/vmlinux",
                  "/vm/rootfs.ext4", "/vm/config.json", "/run"] + [f"/{e}" for e in self.jail_extra]
        (proc / "mountinfo").write_text("".join(f"{i} 1 0:1 / {m} rw - x x rw\n" for i, m in enumerate(mounts)))
        (proc / "net").mkdir()
        (proc / "net" / "dev").write_text("h1\nh2\n" + "".join(f"  {i}: 0 0\n" for i in self.ifaces))
        props = dict(argv[i + 1].split("=", 1) for i, a in enumerate(argv) if a == "-p")
        runtime_max = int(props["RuntimeMaxSec"])
        if runtime_max <= 5:  # the backstop case: systemd stops the scope by itself
            def stop():
                time.sleep(runtime_max)
                process.exit_code = 0
                try:
                    (scope / "cgroup.events").write_text("populated 0\n")
                except OSError:
                    pass  # already torn down and removed
            threading.Thread(target=stop, daemon=True).start()
        # systemd removes an emptied scope: emulate on kill.
        original_poll = process.poll
        ended: dict[str, int] = {}

        def poll():
            if "rc" in ended:
                return ended["rc"]
            result = original_poll()
            if result is not None:
                ended["rc"] = result
                (self.env.proc / str(fc) / "cmdline").write_bytes(b"")
                (self.env.proc / str(fc) / "comm").write_text("gone\n")
                shutil.rmtree(scope, ignore_errors=True)
            return result

        process.poll = poll
        return process


def _identity(cfg):
    return agent.AgentIdentity(agent_sha256=cfg.guest_agent_sha256, compiler={
        "name": cfg.compiler_name, "version": cfg.compiler_version, "sha256": cfg.compiler_sha256})


def make_driver(env, *, target="candidate_guest", broken=(), launcher_kw=None):
    manifest = load_manifest(CANARIES)
    cfg = env.cfg(boot_timeout_ms=3000)
    launchers = []

    def factory(c, **kw):
        launcher = JailedLauncher(env, c, executor=_canary_results(manifest, set(broken)), **(launcher_kw or {}))
        launchers.append(launcher)
        return FirecrackerRuntime(c, launcher=launcher, cgroup_root=env.cgroup, proc_root=env.proc,
                                  kvm_path=Path("/dev/null"), **kw)

    driver = ContainmentDriver(cfg, manifest, target=target, runtime_factory=factory, proc_root=env.proc,
                               cgroup_root=env.cgroup, uid=1000, inspect_timeout=2.0, backstop_seconds=1)
    return driver, launchers, cfg


def test_full_validation_passes_and_its_report_enables_the_runtime(env):
    driver, launchers, cfg = make_driver(env)
    report = driver.run()
    failing = {c.case: c.failures for c in report.cases if c.status != "passed"}
    assert failing == {}
    assert report.overall == "passed" and {c.check for c in report.checks} == set(REQUIRED_CHECKS)
    assert report.identity == config_identity(cfg)
    # Only canary sources were compiled; every VM was torn down.
    starts = sum(len(lch.starts) for lch in launchers)
    assert starts == 3 + 13 + 12 + 5  # host probes, compiles, executes, fuzz
    assert list(Path(cfg.state_dir).iterdir()) == []
    # The report enables execution for exactly this configuration.
    data = report_bytes(report)
    path = env.root / "validated.json"
    path.write_bytes(data)
    enabled = cfg.model_copy(update={"containment_report_path": path,
                                     "containment_verification_sha256": hashlib.sha256(data).hexdigest()})
    rt = FirecrackerRuntime(enabled, launcher=FakeLauncher(env, enabled), kvm_path=Path("/dev/null"))
    assert rt.preflight(PreflightRequest(compile_limits=None, execute_limits=None)).runtime == "firecracker"


@pytest.mark.parametrize(
    ("kw", "check", "case"),
    [
        ({"broken": {"net"}}, "V1", "net"),
        ({"launcher_kw": {"jail_extra": ("home",)}}, "F1", "jail_view"),
        ({"launcher_kw": {"seccomp": "0"}}, "F3", "vmm_seccomp"),
        ({"launcher_kw": {"ifaces": ("lo", "eth0")}}, "F2", "host_sockets_and_netns"),
    ],
)
def test_any_containment_failure_leaves_execution_disabled(env, kw, check, case):
    driver, _, cfg = make_driver(env, **kw)
    report = driver.run()
    assert report.overall == "failed"
    assert {c.check: c.status for c in report.checks}[check] == "failed"
    assert {c.case: c.status for c in report.cases}[case] == "failed"
    data = report_bytes(report)
    path = env.root / "failed.json"
    path.write_bytes(data)
    bad = cfg.model_copy(update={"containment_report_path": path,
                                 "containment_verification_sha256": hashlib.sha256(data).hexdigest()})
    rt = FirecrackerRuntime(bad, launcher=FakeLauncher(env, bad), kvm_path=Path("/dev/null"))
    with pytest.raises(AegisError) as info:
        rt.preflight(PreflightRequest(compile_limits=None, execute_limits=None))
    assert _blockers(info) == ["containment_report_rejected"]


def test_smoke_fixture_runs_host_checks_only_and_never_enables_execution(env):
    driver, launchers, _ = make_driver(env, target="smoke_fixture")
    report = driver.run()
    statuses = {c.case: c.status for c in report.cases}
    assert all(statuses[c] == "passed" for c in ("jail_view", "vmm_seccomp", "host_sockets_and_netns",
                                                 "teardown_verified", "backstop", "readback_mismatch",
                                                 "pin_mismatch", "report_enforcement", "no_leftovers",
                                                 "rootfs_unchanged"))
    assert "net" not in statuses and report.overall == "incomplete"
    assert sum(len(lch.starts) for lch in launchers) == 3
    assert not report_permits_execution(report_bytes(report), report.identity)
    # The smoke VM boots with its own init, never the agent's.
    vm_config = launchers[0].starts[0]["vm_config"]
    assert "init=" not in vm_config["boot-source"]["boot_args"]


def test_inspection_failure_is_an_error_for_every_dependent_case(env):
    driver, _, _ = make_driver(env, target="smoke_fixture", launcher_kw={"readback": {"pids.max": "max"}})
    report = driver.run()
    statuses = {c.case: c.status for c in report.cases}
    for case in ("teardown_verified", "jail_view", "vmm_seccomp", "host_sockets_and_netns", "backstop"):
        assert statuses[case] == "error"
    assert report.overall == "failed"


# ----------------------------------------------------------------- the CLI


def _config_file(env, cfg) -> Path:
    section = json.loads(cfg.model_dump_json(exclude_none=True))
    lines = ["[attack_lab.candidate_execution]", 'runtime = "firecracker"', "",
             "[attack_lab.candidate_execution.firecracker]"]
    lines += [f"{k} = {json.dumps(v)}" for k, v in section.items()]
    path = env.root / "aegis.toml"
    path.write_text("\n".join(lines) + "\n")
    return path


def test_cli_plan_starts_nothing_and_run_requires_approval(env, capsys, monkeypatch):
    cfg = env.cfg()
    path = _config_file(env, cfg)
    started = []
    monkeypatch.setattr("aegis_core.lab_firecracker.SubprocessLauncher.start",
                        lambda *a, **k: started.append(a) or (_ for _ in ()).throw(AssertionError("launch")))
    assert main(["plan", "--config", str(path), "--target", "candidate_guest", "--canaries", str(CANARIES)]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["starts_vms"] == 33 and plan["concurrent_vms"] == 1
    assert plan["peak_scope_memory_bytes"] > 0 and "no sudo" in plan["privileges"]
    assert main(["run", "--config", str(path), "--target", "smoke_fixture", "--canaries", str(CANARIES),
                 "--report", str(env.root / "r.json")]) == 2
    assert started == [] and not (env.root / "r.json").exists()


# ------------------------------------------------------- canary fixtures


def test_manifest_and_check_catalog_agree():
    manifest = load_manifest(CANARIES)
    canary_cases = {c.case for c in manifest.cases}
    referenced = {n for _, names in CHECKS.values() for n in names}
    from aegis_core.lab_containment import FUZZ_CASES, HOST_CASES

    assert canary_cases | set(HOST_CASES) | set(FUZZ_CASES) == referenced
    assert len(manifest.sha256) == 64 and len(manifest.digests) == 12


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")
@pytest.mark.parametrize("source", sorted(p.name for p in CANARIES.glob("*.c")))
def test_canaries_pass_strict_syntax_checks(source):
    # -fsyntax-only: no object file, no binary, nothing executed.
    proc = subprocess.run(["gcc", "-std=c11", "-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-I", str(CANARIES),
                           str(CANARIES / source)], capture_output=True, check=False, shell=False)
    assert proc.returncode == 0, proc.stderr.decode()
