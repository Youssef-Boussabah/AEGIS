"""Read-only host prerequisite probe (aegis_core.lab_host), on a fake /proc, /sys and /dev."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_core import lab_host
from aegis_core.lab_host import HOST_BLOCKERS, probe_host

UID = 4242


def make_host(
    root: Path,
    *,
    cgroup_v2: bool = True,
    delegated: str | None = "cpu memory pids",
    max_userns: str | None = "1000",
    clone: str | None = None,
    kvm: bool = True,
) -> dict:
    proc, sysfs, dev = root / "proc", root / "sys", root / "dev"
    for d in (proc, sysfs, dev):
        d.mkdir()
    cgroup = sysfs / "fs" / "cgroup"
    cgroup.mkdir(parents=True)
    if cgroup_v2:
        (cgroup / "cgroup.controllers").write_text("cpuset cpu io memory pids\n")
    if delegated is not None:
        service = cgroup / "user.slice" / f"user-{UID}.slice" / f"user@{UID}.service"
        service.mkdir(parents=True)
        (service / "cgroup.subtree_control").write_text(delegated + "\n")
    if max_userns is not None:
        (proc / "sys" / "user").mkdir(parents=True)
        (proc / "sys" / "user" / "max_user_namespaces").write_text(max_userns + "\n")
    if clone is not None:
        (proc / "sys" / "kernel").mkdir(parents=True)
        (proc / "sys" / "kernel" / "unprivileged_userns_clone").write_text(clone + "\n")
    if kvm:
        (dev / "kvm").write_bytes(b"")
    return {"proc": proc, "sys_root": sysfs, "dev": dev, "uid": UID}


def tools(*present: str):
    return lambda name: f"/opt/bin/{name}" if name in present else None


def test_ready_host_has_no_blockers_but_never_claims_enforcement(tmp_path):
    probe = probe_host(**make_host(tmp_path), which=tools("runsc", "systemd-run"))
    assert probe.blockers == []
    assert probe.runsc_path == "/opt/bin/runsc"
    assert probe.user_delegated_controllers == ["cpu", "memory", "pids"]
    assert probe.io_controller_delegated is False
    assert probe.kvm_device_accessible is True
    assert probe.enforcement_verified is False


def test_this_workstation_shape_reports_only_missing_runsc(tmp_path):
    probe = probe_host(**make_host(tmp_path), which=tools("systemd-run"))
    assert probe.blockers == ["runsc_not_installed"]


@pytest.mark.parametrize(
    ("host", "which", "blocker"),
    [
        ({}, tools("runsc"), "systemd_run_missing"),
        # Without cgroup v2 there can be no delegation either.
        ({"cgroup_v2": False}, tools("runsc", "systemd-run"), "cgroup_v2_unavailable+user_cgroup_delegation_missing"),
        ({"delegated": "cpu memory"}, tools("runsc", "systemd-run"), "user_cgroup_delegation_missing"),
        ({"delegated": None}, tools("runsc", "systemd-run"), "user_cgroup_delegation_missing"),
        ({"max_userns": "0"}, tools("runsc", "systemd-run"), "unprivileged_userns_unavailable"),
        ({"max_userns": "garbage"}, tools("runsc", "systemd-run"), "unprivileged_userns_unavailable"),
        ({"max_userns": None}, tools("runsc", "systemd-run"), "unprivileged_userns_unavailable"),
        ({"clone": "0"}, tools("runsc", "systemd-run"), "unprivileged_userns_unavailable"),
    ],
)
def test_each_missing_prerequisite_is_a_blocker(tmp_path, host, which, blocker):
    probe = probe_host(**make_host(tmp_path, **host), which=which)
    assert probe.blockers == blocker.split("+")
    assert set(probe.blockers) <= HOST_BLOCKERS


def test_io_delegation_and_kvm_are_informational(tmp_path):
    probe = probe_host(**make_host(tmp_path, delegated="cpu io memory pids", kvm=False), which=tools("runsc", "systemd-run"))
    assert probe.blockers == []
    assert probe.io_controller_delegated is True
    assert probe.kvm_device_accessible is False


def test_main_prints_json_and_exits_nonzero_with_blockers(tmp_path, monkeypatch, capsys):
    host = make_host(tmp_path)
    monkeypatch.setattr(lab_host, "probe_host", lambda **kw: probe_host(**host, which=tools("systemd-run"), **kw))
    assert lab_host.main([]) == 1
    assert json.loads(capsys.readouterr().out)["blockers"] == ["runsc_not_installed"]
    monkeypatch.setattr(
        lab_host, "probe_host", lambda **kw: probe_host(**host, which=tools("runsc", "systemd-run"), **kw)
    )
    assert lab_host.main([]) == 0
    capsys.readouterr()
    # Firecracker mode needs bwrap and KVM instead of runsc.
    monkeypatch.setattr(lab_host, "probe_host", lambda **kw: probe_host(**host, which=tools("systemd-run"), **kw))
    assert lab_host.main(["--runtime", "firecracker"]) == 1
    assert json.loads(capsys.readouterr().out)["blockers"] == ["bwrap_missing"]
    assert lab_host.main(["--bogus"]) == 2


def test_firecracker_probe_blockers(tmp_path):
    host = make_host(tmp_path, kvm=False)
    probe = probe_host(**host, which=tools("systemd-run"), runtime="firecracker")
    assert probe.blockers == ["bwrap_missing", "kvm_unavailable"]
    assert probe.runtime == "firecracker"
    (tmp_path / "b").mkdir()
    ready = probe_host(**make_host(tmp_path / "b"), which=tools("bwrap", "systemd-run"), runtime="firecracker")
    assert ready.blockers == [] and ready.enforcement_verified is False
