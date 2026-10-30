"""Read-only probe of host prerequisites for gVisor or Firecracker isolation.

It only reads files under ``/proc``, ``/sys`` and ``/dev`` and searches ``PATH``.
It never starts a process, creates a cgroup, opens a device or changes anything.
A passing probe means the *prerequisites are present*; it does **not** show
that limits are enforced. Enforcement must be verified separately (ADR 0004,
V1-V11), and it is never reported here.

Run ``python -m aegis_core.lab_host`` to print the probe as JSON.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from .models import AegisModel

REQUIRED_DELEGATED_CONTROLLERS = ("cpu", "memory", "pids")

HOST_BLOCKERS = frozenset(
    {
        "runsc_not_installed",
        "bwrap_missing",
        "kvm_unavailable",
        "systemd_run_missing",
        "cgroup_v2_unavailable",
        "user_cgroup_delegation_missing",
        "unprivileged_userns_unavailable",
    }
)


class HostIsolationProbe(AegisModel):
    probe: Literal["aegis.core.lab-host-probe.v1"] = "aegis.core.lab-host-probe.v1"
    runtime: Literal["gvisor-runsc", "firecracker"] = "gvisor-runsc"
    runsc_path: str | None
    bwrap_path: str | None = None
    systemd_run_path: str | None
    cgroup_v2: bool
    user_delegated_controllers: list[str]
    """Controllers the systemd user manager may delegate to transient scopes."""
    io_controller_delegated: bool
    unprivileged_userns: bool
    kvm_device_accessible: bool
    """/dev/kvm exists and is readable and writable by this user (not opened)."""
    blockers: list[str]
    enforcement_verified: Literal[False] = False
    """Always false: a static probe cannot show that any limit is enforced."""


def _read_text(path: Path) -> str | None:
    try:
        with open(path, encoding="ascii", errors="replace") as handle:
            return handle.read(4096)
    except OSError:
        return None


def probe_host(
    *,
    proc: Path = Path("/proc"),
    sys_root: Path = Path("/sys"),
    dev: Path = Path("/dev"),
    uid: int | None = None,
    which: Callable[[str], str | None] = shutil.which,
    runtime: Literal["gvisor-runsc", "firecracker"] = "gvisor-runsc",
) -> HostIsolationProbe:
    """Inspect the host for one backend. Paths and ``which`` are injectable for tests.

    Firecracker needs ``bwrap`` and a read-write ``/dev/kvm`` instead of ``runsc``;
    both backends need systemd-run, cgroup v2 delegation and user namespaces.
    """
    if uid is None:
        uid = os.getuid() if hasattr(os, "getuid") else -1
    runsc = which("runsc")
    bwrap = which("bwrap")
    systemd_run = which("systemd-run")

    cgroup_root = sys_root / "fs" / "cgroup"
    cgroup_v2 = (cgroup_root / "cgroup.controllers").is_file()

    user_service = (
        cgroup_root
        / "user.slice"
        / f"user-{uid}.slice"
        / f"user@{uid}.service"
        / "cgroup.subtree_control"
    )
    text = _read_text(user_service) if cgroup_v2 else None
    delegated = sorted(set(text.split())) if text else []

    max_userns = _read_text(proc / "sys" / "user" / "max_user_namespaces")
    clone = _read_text(proc / "sys" / "kernel" / "unprivileged_userns_clone")
    try:
        userns = max_userns is not None and int(max_userns.strip()) > 0
    except ValueError:
        userns = False
    if clone is not None and clone.strip() != "1":
        userns = False

    kvm = dev / "kvm"
    kvm_ok = kvm.exists() and os.access(kvm, os.R_OK | os.W_OK)

    blockers: list[str] = []
    if runtime == "gvisor-runsc" and runsc is None:
        blockers.append("runsc_not_installed")
    if runtime == "firecracker":
        if bwrap is None:
            blockers.append("bwrap_missing")
        if not kvm_ok:
            blockers.append("kvm_unavailable")
    if systemd_run is None:
        blockers.append("systemd_run_missing")
    if not cgroup_v2:
        blockers.append("cgroup_v2_unavailable")
    if not all(c in delegated for c in REQUIRED_DELEGATED_CONTROLLERS):
        blockers.append("user_cgroup_delegation_missing")
    if not userns:
        blockers.append("unprivileged_userns_unavailable")

    return HostIsolationProbe(
        runtime=runtime,
        runsc_path=runsc,
        bwrap_path=bwrap,
        systemd_run_path=systemd_run,
        cgroup_v2=cgroup_v2,
        user_delegated_controllers=delegated,
        io_controller_delegated="io" in delegated,
        unprivileged_userns=userns,
        kvm_device_accessible=kvm_ok,
        blockers=blockers,
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    runtime = "firecracker" if args == ["--runtime", "firecracker"] else "gvisor-runsc"
    if args and runtime == "gvisor-runsc" and args != ["--runtime", "gvisor-runsc"]:
        sys.stderr.write("usage: python -m aegis_core.lab_host [--runtime gvisor-runsc|firecracker]\n")
        return 2
    probe = probe_host(runtime=runtime)
    sys.stdout.write(probe.model_dump_json(indent=2) + "\n")
    return 0 if not probe.blockers else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
