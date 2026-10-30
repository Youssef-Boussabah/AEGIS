"""Firecracker isolation backend for candidate execution (host side).

One fresh microVM per compile and per execute. Each microVM runs as::

    systemd-run --user --scope   (MemoryMax, MemorySwapMax=0, TasksMax, CPUQuota, RuntimeMaxSec)
      bwrap                      (rootless: new user/mount/pid/ipc/uts/net/cgroup namespaces,
                                  empty root, no /home, no network, no capabilities)
        firecracker --no-api --config-file   (built-in seccomp left enabled)

The microVM has one read-only, rate-limited root drive, no network interface,
no balloon, no MMDS, no shared host directory and no serial console. The host
talks to the guest agent only over virtio-vsock with the authenticated,
size-bounded ``aegis.core.vm-agent.v1`` protocol, and it sends the job only
**after** reading the scope's cgroup limits back and receiving the agent's
READY.

This is a **rootless replacement** for Firecracker's jailer, not the jailer: no
chroot pivot by a privileged parent, no per-VM host uid, no host cgroup created
by root. Its containment is unproven until the F1-F5 and V1-V11 checks of ADR
0004 have run on the target host; the backend refuses to run
(``containment_unverified``) unless the operator pins the digest of that report.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import math
import os
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from . import lab_vm_protocol as proto
from .config import FirecrackerConfig
from .errors import AegisError
from .lab_execution import (
    CompileJob,
    CompileObservation,
    ExecuteJob,
    ExecuteObservation,
    HostEnforcement,
    PreflightRequest,
    RuntimeAttestation,
    sandbox_failure,
    sandbox_unavailable,
)
from .lab_limits import MIB, CompileLimits, SandboxLimits

FIRECRACKER_VERSION = "v1.17.0"
GUEST_CID = 3
JAIL_FIRECRACKER = "/vm/firecracker"
JAIL_KERNEL = "/vm/vmlinux"
JAIL_ROOTFS = "/vm/rootfs.ext4"
JAIL_CONFIG = "/vm/config.json"
JAIL_RUN = "/run"
VSOCK_NAME = "vsock.sock"
# No console (8250.nr_uarts=0): the serial port is not an output channel.
BOOT_ARGS = (
    "reboot=k panic=1 pci=off ro root=/dev/vda rootfstype=ext4 init=/sbin/aegis-init "
    "8250.nr_uarts=0 quiet random.trust_cpu=on"
)
VMM_STDERR_BYTES = 64 * 1024
MAX_VM_MEMORY_MIB = 32 * 1024
CONNECT_RETRY_SECONDS = 0.05
MAX_UNIX_PATH = 107
MAX_PINNED_ASSET_BYTES = 2 * 1024 * MIB


# ------------------------------------------------------------ pinned files


@dataclass(frozen=True)
class FileIdentity:
    path: Path
    sha256: str
    device: int
    inode: int
    size: int
    mtime_ns: int


class PinError(Exception):
    def __init__(self, blocker: str):
        super().__init__(blocker)
        self.blocker = blocker


def verify_pinned(path: Path, expected_sha256: str, *, name: str, uid: int) -> FileIdentity:
    """A regular, non-symlink file owned by the operator or root, not group/world
    writable, whose bytes hash to the pin. Raises ``PinError`` with a fixed blocker."""
    try:
        info = os.lstat(path)
    except OSError:
        raise PinError(f"{name}_missing") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PinError(f"{name}_not_regular_file")
    if info.st_uid not in (uid, 0) or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PinError(f"{name}_unsafe_permissions")
    if info.st_size > MAX_PINNED_ASSET_BYTES:
        raise PinError("pinned_assets_too_large")
    digest = hashlib.sha256()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise PinError(f"{name}_unreadable") from None
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise PinError(f"{name}_changed")
        remaining = info.st_size + 1
        while remaining and (chunk := os.read(fd, min(1 << 20, remaining))):
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (info.st_size, info.st_mtime_ns, info.st_ctime_ns):
            raise PinError(f"{name}_changed")
    finally:
        os.close(fd)
    if digest.hexdigest() != expected_sha256:
        raise PinError(f"{name}_digest_mismatch")
    return FileIdentity(path, expected_sha256, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def unchanged(identity: FileIdentity) -> bool:
    try:
        info = os.lstat(identity.path)
    except OSError:
        return False
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == (
        identity.device,
        identity.inode,
        identity.size,
        identity.mtime_ns,
    ) and stat.S_ISREG(info.st_mode)


def sealed_asset(identity: FileIdentity) -> int:
    """Copy and hash the bytes actually used at launch, then seal the anonymous file.

    An open original inode alone would still permit in-place writes. The sealed
    copy prevents both path replacement and writes through another descriptor.
    Its /proc/<Core pid>/fd alias is held open until verified VM teardown.
    """
    fd = os.memfd_create("aegis-pinned-asset", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    source = None
    try:
        source = os.open(identity.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        info = os.fstat(source)
        if not stat.S_ISREG(info.st_mode) or info.st_size != identity.size or info.st_size > MAX_PINNED_ASSET_BYTES:
            raise PinError("pinned_asset_not_bounded")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(source, 1 << 20):
            size += len(chunk)
            if size > identity.size:
                raise PinError("pinned_asset_not_bounded")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(fd, view):]
        if digest.hexdigest() != identity.sha256:
            raise PinError("pinned_asset_changed")
        os.fchmod(fd, 0o500 if info.st_mode & 0o111 else 0o400)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise
    finally:
        if source is not None:
            os.close(source)


# ------------------------------------------------------------------- planning


@dataclass(frozen=True)
class VmPlan:
    vm_memory_mib: int
    scope_memory_max_bytes: int
    tasks_max: int
    cpu_quota_percent: int
    runtime_max_sec: int
    boot_seconds: float
    job_seconds: float


def plan_vm(cfg: FirecrackerConfig, limits: SandboxLimits) -> VmPlan:
    """Guest RAM holds the job's memory and its tmpfs scratch plus guest overhead;
    the host scope adds the VMM's own overhead. No swap."""
    vm_mib = math.ceil((limits.memory_bytes + limits.scratch_bytes) / MIB) + cfg.guest_overhead_mib
    if vm_mib > MAX_VM_MEMORY_MIB:
        raise ValueError("microVM memory would exceed the supported maximum")
    boot = cfg.boot_timeout_ms / 1000
    job = (limits.wall_ms + cfg.host_grace_ms) / 1000
    total = boot + job + cfg.teardown_timeout_ms / 1000
    return VmPlan(
        vm_memory_mib=vm_mib,
        scope_memory_max_bytes=(vm_mib + cfg.vmm_overhead_mib) * MIB,
        tasks_max=cfg.vmm_tasks,
        cpu_quota_percent=100 * cfg.vcpu_count,
        runtime_max_sec=math.ceil(total) + 1,
        boot_seconds=boot,
        job_seconds=job,
    )


def firecracker_config(cfg: FirecrackerConfig, plan: VmPlan, boot_args: str = BOOT_ARGS) -> dict[str, Any]:
    """The complete v1.17 ``--config-file`` document. Paths are jail paths."""
    return {
        "boot-source": {"kernel_image_path": JAIL_KERNEL, "boot_args": boot_args},
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": JAIL_ROOTFS,
                "is_root_device": True,
                "is_read_only": True,
                "io_engine": "Sync",
                "rate_limiter": {
                    "bandwidth": {"size": cfg.block_bandwidth_bytes_per_s, "refill_time": 1000},
                    "ops": {"size": cfg.block_ops_per_s, "refill_time": 1000},
                },
            }
        ],
        "machine-config": {
            "vcpu_count": cfg.vcpu_count,
            "mem_size_mib": plan.vm_memory_mib,
            "smt": False,
            "track_dirty_pages": False,
            "huge_pages": "None",
        },
        "network-interfaces": [],
        "vsock": {"guest_cid": GUEST_CID, "uds_path": f"{JAIL_RUN}/{VSOCK_NAME}"},
    }


def bwrap_argv(cfg: FirecrackerConfig, *, config_file: Path, sock_dir: Path, vm_id: str) -> list[str]:
    """Rootless jail: only /dev/kvm, the pinned VMM, kernel and image (read-only),
    the VM config (read-only) and the per-VM socket directory are visible."""
    return [
        str(cfg.bwrap_path),
        "--unshare-all",  # user, ipc, pid, net, uts, cgroup namespaces: no host network
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop", "ALL",
        "--uid", "65534",
        "--gid", "65534",
        "--dev", "/dev",
        "--dev-bind", "/dev/kvm", "/dev/kvm",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--ro-bind", str(cfg.firecracker_path), JAIL_FIRECRACKER,
        "--ro-bind", str(cfg.kernel_path), JAIL_KERNEL,
        "--ro-bind", str(cfg.rootfs_path), JAIL_ROOTFS,
        "--ro-bind", str(config_file), JAIL_CONFIG,
        "--bind", str(sock_dir), JAIL_RUN,
        "--chdir", "/tmp",
        "--",
        JAIL_FIRECRACKER,
        "--no-api",
        "--config-file", JAIL_CONFIG,
        "--id", vm_id,
        "--level", "Warn",
    ]


def scope_unit(vm_id: str) -> str:
    return f"aegis-fc-{vm_id}"


def scope_argv(cfg: FirecrackerConfig, *, vm_id: str, plan: VmPlan, inner: list[str]) -> list[str]:
    return [
        str(cfg.systemd_run_path),
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        f"--unit={scope_unit(vm_id)}",
        "-p", f"MemoryMax={plan.scope_memory_max_bytes}",
        "-p", "MemorySwapMax=0",
        "-p", f"TasksMax={plan.tasks_max}",
        "-p", f"CPUQuota={plan.cpu_quota_percent}%",
        "-p", f"RuntimeMaxSec={plan.runtime_max_sec}",
        "--",
        *inner,
    ]


def expected_cgroup_limits(plan: VmPlan) -> dict[str, str]:
    return {
        "memory.max": str(plan.scope_memory_max_bytes),
        "memory.swap.max": "0",
        "pids.max": str(plan.tasks_max),
        "cpu.max": f"{plan.cpu_quota_percent * 1000} 100000",
    }


def host_environment() -> dict[str, str]:
    """systemd-run needs the user manager's bus; nothing else is passed (bwrap clears it)."""
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


# ------------------------------------------------------------- host process


class VmProcess(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def wait(self, timeout: float) -> int | None: ...

    def kill(self) -> None: ...

    def stderr_tail(self) -> bytes: ...


class Launcher(Protocol):
    def start(self, argv: list[str], env: dict[str, str]) -> VmProcess: ...


class _Process:
    def __init__(self, popen: subprocess.Popen[bytes]):
        self._popen = popen
        self.pid = popen.pid
        self._tail = bytearray()
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

    def _drain(self) -> None:
        assert self._popen.stderr is not None
        while chunk := self._popen.stderr.read(4096):
            self._tail += chunk
            del self._tail[:-VMM_STDERR_BYTES]

    def poll(self) -> int | None:
        return self._popen.poll()

    def wait(self, timeout: float) -> int | None:
        try:
            return self._popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self) -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.pid, signal.SIGKILL)

    def stderr_tail(self) -> bytes:
        return bytes(self._tail)


class SubprocessLauncher:
    """argv array, no shell, stdin closed, own session, bounded stderr."""

    def start(self, argv: list[str], env: dict[str, str]) -> VmProcess:
        popen = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        return _Process(popen)


# --------------------------------------------------------------------- cgroup


class ScopeCgroup:
    """The transient scope's cgroup directory (delegated to the operator by systemd)."""

    def __init__(self, path: Path):
        self.path = path

    def read(self, name: str) -> str:
        return (self.path / name).read_text().strip()

    def read_limits(self) -> dict[str, str]:
        return {name: self.read(name) for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max")}

    def _field(self, name: str, key: str) -> int | None:
        try:
            for line in (self.path / name).read_text().splitlines():
                field, _, value = line.partition(" ")
                if field == key:
                    return int(value)
        except (OSError, ValueError):
            return None
        return None

    def cpu_usec(self) -> int | None:
        return self._field("cpu.stat", "usage_usec")

    def oom_kills(self) -> int:
        return self._field("memory.events", "oom_kill") or 0

    def memory_peak(self) -> int | None:
        try:
            return int(self.read("memory.peak"))
        except (OSError, ValueError):
            return None

    def kill(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            (self.path / "cgroup.kill").write_text("1")

    def populated(self) -> bool:
        """True while any process remains. A removed scope directory is empty."""
        value = self._field("cgroup.events", "populated")
        if value is None:
            return self.path.exists()
        return value != 0


def find_scope(
    pid: int,
    unit: str,
    *,
    proc_root: Path,
    cgroup_root: Path,
    deadline: proto.Deadline,
    process: VmProcess | None = None,
) -> ScopeCgroup:
    """The cgroup of ``pid`` once systemd-run has moved it into ``<unit>.scope``.

    Raises ``TimeoutError`` at the deadline, and ``ChildProcessError`` if the
    process already exited (for example: no user bus, so systemd-run failed)."""
    while True:
        try:
            text = (proc_root / str(pid) / "cgroup").read_text()
        except OSError:
            text = ""
        for line in text.splitlines():
            if line.startswith("0::/"):
                relative = line[4:].strip()
                if relative.endswith(f"/{unit}.scope") and ".." not in relative.split("/"):
                    return ScopeCgroup(cgroup_root / relative)
        if process is not None and process.poll() is not None:
            raise ChildProcessError("launcher exited before its scope existed")
        deadline.remaining()  # raises TimeoutError
        time.sleep(0.01)


def config_identity(cfg: FirecrackerConfig) -> dict[str, Any]:
    """Everything a containment report is bound to: pinned artifacts and host controls.
    Changing any of them invalidates a report."""
    return {
        "firecracker_version": FIRECRACKER_VERSION,
        "firecracker_sha256": cfg.firecracker_sha256,
        "bwrap_sha256": cfg.bwrap_sha256,
        "kernel_sha256": cfg.kernel_sha256,
        "rootfs_sha256": cfg.rootfs_sha256,
        "guest_agent_sha256": cfg.guest_agent_sha256,
        "compiler_name": cfg.compiler_name,
        "compiler_version": cfg.compiler_version,
        "compiler_sha256": cfg.compiler_sha256,
        "vcpu_count": cfg.vcpu_count,
        "guest_overhead_mib": cfg.guest_overhead_mib,
        "vmm_overhead_mib": cfg.vmm_overhead_mib,
        "vmm_tasks": cfg.vmm_tasks,
        "block_bandwidth_bytes_per_s": cfg.block_bandwidth_bytes_per_s,
        "block_ops_per_s": cfg.block_ops_per_s,
        "agent_port": cfg.agent_port,
        "boot_args": BOOT_ARGS,
        "host_asset_binding": "sealed-memfd-v1",
    }


MAX_REPORT_BYTES = 1024 * 1024


def read_bounded(path: Path, limit: int) -> bytes:
    """A regular, non-symlink file of at most ``limit`` bytes, read once."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise OSError("not a bounded regular file")
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise OSError("file grew while read")
    return data


# -------------------------------------------------------------------- runtime


def _unavailable(blocker: str) -> AegisError:
    return sandbox_unavailable([blocker], "The Firecracker backend is not available.")


@dataclass(frozen=True)
class VmContext:
    """A running microVM, handed to validation inspectors (host side only)."""

    vm_id: str
    process: VmProcess
    scope: ScopeCgroup
    rundir: Path
    sock_dir: Path
    plan: VmPlan
    readback: dict[str, str]


class FirecrackerRuntime:
    """``IsolationRuntime`` backed by one rootless Firecracker microVM per stage.

    Normal mode serves a ``CandidateExecutionSession`` and requires a pinned,
    passing containment report for exactly this configuration.

    Validation mode (``validation_digests``) exists only for the containment
    driver: it never serves a session (``preflight`` refuses), it compiles only
    sources whose SHA-256 is in ``validation_digests`` (the trusted canaries) and
    executes only binaries it compiled itself.
    """

    def __init__(
        self,
        cfg: FirecrackerConfig,
        *,
        launcher: Launcher | None = None,
        cgroup_root: Path = Path("/sys/fs/cgroup"),
        proc_root: Path = Path("/proc"),
        kvm_path: Path = Path("/dev/kvm"),
        uid: int | None = None,
        id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
        key_factory: Callable[[], bytes] = lambda: os.urandom(proto.KEY_BYTES),
        monotonic: Callable[[], float] = time.monotonic,
        validation_digests: frozenset[str] | None = None,
        inspect: Callable[[VmContext], None] | None = None,
        stale_after_seconds: float | None = None,
        boot_args: str | None = None,
    ):
        self.cfg = FirecrackerConfig.model_validate(cfg.model_dump())
        self.launcher = launcher or SubprocessLauncher()
        self.cgroup_root = cgroup_root
        self.proc_root = proc_root
        self.kvm_path = kvm_path
        self.uid = os.getuid() if uid is None else uid
        self._id = id_factory
        self._key = key_factory
        self._monotonic = monotonic
        self._validation = validation_digests
        self._inspect = inspect if validation_digests is not None else None
        if boot_args is not None and validation_digests is None:
            raise ValueError("boot arguments can be overridden only in validation mode")
        self.boot_args = BOOT_ARGS if boot_args is None else boot_args
        self._stale_after = (
            max(60.0, 2 * cfg.boot_timeout_ms / 1000) if stale_after_seconds is None else stale_after_seconds
        )
        self._identities: list[FileIdentity] | None = None
        self._attestation: RuntimeAttestation | None = None
        self._ready = False
        self._closed = False
        self._lock = threading.Lock()
        self._live_dirs: set[Path] = set()
        self._pending_cleanup: dict[Path, tuple[VmProcess | None, ScopeCgroup | None]] = {}
        self._asset_fds: list[int] = []
        self._launch_cfg: FirecrackerConfig | None = None
        self._validation_binaries: set[str] = set()
        self.vm_runs = 0
        self.swept: list[str] = []

    @property
    def validation_mode(self) -> bool:
        return self._validation is not None

    # -------------------------------------------------------------- preflight

    def preflight(self, request: PreflightRequest) -> RuntimeAttestation:
        if self.validation_mode:
            raise _unavailable("validation_runtime_cannot_serve_sessions")
        cfg = self.cfg
        self._verify_containment_report()
        self._preflight_host(request)
        self._attestation = RuntimeAttestation(
            runtime="firecracker",
            runtime_version=f"firecracker-{FIRECRACKER_VERSION}",
            runtime_sha256=cfg.firecracker_sha256,
            platform="kvm",
            rootless=True,
            network="none",
            rootfs_sha256=cfg.rootfs_sha256,
            compiler_name=cfg.compiler_name,
            compiler_version=cfg.compiler_version,
            compiler_sha256=cfg.compiler_sha256,
            limits_enforcement="verified_by_cgroup_readback",
            isolation_verified=True,
            guest_kernel_sha256=cfg.kernel_sha256,
            guest_agent_sha256=cfg.guest_agent_sha256,
            containment_verification_sha256=cfg.containment_verification_sha256,
        )
        self._ready = True
        return self._attestation

    def validation_preflight(self, request: PreflightRequest) -> None:
        """Host checks for the containment driver. No report is required (it is being made)."""
        if not self.validation_mode:
            raise _unavailable("not_a_validation_runtime")
        self._preflight_host(request)
        self._ready = True

    def _verify_containment_report(self) -> None:
        """Execution needs a pinned report that passed, for this exact configuration."""
        cfg = self.cfg
        if cfg.containment_verification_sha256 is None or cfg.containment_report_path is None:
            raise _unavailable("containment_unverified")
        try:
            data = read_bounded(cfg.containment_report_path, MAX_REPORT_BYTES)
        except OSError:
            raise _unavailable("containment_report_unreadable") from None
        if hashlib.sha256(data).hexdigest() != cfg.containment_verification_sha256:
            raise _unavailable("containment_report_mismatch")
        from .lab_containment import report_permits_execution

        if not report_permits_execution(data, config_identity(cfg)):
            raise _unavailable("containment_report_rejected")

    def _preflight_host(self, request: PreflightRequest) -> None:
        cfg = self.cfg
        try:
            info = os.stat(self.kvm_path)
        except OSError:
            raise _unavailable("kvm_unavailable") from None
        if not stat.S_ISCHR(info.st_mode) or not os.access(self.kvm_path, os.R_OK | os.W_OK):
            raise _unavailable("kvm_unavailable")
        if not (cfg.systemd_run_path.is_file() and os.access(cfg.systemd_run_path, os.X_OK)):
            raise _unavailable("systemd_run_missing")
        try:
            self._identities = [
                verify_pinned(cfg.firecracker_path, cfg.firecracker_sha256, name="firecracker", uid=self.uid),
                verify_pinned(cfg.bwrap_path, cfg.bwrap_sha256, name="bwrap", uid=self.uid),
                verify_pinned(cfg.kernel_path, cfg.kernel_sha256, name="kernel", uid=self.uid),
                verify_pinned(cfg.rootfs_path, cfg.rootfs_sha256, name="rootfs", uid=self.uid),
            ]
        except PinError as exc:
            raise _unavailable(exc.blocker) from None
        self._check_state_dir()
        self._sweep_stale()
        for limits in (request.compile_limits, request.execute_limits):
            if limits is not None:
                try:
                    plan_vm(cfg, limits)
                except ValueError:
                    raise _unavailable("limits_exceed_vm_capacity") from None
        if self._asset_fds:
            raise _unavailable("runtime_already_preflighted")
        assert self._identities is not None
        if sum(i.size for i in self._identities) > MAX_PINNED_ASSET_BYTES:
            raise _unavailable("pinned_assets_too_large")
        try:
            for identity in self._identities:
                self._asset_fds.append(sealed_asset(identity))
            paths = [Path(f"/proc/{os.getpid()}/fd/{fd}") for fd in self._asset_fds]
            self._launch_cfg = cfg.model_copy(update=dict(zip(
                ("firecracker_path", "bwrap_path", "kernel_path", "rootfs_path"), paths)))
        except (OSError, PinError) as exc:
            self._release_assets()
            raise _unavailable(exc.blocker if isinstance(exc, PinError) else "pinned_asset_snapshot_failed") from None
        except BaseException:
            self._release_assets()
            raise

    def _check_state_dir(self) -> None:
        path = self.cfg.state_dir
        # <state_dir>/<32 hex>/sock/vsock.sock must fit a Unix socket path (107 bytes).
        if len(os.fsencode(path)) + 1 + 32 + len(f"/sock/{VSOCK_NAME}") > MAX_UNIX_PATH:
            raise _unavailable("state_dir_path_too_long")
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = os.lstat(path)
        except OSError:
            raise _unavailable("state_dir_unusable") from None
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.uid
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise _unavailable("state_dir_unsafe")

    def _scope_exists(self, vm_id: str) -> bool:
        base = self.cgroup_root / "user.slice" / f"user-{self.uid}.slice" / f"user@{self.uid}.service"
        return any(base.rglob(f"{scope_unit(vm_id)}.scope"))

    def _sweep_stale(self) -> None:
        """Remove per-VM directories left by a crashed Core: old enough, and no scope."""
        now = time.time()
        try:
            entries = list(os.scandir(self.cfg.state_dir))
        except OSError:
            return
        for entry in entries:
            if len(entry.name) != 32 or not all(c in "0123456789abcdef" for c in entry.name):
                continue
            if not entry.is_dir(follow_symlinks=False):
                continue
            try:
                age = now - entry.stat(follow_symlinks=False).st_mtime
            except OSError:
                continue
            if age >= self._stale_after and not self._scope_exists(entry.name):
                shutil.rmtree(entry.path, ignore_errors=True)
                self.swept.append(entry.name)

    # ----------------------------------------------------------------- stages

    def compile(self, job: CompileJob) -> CompileObservation:
        if self._validation is not None and hashlib.sha256(job.candidate.data).hexdigest() not in self._validation:
            raise sandbox_failure("sandbox_start_failed", "Validation mode compiles only the pinned canaries.")
        files = [job.candidate, *job.support_files]
        header = {
            "stage": "compile",
            "files": [f.name for f in files],
            "translation_units": list(job.translation_units),
            "flags": list(job.flags),
            "limits": job.limits.model_dump(),
        }
        obs = self._run(header, [f.data for f in files], job.limits, CompileObservation)
        if self._validation is not None and obs.binary is not None:
            self._validation_binaries.add(hashlib.sha256(obs.binary).hexdigest())
        return obs

    def execute(self, job: ExecuteJob) -> ExecuteObservation:
        if self._validation is not None and hashlib.sha256(job.binary).hexdigest() not in self._validation_binaries:
            raise sandbox_failure("sandbox_start_failed", "Validation mode runs only canaries it compiled.")
        header = {"stage": "execute", "args": list(job.args), "limits": job.limits.model_dump()}
        return self._run(header, [job.binary], job.limits, ExecuteObservation)

    def close(self) -> None:
        """Refuse further runs; fail if any microVM directory of this runtime remains."""
        with self._lock:
            self._closed = True
            for path, (process, scope) in list(self._pending_cleanup.items()):
                self._teardown(process, scope, path)
            leftovers = [p for p in self._live_dirs if os.path.lexists(p)]
            if leftovers or self._pending_cleanup:
                raise sandbox_failure("cleanup_failed", "VM teardown remains unverified after close.")
            self._release_assets()

    def _release_assets(self) -> None:
        for fd in self._asset_fds:
            os.close(fd)
        self._asset_fds.clear()
        self._launch_cfg = None

    # ------------------------------------------------- validation-only probes

    def boot_only(
        self,
        limits: SandboxLimits,
        inspect: Callable[[VmContext], Any],
        *,
        expected_override: dict[str, str] | None = None,
        backstop_seconds: int | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        """Boot a microVM, verify its scope, call ``inspect`` while it runs, tear it down.

        With ``backstop_seconds`` the scope's RuntimeMaxSec is set to that value and the
        host does **not** kill the VM: it waits for systemd to stop it (V9 backstop).
        With ``expected_override`` the read-back is compared to wrong values on purpose
        and must fail (V10). Validation mode only."""
        if not self.validation_mode:
            raise _unavailable("not_a_validation_runtime")
        plan = plan_vm(self.cfg, limits)
        if backstop_seconds is not None:
            plan = VmPlan(**{**plan.__dict__, "runtime_max_sec": backstop_seconds})
        facts: dict[str, Any] = {}

        def body(ctx: VmContext) -> Any:
            result = inspect(ctx)
            if backstop_seconds is not None:
                end = self._monotonic() + backstop_seconds + 15
                while ctx.scope.populated() and self._monotonic() < end:
                    time.sleep(0.2)
                facts["backstop_stopped_scope"] = not ctx.scope.populated()
            return result

        return self._with_vm(plan, body, expected=expected_override), facts

    def raw_session(self, limits: SandboxLimits, action: Callable[[VmContext, socket.socket], Any]) -> tuple[Any, bool]:
        """Boot a microVM, open the vsock connection, hand it to ``action`` (fuzzing),
        then report whether the VM powered itself off within the boot timeout."""
        if not self.validation_mode:
            raise _unavailable("not_a_validation_runtime")
        plan = plan_vm(self.cfg, limits)
        exited: dict[str, bool] = {}

        def body(ctx: VmContext) -> Any:
            boot = proto.Deadline(plan.boot_seconds, self._monotonic)
            conn = self._connect(ctx.process, ctx.sock_dir / VSOCK_NAME, boot)
            try:
                result = action(ctx, conn)
            finally:
                with contextlib.suppress(OSError):
                    conn.close()
            end = self._monotonic() + plan.boot_seconds
            while ctx.process.poll() is None and self._monotonic() < end:
                time.sleep(0.05)
            exited["self"] = ctx.process.poll() is not None
            return result

        result = self._with_vm(plan, body)
        return result, exited.get("self", False)

    # -------------------------------------------------------------- lifecycle

    def _run(self, header: dict[str, Any], blobs: list[bytes], limits: SandboxLimits, kind: type) -> Any:
        with self._lock:
            if self._closed or not self._ready or self._identities is None:
                raise sandbox_failure("sandbox_start_failed", "The runtime is closed or not preflighted.")
            if not all(unchanged(i) for i in self._identities):
                raise sandbox_failure("sandbox_start_failed", "A pinned file changed after preflight.")
            self.vm_runs += 1
            plan = plan_vm(self.cfg, limits)
            started = self._monotonic()

            def body(ctx: VmContext) -> Any:
                boot = proto.Deadline(plan.boot_seconds, self._monotonic)
                conn, channel = self._handshake(ctx.process, ctx.sock_dir / VSOCK_NAME, ctx.vm_id, boot)
                try:
                    if self._inspect is not None:
                        self._inspect(ctx)
                    channel.send(proto.JOB, proto.pack(header, blobs), proto.Deadline(30, self._monotonic))
                    enforcement = {
                        "memory_max_bytes": plan.scope_memory_max_bytes,
                        "memory_swap_max_bytes": 0,
                        "pids_max": plan.tasks_max,
                        "cpu_quota_us": plan.cpu_quota_percent * 1000,
                        "cpu_period_us": 100_000,
                        "vm_memory_mib": plan.vm_memory_mib,
                        "vcpu_count": self.cfg.vcpu_count,
                        "block_bandwidth_bytes_per_s": self.cfg.block_bandwidth_bytes_per_s,
                        "block_ops_per_s": self.cfg.block_ops_per_s,
                    }
                    return self._receive(channel, ctx.process, ctx.scope, limits, kind, plan, started, enforcement)
                finally:
                    with contextlib.suppress(OSError):
                        conn.close()

            return self._with_vm(plan, body)

    def _with_vm(self, plan: VmPlan, body: Callable[[VmContext], Any], *, expected: dict[str, str] | None = None) -> Any:
        """Prepare, launch, verify the scope, run ``body``, then always tear down and verify."""
        if self._closed or not self._ready or self._identities is None:
            raise sandbox_failure("sandbox_start_failed", "The runtime is closed or not preflighted.")
        cfg = self.cfg
        if not all(unchanged(i) for i in self._identities):
            raise sandbox_failure("sandbox_start_failed", "A pinned file changed after preflight.")
        assert self._launch_cfg is not None
        vm_id = self._id()
        rundir = cfg.state_dir / vm_id
        sock_dir = rundir / "sock"
        config_file = rundir / "config.json"
        created = False
        try:
            os.mkdir(rundir, 0o700)
            created = True
            self._live_dirs.add(rundir)
            self._pending_cleanup[rundir] = (None, None)
            os.mkdir(sock_dir, 0o700)
            fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(fd, "w") as handle:
                json.dump(firecracker_config(cfg, plan, self.boot_args), handle)
        except OSError:
            if created:
                self._teardown(None, None, rundir)
            raise sandbox_failure("sandbox_start_failed", "The per-VM directory cannot be prepared.") from None
        argv = scope_argv(
            self._launch_cfg, vm_id=vm_id, plan=plan,
            inner=bwrap_argv(self._launch_cfg, config_file=config_file, sock_dir=sock_dir, vm_id=vm_id),
        )
        process: VmProcess | None = None
        scope: ScopeCgroup | None = None
        outcome: Any = None
        error: BaseException | None = None
        try:
            try:
                process = self.launcher.start(argv, host_environment())
                self._pending_cleanup[rundir] = (process, None)
            except OSError:
                raise sandbox_failure("sandbox_start_failed", "The microVM could not be started.") from None
            boot = proto.Deadline(plan.boot_seconds, self._monotonic)
            try:
                scope = find_scope(
                    process.pid, scope_unit(vm_id),
                    proc_root=self.proc_root, cgroup_root=self.cgroup_root, deadline=boot, process=process,
                )
                self._pending_cleanup[rundir] = (process, scope)
                readback = scope.read_limits()
            except ChildProcessError:
                raise sandbox_failure("sandbox_start_failed", "The launcher exited before the scope existed.") from None
            except (TimeoutError, OSError):
                raise sandbox_failure(
                    "resource_enforcement_failed", "The sandbox scope could not be verified."
                ) from None
            if readback != (expected if expected is not None else expected_cgroup_limits(plan)):
                raise sandbox_failure(
                    "resource_enforcement_failed", "Cgroup limits read back differ from the plan."
                )
            outcome = body(VmContext(vm_id, process, scope, rundir, sock_dir, plan, readback))
        except BaseException as exc:  # includes KeyboardInterrupt: cleanup first, then re-raise
            error = exc
        finally:
            cleanup_ok = self._teardown(process, scope, rundir)
        if not cleanup_ok:
            self._ready = False
            if error is not None and not isinstance(error, Exception):
                error.add_note("VM cleanup failed; runtime retains state for a retry.")
                raise error
            raise sandbox_failure("cleanup_failed", "The microVM or its state was not fully removed.")
        if error is not None:
            raise error
        return outcome

    def _connect(self, process: VmProcess, sock_path: Path, boot: proto.Deadline) -> socket.socket:
        while True:
            if process.poll() is not None:
                raise sandbox_failure("sandbox_start_failed", "The microVM exited during boot.")
            conn = None
            try:
                if os.path.exists(sock_path):
                    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    conn.settimeout(boot.remaining())
                    conn.connect(str(sock_path))
                    proto.firecracker_connect(conn, self.cfg.agent_port, boot)
                    return conn
            except TimeoutError:
                if conn is not None:
                    conn.close()
                raise sandbox_failure("sandbox_start_failed", "The guest agent did not start in time.") from None
            except (OSError, proto.ProtocolError):
                if conn is not None:
                    conn.close()
            try:
                boot.remaining()
            except TimeoutError:
                raise sandbox_failure("sandbox_start_failed", "The guest agent did not start in time.") from None
            time.sleep(CONNECT_RETRY_SECONDS)

    def _handshake(
        self, process: VmProcess, sock_path: Path, vm_id: str, boot: proto.Deadline
    ) -> tuple[socket.socket, proto.Channel]:
        key = self._key()
        conn = self._connect(process, sock_path, boot)
        channel = proto.Channel(conn, key)
        try:
            channel.send(proto.HELLO, proto.hello_payload(vm_id, key), boot)
            _, payload = channel.recv({proto.READY}, 4096, boot)
            ready, blobs = proto.unpack(payload)
        except TimeoutError:
            conn.close()
            raise sandbox_failure("sandbox_start_failed", "The guest agent did not answer in time.") from None
        except (OSError, proto.ProtocolError):
            conn.close()
            raise sandbox_failure("protocol_violation", "The guest agent handshake was invalid.") from None
        expected_compiler = {
            "name": self.cfg.compiler_name,
            "version": self.cfg.compiler_version,
            "sha256": self.cfg.compiler_sha256,
        }
        if (
            blobs
            or ready.get("protocol") != proto.PROTOCOL
            or ready.get("vm_id") != vm_id
            or ready.get("agent_sha256") != self.cfg.guest_agent_sha256
            or ready.get("compiler") != expected_compiler
        ):
            conn.close()
            raise sandbox_failure("sandbox_start_failed", "The guest identity differs from the pinned image.")
        return conn, channel

    def _receive(
        self,
        channel: proto.Channel,
        process: VmProcess,
        scope: ScopeCgroup,
        limits: SandboxLimits,
        kind: type,
        plan: VmPlan,
        started: float,
        enforcement: dict[str, Any],
    ) -> Any:
        binary_cap = limits.binary_bytes if isinstance(limits, CompileLimits) else 0
        max_payload = 4 + proto.MAX_JSON_BYTES + limits.stdout_bytes + limits.stderr_bytes + binary_cap
        deadline = proto.Deadline(plan.job_seconds, self._monotonic)

        def host_observed(status: str, limit: str | None = None) -> Any:
            scope.kill()
            return kind(
                status=status,
                limit=limit,
                duration_ms=int((self._monotonic() - started) * 1000),
                host_enforcement=self._accounting(scope, enforcement),
            )

        try:
            frame_type, payload = channel.recv({proto.RESULT, proto.ERROR}, max_payload, deadline)
        except TimeoutError:
            # The guest did not report within wall + grace: the host stops it.
            return host_observed("timeout")
        except proto.ProtocolError as exc:
            if exc.code in ("connection_closed", "truncated_frame") and scope.oom_kills() > 0:
                return host_observed("limit_exceeded", "memory")
            if exc.code == "connection_closed":
                raise sandbox_failure("sandbox_failed", "The microVM ended without a result.") from None
            if exc.code == "frame_too_large":
                raise sandbox_failure("protocol_violation", "The guest exceeded the output limits.") from None
            raise sandbox_failure("protocol_violation", "The guest sent an invalid result.") from None
        except OSError:
            if scope.oom_kills() > 0:
                return host_observed("limit_exceeded", "memory")
            raise sandbox_failure("sandbox_failed", "The microVM connection failed.") from None
        # A valid RESULT (or ERROR) cannot erase an authoritative host limit.
        if scope.oom_kills() > 0:
            return host_observed("limit_exceeded", "memory")
        try:
            deadline.remaining()
        except TimeoutError:
            return host_observed("timeout")
        if frame_type == proto.ERROR:
            raise sandbox_failure("sandbox_failed", "The guest agent could not run the job.")
        observation = self._observation(payload, limits, kind, scope, enforcement)
        if observation.host_enforcement.host_oom_kills > 0:
            return host_observed("limit_exceeded", "memory")
        try:
            deadline.remaining()
        except TimeoutError:
            return host_observed("timeout")
        return observation

    def _observation(
        self, payload: bytes, limits: SandboxLimits, kind: type, scope: ScopeCgroup, enforcement: dict[str, Any]
    ) -> Any:
        try:
            header, blobs = proto.unpack(payload)
        except proto.ProtocolError:
            raise sandbox_failure("protocol_violation", "The guest result is malformed.") from None
        expected = {
            "status", "exit_code", "signal", "limit", "stdout_truncated", "stderr_truncated",
            "duration_ms", "cpu_ms", "peak_memory_bytes", "has_binary", "blobs",
        }
        has_binary = header.get("has_binary")
        if set(header) != expected or type(has_binary) is not bool or len(blobs) != 2 + int(has_binary):
            raise sandbox_failure("protocol_violation", "The guest result has unexpected fields.")
        stdout, stderr = blobs[0], blobs[1]
        binary = blobs[2] if has_binary else None
        if len(stdout) > limits.stdout_bytes or len(stderr) > limits.stderr_bytes:
            raise sandbox_failure("protocol_violation", "The guest exceeded the output limits.")
        if binary is not None and (kind is not CompileObservation or len(binary) > limits.binary_bytes):
            raise sandbox_failure("protocol_violation", "The guest returned an unexpected binary.")
        fields = {k: header[k] for k in expected - {"has_binary", "blobs"}}
        extra = {"binary": binary} if kind is CompileObservation else {}
        try:
            return kind(
                **fields, stdout=stdout, stderr=stderr,
                host_enforcement=self._accounting(scope, enforcement), **extra,
            )
        except ValidationError:
            raise sandbox_failure("protocol_violation", "The guest result is inconsistent.") from None

    @staticmethod
    def _accounting(scope: ScopeCgroup, enforcement: dict[str, Any]) -> HostEnforcement:
        return HostEnforcement(
            **enforcement,
            host_cpu_usec=scope.cpu_usec(),
            host_memory_peak_bytes=scope.memory_peak(),
            host_oom_kills=scope.oom_kills(),
        )

    def _teardown(self, process: VmProcess | None, scope: ScopeCgroup | None, rundir: Path) -> bool:
        """Kill everything in the scope, wait for it to empty, remove per-VM state. True if verified.
        Never raises: a teardown error is a failed cleanup, not a different exception."""
        try:
            return self._teardown_steps(process, scope, rundir)
        except Exception:
            return False

    def _teardown_steps(self, process: VmProcess | None, scope: ScopeCgroup | None, rundir: Path) -> bool:
        ok = True
        timeout = self.cfg.teardown_timeout_ms / 1000
        if scope is not None:
            try:
                scope.kill()  # every process of the scope, including Firecracker
            except OSError:
                ok = False  # e.g. cgroup.kill not writable: fall back to the process group
        if process is not None:
            # Only signal a child that has not been reaped yet, so its process group id
            # cannot have been reused. Killing bwrap's group stops the jail: its sandboxed
            # child has PR_SET_PDEATHSIG (--die-with-parent) and the PID namespace dies with it.
            if process.poll() is None:
                process.kill()
            if process.wait(timeout) is None:
                ok = False
        if scope is not None:
            end = self._monotonic() + timeout
            while scope.populated():
                if self._monotonic() >= end:
                    ok = False
                    break
                time.sleep(0.01)
        if not ok:
            return False
        shutil.rmtree(rundir, ignore_errors=True)
        removed = not os.path.lexists(rundir)
        if removed:
            self._live_dirs.discard(rundir)
            self._pending_cleanup.pop(rundir, None)
        return ok and removed
