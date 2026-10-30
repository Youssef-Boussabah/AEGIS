"""Guest agent for Firecracker sandboxes (runs **inside** the microVM as PID 1).

Standard library only; installed in the read-only guest image as
``/opt/aegis/lab_guest_agent.py`` next to ``lab_vm_protocol.py`` and started by
``/sbin/aegis-init``. One microVM runs exactly one job:

1. listen on vsock ``AGENT_PORT``; accept one host connection;
2. HELLO -> READY: report this agent's SHA-256 and the compiler identity from
   ``/etc/aegis/guest.json`` *before* any untrusted input exists in the guest;
3. JOB -> run it in a fresh tmpfs scratch, as an unprivileged user, in a guest
   cgroup with the job's memory, process and CPU limits and a wall clock;
4. RESULT (observations only, never a verdict) -> power off.

The guest has no network device, no host directory and no credentials. The
agent never receives hidden-test expectations. Everything the job produces is
untrusted; after the candidate has run, a compromised guest kernel can forge
any report, so the host treats RESULT as an observation and relies on its own
limits and timeouts.

``GuestExecutor`` forks and executes the compiler or the candidate. It is
exercised only inside an approved guest; host tests cover parsing,
classification and the protocol loop with a scripted executor.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import select
import signal
import socket
import time
from dataclasses import dataclass
from typing import Any, Protocol

try:  # inside the package (host tests) or flat in the guest image
    from . import lab_vm_protocol as proto
except ImportError:  # pragma: no cover - guest layout
    import lab_vm_protocol as proto  # type: ignore[no-redef]

AGENT_VERSION = "aegis.core.guest-agent.v1"
AGENT_PORT = 10000
GUEST_MANIFEST = "/etc/aegis/guest.json"
SCRATCH = "/scratch"
JOB_CGROUP = "/sys/fs/cgroup/aegis-job"
RUNNER_UID = RUNNER_GID = 1000
BINARY_NAME = "candidate"
MAX_JOB_PAYLOAD = 80 * 1024 * 1024
HANDSHAKE_SECONDS = 30.0
SEND_SECONDS = 30.0

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}\.[ch]$")
ARG_RE = re.compile(r"^[A-Za-z0-9_.+:=,-]{1,256}$")
FLAG_RE = re.compile(
    r"^-(?:std=c11|O[0-3s]|static|fwrapv|fno-strict-aliasing|fno-builtin|fno-pie|no-pie|w|Wall|"
    r"Wextra|pedantic|Werror=[a-z][a-z-]{0,62})$"
)
LIMIT_KEYS = ("wall_ms", "cpu_ms", "memory_bytes", "max_processes", "scratch_bytes", "stdout_bytes", "stderr_bytes")


# ------------------------------------------------------------------ job model


@dataclass(frozen=True)
class GuestJob:
    stage: str
    limits: dict[str, int]
    files: tuple[tuple[str, bytes], ...] = ()
    translation_units: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    binary: bytes = b""
    args: tuple[str, ...] = ()


@dataclass
class GuestResult:
    status: str
    exit_code: int | None = None
    signal: int | None = None
    limit: str | None = None
    stdout: bytes = b""
    stdout_truncated: bool = False
    stderr: bytes = b""
    stderr_truncated: bool = False
    duration_ms: int = 0
    cpu_ms: int | None = None
    peak_memory_bytes: int | None = None
    binary: bytes | None = None

    def payload(self) -> bytes:
        header = {
            "status": self.status,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "limit": self.limit,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "duration_ms": self.duration_ms,
            "cpu_ms": self.cpu_ms,
            "peak_memory_bytes": self.peak_memory_bytes,
            "has_binary": self.binary is not None,
        }
        blobs = [self.stdout, self.stderr] + ([self.binary] if self.binary is not None else [])
        return proto.pack(header, blobs)


def _limits(value: Any, stage: str) -> dict[str, int]:
    keys = LIMIT_KEYS + (("binary_bytes",) if stage == "compile" else ())
    if not isinstance(value, dict) or set(value) != set(keys):
        raise proto.ProtocolError("bad_limits")
    if not all(type(value[k]) is int and value[k] > 0 for k in keys):
        raise proto.ProtocolError("bad_limits")
    return dict(value)


def parse_job(header: dict[str, Any], blobs: list[bytes]) -> GuestJob:
    """Re-validate a JOB inside the guest (defense in depth; the host validated it first)."""
    stage = header.get("stage")
    if stage == "compile":
        allowed = {"stage", "files", "translation_units", "flags", "limits", "blobs"}
        if set(header) != allowed:
            raise proto.ProtocolError("bad_job")
        names = header["files"]
        if not isinstance(names, list) or len(names) != len(blobs) or not names:
            raise proto.ProtocolError("bad_files")
        if len(set(names)) != len(names) or not all(isinstance(n, str) and NAME_RE.match(n) for n in names):
            raise proto.ProtocolError("bad_files")
        units = header["translation_units"]
        if (
            not isinstance(units, list)
            or not units
            or len(set(units)) != len(units)
            or not all(u in names and u.endswith(".c") for u in units)
        ):
            raise proto.ProtocolError("bad_translation_units")
        flags = header["flags"]
        if not isinstance(flags, list) or not all(isinstance(f, str) and FLAG_RE.match(f) for f in flags):
            raise proto.ProtocolError("bad_flags")
        return GuestJob(
            stage="compile",
            limits=_limits(header["limits"], "compile"),
            files=tuple(zip(names, blobs)),
            translation_units=tuple(units),
            flags=tuple(flags),
        )
    if stage == "execute":
        if set(header) != {"stage", "args", "limits", "blobs"} or len(blobs) != 1 or not blobs[0]:
            raise proto.ProtocolError("bad_job")
        args = header["args"]
        if not isinstance(args, list) or len(args) > 64 or not all(isinstance(a, str) and ARG_RE.match(a) for a in args):
            raise proto.ProtocolError("bad_args")
        return GuestJob(stage="execute", limits=_limits(header["limits"], "execute"), binary=blobs[0], args=tuple(args))
    raise proto.ProtocolError("unsupported_stage")


class Executor(Protocol):
    def run(self, job: GuestJob) -> GuestResult: ...


# --------------------------------------------------------------- serve loop


@dataclass
class AgentIdentity:
    agent_sha256: str
    compiler: dict[str, str]


def serve(conn: socket.socket, executor: Executor, identity: AgentIdentity) -> str:
    """Handle one host connection. Returns how it ended (for logging only)."""
    channel = proto.Channel(conn)
    _, hello = channel.recv({proto.HELLO}, 4096, proto.Deadline(HANDSHAKE_SECONDS))
    header, _ = proto.unpack(hello)
    vm_id = header.get("vm_id")
    if not isinstance(vm_id, str) or not re.fullmatch(r"[0-9a-f]{32}", vm_id):
        raise proto.ProtocolError("bad_hello")
    ready = {
        "protocol": proto.PROTOCOL,
        "vm_id": vm_id,
        "agent_version": AGENT_VERSION,
        "agent_sha256": identity.agent_sha256,
        "compiler": identity.compiler,
    }
    channel.send(proto.READY, proto.pack(ready), proto.Deadline(SEND_SECONDS))
    _, payload = channel.recv({proto.JOB}, MAX_JOB_PAYLOAD, proto.Deadline(HANDSHAKE_SECONDS))
    try:
        job = parse_job(*proto.unpack(payload))
    except proto.ProtocolError:
        channel.send(proto.ERROR, proto.pack({"code": "bad_request"}), proto.Deadline(SEND_SECONDS))
        return "bad_request"
    try:
        result = executor.run(job)
    except Exception:
        channel.send(proto.ERROR, proto.pack({"code": "setup_failed"}), proto.Deadline(SEND_SECONDS))
        return "setup_failed"
    channel.send(proto.RESULT, result.payload(), proto.Deadline(SEND_SECONDS))
    return "result"


# ------------------------------------------------------------ classification


def classify(
    *,
    returncode: int | None,
    timed_out: bool,
    overflow: str | None,
    oom_kills: int,
    pids_max_events: int,
    cpu_usec: int | None,
    limits: dict[str, int],
) -> tuple[str, int | None, int | None, str | None]:
    """Map what the agent saw to (status, exit_code, signal, limit). Order: strongest cause first."""
    if overflow is not None:
        return "limit_exceeded", None, None, overflow
    if oom_kills > 0:
        return "limit_exceeded", None, None, "memory"
    if cpu_usec is not None and cpu_usec >= limits["cpu_ms"] * 1000:
        return "limit_exceeded", None, None, "cpu"
    if timed_out:
        return "timeout", None, None, None
    if returncode is None:
        return "timeout", None, None, None
    if returncode < 0:
        if -returncode == signal.SIGXCPU:
            return "limit_exceeded", None, None, "cpu"
        return "signaled", None, -returncode, None
    if returncode != 0 and pids_max_events > 0:
        return "limit_exceeded", None, None, "processes"
    return "exited", returncode, None, None


def cpu_rlimit_seconds(cpu_ms: int) -> int:
    """RLIMIT_CPU has 1 s granularity: round up, so the cgroup measurement decides near the edge."""
    return max(1, math.ceil(cpu_ms / 1000))


def compiler_argv(compiler_path: str, job: GuestJob) -> list[str]:
    return [compiler_path, *job.flags, "-o", BINARY_NAME, *job.translation_units]


# ----------------------------------------------------------- real executor

# mount(2) flags and prctl numbers (Linux, stable ABI).
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
PR_SET_NO_NEW_PRIVS = 38
EBUSY = 16


def _write(path: str, text: str) -> None:
    with open(path, "w") as handle:
        handle.write(text)


def _read_int_field(path: str, key: str) -> int:
    try:
        with open(path) as handle:
            for line in handle:
                name, _, value = line.partition(" ")
                if name == key:
                    return int(value)
    except (OSError, ValueError):
        pass
    return 0


def _libc():  # pragma: no cover - guest only
    import ctypes

    return ctypes.CDLL(None, use_errno=True)


def mount(source: str, target: str, fstype: str, flags: int, data: str = "", *, libc=None) -> None:
    """mount(2) without a mount binary (the guest image ships none and no setuid files)."""
    import ctypes

    libc = libc or _libc()
    rc = libc.mount(source.encode(), target.encode(), fstype.encode(), ctypes.c_ulong(flags),
                    data.encode() if data else None)
    if rc != 0:
        raise OSError(ctypes.get_errno(), f"mount {target} failed")


# The guest's early mounts, in order: (source, target, fstype, flags, data, ignore EBUSY).
INIT_MOUNTS: tuple[tuple[str, str, str, int, str, bool], ...] = (
    ("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "", False),
    ("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY, "", False),
    ("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "", True),  # may be auto-mounted
    ("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, "", False),
    ("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=8m,mode=0755", False),
    ("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=8m,mode=1777", False),
)


def init_mounts(mounter=mount) -> None:
    for source, target, fstype, flags, data, ignore_busy in INIT_MOUNTS:
        try:
            mounter(source, target, fstype, flags, data)
        except OSError as exc:
            if not (ignore_busy and exc.errno == EBUSY):
                raise


def scratch_mount_options(limits: dict[str, int]) -> tuple[int, str]:
    """Bounded, private scratch. Executable (the candidate binary runs from it) but nosuid/nodev."""
    return MS_NOSUID | MS_NODEV, f"size={limits['scratch_bytes']},mode=0700,uid={RUNNER_UID},gid={RUNNER_GID}"


def job_environment(scratch: str) -> dict[str, str]:
    # TMPDIR keeps compiler temporaries inside the bounded scratch, not the shared /tmp.
    return {"PATH": "/usr/bin", "LANG": "C", "TMPDIR": scratch, "HOME": scratch}


@dataclass
class Supervision:
    returncode: int | None
    timed_out: bool
    overflow: str | None
    stdout: bytearray
    stderr: bytearray
    cpu_exceeded: bool = False


def supervise(
    pid: int,
    out_fd: int,
    err_fd: int,
    caps: dict[str, int],
    deadline: float,
    *,
    kill,
    waitpid=os.waitpid,
    monotonic=time.monotonic,
    select_fn=select.select,
    read=os.read,
    poll_interval: float = 0.01,
    cpu_usage_usec=None,
    cpu_budget_usec: int | None = None,
) -> Supervision:
    """Collect bounded output until the process exits, the deadline passes or a stream
    overflows. Closing stdout/stderr does **not** end supervision: the process must
    also exit before the deadline, otherwise it is a timeout. ``kill`` stops the job's
    whole cgroup; it is always called before returning, including on I/O errors.
    After reaping the leader, kill descendants and drain both pipes to EOF.
    CPU usage, when supplied, is the aggregate cgroup usage, polled throughout
    execution. Polling can overshoot the budget; RLIMIT_CPU is only a backstop."""
    if (cpu_usage_usec is None) != (cpu_budget_usec is None):
        raise ValueError("CPU accounting and budget must be supplied together")
    names = {out_fd: "stdout", err_fd: "stderr"}
    data = {out_fd: bytearray(), err_fd: bytearray()}
    open_fds = {out_fd, err_fd}
    overflow = None
    timed_out = False
    status = None
    cpu_exceeded = False
    killed = False

    def stop():
        nonlocal killed
        if not killed:
            kill()
            killed = True

    try:
        while status is None or open_fds:
            left = deadline - monotonic()
            if left <= 0:
                timed_out = True
                break
            if cpu_usage_usec is not None and cpu_usage_usec() >= cpu_budget_usec:
                cpu_exceeded = True
                break
            if open_fds:
                ready, _, _ = select_fn(list(open_fds), [], [], min(left, poll_interval))
                for fd in ready:
                    # At most cap + 1 bytes are ever retained, even for a flood.
                    chunk = read(fd, min(65536, caps[names[fd]] + 1 - len(data[fd])))
                    if not chunk:
                        open_fds.discard(fd)
                        continue
                    data[fd] += chunk
                    if len(data[fd]) > caps[names[fd]]:
                        overflow = names[fd]
                if overflow:
                    break
            if status is None:
                done, raw = waitpid(pid, os.WNOHANG)
                if done == pid:
                    status = raw
                    stop()
                elif not open_fds:
                    time.sleep(min(poll_interval, max(left, 0)))
    finally:
        stop()
        if status is None:
            _, status = waitpid(pid, 0)
    returncode = None
    if not (timed_out or overflow or cpu_exceeded):
        returncode = -os.WTERMSIG(status) if os.WIFSIGNALED(status) else os.WEXITSTATUS(status)
    return Supervision(returncode, timed_out, overflow, data[out_fd], data[err_fd], cpu_exceeded)


def job_cpu_usec(cgroup: str) -> int:
    """CPU supervision must fail closed if aggregate accounting is unavailable."""
    with open(f"{cgroup}/cpu.stat") as handle:
        for line in handle:
            key, _, value = line.partition(" ")
            if key == "usage_usec":
                usage = int(value)
                if usage >= 0:
                    return usage
    raise OSError("job CPU accounting unavailable")


@dataclass
class GuestExecutor:
    """Runs one job as ``RUNNER_UID`` in ``JOB_CGROUP`` on a fresh tmpfs. Guest only."""

    compiler_path: str
    scratch: str = SCRATCH
    cgroup: str = JOB_CGROUP

    def run(self, job: GuestJob) -> GuestResult:  # pragma: no cover - runs only in the guest
        limits = job.limits
        flags, data = scratch_mount_options(limits)
        mount("tmpfs", self.scratch, "tmpfs", flags, data)
        _write("/sys/fs/cgroup/cgroup.subtree_control", "+memory +pids +cpu")
        os.makedirs(self.cgroup, exist_ok=True)
        _write(f"{self.cgroup}/memory.max", str(limits["memory_bytes"]))
        _write(f"{self.cgroup}/memory.swap.max", "0")
        _write(f"{self.cgroup}/pids.max", str(limits["max_processes"]))
        if job.stage == "compile":
            for name, content in job.files:
                self._put(name, content, 0o400)
            argv = compiler_argv(self.compiler_path, job)
        else:
            self._put(BINARY_NAME, job.binary, 0o500)
            argv = [f"./{BINARY_NAME}", *job.args]
        result = self._spawn(argv, limits)
        if job.stage == "compile" and result.status == "exited" and result.exit_code == 0:
            path = os.path.join(self.scratch, BINARY_NAME)
            size = os.path.getsize(path) if os.path.isfile(path) else 0
            if size > limits["binary_bytes"]:
                result = GuestResult("limit_exceeded", limit="binary", duration_ms=result.duration_ms,
                                     stderr=result.stderr, stderr_truncated=result.stderr_truncated)
            elif size > 0:
                with open(path, "rb") as handle:
                    result.binary = handle.read(limits["binary_bytes"] + 1)
            else:
                result = GuestResult("exited", exit_code=1, duration_ms=result.duration_ms,
                                     stderr=result.stderr, stderr_truncated=result.stderr_truncated)
        return result

    def _put(self, name: str, content: bytes, mode: int) -> None:  # pragma: no cover
        path = os.path.join(self.scratch, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        os.chown(path, RUNNER_UID, RUNNER_GID)

    def _spawn(self, argv: list[str], limits: dict[str, int]) -> GuestResult:  # pragma: no cover
        import resource

        out_r, out_w = os.pipe()
        err_r, err_w = os.pipe()
        env = job_environment(self.scratch)
        started = time.monotonic()
        pid = os.fork()
        if pid == 0:
            try:
                _write(f"{self.cgroup}/cgroup.procs", str(os.getpid()))
                os.setsid()
                os.dup2(os.open("/dev/null", os.O_RDONLY), 0)
                os.dup2(out_w, 1)
                os.dup2(err_w, 2)
                os.closerange(3, 1024)
                cpu = cpu_rlimit_seconds(limits["cpu_ms"])
                resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                resource.setrlimit(resource.RLIMIT_FSIZE, (limits["scratch_bytes"],) * 2)
                os.setgroups([])
                os.setgid(RUNNER_GID)
                os.setuid(RUNNER_UID)
                if _libc().prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                    os._exit(126)
                os.umask(0o077)
                os.chdir(self.scratch)
                os.execve(argv[0], argv, env)
            finally:
                os._exit(127)
        os.close(out_w)
        os.close(err_w)
        try:
            sup = supervise(
                pid, out_r, err_r, {"stdout": limits["stdout_bytes"], "stderr": limits["stderr_bytes"]},
                started + limits["wall_ms"] / 1000, kill=lambda: _write(f"{self.cgroup}/cgroup.kill", "1"),
                cpu_usage_usec=lambda: job_cpu_usec(self.cgroup), cpu_budget_usec=limits["cpu_ms"] * 1000)
        finally:
            os.close(out_r)
            os.close(err_r)
        cpu_usec = job_cpu_usec(self.cgroup)
        status_, code, sig, limit = classify(
            returncode=sup.returncode, timed_out=sup.timed_out, overflow=sup.overflow,
            oom_kills=_read_int_field(f"{self.cgroup}/memory.events", "oom_kill"),
            pids_max_events=_read_int_field(f"{self.cgroup}/pids.events", "max"),
            cpu_usec=cpu_usec, limits=limits)
        try:
            with open(f"{self.cgroup}/memory.peak") as handle:
                peak = int(handle.read().strip())
        except (OSError, ValueError):
            peak = None
        so, se = limits["stdout_bytes"], limits["stderr_bytes"]
        return GuestResult(
            status_, exit_code=code, signal=sig, limit=limit,
            stdout=bytes(sup.stdout[:so]), stdout_truncated=len(sup.stdout) > so,
            stderr=bytes(sup.stderr[:se]), stderr_truncated=len(sup.stderr) > se,
            duration_ms=int((time.monotonic() - started) * 1000), cpu_ms=cpu_usec // 1000,
            peak_memory_bytes=peak)


# ---------------------------------------------------------------------- main


def _identity() -> AgentIdentity:  # pragma: no cover - guest only
    with open(__file__, "rb") as handle:
        agent_sha = hashlib.sha256(handle.read()).hexdigest()
    with open(GUEST_MANIFEST, "rb") as handle:
        manifest = proto.loads_strict(handle.read())
    compiler = manifest["compiler"]
    with open(compiler["path"], "rb") as handle:
        if hashlib.sha256(handle.read()).hexdigest() != compiler["sha256"]:
            raise SystemExit("compiler digest mismatch")
    return AgentIdentity(agent_sha256=agent_sha, compiler={k: compiler[k] for k in ("name", "version", "sha256")})


def _power_off() -> None:  # pragma: no cover - guest only
    os.sync()
    _libc().reboot(0x01234567)  # RB_AUTOBOOT: with reboot=k, Firecracker's VMM exits
    os._exit(0)


def main() -> None:  # pragma: no cover - guest only
    try:
        identity = _identity()
        executor = GuestExecutor(compiler_path=_identity_path())
        listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        listener.bind((socket.VMADDR_CID_ANY, AGENT_PORT))
        listener.listen(1)
        conn, _ = listener.accept()
        listener.close()  # nothing else, the candidate included, can reach the agent
        try:
            serve(conn, executor, identity)
        finally:
            conn.close()
    finally:
        _power_off()


def init_main() -> None:  # pragma: no cover - guest only
    """PID 1 entry (``/sbin/aegis-init``): early mounts, then serve one job, then power off."""
    try:
        init_mounts()
    except Exception:
        _power_off()
    main()


def _identity_path() -> str:  # pragma: no cover - guest only
    with open(GUEST_MANIFEST, "rb") as handle:
        return proto.loads_strict(handle.read())["compiler"]["path"]


if __name__ == "__main__":  # pragma: no cover
    main()
