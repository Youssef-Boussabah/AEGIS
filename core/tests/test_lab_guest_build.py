"""Guest-side logic and the rootless image tooling.

- ``supervise``: real pipes, a scripted ``waitpid`` (no child process is created);
- early mounts and scratch options with a recording mounter (no mount happens);
- ``debpack``: synthetic .deb files built here, never real packages, no network;
- ``kernel_config_check``.
"""

from __future__ import annotations

import errno
import hashlib
import io
import lzma
import os
import sys
import tarfile
import time
from pathlib import Path

import pytest

from aegis_core import lab_guest_agent as agent

GUEST = Path(__file__).resolve().parents[1] / "guest"
sys.path.insert(0, str(GUEST))
import debpack  # noqa: E402
import kernel_config_check  # noqa: E402

CAPS = {"stdout": 16, "stderr": 16}


# ---------------------------------------------------------------- supervise


class FakeChild:
    """A scripted child: exits at ``exit_at`` (monotonic) with ``status``, or never."""

    def __init__(self, exit_at=None, status=0):
        self.exit_at, self.status, self.killed, self.reaped = exit_at, status, False, False

    def waitpid(self, pid, flags):
        done = self.killed or (self.exit_at is not None and time.monotonic() >= self.exit_at)
        if flags == os.WNOHANG and not done:
            return 0, 0
        self.reaped = True
        return pid, (9 if self.killed and self.exit_at is None else self.status << 8)

    def kill(self):
        self.killed = True


def run_supervise(child, writes=(), close=True, deadline=0.5, **kw):
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    for fd, data in writes:
        os.write(out_w if fd == 1 else err_w, data)
    if close:
        os.close(out_w)
        os.close(err_w)
    try:
        return agent.supervise(42, out_r, err_r, CAPS, time.monotonic() + deadline, kill=child.kill,
                               waitpid=child.waitpid, **kw)
    finally:
        os.close(out_r)
        os.close(err_r)
        if not close:
            os.close(out_w)
            os.close(err_w)


def test_normal_exit_collects_output_and_always_kills_the_cgroup():
    child = FakeChild(exit_at=time.monotonic(), status=3)
    sup = run_supervise(child, writes=[(1, b"out"), (2, b"err")])
    assert (sup.returncode, sup.timed_out, sup.overflow) == (3, False, None)
    assert (bytes(sup.stdout), bytes(sup.stderr)) == (b"out", b"err")
    assert child.killed and child.reaped


def test_closing_outputs_does_not_end_supervision_before_exit():
    """The fixed defect: a candidate that closes stdout/stderr and keeps running is a timeout."""
    child = FakeChild(exit_at=None)
    sup = run_supervise(child, close=True, deadline=0.3)
    assert sup.timed_out and sup.returncode is None and child.killed


def test_overflow_stops_the_job():
    child = FakeChild(exit_at=None)
    sup = run_supervise(child, writes=[(1, b"x" * 17)], close=False)
    assert sup.overflow == "stdout" and sup.returncode is None and child.killed


def test_silent_running_process_times_out_with_open_pipes():
    child = FakeChild(exit_at=None)
    sup = run_supervise(child, close=False, deadline=0.2)
    assert sup.timed_out and child.killed


def test_reaped_child_output_is_drained_across_multiple_reads():
    child = FakeChild(exit_at=time.monotonic(), status=3)
    # Force more than one read per pipe, including a read after waitpid reaps.
    sup = run_supervise(child, writes=[(1, b"abcdefgh"), (2, b"diagnostic")],
                        read=lambda fd, cap: os.read(fd, min(2, cap)))
    assert (bytes(sup.stdout), bytes(sup.stderr)) == (b"abcdefgh", b"diagnostic")
    assert sup.returncode == 3 and not sup.timed_out


def test_output_overflow_after_reaping_is_still_a_limit():
    child = FakeChild(exit_at=time.monotonic())
    sup = run_supervise(child, writes=[(1, b"x" * 17)],
                        read=lambda fd, cap: os.read(fd, min(2, cap)))
    assert sup.overflow == "stdout" and len(sup.stdout) == CAPS["stdout"] + 1


def test_aggregate_cpu_budget_kills_a_live_job_before_the_wall_deadline():
    child = FakeChild()
    usage = iter([0, 5000, 10000])
    sup = run_supervise(child, close=False, cpu_usage_usec=lambda: next(usage), cpu_budget_usec=10000)
    assert sup.cpu_exceeded and not sup.timed_out and sup.returncode is None
    assert child.killed and child.reaped


def test_accounting_failure_stops_and_reaps_the_job():
    child = FakeChild()

    def unavailable():
        raise OSError("missing accounting")

    with pytest.raises(OSError, match="missing accounting"):
        run_supervise(child, cpu_usage_usec=unavailable, cpu_budget_usec=10000)
    assert child.killed and child.reaped


def test_pipe_failure_stops_and_reaps_the_job():
    child = FakeChild()

    def broken(*args):
        raise OSError("broken pipe")

    with pytest.raises(OSError, match="broken pipe"):
        run_supervise(child, writes=[(1, b"x")], read=broken)
    assert child.killed and child.reaped


def test_cpu_accounting_requires_a_nonnegative_usage_field(tmp_path):
    path = tmp_path / "cpu.stat"
    for data in ("", "usage_usec -1\n", "usage_usec bad\n"):
        path.write_text(data)
        with pytest.raises((OSError, ValueError)):
            agent.job_cpu_usec(str(tmp_path))
    path.write_text("usage_usec 10000\nuser_usec 5000\n")
    assert agent.job_cpu_usec(str(tmp_path)) == 10000


def test_classification_of_supervised_outcomes():
    limits = {"cpu_ms": 1000}
    timed = agent.classify(returncode=None, timed_out=True, overflow=None, oom_kills=0, pids_max_events=0,
                           cpu_usec=5, limits=limits)
    assert timed == ("timeout", None, None, None)


# ------------------------------------------------------------ init / scratch


def test_init_mounts_order_and_busy_devtmpfs():
    calls = []

    def mounter(source, target, fstype, flags, data=""):
        calls.append((target, fstype, flags, data))
        if target == "/dev":
            raise OSError(errno.EBUSY, "busy")

    agent.init_mounts(mounter)
    assert [c[0] for c in calls] == ["/proc", "/sys", "/dev", "/sys/fs/cgroup", "/run", "/tmp"]
    sys_flags = calls[1][2]
    assert sys_flags & agent.MS_RDONLY and sys_flags & agent.MS_NOEXEC
    assert all(c[2] & agent.MS_NOSUID for c in calls)

    def failing(source, target, fstype, flags, data=""):
        if target == "/sys/fs/cgroup":
            raise OSError(errno.EPERM, "no")

    with pytest.raises(OSError):
        agent.init_mounts(failing)


def test_scratch_is_bounded_private_nosuid_and_hosts_temporaries():
    flags, data = agent.scratch_mount_options({"scratch_bytes": 8 << 20})
    assert flags & agent.MS_NOSUID and flags & agent.MS_NODEV and not flags & agent.MS_NOEXEC
    assert data == f"size={8 << 20},mode=0700,uid=1000,gid=1000"
    env = agent.job_environment("/scratch")
    assert env["TMPDIR"] == "/scratch" and env["PATH"] == "/usr/bin" and set(env) == {"PATH", "LANG", "TMPDIR", "HOME"}


def test_mount_uses_the_syscall_and_reports_errno():
    class Libc:
        def __init__(self, rc):
            self.rc, self.args = rc, None

        def mount(self, *args):
            self.args = args
            return self.rc

    libc = Libc(0)
    agent.mount("tmpfs", "/scratch", "tmpfs", agent.MS_NOSUID, "size=1", libc=libc)
    assert libc.args[0] == b"tmpfs" and libc.args[1] == b"/scratch"
    with pytest.raises(OSError):
        agent.mount("tmpfs", "/scratch", "tmpfs", 0, libc=Libc(-1))


def test_init_script_is_python_without_a_shell():
    text = (GUEST / "aegis-init").read_text()
    assert text.startswith("#!/usr/bin/python3 -IS\n") and "init_main()" in text


# ------------------------------------------------------------------ debpack


def tar_bytes(entries, compress=lzma.compress) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, kind, payload, mode in entries:
            info = tarfile.TarInfo(name)
            info.mode, info.mtime, info.uid, info.gid = mode, 4_000_000_000, 0, 0
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "sym":
                info.type, info.linkname = tarfile.SYMTYPE, payload
                tar.addfile(info)
            else:
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
    return compress(buf.getvalue())


def make_deb(entries) -> bytes:
    def member(name: str, data: bytes) -> bytes:
        header = f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
        return header + data + (b"\n" if len(data) % 2 else b"")

    return b"!<arch>\n" + member("debian-binary", b"2.0\n") + member("control.tar.xz", lzma.compress(b"")) + \
        member("data.tar.xz", tar_bytes(entries))


def test_build_tar_is_deterministic_root_owned_and_strips_setid(tmp_path):
    deb_a = make_deb([("./usr/bin/", "dir", None, 0o755), ("./usr/bin/tool", "file", b"bin", 0o4755),
                      ("./usr/bin/cc", "sym", "tool", 0o777), ("./usr/share/doc/a/README", "file", b"doc", 0o644)])
    deb_b = make_deb([("./usr/bin/tool", "file", b"other", 0o755), ("./usr/sbin/grp", "file", b"g", 0o2755)])
    overlay = tmp_path / "overlay"
    (overlay / "opt" / "aegis").mkdir(parents=True)
    (overlay / "opt" / "aegis" / "agent.py").write_text("print(1)\n")
    out1, out2 = tmp_path / "a.tar", tmp_path / "b.tar"
    stats = debpack.build_tar([deb_a, deb_b], overlay, out1, epoch=1_700_000_000)
    debpack.build_tar([deb_a, deb_b], overlay, out2, epoch=1_700_000_000)
    assert out1.read_bytes() == out2.read_bytes()  # reproducible
    assert sorted(stats.setid_stripped) == ["./usr/bin/tool", "./usr/sbin/grp"]
    assert stats.duplicates == ["./usr/bin/tool"]
    with tarfile.open(out1) as tar:
        members = {m.name: m for m in tar.getmembers()}
    names = list(members)
    assert names == sorted(names)
    assert not any(m.mode & 0o6000 for m in members.values())
    assert all(m.mtime <= 1_700_000_000 for m in members.values())
    assert "./usr/share/doc/a/README" not in members
    assert members["./bin"].issym() and members["./bin"].linkname == "usr/bin"
    assert members["./opt/aegis/agent.py"].uid == 0 and members["./opt/aegis/agent.py"].mode == 0o444
    assert members["./tmp"].mode == 0o1777 and members["./scratch"].isdir()
    real, data = debpack.tree_file(out1, "/usr/bin/cc")
    assert (real, data) == ("/usr/bin/tool", b"bin")  # first package wins; symlink resolved in-tree


def test_deb_parsing_rejects_garbage():
    with pytest.raises(debpack.BuildError):
        debpack.deb_data(b"not an archive")
    with pytest.raises(debpack.BuildError):
        debpack.deb_data(b"!<arch>\n")


PACKAGES = """\
Package: gcc
Depends: cpp (>= 4), libc6-dev | libc-dev, binutils
Filename: pool/g/gcc.deb

Package: cpp
Pre-Depends: dpkg
Depends: libc6

Package: libc6

Package: musl-dev
Provides: libc-dev

Package: binutils
Depends: libc6, perl-base | mawk

Package: mawk
"""


def test_resolution_follows_alternatives_provides_and_exclusions():
    index = debpack.Index.from_text(PACKAGES)
    assert debpack.resolve(index, ["gcc"], {"dpkg", "perl-base"}) == ["binutils", "cpp", "gcc", "libc6", "mawk", "musl-dev"]
    assert debpack.resolve(debpack.Index.from_text(PACKAGES + "\nPackage: libc6-dev\n"), ["gcc"],
                           {"dpkg", "perl-base"}) == ["binutils", "cpp", "gcc", "libc6", "libc6-dev", "mawk"]
    with pytest.raises(debpack.BuildError):
        debpack.resolve(index, ["gcc"], {"dpkg", "perl-base", "musl-dev"})  # libc-dev unsatisfiable
    with pytest.raises(debpack.BuildError):  # an alternative that is neither present nor excluded
        debpack.resolve(debpack.Index.from_text(PACKAGES.replace("Package: mawk\n", "")), ["gcc"],
                        {"dpkg", "perl-base"})


def test_release_hash_chain():
    release = b"Origin: Debian\nSHA256:\n " + b"a" * 64 + b" 12 main/binary-amd64/Packages.xz\n"
    assert debpack.release_sha256(release) == {"main/binary-amd64/Packages.xz": ("a" * 64, 12)}
    data = b"payload"
    debpack.check_digest(data, hashlib.sha256(data).hexdigest(), len(data), "x")
    with pytest.raises(debpack.BuildError):
        debpack.check_digest(data + b"!", hashlib.sha256(data).hexdigest(), len(data), "x")


def test_clearsigned_body_is_dash_unescaped():
    signed = (b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\n- -dashed\n"
              b"-----BEGIN PGP SIGNATURE-----\nxxx\n-----END PGP SIGNATURE-----\n")
    assert debpack._clearsigned_body(signed) == b"Origin: Debian\n-dashed\n"


def test_gpgv_requires_a_pinned_fingerprint(tmp_path):
    fake = tmp_path / "gpgv"
    fake.write_text(f"#!{sys.executable}\nprint('[GNUPG:] VALIDSIG ABCDEF0123 2026-10-01 x')\n")
    fake.chmod(0o755)
    inrelease = tmp_path / "InRelease"
    inrelease.write_bytes(b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nSuite: trixie\n"
                          b"-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n")
    assert debpack.gpgv_verify(inrelease, tmp_path / "k.gpg", {"abcdef0123"}, gpgv=str(fake)) == b"Suite: trixie\n"
    with pytest.raises(debpack.BuildError):
        debpack.gpgv_verify(inrelease, tmp_path / "k.gpg", {"0000"}, gpgv=str(fake))


def test_specs_pin_nothing_dangerous():
    import json

    guest = json.loads((GUEST / "guest-packages.json").read_text())
    # The agent imports ctypes, socket, hmac, select and resource, which are not
    # all provided by Debian's minimal interpreter/stdlib package split.
    assert guest["packages"] == ["gcc", "libc6-dev", "python3"]
    assert {"dash", "bash", "util-linux", "mount", "sudo", "passwd", "login"} <= set(guest["exclude"])
    assert guest["snapshot"].startswith("PIN-ME")  # fetching refuses until an operator pins it


# --------------------------------------------------------- kernel config


def test_kernel_config_check():
    fragment = (GUEST / "aegis-kernel.fragment").read_text()
    good = "\n".join(line for line in fragment.splitlines() if line.startswith("CONFIG_")) + \
        "\n# CONFIG_INET is not set\nCONFIG_EXT2_FS=y\n"
    assert kernel_config_check.violations(good, fragment) == []
    bad = good.replace("CONFIG_VIRTIO_VSOCKETS=y", "CONFIG_VIRTIO_VSOCKETS=m") + "CONFIG_USER_NS=y\nCONFIG_INET=y\n"
    problems = kernel_config_check.violations(bad, fragment)
    assert "CONFIG_VIRTIO_VSOCKETS must be y, is m" in problems
    assert "CONFIG_USER_NS must not be set, is y" in problems and "CONFIG_INET must not be set, is y" in problems
