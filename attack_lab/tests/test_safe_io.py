"""Bounded file loading and strict JSON parsing. Local temporary files only."""

from __future__ import annotations

import os
import socket
import threading
from pathlib import Path

import pytest

import aegis_lab.safe_io as safe_io
from aegis_lab.safe_io import LOAD_ERROR_CATEGORIES, LoadError, parse_strict_json, read_regular_file


def category(fn, *args) -> str:
    with pytest.raises(LoadError) as exc:
        fn(*args)
    assert str(exc.value) == exc.value.category  # no path, content or OS message
    return exc.value.category


# --- read_regular_file --------------------------------------------------------------------------

def test_reads_regular_file(tmp_path):
    path = tmp_path / "m.json"
    path.write_bytes(b"{}")
    assert read_regular_file(path, 10) == b"{}"


def test_exact_limit_is_accepted_and_one_more_byte_is_rejected(tmp_path):
    path = tmp_path / "m.json"
    path.write_bytes(b"x" * 100)
    assert read_regular_file(path, 100) == b"x" * 100
    path.write_bytes(b"x" * 101)
    assert category(read_regular_file, path, 100) == "too_large"


def test_large_file_is_rejected_before_reading(tmp_path, monkeypatch):
    path = tmp_path / "big.json"
    with path.open("wb") as handle:
        handle.truncate(1 << 30)  # sparse 1 GiB
    reads = []
    monkeypatch.setattr(safe_io.os, "read", lambda fd, n: reads.append(n) or b"")
    assert category(read_regular_file, path, 1_048_576) == "too_large"
    assert reads == []


def _growing_read(path: Path, extra: bytes):
    real_read = os.read
    state = {"grown": False}

    def read(fd, n):
        chunk = real_read(fd, n)
        if not state["grown"]:
            state["grown"] = True
            with path.open("ab") as handle:
                handle.write(extra)
        return chunk

    return read


def test_file_growing_past_limit_reads_at_most_limit_plus_one(tmp_path, monkeypatch):
    path = tmp_path / "grow.json"
    path.write_bytes(b"x" * 50)
    returned = []
    grow = _growing_read(path, b"y" * 10_000)

    def read(fd, n):
        chunk = grow(fd, n)
        returned.append(len(chunk))
        return chunk

    monkeypatch.setattr(safe_io.os, "read", read)
    assert category(read_regular_file, path, 100) == "too_large"
    assert sum(returned) == 101  # never reads more than the limit + 1 byte


def test_file_growing_within_limit_is_detected(tmp_path, monkeypatch):
    path = tmp_path / "grow.json"
    path.write_bytes(b"x" * 50)
    monkeypatch.setattr(safe_io.os, "read", _growing_read(path, b"y" * 10))
    assert category(read_regular_file, path, 100) == "file_changed"


def test_file_truncated_during_read_is_detected(tmp_path, monkeypatch):
    path = tmp_path / "shrink.json"
    path.write_bytes(b"x" * 50)
    real_read = os.read

    def read(fd, n):
        chunk = real_read(fd, n)
        os.truncate(path, 10)
        return chunk

    monkeypatch.setattr(safe_io.os, "read", read)
    assert category(read_regular_file, path, 100) == "file_changed"


def test_fifo_is_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)
    result: dict[str, str] = {}

    def attempt():
        try:
            read_regular_file(fifo, 100)
        except LoadError as exc:
            result["category"] = exc.category

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=5)
    if worker.is_alive():  # unblock the stuck reader before failing
        with open(fifo, "wb"):
            pass
        pytest.fail("loader blocked on a FIFO")
    assert result == {"category": "not_regular_file"}


@pytest.mark.parametrize("device", ["/dev/null", "/dev/zero", "/dev/urandom"])
def test_devices_are_rejected(device):
    if not os.path.exists(device):
        pytest.skip(f"{device} not present")
    assert category(read_regular_file, device, 100) == "not_regular_file"


def test_unix_socket_is_rejected(tmp_path):
    path = tmp_path / "s.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
    except OSError:
        pytest.skip("cannot create a Unix socket here")
    try:
        assert category(read_regular_file, path, 100) == "not_regular_file"
    finally:
        server.close()


def test_directory_is_rejected(tmp_path):
    assert category(read_regular_file, tmp_path, 100) == "not_regular_file"


def test_final_symlink_is_rejected(tmp_path):
    target = tmp_path / "real.json"
    target.write_bytes(b"{}")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert category(read_regular_file, link, 100) == "symlink_rejected"


def test_dangling_and_device_symlinks_are_rejected(tmp_path):
    dangling = tmp_path / "dangling.json"
    dangling.symlink_to(tmp_path / "missing")
    assert category(read_regular_file, dangling, 100) == "symlink_rejected"
    to_device = tmp_path / "zero.json"
    to_device.symlink_to("/dev/zero")
    assert category(read_regular_file, to_device, 100) == "symlink_rejected"


def test_symlinked_parent_directory_is_followed_by_policy(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "m.json").write_bytes(b"{}")
    (tmp_path / "alias").symlink_to(real, target_is_directory=True)
    assert read_regular_file(tmp_path / "alias" / "m.json", 100) == b"{}"


def test_missing_empty_and_invalid_paths(tmp_path):
    assert category(read_regular_file, tmp_path / "missing", 100) == "not_found"
    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    assert category(read_regular_file, empty, 100) == "empty"
    assert category(read_regular_file, str(tmp_path / "nul\x00byte"), 100) == "invalid_path"


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file permissions")
def test_unreadable_file_is_reported(tmp_path):
    path = tmp_path / "private.json"
    path.write_bytes(b"{}")
    path.chmod(0)
    try:
        assert category(read_regular_file, path, 100) == "permission_denied"
    finally:
        path.chmod(0o600)


def test_read_error_is_controlled(tmp_path, monkeypatch):
    path = tmp_path / "m.json"
    path.write_bytes(b"{}")

    def fail(fd, n):
        raise OSError(5, "Input/output error: /very/secret/path")

    monkeypatch.setattr(safe_io.os, "read", fail)
    assert category(read_regular_file, path, 100) == "read_failed"


def test_file_descriptors_are_closed(tmp_path):
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("needs /proc/self/fd")
    path = tmp_path / "m.json"
    path.write_bytes(b"x" * 200)
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(50):
        read_regular_file(path, 1000)
        with pytest.raises(LoadError):
            read_regular_file(path, 10)
        with pytest.raises(LoadError):
            read_regular_file(tmp_path, 10)
    assert len(os.listdir("/proc/self/fd")) <= before


def test_unregistered_category_is_a_programming_error():
    with pytest.raises(AssertionError):
        LoadError("some free text")
    assert "file_changed" in LOAD_ERROR_CATEGORIES


# --- parse_strict_json --------------------------------------------------------------------------

def test_parses_valid_json():
    assert parse_strict_json(b'{"a": [1, 2.5, "\xc3\xa9", null, true]}') == {"a": [1, 2.5, "é", None, True]}


@pytest.mark.parametrize(("raw", "expected"), [
    (b'{"a": 1, "a": 1}', "duplicate_key"),
    (b'{"a": {"b": 1, "b": 2}}', "duplicate_key"),
    (b'[{"x": 1}, {"y": 1, "y": 1}]', "duplicate_key"),
    (b'{"a": NaN}', "non_finite_number"),
    (b'{"a": Infinity}', "non_finite_number"),
    (b'{"a": -Infinity}', "non_finite_number"),
    (b'{"a": 1e999}', "non_finite_number"),
    (b'{"a": -1e999}', "non_finite_number"),
    (b"\xff\xfe{\x00}\x00", "invalid_utf8"),
    (b'{"a": "\xc3"}', "invalid_utf8"),
    (b"\xef\xbb\xbf{}", "malformed_json"),
    (b"{", "malformed_json"),
    (b"{} trailing", "malformed_json"),
    (b"[" * 200_000 + b"]" * 200_000, "malformed_json"),
    (b'{"a": ' + b"9" * 5000 + b"}", "malformed_json"),
    (b"", "malformed_json"),
])
def test_rejects_ambiguous_or_malformed_json(raw, expected):
    assert category(parse_strict_json, raw) == expected


# --- hash_regular_file: same policy, streamed ----------------------------------------------------

def test_hash_streams_exact_bytes_to_the_sink(tmp_path):
    import hashlib

    from aegis_lab.safe_io import hash_regular_file

    data = os.urandom(200_000)
    path = tmp_path / "artifact"
    path.write_bytes(data)
    copied = bytearray()
    assert hash_regular_file(path, len(data), copied.extend) == (hashlib.sha256(data).hexdigest(), len(data))
    assert bytes(copied) == data


def test_hash_rejects_fifo_without_blocking(tmp_path):
    from aegis_lab.safe_io import hash_regular_file

    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    result: dict = {}
    worker = threading.Thread(target=lambda: result.update(c=category(hash_regular_file, fifo, 100)), daemon=True)
    worker.start()
    worker.join(5)
    if worker.is_alive():
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
    assert not worker.is_alive()
    assert result["c"] == "not_regular_file"


def test_hash_rejects_symlink_empty_and_oversized_before_reading(tmp_path, monkeypatch):
    from aegis_lab.safe_io import hash_regular_file

    target = tmp_path / "t"
    target.write_bytes(b"x")
    (tmp_path / "link").symlink_to(target)
    assert category(hash_regular_file, tmp_path / "link", 10) == "symlink_rejected"
    (tmp_path / "empty").touch()
    assert category(hash_regular_file, tmp_path / "empty", 10) == "empty"
    big = tmp_path / "big"
    with big.open("wb") as handle:
        handle.truncate(1 << 30)
    reads = []
    monkeypatch.setattr(safe_io.os, "read", lambda fd, n: reads.append(n) or b"")
    assert category(hash_regular_file, big, 1 << 20) == "too_large"
    assert reads == []


def test_hash_detects_growth_during_copy(tmp_path, monkeypatch):
    from aegis_lab.safe_io import hash_regular_file

    path = tmp_path / "grow"
    path.write_bytes(b"x" * 50)
    monkeypatch.setattr(safe_io.os, "read", _growing_read(path, b"y"))
    assert category(hash_regular_file, path, 100) == "file_changed"


def test_hash_sink_errors_propagate_unchanged(tmp_path):
    from aegis_lab.safe_io import hash_regular_file

    path = tmp_path / "f"
    path.write_bytes(b"data")

    def full(chunk):
        raise OSError(28, "No space left on device")

    with pytest.raises(OSError) as exc:
        hash_regular_file(path, 10, full)
    assert exc.value.errno == 28 and not isinstance(exc.value, LoadError)
