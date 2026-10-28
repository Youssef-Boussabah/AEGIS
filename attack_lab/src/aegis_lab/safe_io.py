"""Bounded, race-conscious loading of local JSON records.

File policy (``read_regular_file``):

- The final path component must not be a symlink (``O_NOFOLLOW``). Parent
  directories are resolved normally; the caller chooses the directory.
- Only regular files are read. The file is opened non-blocking, so a FIFO,
  socket, device or directory is rejected after ``fstat`` without blocking and
  before any byte is read.
- At most ``max_bytes + 1`` bytes are read, so a file that is larger than its
  declared size, or grows while being read, cannot exhaust memory.
  ``hash_regular_file`` applies the same policy while streaming (no full copy
  in memory), for example to stage a private copy of a binary.
- The opened file's identity, size and timestamps are compared before and after
  the read. Any observed change is an error. All later parsing and hashing uses
  the bytes that were read, never a second read of the path.

JSON policy (``parse_strict_json``): strict UTF-8, no duplicate object keys,
no ``NaN``/``Infinity`` and no number that overflows to infinity.

Every failure is a ``LoadError`` whose ``category`` is a fixed code. It never
contains a path, file content or operating-system message.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import math
import os
import stat
from collections.abc import Callable
from pathlib import Path

LOAD_ERROR_CATEGORIES = frozenset({
    "not_found",
    "permission_denied",
    "symlink_rejected",
    "invalid_path",
    "not_regular_file",
    "open_failed",
    "read_failed",
    "too_large",
    "empty",
    "file_changed",
    "invalid_utf8",
    "malformed_json",
    "duplicate_key",
    "non_finite_number",
    "retired_schema_version",
})


class LoadError(ValueError):
    """A record could not be loaded. ``category`` is safe to show to users."""

    def __init__(self, category: str) -> None:
        if category not in LOAD_ERROR_CATEGORIES:
            raise AssertionError(f"unregistered load error category {category!r}")
        self.category = category
        super().__init__(category)


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _open_regular(path: str | os.PathLike[str], max_bytes: int) -> tuple[int, os.stat_result]:
    """Open without following a final symlink and without blocking; return a blocking fd to a regular file."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    try:
        fd = os.open(Path(path), flags)
    except FileNotFoundError:
        raise LoadError("not_found") from None
    except PermissionError:
        raise LoadError("permission_denied") from None
    except ValueError:  # e.g. an embedded NUL byte
        raise LoadError("invalid_path") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise LoadError("symlink_rejected") from None
        if exc.errno in (errno.ENXIO, errno.EOPNOTSUPP):  # e.g. a Unix socket
            raise LoadError("not_regular_file") from None
        raise LoadError("open_failed") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise LoadError("not_regular_file")
        if before.st_size > max_bytes:
            raise LoadError("too_large")
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)
    except OSError:
        os.close(fd)
        raise LoadError("read_failed") from None
    except BaseException:
        os.close(fd)
        raise
    return fd, before


def _read_bounded(path: str | os.PathLike[str], max_bytes: int, sink: Callable[[bytes], None]) -> int:
    """Pass each chunk of an unchanged regular file to ``sink``; return the byte count.

    Chunks reach ``sink`` before the final change check, so callers must discard
    whatever they built if this raises. Exceptions raised by ``sink`` propagate unchanged.
    """
    fd, before = _open_regular(path, max_bytes)
    try:
        total = 0
        while total <= max_bytes:
            try:
                chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            except OSError:
                raise LoadError("read_failed") from None
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise LoadError("too_large")
            sink(chunk)
        try:
            after = os.fstat(fd)
        except OSError:
            raise LoadError("read_failed") from None
        if _identity(before) != _identity(after) or after.st_size != total:
            raise LoadError("file_changed")
    finally:
        os.close(fd)
    if total == 0:
        raise LoadError("empty")
    return total


def read_regular_file(path: str | os.PathLike[str], max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    _read_bounded(path, max_bytes, chunks.append)
    return b"".join(chunks)


def hash_regular_file(
    path: str | os.PathLike[str], max_bytes: int, sink: Callable[[bytes], None] | None = None
) -> tuple[str, int]:
    """Stream a file under the same policy as ``read_regular_file``; return (sha256 hex, size).

    The digest covers exactly the bytes passed to ``sink`` (for example, a private
    copy), so a later change of the source path cannot alter what was hashed.
    """
    digest = hashlib.sha256()

    def consume(chunk: bytes) -> None:
        digest.update(chunk)
        if sink is not None:
            sink(chunk)

    size = _read_bounded(path, max_bytes, consume)
    return digest.hexdigest(), size


class _DuplicateKey(Exception):
    pass


class _NonFinite(Exception):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _reject_constant(_name: str) -> float:
    raise _NonFinite


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):  # e.g. 1e999
        raise _NonFinite
    return value


def parse_strict_json(data: bytes) -> object:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise LoadError("invalid_utf8") from None
    try:
        return json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_reject_constant, parse_float=_finite_float
        )
    except _DuplicateKey:
        raise LoadError("duplicate_key") from None
    except _NonFinite:
        raise LoadError("non_finite_number") from None
    except (ValueError, RecursionError):  # JSONDecodeError, integer digit limit, deep nesting
        raise LoadError("malformed_json") from None
