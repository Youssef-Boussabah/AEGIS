"""Host <-> guest-agent protocol for Firecracker sandboxes (``aegis.core.vm-agent.v1``).

Standard library only: this file is copied unchanged into the guest image, next
to ``lab_guest_agent.py``.

Transport: one virtio-vsock stream per microVM. The host connects through
Firecracker's Unix socket (``CONNECT <port>\\n`` -> ``OK <n>\\n``); the guest
never initiates a connection and there is no network device.

Frame::

    magic "AGV1" | type u8 | seq u64 | length u32 | payload | HMAC-SHA256(32)

The tag covers magic, type, seq, length and payload, keyed with a 32-byte key
chosen by the host for this microVM only. The host sends the key in HELLO, the
first frame on the private channel; every later frame in either direction must
carry a valid tag and the next sequence number for its direction. This binds
every message to one session and one VM and rejects replayed, reordered or
stale frames. It does **not** authenticate a compromised guest: code that
controls the guest kernel can read the key. Host-observed facts (timeouts,
cgroup OOM, output caps) therefore take precedence over guest reports.

Messages:

- HELLO   host->guest  {protocol, vm_id, key}            (tag computed with that key)
- READY   guest->host  {protocol, vm_id, agent_sha256, compiler: {name, version, sha256}}
- JOB     host->guest  {stage, ...}  + blobs: compile sources, or the binary
- RESULT  guest->host  {status, exit_code, signal, limit, ...} + blobs: stdout, stderr, binary
- ERROR   guest->host  {code}

A JOB never contains hidden-test expectations: it is built only from Core's
``CompileJob``/``ExecuteJob``, which carry none.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import socket
import struct
import time
from typing import Any

PROTOCOL = "aegis.core.vm-agent.v1"
MAGIC = b"AGV1"
HEADER = struct.Struct(">4sBQI")
TAG_BYTES = 32
KEY_BYTES = 32
MAX_JSON_BYTES = 64 * 1024
MAX_HANDSHAKE_LINE = 64

HELLO, READY, JOB, RESULT, ERROR = 1, 2, 3, 4, 5
FRAME_TYPES = frozenset({HELLO, READY, JOB, RESULT, ERROR})

AGENT_ERROR_CODES = frozenset(
    {"bad_request", "unsupported_stage", "setup_failed", "internal_error"}
)


class ProtocolError(Exception):
    """A malformed, oversized, unauthenticated or out-of-order message. Never echoes data."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Deadline:
    def __init__(self, seconds: float, monotonic=time.monotonic):
        self._monotonic = monotonic
        self._end = monotonic() + seconds

    def remaining(self) -> float:
        left = self._end - self._monotonic()
        if left <= 0:
            raise TimeoutError("deadline exceeded")
        return left


def _tag(key: bytes, header: bytes, payload: bytes) -> bytes:
    return hmac.new(key, header + payload, hashlib.sha256).digest()


def encode_frame(key: bytes, frame_type: int, seq: int, payload: bytes) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError("key must be 32 bytes")
    if frame_type not in FRAME_TYPES:
        raise ValueError("unknown frame type")
    header = HEADER.pack(MAGIC, frame_type, seq, len(payload))
    return header + payload + _tag(key, header, payload)


def _recv_exact(sock: socket.socket, size: int, deadline: Deadline, *, frame_start: bool = False) -> bytes:
    """Read exactly ``size`` bytes. A clean end of stream before the first byte of a
    frame is ``connection_closed``; anywhere else it is ``truncated_frame``."""
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        sock.settimeout(deadline.remaining())
        try:
            chunk = sock.recv(min(remaining, 1 << 16))
        except socket.timeout:
            raise TimeoutError("deadline exceeded") from None
        if not chunk:
            raise ProtocolError("connection_closed" if frame_start and not chunks else "truncated_frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class Channel:
    """One authenticated, ordered, size-bounded message stream over a connected socket."""

    def __init__(self, sock: socket.socket, key: bytes | None = None):
        self.sock = sock
        self.key = key
        self.send_seq = 0
        self.recv_seq = 0

    def send(self, frame_type: int, payload: bytes, deadline: Deadline) -> None:
        if self.key is None:
            raise ProtocolError("no_session_key")
        data = encode_frame(self.key, frame_type, self.send_seq, payload)
        self.send_seq += 1
        view = memoryview(data)
        while view:
            self.sock.settimeout(deadline.remaining())
            try:
                sent = self.sock.send(view)
            except socket.timeout:
                raise TimeoutError("deadline exceeded") from None
            view = view[sent:]

    def recv(self, expected: set[int], max_payload: int, deadline: Deadline) -> tuple[int, bytes]:
        header = _recv_exact(self.sock, HEADER.size, deadline, frame_start=True)
        magic, frame_type, seq, length = HEADER.unpack(header)
        if magic != MAGIC:
            raise ProtocolError("bad_magic")
        if frame_type not in expected:
            raise ProtocolError("unexpected_frame")
        if length > max_payload:
            raise ProtocolError("frame_too_large")
        if seq != self.recv_seq:
            raise ProtocolError("bad_sequence")
        payload = _recv_exact(self.sock, length, deadline)
        tag = _recv_exact(self.sock, TAG_BYTES, deadline)
        if self.key is None:
            # Only the HELLO establishes the key; it is tagged with the key it carries.
            if frame_type != HELLO:
                raise ProtocolError("no_session_key")
            key = _hello_key(payload)
            if not hmac.compare_digest(tag, _tag(key, header, payload)):
                raise ProtocolError("bad_tag")
            self.key = key
        elif not hmac.compare_digest(tag, _tag(self.key, header, payload)):
            raise ProtocolError("bad_tag")
        self.recv_seq += 1
        return frame_type, payload


# ------------------------------------------------------------------ payloads


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-finite number")


def loads_strict(data: bytes) -> Any:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("bad_json") from None
    if isinstance(value, float) and not math.isfinite(value):
        raise ProtocolError("bad_json")
    return value


def dumps(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def pack(header: dict[str, Any], blobs: list[bytes] = ()) -> bytes:
    """``u32 json_len | json | blob...``; blob lengths are listed in ``header["blobs"]``."""
    header = dict(header, blobs=[len(b) for b in blobs])
    body = dumps(header)
    if len(body) > MAX_JSON_BYTES:
        raise ValueError("header too large")
    return struct.pack(">I", len(body)) + body + b"".join(blobs)


def unpack(payload: bytes) -> tuple[dict[str, Any], list[bytes]]:
    if len(payload) < 4:
        raise ProtocolError("truncated_payload")
    (json_len,) = struct.unpack(">I", payload[:4])
    if json_len > MAX_JSON_BYTES or 4 + json_len > len(payload):
        raise ProtocolError("bad_header_length")
    header = loads_strict(payload[4 : 4 + json_len])
    if not isinstance(header, dict):
        raise ProtocolError("bad_header")
    sizes = header.get("blobs")
    if not isinstance(sizes, list) or not all(type(n) is int and n >= 0 for n in sizes):
        raise ProtocolError("bad_blob_sizes")
    offset = 4 + json_len
    if offset + sum(sizes) != len(payload):
        raise ProtocolError("blob_size_mismatch")
    blobs = []
    for size in sizes:
        blobs.append(payload[offset : offset + size])
        offset += size
    return header, blobs


def hello_payload(vm_id: str, key: bytes) -> bytes:
    return pack({"protocol": PROTOCOL, "vm_id": vm_id, "key": key.hex()})


def _hello_key(payload: bytes) -> bytes:
    header, blobs = unpack(payload)
    key = header.get("key")
    if header.get("protocol") != PROTOCOL or blobs or not isinstance(key, str):
        raise ProtocolError("bad_hello")
    try:
        raw = bytes.fromhex(key)
    except ValueError:
        raise ProtocolError("bad_hello") from None
    if len(raw) != KEY_BYTES:
        raise ProtocolError("bad_hello")
    return raw


# ---------------------------------------------------------------- handshake


def firecracker_connect(sock: socket.socket, port: int, deadline: Deadline) -> None:
    """Firecracker's host-initiated vsock handshake on an already connected Unix socket."""
    sock.settimeout(deadline.remaining())
    sock.sendall(f"CONNECT {int(port)}\n".encode("ascii"))
    line = b""
    while not line.endswith(b"\n"):
        sock.settimeout(deadline.remaining())
        try:
            chunk = sock.recv(1)
        except socket.timeout:
            raise TimeoutError("deadline exceeded") from None
        if not chunk:
            raise ProtocolError("vsock_connect_refused")
        line += chunk
        if len(line) > MAX_HANDSHAKE_LINE:
            raise ProtocolError("vsock_bad_handshake")
    parts = line.decode("ascii", errors="replace").split()
    if len(parts) != 2 or parts[0] != "OK" or not parts[1].isdigit():
        raise ProtocolError("vsock_bad_handshake")
