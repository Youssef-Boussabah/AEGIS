"""Host <-> guest protocol (lab_vm_protocol) and the guest agent's parsing and serve loop.

The agent's real executor is never called here: ``serve`` runs with a scripted
executor over a socketpair. Nothing is compiled or executed.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from aegis_core import lab_guest_agent as agent
from aegis_core import lab_vm_protocol as proto

KEY = bytes(range(32))
VM_ID = "f" * 32


def pair():
    a, b = socket.socketpair()
    return a, b


def dl(seconds=2.0):
    return proto.Deadline(seconds)


# ------------------------------------------------------------------ framing


def test_hello_establishes_the_key_and_frames_round_trip():
    host_sock, guest_sock = pair()
    host = proto.Channel(host_sock, KEY)
    guest = proto.Channel(guest_sock)
    host.send(proto.HELLO, proto.hello_payload(VM_ID, KEY), dl())
    ftype, payload = guest.recv({proto.HELLO}, 4096, dl())
    assert ftype == proto.HELLO and guest.key == KEY
    guest.send(proto.READY, proto.pack({"x": 1}, [b"\x00\xff"]), dl())
    ftype, payload = host.recv({proto.READY}, 4096, dl())
    header, blobs = proto.unpack(payload)
    assert header == {"x": 1, "blobs": [2]} and blobs == [b"\x00\xff"]
    assert (host.send_seq, host.recv_seq, guest.send_seq, guest.recv_seq) == (1, 1, 1, 1)


def _raw(frame_type=proto.READY, seq=0, payload=b"{}", key=KEY, magic=proto.MAGIC, length=None):
    header = proto.HEADER.pack(magic, frame_type, seq, len(payload) if length is None else length)
    import hashlib
    import hmac

    return header + payload + hmac.new(key, header + payload, hashlib.sha256).digest()


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (_raw(magic=b"XXXX"), "bad_magic"),
        (_raw(frame_type=proto.JOB), "unexpected_frame"),
        (_raw(seq=1), "bad_sequence"),  # replayed or reordered
        (_raw(key=b"k" * 32), "bad_tag"),  # another session's key
        (_raw(payload=b"x" * 5000), "frame_too_large"),
        (_raw()[:-1], "truncated_frame"),
        (b"", "connection_closed"),  # clean end of stream before any frame byte
        (_raw(length=10)[: proto.HEADER.size + 3], "truncated_frame"),
    ],
)
def test_receiver_rejects_bad_frames(data, code):
    sender, receiver = pair()
    sender.sendall(data)
    sender.shutdown(socket.SHUT_WR)
    with pytest.raises(proto.ProtocolError) as info:
        proto.Channel(receiver, KEY).recv({proto.READY}, 4096, dl())
    assert info.value.code == code


def test_tampered_payload_fails_the_tag():
    frame = bytearray(proto.encode_frame(KEY, proto.READY, 0, b'{"a":1}'))
    frame[proto.HEADER.size] ^= 1
    sender, receiver = pair()
    sender.sendall(bytes(frame))
    with pytest.raises(proto.ProtocolError) as info:
        proto.Channel(receiver, KEY).recv({proto.READY}, 4096, dl())
    assert info.value.code == "bad_tag"


def test_keyless_receiver_accepts_only_a_valid_hello():
    for frame, code in (
        (proto.encode_frame(KEY, proto.READY, 0, b"{}"), "no_session_key"),
        (proto.encode_frame(KEY, proto.HELLO, 0, proto.pack({"protocol": "x", "key": KEY.hex()})), "bad_hello"),
        (proto.encode_frame(KEY, proto.HELLO, 0, proto.pack({"protocol": proto.PROTOCOL, "key": "00"})),
         "bad_hello"),
        (proto.encode_frame(b"o" * 32, proto.HELLO, 0, proto.hello_payload(VM_ID, KEY)), "bad_tag"),
    ):
        sender, receiver = pair()
        sender.sendall(frame)
        with pytest.raises(proto.ProtocolError) as info:
            proto.Channel(receiver).recv({proto.HELLO, proto.READY}, 4096, dl())
        assert info.value.code == code


def test_deadline_applies_to_silent_peers():
    _, receiver = pair()
    with pytest.raises(TimeoutError):
        proto.Channel(receiver, KEY).recv({proto.READY}, 4096, proto.Deadline(0.05))


def test_sender_without_key_refuses():
    a, _ = pair()
    with pytest.raises(proto.ProtocolError):
        proto.Channel(a).send(proto.READY, b"{}", dl())
    with pytest.raises(ValueError):
        proto.encode_frame(b"short", proto.READY, 0, b"")
    with pytest.raises(ValueError):
        proto.encode_frame(KEY, 99, 0, b"")


@pytest.mark.parametrize(
    "payload",
    [
        b"\x00\x00",
        struct.pack(">I", 999) + b"{}",
        struct.pack(">I", 2) + b"[]",
        struct.pack(">I", 15) + b'{"a":1,"a":2}  ',
        struct.pack(">I", 23) + b'{"blobs":[],"x":NaN}   ',
        struct.pack(">I", 12) + b'{"blobs":[3]}'[:12] + b"abc",
        struct.pack(">I", 13) + b'{"blobs":[3]}' + b"ab",
        struct.pack(">I", 14) + b'{"blobs":[-1]}',
        struct.pack(">I", 2) + b"\xff\xfe",
    ],
)
def test_unpack_is_strict(payload):
    with pytest.raises(proto.ProtocolError):
        proto.unpack(payload)


def test_pack_rejects_oversized_headers():
    with pytest.raises(ValueError):
        proto.pack({"x": "a" * proto.MAX_JSON_BYTES})


# -------------------------------------------------------- firecracker vsock


def _handshake_peer(reply: bytes | None):
    host, fake_fc = pair()

    def serve():
        line = b""
        while not line.endswith(b"\n"):
            line += fake_fc.recv(1)
        assert line == b"CONNECT 10000\n"
        if reply is not None:
            fake_fc.sendall(reply)
        fake_fc.shutdown(socket.SHUT_WR)

    threading.Thread(target=serve, daemon=True).start()
    return host


def test_firecracker_connect_handshake():
    proto.firecracker_connect(_handshake_peer(b"OK 1073741824\n"), 10000, dl())
    for reply, code in ((None, "vsock_connect_refused"), (b"NO\n", "vsock_bad_handshake"),
                        (b"OK " + b"9" * 80, "vsock_bad_handshake")):
        with pytest.raises(proto.ProtocolError) as info:
            proto.firecracker_connect(_handshake_peer(reply), 10000, dl())
        assert info.value.code == code


# --------------------------------------------------------------- guest agent

LIMITS = {"wall_ms": 1000, "cpu_ms": 1000, "memory_bytes": 64 << 20, "max_processes": 4,
          "scratch_bytes": 4 << 20, "stdout_bytes": 4096, "stderr_bytes": 4096}
COMPILE_LIMITS = {**LIMITS, "binary_bytes": 1 << 20}


def compile_header(**over):
    header = {"stage": "compile", "files": ["candidate.c", "unit.c"], "translation_units": ["unit.c"],
              "flags": ["-std=c11", "-O2"], "limits": COMPILE_LIMITS, "blobs": [1, 1]}
    header.update(over)
    return header


def test_parse_compile_and_execute_jobs():
    job = agent.parse_job(compile_header(), [b"a", b"b"])
    assert job.translation_units == ("unit.c",) and dict(job.files) == {"candidate.c": b"a", "unit.c": b"b"}
    assert agent.compiler_argv("/usr/bin/gcc", job) == ["/usr/bin/gcc", "-std=c11", "-O2", "-o", "candidate", "unit.c"]
    run = agent.parse_job({"stage": "execute", "args": ["1", "2"], "limits": LIMITS, "blobs": [3]}, [b"bin"])
    assert run.binary == b"bin" and run.args == ("1", "2")


@pytest.mark.parametrize(
    ("header", "blobs"),
    [
        (compile_header(files=["../x.c", "unit.c"]), [b"a", b"b"]),
        (compile_header(files=["unit.c", "unit.c"]), [b"a", b"b"]),
        (compile_header(translation_units=["other.c"]), [b"a", b"b"]),
        (compile_header(files=["candidate.c", "x.h"], translation_units=["x.h"]), [b"a", b"b"]),
        (compile_header(translation_units=[]), [b"a", b"b"]),
        (compile_header(flags=["-fplugin=/x.so"]), [b"a", b"b"]),
        (compile_header(limits=LIMITS), [b"a", b"b"]),  # compile needs binary_bytes
        (compile_header(limits={**COMPILE_LIMITS, "wall_ms": True}), [b"a", b"b"]),
        (compile_header(expected=[1]), [b"a", b"b"]),  # nothing beyond the job, ever
        (compile_header(), [b"a"]),
        ({"stage": "execute", "args": ["1 2"], "limits": LIMITS, "blobs": [1]}, [b"b"]),
        ({"stage": "execute", "args": [], "limits": LIMITS, "blobs": [0]}, [b""]),
        ({"stage": "link", "blobs": []}, []),
    ],
)
def test_agent_rejects_malformed_jobs(header, blobs):
    with pytest.raises(proto.ProtocolError):
        agent.parse_job(header, blobs)


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"returncode": 0}, ("exited", 0, None, None)),
        ({"returncode": 3}, ("exited", 3, None, None)),
        ({"returncode": -11}, ("signaled", None, 11, None)),
        ({"returncode": -24}, ("limit_exceeded", None, None, "cpu")),  # SIGXCPU
        ({"returncode": None, "timed_out": True}, ("timeout", None, None, None)),
        ({"returncode": None, "overflow": "stdout"}, ("limit_exceeded", None, None, "stdout")),
        ({"returncode": -9, "oom_kills": 1}, ("limit_exceeded", None, None, "memory")),
        ({"returncode": 0, "cpu_usec": 1_000_001}, ("limit_exceeded", None, None, "cpu")),
        ({"returncode": 1, "pids_max_events": 2}, ("limit_exceeded", None, None, "processes")),
        ({"returncode": 0, "pids_max_events": 2}, ("exited", 0, None, None)),
    ],
)
def test_classification(kw, expected):
    args = {"returncode": None, "timed_out": False, "overflow": None, "oom_kills": 0,
            "pids_max_events": 0, "cpu_usec": 10, "limits": LIMITS}
    args.update(kw)
    assert agent.classify(**args) == expected


def test_cpu_rlimit_rounds_up():
    assert [agent.cpu_rlimit_seconds(v) for v in (10, 1000, 1001, 2500)] == [1, 1, 2, 3]


class Scripted:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.jobs = result, error, []

    def run(self, job):
        self.jobs.append(job)
        if self.error:
            raise self.error
        return self.result


IDENTITY = agent.AgentIdentity(agent_sha256="a" * 64, compiler={"name": "gcc", "version": "14", "sha256": "c" * 64})


def _host_session(job_header, job_blobs, executor):
    host_sock, guest_sock = pair()
    outcome = {}
    thread = threading.Thread(target=lambda: outcome.setdefault("r", agent.serve(guest_sock, executor, IDENTITY)))
    thread.start()
    host = proto.Channel(host_sock, KEY)
    host.send(proto.HELLO, proto.hello_payload(VM_ID, KEY), dl())
    _, ready = host.recv({proto.READY}, 4096, dl())
    host.send(proto.JOB, proto.pack(job_header, job_blobs), dl())
    ftype, payload = host.recv({proto.RESULT, proto.ERROR}, 1 << 20, dl())
    thread.join(2)
    return proto.unpack(ready)[0], ftype, proto.unpack(payload), outcome.get("r")


def test_serve_runs_one_job_and_reports_observations_only():
    result = agent.GuestResult("exited", exit_code=0, stdout=b"AEGIS-RESULT 7\n", duration_ms=3)
    executor = Scripted(result)
    header = {"stage": "execute", "args": ["6"], "limits": LIMITS}
    ready, ftype, (res, blobs), ended = _host_session(header, [b"BIN"], executor)
    assert ready["vm_id"] == VM_ID and ready["agent_sha256"] == "a" * 64 and ready["compiler"]["name"] == "gcc"
    assert ftype == proto.RESULT and ended == "result"
    assert res["status"] == "exited" and blobs[0] == b"AEGIS-RESULT 7\n" and res["has_binary"] is False
    assert executor.jobs[0].binary == b"BIN" and executor.jobs[0].args == ("6",)


def test_serve_answers_bad_jobs_and_executor_failures_with_error_codes():
    _, ftype, (res, _), ended = _host_session({"stage": "nope"}, [], Scripted())
    assert (ftype, res["code"], ended) == (proto.ERROR, "bad_request", "bad_request")
    header = {"stage": "execute", "args": [], "limits": LIMITS}
    _, ftype, (res, _), ended = _host_session(header, [b"B"], Scripted(error=RuntimeError("x")))
    assert (ftype, res["code"], ended) == (proto.ERROR, "setup_failed", "setup_failed")


def test_serve_rejects_a_bad_vm_id():
    host_sock, guest_sock = pair()
    errors = []

    def run():
        try:
            agent.serve(guest_sock, Scripted(), IDENTITY)
        except proto.ProtocolError as exc:
            errors.append(exc.code)

    thread = threading.Thread(target=run)
    thread.start()
    proto.Channel(host_sock, KEY).send(proto.HELLO, proto.hello_payload("../x", KEY), dl())
    thread.join(2)
    assert errors == ["bad_hello"]
