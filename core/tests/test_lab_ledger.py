"""Grant-wide budgets: the ledger (aegis_core.lab_ledger) and its use by sessions.

Every runtime is the scripted, non-executing test double. The cross-process test
starts Python subprocesses that only call the ledger; nothing is compiled or run.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from aegis_core.errors import AegisError
from aegis_core.lab_authorization import LabBindings, grant_sha256
from aegis_core.lab_execution import SourceFile, open_session
from aegis_core.lab_ledger import LEDGER_DIR, GrantLedger
from aegis_core.lab_limits import CompileLimits, SandboxLimits
from aegis_core.models import ErrorCode
from aegis_core.testing.scripted_runtime import ScriptedIsolationRuntime
from lab_fixtures import (
    CANDIDATE_A,
    CANDIDATE_B,
    ID_A,
    ID_B,
    LAB_NOW,
    compile_limits_data,
    execute_limits_data,
    lab_bindings_data,
)

FLAGS = ["-std=c11", "-O2", "-static"]
UNITS = ["candidate.c"]


@pytest.fixture
def opener(lab_config, make_grant):
    config = lab_config()

    def open_(grant=None, runtime=None, **grant_overrides):
        runtime = runtime or ScriptedIsolationRuntime()
        session = open_session(
            config,
            grant or make_grant(**grant_overrides),
            lab_bindings=LabBindings.model_validate(lab_bindings_data()),
            runtime=runtime,
            clock=lambda: LAB_NOW,
        )
        return session, runtime

    open_.config = config
    return open_


def _compile(session, cid=ID_A, data=CANDIDATE_A, **limits):
    return session.compile(
        cid,
        SourceFile(name="candidate.c", data=data),
        translation_units=UNITS,
        flags=FLAGS,
        limits=CompileLimits.model_validate(compile_limits_data(**limits)),
    )


def _execute(session, binary, cid=ID_A):
    return session.execute(cid, binary, args=["1"], limits=SandboxLimits.model_validate(execute_limits_data()))


def _reason(info) -> str:
    assert info.value.code is ErrorCode.AUTHORIZATION_REQUIRED, info.value
    return info.value.details["reason"]


def _ledger_dir(opener, grant_id="d" * 32) -> Path:
    return Path(opener.config.storage.root) / LEDGER_DIR / grant_id


# ------------------------------------------------- budgets span all sessions


def test_second_session_cannot_reset_the_compilation_budget(opener):
    first, _ = opener()
    _compile(first)
    second, runtime = opener()
    with pytest.raises(AegisError) as info:
        _compile(second)
    assert _reason(info) == "compilation_budget_exhausted"
    assert runtime.compile_jobs == []


def test_execution_budget_is_shared_across_sessions(opener):
    # Each session compiles a different candidate's binary, but executions of one
    # candidate are counted for the grant. max_executions_per_candidate = 3.
    s1, _ = opener(max_compilations_per_candidate=2)
    s2, _ = opener(max_compilations_per_candidate=2)
    b1, b2 = _compile(s1).binary, _compile(s2).binary
    _execute(s1, b1)
    _execute(s1, b1)
    record = _execute(s2, b2)
    assert record.executions_used == 3  # grant-wide, not this session's 1
    with pytest.raises(AegisError) as info:
        _execute(s1, b1)
    assert _reason(info) == "execution_budget_exhausted"


def test_wall_budget_is_shared_across_sessions(opener):
    s1, _ = opener(max_total_wall_ms=50_000)
    s2, _ = opener(max_total_wall_ms=50_000)
    _compile(s1)  # 30 000 reserved
    with pytest.raises(AegisError) as info:
        _compile(s2, ID_B, CANDIDATE_B)  # would need 60 000
    assert _reason(info) == "wall_budget_exhausted"
    assert info.value.details["reserved_ms"] == 30_000
    record = _compile(s2, ID_B, CANDIDATE_B, wall_ms=20_000).record
    assert record.wall_ms_reserved == 50_000
    assert s1.wall_ms_reserved == s2.wall_ms_reserved == 50_000


def test_usage_survives_a_new_ledger_instance_and_process_restart(opener, make_grant):
    s1, _ = opener()
    _compile(s1)
    fresh = GrantLedger.for_config(opener.config)  # as a new process would build it
    usage = fresh.usage(make_grant().grant_id)
    assert usage.compilations == {ID_A: 1}
    assert usage.wall_ms_reserved == 30_000
    assert usage.sessions_opened == 1
    assert usage.grant_sha256 == grant_sha256(make_grant())


def test_refused_reservation_changes_nothing(opener, make_grant):
    s1, _ = opener()
    _compile(s1)
    before = GrantLedger.for_config(opener.config).usage(make_grant().grant_id)
    with pytest.raises(AegisError):
        _compile(s1)
    after = GrantLedger.for_config(opener.config).usage(make_grant().grant_id)
    assert after == before


def test_sessions_are_counted(opener, make_grant):
    for _ in range(3):
        opener()
    assert GrantLedger.for_config(opener.config).usage(make_grant().grant_id).sessions_opened == 3


def test_unused_grant_has_no_usage(opener):
    assert GrantLedger.for_config(opener.config).usage("f" * 32) is None


# ------------------------------------------------------ grant identity binding


def test_reusing_a_grant_id_with_different_contents_is_refused(opener):
    s1, _ = opener()
    _compile(s1)
    runtime = ScriptedIsolationRuntime()
    with pytest.raises(AegisError) as info:
        opener(runtime=runtime, max_compilations_per_candidate=16)  # same id, bigger budget
    assert _reason(info) == "grant_ledger_conflict"
    assert runtime.preflights == []  # refused before the runtime is touched


def test_a_different_grant_id_has_its_own_ledger(opener):
    s1, _ = opener()
    _compile(s1)
    s2, _ = opener(grant_id="e" * 32)
    _compile(s2)


# ------------------------------------------------------------- fail closed


def test_corrupt_ledger_fails_closed(opener):
    opener()
    (_ledger_dir(opener) / "ledger.json").write_text('{"schema_version": "x"}')
    runtime = ScriptedIsolationRuntime()
    with pytest.raises(AegisError) as info:
        opener(runtime=runtime)
    assert info.value.code is ErrorCode.STORAGE_ERROR
    assert runtime.preflights == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(wall_ms_reserved=-1),
        lambda d: d.update(wall_ms_reserved="0"),
        lambda d: d.update(grant_id="f" * 32),
        lambda d: d.update(extra=1),
    ],
)
def test_tampered_ledger_contents_fail_closed(opener, mutate):
    s1, _ = opener()
    _compile(s1)
    path = _ledger_dir(opener) / "ledger.json"
    data = json.loads(path.read_text())
    mutate(data)
    path.write_text(json.dumps(data))
    with pytest.raises(AegisError) as info:
        _compile(s1, ID_B, CANDIDATE_B)
    assert info.value.code is ErrorCode.STORAGE_ERROR


def test_symlinked_ledger_file_or_directory_is_rejected(opener, tmp_path):
    opener()
    directory = _ledger_dir(opener)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text((directory / "ledger.json").read_text())
    (directory / "ledger.json").unlink()
    (directory / "ledger.json").symlink_to(elsewhere)
    with pytest.raises(AegisError) as info:
        opener()
    assert info.value.code is ErrorCode.STORAGE_ERROR

    other = tmp_path / "other-dir"
    other.mkdir()
    link = directory.parent / ("e" * 32)
    link.symlink_to(other, target_is_directory=True)
    with pytest.raises(AegisError) as info:
        opener(grant_id="e" * 32)
    assert info.value.code is ErrorCode.STORAGE_ERROR


def test_oversized_ledger_fails_closed(opener):
    opener()
    (_ledger_dir(opener) / "ledger.json").write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(AegisError) as info:
        opener()
    assert info.value.code is ErrorCode.STORAGE_ERROR


def test_ledger_files_are_private(opener):
    opener()
    directory = _ledger_dir(opener)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / "ledger.json").stat().st_mode) == 0o600
    assert not list(directory.glob(".ledger.*.tmp"))


def test_invalid_grant_id_never_becomes_a_path(tmp_path):
    with pytest.raises(AegisError) as info:
        GrantLedger(tmp_path).usage("../" + "a" * 29)
    assert info.value.code is ErrorCode.STORAGE_ERROR
    assert not any(tmp_path.iterdir())


# ---------------------------------------------------------------- concurrency


def test_concurrent_threads_never_exceed_the_budget(opener, make_grant):
    grant = make_grant(max_executions_per_candidate=5)
    ledger = GrantLedger.for_config(opener.config)
    digest = grant_sha256(grant)
    ledger.register_session(grant, digest, LAB_NOW)
    ok, refused = [], []

    def worker():
        for _ in range(3):
            try:
                ledger.reserve(grant, digest, stage="execute", candidate_id=ID_A, wall_ms=10, now=LAB_NOW)
                ok.append(1)
            except AegisError as exc:
                refused.append(exc.details["reason"])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ok) == 5 and len(refused) == 19
    assert set(refused) == {"execution_budget_exhausted"}
    assert ledger.usage(grant.grant_id).executions == {ID_A: 5}


_CHILD = """
import json, sys
from datetime import datetime
from aegis_core.errors import AegisError
from aegis_core.lab_authorization import CandidateExecutionGrant, grant_sha256
from aegis_core.lab_ledger import GrantLedger
root, grant_json = sys.argv[1], sys.argv[2]
grant = CandidateExecutionGrant.model_validate_json(open(grant_json).read())
ledger = GrantLedger(root)
now = datetime.fromisoformat("2026-10-29T12:00:00+00:00")
ok = 0
for _ in range(4):
    try:
        ledger.reserve(grant, grant_sha256(grant), stage="execute", candidate_id="a" * 32, wall_ms=10, now=now)
        ok += 1
    except AegisError:
        pass
print(ok)
"""


def test_concurrent_processes_share_one_ledger(tmp_path, make_grant):
    grant = make_grant(max_executions_per_candidate=6)
    grant_file = tmp_path / "grant.json"
    grant_file.write_text(grant.model_dump_json())
    root = tmp_path / "store" / LEDGER_DIR
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": os.pathsep.join(sys.path)}
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD, str(root), str(grant_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        for _ in range(4)
    ]
    results = []
    for proc in procs:
        out, err = proc.communicate(timeout=60)
        assert proc.returncode == 0, err
        results.append(int(out.strip()))
    assert sum(results) == 6  # 16 attempts, exactly the budget succeeds
    assert GrantLedger(root).usage(grant.grant_id).executions == {ID_A: 6}
