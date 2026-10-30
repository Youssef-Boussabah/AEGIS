"""Candidate execution session, worker contract and fail-closed runtime (aegis_core.lab_execution).

Every runtime here is either the refusing ``UnavailableRuntime`` or the scripted
test double. Nothing in these tests compiles or executes code.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest
from pydantic import ValidationError

from aegis_core.errors import AegisError
from aegis_core.lab_authorization import LabBindings
from aegis_core.lab_execution import (
    ISOLATION_BLOCKERS,
    SANDBOX_FAILURES,
    CandidateExecutionRecord,
    CompileObservation,
    ExecuteObservation,
    RuntimeAttestation,
    SourceFile,
    UnavailableRuntime,
    configured_runtime,
    open_session,
    sandbox_failure,
)
from aegis_core.lab_limits import CompileLimits, SandboxLimits
from aegis_core.models import ErrorCode
from aegis_core.testing.scripted_runtime import (
    SCRIPTED_BINARY_PREFIX,
    ScriptedIsolationRuntime,
    scripted_attestation,
)
from lab_fixtures import (
    CANDIDATE_A,
    CANDIDATE_B,
    ID_A,
    ID_B,
    LAB_NOW,
    compile_limits_data,
    execute_limits_data,
    lab_bindings_data,
    bind_bundle,
)

FLAGS = ["-std=c11", "-O2", "-static"]
HARNESS = SourceFile(name="aegis_harness.c", data=b"int main(void) { return 0; }\n")
UNITS = ["candidate.c", HARNESS.name]
OTHER_GRANT = "e" * 32


class Clock:
    def __init__(self):
        self.now = LAB_NOW

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def bindings():
    return LabBindings.model_validate(lab_bindings_data())


@pytest.fixture
def session_factory(lab_config, make_grant, bindings, clock):
    def factory(runtime=None, *, config=None, grant=None, bundle_files=None, bundle_units=None, **grant_overrides):
        runtime = runtime if runtime is not None else ScriptedIsolationRuntime()
        session = open_session(
            config or lab_config(),
            bind_bundle(grant or make_grant(**grant_overrides), bundle_files, bundle_units),
            lab_bindings=bindings,
            runtime=runtime,
            clock=clock,
        )
        return session, runtime

    return factory


def compile_limits(**kw) -> CompileLimits:
    return CompileLimits.model_validate(compile_limits_data(**kw))


def execute_limits(**kw) -> SandboxLimits:
    return SandboxLimits.model_validate(execute_limits_data(**kw))


def candidate(data: bytes = CANDIDATE_A, name: str = "candidate.c") -> SourceFile:
    return SourceFile(name=name, data=data)


def compile_a(session, **kw):
    kw.setdefault("support_files", [HARNESS])
    kw.setdefault("translation_units", UNITS)
    kw.setdefault("flags", FLAGS)
    kw.setdefault("limits", compile_limits())
    return session.compile(ID_A, kw.pop("source", candidate()), **kw)


def _reason(info) -> str:
    assert info.value.code is ErrorCode.AUTHORIZATION_REQUIRED, info.value
    return info.value.details["reason"]


# ------------------------------------------------- configured runtime refuses


def test_default_runtime_refuses_and_nothing_runs(lab_config, make_grant, bindings, clock):
    with pytest.raises(AegisError) as info:
        open_session(lab_config(), make_grant(), lab_bindings=bindings, clock=clock)
    assert info.value.code is ErrorCode.SANDBOX_UNAVAILABLE
    blockers = info.value.details["blockers"]
    assert blockers[: len(ISOLATION_BLOCKERS)] == list(ISOLATION_BLOCKERS)


def test_configured_runtime_adds_host_blockers_and_survives_probe_failure(lab_config):
    runtime = configured_runtime(lab_config(), host_blockers=lambda: ("runsc_not_installed",))
    assert isinstance(runtime, UnavailableRuntime)
    assert runtime.blockers == (*ISOLATION_BLOCKERS, "runsc_not_installed")

    def broken() -> tuple[str, ...]:
        raise OSError("probe failed")

    assert configured_runtime(lab_config(), host_blockers=broken).blockers[-1] == "host_probe_failed"


def test_unavailable_runtime_refuses_every_operation(lab_config):
    runtime = configured_runtime(lab_config(), host_blockers=lambda: ())
    for call in (
        lambda: runtime.preflight(None),
        lambda: runtime.compile(None),
        lambda: runtime.execute(None),
    ):
        with pytest.raises(AegisError) as info:
            call()
        assert info.value.code is ErrorCode.SANDBOX_UNAVAILABLE
    runtime.close()
    with pytest.raises(ValueError):
        UnavailableRuntime(())


# ------------------------------------------------------ gates before preflight


@pytest.mark.parametrize(
    ("config_kwargs", "reason"),
    [
        ({"attack_lab": False}, "attack_lab_disabled"),
        ({"candidate_execution": False}, "candidate_execution_disabled"),
    ],
)
def test_gates_are_checked_before_the_runtime_is_touched(lab_config, session_factory, config_kwargs, reason):
    runtime = ScriptedIsolationRuntime()
    with pytest.raises(AegisError) as info:
        session_factory(runtime, config=lab_config(**config_kwargs))
    assert _reason(info) == reason
    assert runtime.preflights == [] and runtime.compile_jobs == []


def test_lab_bindings_must_match_the_grant(lab_config, make_grant, clock):
    runtime = ScriptedIsolationRuntime()
    other = LabBindings.model_validate({**lab_bindings_data(), "hidden_test_suite_sha256": "9" * 64})
    with pytest.raises(AegisError) as info:
        open_session(lab_config(), make_grant(), lab_bindings=other, runtime=runtime, clock=clock)
    assert _reason(info) == "lab_bindings_mismatch"
    assert info.value.details["fields"] == ["hidden_test_suite_sha256"]
    assert runtime.preflights == []


def test_preflight_receives_the_grant_limits(session_factory, make_grant):
    session, runtime = session_factory()
    [request] = runtime.preflights
    grant = make_grant()
    assert request.compile_limits == grant.compile_limits
    assert request.execute_limits == grant.execute_limits
    assert session.attestation == scripted_attestation()


@pytest.mark.parametrize(
    ("error", "code", "detail"),
    [
        (RuntimeError("boom"), ErrorCode.SANDBOX_UNAVAILABLE, ["runtime_preflight_failed"]),
        (AegisError(ErrorCode.INTERNAL_ERROR, "x"), ErrorCode.SANDBOX_UNAVAILABLE, ["runtime_preflight_failed"]),
        (sandbox_failure("resource_enforcement_failed", "x"), ErrorCode.SANDBOX_FAILED, None),
    ],
)
def test_preflight_failures_fail_closed_and_close_the_runtime(session_factory, error, code, detail):
    runtime = ScriptedIsolationRuntime(preflight_error=error)
    with pytest.raises(AegisError) as info:
        session_factory(runtime)
    assert info.value.code is code
    if detail is not None:
        assert info.value.details["blockers"] == detail
    assert runtime.closed == 1


def test_mutated_inconsistent_attestation_is_rejected(session_factory):
    attestation = scripted_attestation()
    attestation.isolation_verified = True  # models are not frozen; Core re-validates
    runtime = ScriptedIsolationRuntime(attestation=attestation)
    with pytest.raises(AegisError) as info:
        session_factory(runtime)
    assert info.value.code is ErrorCode.SANDBOX_UNAVAILABLE


def _gvisor_attestation(**overrides) -> dict:
    data = {
        "runtime": "gvisor-runsc",
        "runtime_version": "release-20261001.0",
        "runtime_sha256": "e" * 64,
        "platform": "systrap",
        "rootless": True,
        "network": "none",
        "rootfs_sha256": "f" * 64,
        "compiler_name": "gcc",
        "compiler_version": "16.2.1",
        "compiler_sha256": "0" * 64,
        "limits_enforcement": "verified_by_cgroup_readback",
        "isolation_verified": True,
    }
    data.update(overrides)
    return data


def test_attestation_consistency():
    RuntimeAttestation.model_validate(_gvisor_attestation())
    RuntimeAttestation.model_validate(_gvisor_attestation(platform="kvm"))
    for bad in (
        {"runtime_sha256": None},
        {"platform": "none"},
        {"rootless": False},
        {"rootfs_sha256": None},
        {"limits_enforcement": "not_enforced_test_double"},
        {"isolation_verified": False},
        {"network": "host"},
    ):
        with pytest.raises(ValidationError):
            RuntimeAttestation.model_validate(_gvisor_attestation(**bad))
    double = scripted_attestation().model_dump()
    with pytest.raises(ValidationError):
        RuntimeAttestation.model_validate({**double, "isolation_verified": True})
    with pytest.raises(ValidationError):
        RuntimeAttestation.model_validate({**double, "runtime_sha256": "e" * 64})


# ------------------------------------------------------------------- compile


def test_compile_binds_hashes_and_records(session_factory, make_grant):
    session, runtime = session_factory()
    result = compile_a(session)
    [job] = runtime.compile_jobs
    assert job.candidate.data == CANDIDATE_A and job.support_files == [HARNESS]
    assert job.flags == FLAGS and job.output_name == "candidate"
    assert result.binary is not None and result.binary.startswith(SCRIPTED_BINARY_PREFIX)

    record = result.record
    assert record.stage == "compile"
    assert record.candidate_id == ID_A
    assert record.candidate_sha256 == hashlib.sha256(CANDIDATE_A).hexdigest()
    assert record.binary_sha256 == hashlib.sha256(result.binary).hexdigest()
    assert record.binary_bytes == len(result.binary)
    assert record.support_files_sha256 == {HARNESS.name: hashlib.sha256(HARNESS.data).hexdigest()}
    assert record.grant_id == make_grant().grant_id and record.grant_sha256 == session.grant_sha256
    assert record.lab_bindings == make_grant().lab_bindings
    assert record.runtime.runtime == "test_double" and not record.runtime.isolation_verified
    assert record.limits == compile_limits().model_dump()
    assert record.compilations_used == 1 and record.executions_used == 0
    assert record.wall_ms_reserved == 30_000
    assert record.stdout_sha256 == hashlib.sha256(b"").hexdigest()
    assert record.started_at == LAB_NOW and record.session_id == session.session_id


def test_records_round_trip_through_json_with_binary_output(session_factory):
    def run(job):
        return ExecuteObservation(
            status="exited", exit_code=0, duration_ms=3, stdout=b"AEGIS-RESULT 7\n\xff\x00", stderr=b"\x80"
        )

    session, _ = session_factory(ScriptedIsolationRuntime(execute=run))
    result = compile_a(session)
    record = session.execute(ID_A, result.binary, args=["6"], limits=execute_limits())
    assert record.observation.stdout == b"AEGIS-RESULT 7\n\xff\x00"
    assert record.stdout_sha256 == hashlib.sha256(b"AEGIS-RESULT 7\n\xff\x00").hexdigest()
    assert CandidateExecutionRecord.model_validate_json(record.model_dump_json()) == record


def test_failed_compilation_returns_no_binary_and_registers_nothing(session_factory):
    def failing(job):
        return CompileObservation(status="exited", exit_code=1, duration_ms=5, stderr=b"error: x")

    session, runtime = session_factory(ScriptedIsolationRuntime(compile=failing))
    result = compile_a(session)
    assert result.binary is None and result.record.binary_sha256 is None
    assert result.record.observation.stderr == b"error: x"
    with pytest.raises(AegisError) as info:
        session.execute(ID_A, b"anything", args=[], limits=execute_limits())
    assert _reason(info) == "binary_not_from_session"
    assert runtime.execute_jobs == []


def test_unlisted_candidate_is_refused(session_factory):
    session, runtime = session_factory()
    with pytest.raises(AegisError) as info:
        session.compile(
            "f" * 32, candidate(), translation_units=["candidate.c"], flags=FLAGS, limits=compile_limits()
        )
    assert _reason(info) == "candidate_not_permitted"
    assert runtime.compile_jobs == []


def test_candidate_bytes_must_match_the_permitted_digest(session_factory):
    session, runtime = session_factory()
    with pytest.raises(AegisError) as info:
        compile_a(session, source=candidate(CANDIDATE_A + b" "))
    assert _reason(info) == "candidate_digest_mismatch"
    assert info.value.details["expected_sha256"] == hashlib.sha256(CANDIDATE_A).hexdigest()
    # Candidate B's (permitted) source under A's id is still a mismatch.
    with pytest.raises(AegisError) as info:
        compile_a(session, source=candidate(CANDIDATE_B))
    assert _reason(info) == "candidate_digest_mismatch"
    assert runtime.compile_jobs == []


@pytest.mark.parametrize("flags", [["-O2", "-std=c11", "-static"], ["-std=c11", "-O2"], [*FLAGS, "-w"]])
def test_compile_flags_must_equal_the_grant(session_factory, flags):
    session, runtime = session_factory()
    with pytest.raises(AegisError) as info:
        compile_a(session, flags=flags)
    assert _reason(info) == "compile_flags_mismatch"
    assert runtime.compile_jobs == []


def test_compile_limits_may_not_exceed_the_grant(session_factory):
    session, runtime = session_factory()
    with pytest.raises(AegisError) as info:
        compile_a(session, limits=compile_limits(binary_bytes=4 * 1024 * 1024 + 1, cpu_ms=30_001))
    assert _reason(info) == "limits_exceed_grant"
    assert info.value.details["exceeding"] == ["binary_bytes", "cpu_ms"]
    with pytest.raises(AegisError) as info:
        compile_a(session, limits=execute_limits())  # wrong limit type for the stage
    assert info.value.code is ErrorCode.INVALID_REQUEST
    assert runtime.compile_jobs == []


@pytest.mark.parametrize("name", ["../x.c", "a/b.c", ".hidden.c", "x.so", "x.c\n", "x", "-o.c"])
def test_source_names_are_fixed_components(name):
    with pytest.raises(ValidationError):
        SourceFile(name=name, data=b"")


def test_source_set_rules(session_factory):
    session, runtime = session_factory()
    cases = [
        {"support_files": [SourceFile(name="candidate.c", data=b"")]},  # duplicate name
        {"support_files": [SourceFile(name=f"h{i}.h", data=b"") for i in range(16)]},
        {"source": SourceFile(name="candidate.h", data=CANDIDATE_A)},
        {"support_files": [SourceFile(name=f"h{i}.h", data=b"x" * 1024 * 1024) for i in range(4)]},
    ]
    for kwargs in cases:
        with pytest.raises(AegisError) as info:
            compile_a(session, **kwargs)
        assert info.value.code is ErrorCode.INVALID_REQUEST
    assert runtime.compile_jobs == []


def test_compilation_budget_is_per_candidate(session_factory):
    session, _ = session_factory()
    compile_a(session)
    with pytest.raises(AegisError) as info:
        compile_a(session)
    assert _reason(info) == "compilation_budget_exhausted"
    session.compile(
        ID_B, candidate(CANDIDATE_B), translation_units=["candidate.c"], flags=FLAGS,
        limits=compile_limits(),
    )
    assert session.compilations_used(ID_A) == session.compilations_used(ID_B) == 1


def test_wall_budget_is_reserved_before_running_and_kept_on_failure(session_factory):
    def failing(job):
        raise RuntimeError("sandbox died")

    session, _ = session_factory(max_total_wall_ms=40_000)
    compile_a(session)  # reserves 30 000 of 40 000
    with pytest.raises(AegisError) as info:
        session.compile(
            ID_B, candidate(CANDIDATE_B), translation_units=["candidate.c"], flags=FLAGS,
            limits=compile_limits(),
        )
    assert _reason(info) == "wall_budget_exhausted"
    assert info.value.details == {
        "reason": "wall_budget_exhausted",
        "reserved_ms": 30_000,
        "requested_ms": 30_000,
        "budget_ms": 40_000,
    }

    session2, _ = session_factory(ScriptedIsolationRuntime(compile=failing), grant_id=OTHER_GRANT)
    with pytest.raises(AegisError):
        compile_a(session2)
    assert session2.wall_ms_reserved == 30_000 and session2.compilations_used(ID_A) == 1


# ------------------------------------------------------------------- execute


def test_execute_runs_only_session_binaries_for_their_candidate(session_factory):
    session, runtime = session_factory()
    result = compile_a(session)
    record = session.execute(ID_A, result.binary, args=["41", "-1"], limits=execute_limits())
    [job] = runtime.execute_jobs
    assert job.binary == result.binary and job.args == ["41", "-1"]
    assert record.stage == "execute" and record.args == ["41", "-1"]
    assert record.binary_sha256 == result.record.binary_sha256
    assert record.candidate_sha256 == result.record.candidate_sha256
    assert record.executions_used == 1 and record.wall_ms_reserved == 32_000

    for cand_id, binary in ((ID_A, result.binary + b"x"), (ID_B, result.binary), (ID_A, b"")):
        with pytest.raises(AegisError) as info:
            session.execute(cand_id, binary, args=[], limits=execute_limits())
        assert _reason(info) == "binary_not_from_session"
    assert len(runtime.execute_jobs) == 1


def test_identical_binaries_of_two_candidates_are_tracked_per_candidate(session_factory):
    same = lambda job: CompileObservation(status="exited", exit_code=0, duration_ms=1, binary=b"same")  # noqa: E731
    session, _ = session_factory(ScriptedIsolationRuntime(compile=same))
    a = compile_a(session)
    b = session.compile(
        ID_B, candidate(CANDIDATE_B), translation_units=["candidate.c"], flags=FLAGS, limits=compile_limits()
    )
    assert a.binary == b.binary
    session.execute(ID_A, a.binary, args=[], limits=execute_limits())
    session.execute(ID_B, b.binary, args=[], limits=execute_limits())


def test_execute_budget_and_limits(session_factory):
    session, runtime = session_factory()
    binary = compile_a(session).binary
    for _ in range(3):
        session.execute(ID_A, binary, args=["1"], limits=execute_limits())
    with pytest.raises(AegisError) as info:
        session.execute(ID_A, binary, args=["1"], limits=execute_limits())
    assert _reason(info) == "execution_budget_exhausted"

    session2, _ = session_factory(grant_id=OTHER_GRANT)
    binary = compile_a(session2).binary
    with pytest.raises(AegisError) as info:
        session2.execute(ID_A, binary, args=[], limits=execute_limits(stdout_bytes=4097))
    assert _reason(info) == "limits_exceed_grant"
    with pytest.raises(AegisError) as info:
        session2.execute(ID_A, binary, args=[], limits=compile_limits())
    assert info.value.code is ErrorCode.INVALID_REQUEST


@pytest.mark.parametrize(
    "args",
    [["1 2"], [""], ["$(id)"], ["a;b"], ["x" * 257], ["1"] * 65, [7], ["\x00"], ["é"]],
)
def test_execute_arguments_are_allowlisted_and_never_echoed(session_factory, args):
    session, runtime = session_factory()
    binary = compile_a(session).binary
    with pytest.raises(AegisError) as info:
        session.execute(ID_A, binary, args=args, limits=execute_limits())
    assert info.value.code is ErrorCode.INVALID_REQUEST
    assert all(str(a) not in info.value.message for a in args if len(str(a)) > 2)
    assert runtime.execute_jobs == []


def test_compile_only_grant_refuses_execute(session_factory):
    session, runtime = session_factory(stages=["compile"], execute_limits=None, max_executions_per_candidate=0)
    binary = compile_a(session).binary
    with pytest.raises(AegisError) as info:
        session.execute(ID_A, binary, args=[], limits=execute_limits())
    assert _reason(info) == "stage_not_permitted"
    assert runtime.execute_jobs == []


# ------------------------------------------------------ re-checks per stage


def test_grant_expiry_mid_session_refuses_next_stage(session_factory, clock):
    session, runtime = session_factory()
    binary = compile_a(session).binary
    clock.now = LAB_NOW + timedelta(hours=22)  # grant expires 2026-10-30T10:00Z
    with pytest.raises(AegisError) as info:
        session.execute(ID_A, binary, args=[], limits=execute_limits())
    assert _reason(info) == "grant_expired"
    assert runtime.execute_jobs == []


def test_operator_gate_closed_mid_session_refuses_next_stage(session_factory, lab_config):
    config = lab_config()
    session, runtime = session_factory(config=config)
    config.attack_lab.candidate_execution.enabled = False
    with pytest.raises(AegisError) as info:
        compile_a(session)
    assert _reason(info) == "candidate_execution_disabled"
    config.attack_lab.candidate_execution.enabled = True
    config.attack_lab.enabled = False
    with pytest.raises(AegisError) as info:
        compile_a(session)
    assert _reason(info) == "attack_lab_disabled"
    assert runtime.compile_jobs == []


# ------------------------------------------------------ runtime misbehaviour


@pytest.mark.parametrize(
    ("behaviour", "failure"),
    [
        (RuntimeError("crash"), "sandbox_failed"),
        (AegisError(ErrorCode.INTERNAL_ERROR, "x"), "sandbox_failed"),
        (sandbox_failure("resource_enforcement_failed", "cgroup read-back mismatch"), "resource_enforcement_failed"),
        (sandbox_failure("cleanup_failed", "scope still populated"), "cleanup_failed"),
        ("not an observation", "protocol_violation"),
        (ExecuteObservation(status="exited", exit_code=0, duration_ms=1), "protocol_violation"),  # wrong type
        (CompileObservation(status="exited", exit_code=0, duration_ms=1, stdout=b"x" * (1024 * 1024 + 1)),
         "protocol_violation"),
        (CompileObservation(status="exited", exit_code=0, duration_ms=1, stderr=b"x" * (64 * 1024 + 1)),
         "protocol_violation"),
        (CompileObservation(status="exited", exit_code=0, duration_ms=1, binary=b"x" * (4 * 1024 * 1024 + 1)),
         "protocol_violation"),
    ],
)
def test_runtime_failures_are_infrastructure_errors_and_poison_the_session(session_factory, behaviour, failure):
    def compile(job):
        if isinstance(behaviour, BaseException):
            raise behaviour
        return behaviour

    session, _ = session_factory(ScriptedIsolationRuntime(compile=compile))
    with pytest.raises(AegisError) as info:
        compile_a(session)
    assert info.value.code is ErrorCode.SANDBOX_FAILED
    assert info.value.details["failure"] == failure
    assert session.failed
    with pytest.raises(AegisError) as info:
        session.compile(
            ID_B, candidate(CANDIDATE_B), translation_units=["candidate.c"], flags=FLAGS,
            limits=compile_limits(),
        )
    assert _reason(info) == "session_failed"


def test_mutated_invalid_observation_is_a_protocol_violation(session_factory):
    def compile(job):
        obs = CompileObservation(status="exited", exit_code=0, duration_ms=1)
        obs.status = "signaled"  # inconsistent: no signal set
        return obs

    session, _ = session_factory(ScriptedIsolationRuntime(compile=compile))
    with pytest.raises(AegisError) as info:
        compile_a(session)
    assert info.value.details["failure"] == "protocol_violation"


def test_keyboard_interrupt_propagates_and_poisons(session_factory):
    def compile(job):
        raise KeyboardInterrupt

    session, _ = session_factory(ScriptedIsolationRuntime(compile=compile))
    with pytest.raises(KeyboardInterrupt):
        compile_a(session)
    assert session.failed


def test_candidate_outcomes_are_observations_not_errors(session_factory):
    outcomes = [
        ExecuteObservation(status="signaled", signal=11, duration_ms=1),
        ExecuteObservation(status="timeout", duration_ms=2000),
        ExecuteObservation(status="limit_exceeded", limit="memory", duration_ms=5),
        ExecuteObservation(status="exited", exit_code=3, duration_ms=1, stdout_truncated=True),
    ]
    queue = list(outcomes)
    session, _ = session_factory(
        ScriptedIsolationRuntime(execute=lambda job: queue.pop(0)), max_executions_per_candidate=4
    )
    binary = compile_a(session).binary
    statuses = [session.execute(ID_A, binary, args=[], limits=execute_limits()).observation.status for _ in outcomes]
    assert statuses == ["signaled", "timeout", "limit_exceeded", "exited"]
    assert not session.failed


@pytest.mark.parametrize(
    "fields",
    [
        {"status": "exited"},
        {"status": "exited", "exit_code": 0, "signal": 9},
        {"status": "signaled"},
        {"status": "limit_exceeded"},
        {"status": "timeout", "limit": "cpu"},
        {"status": "exited", "exit_code": 256},
    ],
)
def test_observation_exit_fields_are_consistent(fields):
    with pytest.raises(ValidationError):
        ExecuteObservation(duration_ms=1, **fields)


def test_observation_binary_and_limit_rules():
    with pytest.raises(ValidationError):
        CompileObservation(status="exited", exit_code=1, duration_ms=1, binary=b"x")
    with pytest.raises(ValidationError):
        CompileObservation(status="exited", exit_code=0, duration_ms=1, binary=b"")
    with pytest.raises(ValidationError):
        ExecuteObservation(status="limit_exceeded", limit="binary", duration_ms=1)
    CompileObservation(status="limit_exceeded", limit="binary", duration_ms=1)


def test_sandbox_failure_codes_match_registered_set():
    with pytest.raises(AssertionError):
        sandbox_failure("made_up", "x")
    assert {sandbox_failure(f, "m").details["failure"] for f in SANDBOX_FAILURES} == SANDBOX_FAILURES


# ------------------------------------------------------------------- close


def test_close_is_idempotent_and_ends_the_session(session_factory):
    session, runtime = session_factory()
    with session:
        compile_a(session)
    assert session.closed and runtime.closed == 1
    session.close()
    assert runtime.closed == 1
    with pytest.raises(AegisError) as info:
        compile_a(session)
    assert _reason(info) == "session_closed"


@pytest.mark.parametrize("error", [RuntimeError("leak"), sandbox_failure("cleanup_failed", "populated")])
def test_cleanup_failure_is_reported_and_poisons(session_factory, error):
    session, _ = session_factory(ScriptedIsolationRuntime(close_error=error))
    with pytest.raises(AegisError) as info:
        session.close()
    assert info.value.code is ErrorCode.SANDBOX_FAILED
    assert info.value.details["failure"] == "cleanup_failed"
    assert session.failed and session.closed


def test_session_cleanup_can_be_retried_after_failure(session_factory):
    runtime = ScriptedIsolationRuntime(close_error=RuntimeError("temporary failure"))
    session, _ = session_factory(runtime)
    with pytest.raises(AegisError):
        session.close()
    runtime._close_error = None
    session.close()
    assert runtime.closed == 2 and session.failed and session.closed
    session.close()
    assert runtime.closed == 2


def test_session_enforces_a_private_copy_of_the_grant(lab_config, make_grant, bindings, clock):
    grant = bind_bundle(make_grant())
    session = open_session(
        lab_config(), grant, lab_bindings=bindings, runtime=ScriptedIsolationRuntime(), clock=clock
    )
    digest = session.grant_sha256
    grant.max_compilations_per_candidate = 16  # mutate the caller's object
    session.grant.max_compilations_per_candidate = 16  # and the returned copy
    compile_a(session)
    with pytest.raises(AegisError) as info:
        compile_a(session)
    assert _reason(info) == "compilation_budget_exhausted"
    assert session.grant_sha256 == digest
    assert session.grant.max_compilations_per_candidate == 1


# ------------------------------------------------- translation-unit contract

CANDIDATE_UNIT = SourceFile(
    name="aegis_candidate_unit.c",
    data=b'#include <stdint.h>\nuint32_t aegis_f(uint32_t);\n#include "candidate.c"\n',
)


def test_lab_layout_compiles_only_the_selected_units(session_factory):
    """The Lab's unit includes candidate.c: candidate.c is staged but never compiled itself."""
    session, runtime = session_factory(
        bundle_files={"candidate.c": CANDIDATE_A, HARNESS.name: HARNESS.data, CANDIDATE_UNIT.name: CANDIDATE_UNIT.data},
        bundle_units=[HARNESS.name, CANDIDATE_UNIT.name])
    result = compile_a(
        session,
        support_files=[HARNESS, CANDIDATE_UNIT],
        translation_units=[HARNESS.name, CANDIDATE_UNIT.name],
    )
    [job] = runtime.compile_jobs
    assert job.translation_units == ["aegis_harness.c", "aegis_candidate_unit.c"]
    assert job.compiler_arguments() == [*FLAGS, "-o", "candidate", "aegis_harness.c", "aegis_candidate_unit.c"]
    assert "candidate.c" not in job.compiler_arguments()
    staged = {job.candidate.name, *(f.name for f in job.support_files)}
    assert staged == {"candidate.c", "aegis_harness.c", "aegis_candidate_unit.c"}
    record = result.record
    assert record.translation_units == ["aegis_harness.c", "aegis_candidate_unit.c"]
    # The candidate is still bound by digest even though it is only included.
    assert record.candidate_sha256 == hashlib.sha256(CANDIDATE_A).hexdigest()
    assert set(record.support_files_sha256) == {"aegis_harness.c", "aegis_candidate_unit.c"}


def test_translation_unit_order_is_preserved(session_factory):
    session, runtime = session_factory(bundle_units=[HARNESS.name, "candidate.c"])
    compile_a(session, translation_units=[HARNESS.name, "candidate.c"])
    assert runtime.compile_jobs[0].compiler_arguments()[-2:] == ["aegis_harness.c", "candidate.c"]


def test_execute_records_have_no_translation_units(session_factory):
    session, _ = session_factory()
    binary = compile_a(session).binary
    assert session.execute(ID_A, binary, args=[], limits=execute_limits()).translation_units == []


@pytest.mark.parametrize("change", ["support", "add", "remove", "rename", "order", "selection"])
def test_grant_binds_the_complete_named_compilation_bundle(session_factory, change):
    session, runtime = session_factory()
    source, support, units = candidate(), [HARNESS], list(UNITS)
    if change == "support":
        support = [SourceFile(name=HARNESS.name, data=HARNESS.data + b"/* changed */")]
    elif change == "add":
        support.append(SourceFile(name="extra.h", data=b"/* included support */"))
    elif change == "remove":
        support, units = [], ["candidate.c"]
    elif change == "rename":
        source, units = candidate(name="renamed.c"), ["renamed.c", HARNESS.name]
    elif change == "order":
        units.reverse()
    else:
        units = [HARNESS.name]
    with pytest.raises(AegisError) as info:
        compile_a(session, source=source, support_files=support, translation_units=units)
    assert _reason(info) == "compilation_bundle_mismatch"
    assert runtime.compile_jobs == [] and session.wall_ms_reserved == 0


def test_legacy_grant_permits_only_candidate_c_alone(lab_config, make_grant, bindings, clock):
    runtime = ScriptedIsolationRuntime()
    with open_session(lab_config(), make_grant(), lab_bindings=bindings, runtime=runtime, clock=clock) as session:
        with pytest.raises(AegisError) as info:
            compile_a(session)
        assert _reason(info) == "compilation_bundle_required"
        assert runtime.compile_jobs == [] and session.wall_ms_reserved == 0
        result = session.compile(ID_A, candidate(), translation_units=["candidate.c"], flags=FLAGS, limits=compile_limits())
        assert result.binary is not None


def test_bundle_digest_is_independent_of_file_order_and_binds_unit_order():
    from aegis_core.lab_authorization import compilation_bundle_sha256

    files = {"candidate.c": CANDIDATE_A, HARNESS.name: HARNESS.data}
    digest = compilation_bundle_sha256(files, UNITS)
    assert digest == compilation_bundle_sha256(dict(reversed(list(files.items()))), UNITS)
    assert digest != compilation_bundle_sha256(files, list(reversed(UNITS)))


@pytest.mark.parametrize("stage", ["compile", "execute"])
def test_mutated_invalid_stage_limits_refuse_before_reserving_budget(session_factory, stage):
    session, runtime = session_factory()
    limits = compile_limits() if stage == "compile" else execute_limits()
    limits.cpu_ms = -1
    binary = compile_a(session).binary if stage == "execute" else None
    reserved = session.wall_ms_reserved
    with pytest.raises(AegisError) as info:
        if stage == "compile":
            compile_a(session, limits=limits)
        else:
            session.execute(ID_A, binary, args=[], limits=limits)
    assert info.value.code is ErrorCode.INVALID_REQUEST
    assert session.wall_ms_reserved == reserved and runtime.execute_jobs == []


@pytest.mark.parametrize("args", ["123", None, {"1": "2"}])
def test_argument_containers_are_strict(session_factory, args):
    session, runtime = session_factory()
    binary = compile_a(session).binary
    with pytest.raises(AegisError) as info:
        session.execute(ID_A, binary, args=args, limits=execute_limits())
    assert info.value.code is ErrorCode.INVALID_REQUEST
    assert session.executions_used(ID_A) == 0 and runtime.execute_jobs == []


HEADER = SourceFile(name="aegis_abi.h", data=b"#pragma once\n")


@pytest.mark.parametrize(
    "units",
    [
        [],
        ["candidate.c", "candidate.c"],
        ["missing.c"],
        ["aegis_abi.h"],
        ["../candidate.c"],
        ["/tmp/candidate.c"],
        "candidate.c",  # a string, not a list of names
        None,
        [7],
        [f"u{i}.c" for i in range(17)],
    ],
)
def test_invalid_translation_unit_selection_is_rejected_before_anything_runs(session_factory, units):
    session, runtime = session_factory()
    with pytest.raises(AegisError) as info:
        compile_a(session, support_files=[HARNESS, HEADER], translation_units=units)
    assert info.value.code is ErrorCode.INVALID_REQUEST
    assert runtime.compile_jobs == []
    # A rejected request reserves no budget.
    assert session.compilations_used(ID_A) == 0 and session.wall_ms_reserved == 0


def test_compile_job_itself_enforces_the_selection():
    limits = compile_limits()
    ok = {"candidate": candidate(), "support_files": [HARNESS], "flags": FLAGS, "limits": limits}
    from aegis_core.lab_execution import CompileJob

    CompileJob(translation_units=["candidate.c"], **ok)
    for bad in ([], ["x.c"], ["candidate.c", "candidate.c"]):
        with pytest.raises((ValidationError, AegisError)):
            CompileJob(translation_units=bad, **ok)


# ------------------------------------------------ interrupted preflight cleanup


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
def test_interrupt_during_preflight_closes_the_runtime_and_propagates(session_factory, interrupt):
    runtime = ScriptedIsolationRuntime(preflight_error=interrupt())
    with pytest.raises(interrupt):
        session_factory(runtime)
    assert len(runtime.preflights) == 1
    assert runtime.closed == 1


def test_interrupt_after_preflight_during_session_construction_closes_the_runtime(session_factory, monkeypatch):
    from aegis_core import lab_execution

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(lab_execution.CandidateExecutionSession, "__init__", interrupted)
    runtime = ScriptedIsolationRuntime()
    with pytest.raises(KeyboardInterrupt):
        session_factory(runtime)
    assert runtime.closed == 1


def test_failing_close_does_not_mask_the_interrupt(session_factory):
    runtime = ScriptedIsolationRuntime(preflight_error=KeyboardInterrupt(), close_error=RuntimeError("leak"))
    with pytest.raises(KeyboardInterrupt):
        session_factory(runtime)
    assert runtime.closed == 1


def test_successful_open_does_not_close_the_runtime(session_factory):
    session, runtime = session_factory()
    assert runtime.closed == 0 and not session.closed
