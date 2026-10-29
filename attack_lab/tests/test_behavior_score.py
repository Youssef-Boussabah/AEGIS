"""Phase 4: single-trial behavioral scoring (aegis.lab.behavior-score.v1) through Core.

Execution goes through Core's real ``CandidateExecutionSession`` (gates, grant binding,
budgets, hashing). The runtime is Core's non-executing ``ScriptedIsolationRuntime``;
candidate behavior is a trusted Python model. Nothing is compiled or executed, and
records are labeled ``test_double``. The one real-runtime test shows Core refusing.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("aegis_core.lab_execution", reason="needs Role A's Core candidate-execution contract")

from aegis_core.lab_execution import CandidateExecutionSession  # noqa: E402
from aegis_core.lab_execution import ExecuteObservation as CoreExecute  # noqa: E402
from aegis_core.lab_execution import sandbox_failure  # noqa: E402
from pydantic import ValidationError  # noqa: E402
from scoring_fixtures import (  # noqa: E402
    ARGUMENTS,
    BASELINE_SOURCE,
    INTERFACE,
    MASK,
    attestation_for,
    core_config,
    experiment,
    grant,
    gvisor_policy,
    make_policy,
    reconstruction_bytes,
    reference,
    result_observation,
    scripted,
    suite_bytes,
)

from aegis_lab.behavior_score import (  # noqa: E402
    BehaviorScoreRecord,
    ScoringInputError,
    ScoringInterrupted,
    parse_behavior_score,
    prepare_scoring,
    score_trial,
)
from aegis_lab.canonical import canonical_sha256  # noqa: E402
from aegis_lab.fake_provider import FakeProvider  # noqa: E402
from aegis_lab.safe_io import LoadError  # noqa: E402
from aegis_lab.scoring_policy import ExecutionRefused  # noqa: E402
from aegis_lab.scoring_worker import CompileObservation, ExecuteObservation  # noqa: E402

EXPECTED = [reference(*a) for a in ARGUMENTS]


@pytest.fixture(scope="module")
def fx(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("score")
    data = experiment(tmp)
    data["config"] = core_config(tmp)
    return data


def prep(fx, variant="baseline", *, record=None, report=None, suite=None, policy=None):
    return prepare_scoring(fx["manifests"][variant],
                           reconstruction_bytes=reconstruction_bytes(fx, variant) if record is None else record,
                           evidence_bytes=fx["reports"][variant] if report is None else report,
                           suite_bytes=fx["suite"] if suite is None else suite, policy=policy or fx["policy"])


def run(fx, runtime=None, *, variant="baseline", the_grant=None, prepared=None, config=None,
        **kwargs) -> BehaviorScoreRecord:
    runtime = runtime if runtime is not None else scripted(behavior=reference)
    return score_trial(prepared or prep(fx, variant), config=config or fx["config"],
                       grant=the_grant or grant(fx), runtime=runtime, **kwargs)


def per_case(*observations):
    """An execute script returning these observations in order, then the reference result."""
    pending = list(observations)

    def script(job):
        if pending:
            item = pending.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        return result_observation(reference(*(int(v) for v in job.args)))
    return script


def roundtrip(record: BehaviorScoreRecord) -> BehaviorScoreRecord:
    again = parse_behavior_score(record.to_json_bytes())
    assert again == record
    return again


# --- Outcomes -------------------------------------------------------------------------------------

def test_matching_candidate_satisfies_the_criterion(fx):
    runtime = scripted(behavior=reference)
    record = roundtrip(run(fx, runtime))
    out = record.result.outcome
    assert (out.status, out.stop_reason, out.criterion_satisfied) == ("behavioral_match", "all_cases_evaluated", True)
    assert record.result.summary.matched_cases == record.result.summary.required_cases == len(ARGUMENTS)
    # Core's scripted runtime is a test double: never evidence, however the cases turned out.
    assert out.behaviorally_successful_reconstruction == "not_established"
    assert record.result.evidence.counts_as_behavioral_evidence is False
    assert set(record.result.evidence.reasons) == {"candidate_scripted_by_offline_fake_provider",
                                                   "worker_is_test_double_no_execution"}
    worker = record.result.worker
    assert (worker.kind, worker.core_contract, worker.limits_enforcement, worker.identity_observed) == (
        "test_double", "aegis.core.isolated-worker.v1", "not_enforced_test_double", False)
    assert runtime.closed == 1 and len(runtime.execute_jobs) == len(ARGUMENTS) and len(runtime.compile_jobs) == 1


def test_record_binds_the_core_grant_and_core_records(fx):
    the_grant = grant(fx)
    record = run(fx, the_grant=the_grant)
    from aegis_core.lab_authorization import grant_sha256

    g = record.result.grant
    assert (g.grant_id, g.grant_sha256, g.authorization_reference) == (
        the_grant.grant_id, grant_sha256(the_grant), fx["manifests"]["baseline"].authorization.reference)
    assert g.core_gates == "checked_by_core_before_every_stage" and g.grant_signed is False
    refs = record.run.core_records
    assert [r.stage for r in refs] == ["compile"] + ["execute"] * len(ARGUMENTS)
    assert [r.case_id for r in refs[1:]] == [c.case_id for c in record.result.cases]
    assert len({r.record_id for r in refs}) == len(refs) and record.run.core_session_id is not None


def test_one_wrong_case_fails_the_all_pass_criterion(fx):
    def nearly(a, b, c):
        return reference(a, b, c) ^ (1 if (a, b, c) == ARGUMENTS[5] else 0)
    record = roundtrip(run(fx, scripted(behavior=nearly)))
    assert record.result.outcome.status == "behavioral_mismatch"
    assert record.result.outcome.criterion_satisfied is False
    assert [c.classification for c in record.result.cases].count("mismatch") == 1
    assert record.result.cases[5].classification == "mismatch"


@pytest.mark.parametrize("observation,classification,field,value", [
    (ExecuteObservation(status="signaled", signal=11), "runtime_crash", "signal", 11),
    (ExecuteObservation(status="exited", exit_code=3), "runtime_crash", "exit_code", 3),
    (ExecuteObservation(status="exited", exit_code=125), "runtime_crash", "exit_code", 125),
    (ExecuteObservation(status="timeout"), "timeout", None, None),
    (ExecuteObservation(status="limit_exceeded", limit="memory"), "resource_limit_exceeded", "limit", "memory"),
    (ExecuteObservation(status="limit_exceeded", limit="processes"), "resource_limit_exceeded", "limit",
     "processes"),
    (ExecuteObservation(status="exited", exit_code=0, stdout=b"42\n"), "malformed_output", "detail",
     "result_line_invalid"),
    (ExecuteObservation(status="exited", exit_code=0, stdout=b""), "malformed_output", "detail",
     "result_line_invalid"),
    (ExecuteObservation(status="exited", exit_code=0, stdout=b"AEGIS-RESULT 1\nAEGIS-RESULT 2\n"),
     "malformed_output", "detail", "result_line_invalid"),
    (ExecuteObservation(status="exited", exit_code=0, stdout=b"AEGIS-RESULT 1\n", stdout_truncated=True),
     "malformed_output", "detail", "stdout_truncated"),
])
def test_candidate_case_classifications(fx, observation, classification, field, value):
    record = roundtrip(run(fx, scripted(execute=per_case(observation))))
    first = record.result.cases[0]
    assert first.classification == classification
    if field:
        assert getattr(first, field) == value
    # A candidate failure is still a completed evaluation: the run continues to the end.
    assert record.result.outcome.stop_reason == "all_cases_evaluated"
    assert record.result.outcome.status == "behavioral_mismatch"
    assert record.result.summary.evaluated_cases == len(ARGUMENTS)


@pytest.mark.parametrize("failure,code", [
    (sandbox_failure("sandbox_failed", "x"), "sandbox_failed"),
    (sandbox_failure("resource_enforcement_failed", "x"), "resource_enforcement_failed"),
    (sandbox_failure("protocol_violation", "x"), "worker_contract_violation"),
    (RuntimeError("boom"), "sandbox_failed"),
    (ExecuteObservation(status="exited", exit_code=0, stdout=b"x" * 4097), "worker_contract_violation"),
    (ExecuteObservation(status="exited", exit_code=0, stderr_bytes=65537), "worker_contract_violation"),
    ("not an observation", "worker_contract_violation"),
    (CoreExecute.model_construct(status="exited", exit_code=None, signal=None, limit=None, stdout=b"",
                                 stdout_truncated=False, stderr=b"", stderr_truncated=False, duration_ms=1,
                                 cpu_ms=None, peak_memory_bytes=None), "worker_contract_violation"),
])
def test_infrastructure_failure_stops_the_run_and_is_not_a_candidate_result(fx, failure, code):
    runtime = scripted(execute=per_case(result_observation(EXPECTED[0]), result_observation(EXPECTED[1]), failure))
    record = roundtrip(run(fx, runtime))
    classes = [c.classification for c in record.result.cases]
    assert classes[:3] == ["match", "match", "infrastructure_failure"]
    assert set(classes[3:]) == {"not_evaluated"}
    assert record.result.cases[2].infrastructure_code == code
    out = record.result.outcome
    assert (out.status, out.stop_reason, out.criterion_satisfied) == ("infrastructure_failure", "worker_failure",
                                                                      False)
    assert "outcome_not_attributable_to_candidate" in record.result.evidence.reasons
    assert len(runtime.execute_jobs) == 3 and runtime.closed == 1
    assert record.run.case_seconds[3:] == (None,) * (len(ARGUMENTS) - 3)


# --- Compilation ---------------------------------------------------------------------------------

@pytest.mark.parametrize("observation,status,field,value", [
    (CompileObservation(status="exited", exit_code=1, diagnostics=b"error: conflicting types"), "failed",
     "exit_code", 1),
    (CompileObservation(status="signaled", signal=9), "failed", "signal", 9),
    (CompileObservation(status="timeout"), "timeout", None, None),
    (CompileObservation(status="limit_exceeded", limit="memory"), "resource_limit_exceeded", "limit", "memory"),
    (CompileObservation(status="limit_exceeded", limit="binary"), "resource_limit_exceeded", "limit", "binary"),
])
def test_compilation_failures_are_candidate_outcomes(fx, observation, status, field, value):
    runtime = scripted(behavior=reference, compile=observation)
    record = roundtrip(run(fx, runtime))
    compilation = record.result.compilation
    assert compilation.status == status
    if field:
        assert getattr(compilation, field) == value
    assert (record.result.outcome.status, record.result.outcome.stop_reason) == ("compilation_failed",
                                                                                 "compilation_failed")
    assert {c.classification for c in record.result.cases} == {"not_evaluated"}
    assert runtime.execute_jobs == []
    assert "outcome_not_attributable_to_candidate" not in record.result.evidence.reasons


def test_compiler_diagnostics_are_bounded_and_kept_only_as_valid_text(fx):
    record = run(fx, scripted(compile=CompileObservation(status="exited", exit_code=1, diagnostics=b"bad\xff")))
    diag = record.result.compilation.diagnostics
    assert diag.text is None and diag.withheld == "invalid_text" and diag.byte_count == 4
    assert diag.sha256 == hashlib.sha256(b"bad\xff").hexdigest()
    record = run(fx, scripted(compile=CompileObservation(status="exited", exit_code=1, diagnostics=b"e" * 20000)))
    assert record.result.compilation.diagnostics.withheld == "too_large"
    record = run(fx, scripted(compile=CompileObservation(status="exited", exit_code=1,
                                                         diagnostics=b"x.c:1: error\n")))
    assert record.result.compilation.diagnostics.text == "x.c:1: error\n"


@pytest.mark.parametrize("compile_result,code", [
    (sandbox_failure("sandbox_start_failed", "x"), "sandbox_start_failed"),
    (CompileObservation(status="exited", exit_code=0), "binary_missing"),
    (CompileObservation(status="exited", exit_code=0, binary=b""), "sandbox_failed"),
    (CompileObservation(status="exited", exit_code=0, binary=b"x" * (8 * 2**20 + 1)), "worker_contract_violation"),
    (CompileObservation(status="exited", exit_code=1, diagnostics=b"d" * 65537), "worker_contract_violation"),
    (ValueError("worker bug"), "sandbox_failed"),
])
def test_compilation_infrastructure_failures(fx, compile_result, code):
    def compile_script(job):
        if isinstance(compile_result, BaseException):
            raise compile_result
        return compile_result
    runtime = scripted(behavior=reference, compile=compile_script)
    record = roundtrip(run(fx, runtime))
    assert record.result.compilation.status == "infrastructure_failure"
    assert record.result.compilation.infrastructure_code == code
    assert (record.result.outcome.status, record.result.outcome.stop_reason) == ("infrastructure_failure",
                                                                                 "worker_failure")
    assert runtime.execute_jobs == []


# --- Runtime preflight and cleanup ----------------------------------------------------------------

def test_runtime_start_failure_is_recorded_as_infrastructure(fx):
    runtime = scripted(behavior=reference, preflight_error=sandbox_failure("sandbox_start_failed", "x"))
    record = roundtrip(run(fx, runtime))
    assert record.result.worker.preflight == "failed"
    assert record.result.worker.preflight_code == "sandbox_start_failed"
    assert record.result.outcome.stop_reason == "worker_preflight_failed"
    assert record.result.outcome.status == "infrastructure_failure"
    assert runtime.compile_jobs == [] and runtime.execute_jobs == []
    assert record.result.compilation is None and record.run.core_session_id is None


def test_failing_preflight_is_refused_by_core(fx):
    runtime = scripted(behavior=reference, preflight_error=OSError("no runtime"))
    with pytest.raises(ExecutionRefused) as caught:
        run(fx, runtime)
    assert (caught.value.code, caught.value.reasons) == ("sandbox_unavailable", ("runtime_preflight_failed",))
    assert runtime.compile_jobs == []


@pytest.mark.parametrize("changes,code", [
    ({"compiler_version": "15.0.0"}, "compiler_identity_mismatch"),
    ({"compiler_sha256": "0" * 64}, "compiler_identity_mismatch"),
    ({"compiler_name": "clang"}, "compiler_identity_mismatch"),
    ({"runtime_version": "2"}, "runtime_mismatch"),
])
def test_attestation_must_match_the_policy(fx, changes, code):
    runtime = scripted(behavior=reference, attestation=attestation_for(fx["policy"], **changes))
    record = run(fx, runtime)
    assert (record.result.worker.preflight, record.result.worker.preflight_code) == ("failed", code)
    assert runtime.compile_jobs == [] and runtime.closed == 1


def test_injected_runtime_cannot_claim_isolation(fx):
    claimed = attestation_for(fx["policy"], runtime="gvisor-runsc", runtime_sha256="1" * 64, platform="systrap",
                              rootless=True, rootfs_sha256="2" * 64,
                              limits_enforcement="verified_by_cgroup_readback", isolation_verified=True)
    runtime = scripted(behavior=reference, attestation=claimed)
    with pytest.raises(ExecutionRefused) as caught:
        run(fx, runtime)
    assert caught.value.code == "injected_runtime_not_test_double"
    assert runtime.compile_jobs == [] and runtime.closed == 1


def test_cleanup_failure_overrides_a_complete_match(fx):
    runtime = scripted(behavior=reference, close_error=RuntimeError("scope still populated"))
    record = roundtrip(run(fx, runtime))
    assert record.result.summary.matched_cases == len(ARGUMENTS)
    assert record.result.worker.cleanup == "failed"
    out = record.result.outcome
    assert (out.status, out.stop_reason, out.criterion_satisfied) == ("infrastructure_failure",
                                                                      "worker_cleanup_failed", False)


def test_cleanup_failure_after_compile_failure(fx):
    runtime = scripted(compile=CompileObservation(status="exited", exit_code=1), close_error=RuntimeError("leak"))
    record = roundtrip(run(fx, runtime))
    assert record.result.outcome.stop_reason == "worker_cleanup_failed"
    assert record.result.outcome.status == "infrastructure_failure"


# --- Partial runs ----------------------------------------------------------------------------------

def test_scoring_deadline_leaves_remaining_cases_unevaluated(fx):
    clock = iter([0.0, 0.0, 0.1, 0.1, 0.2, 0.2, 0.3, 700.0] + [700.0] * 50)
    record = roundtrip(run(fx, scripted(behavior=reference), monotonic=lambda: next(clock)))
    classes = [c.classification for c in record.result.cases]
    assert classes[0] == "match" and "not_evaluated" in classes
    out = record.result.outcome
    assert (out.status, out.stop_reason, out.criterion_satisfied) == ("incomplete", "scoring_deadline_exceeded",
                                                                      False)


def test_core_refusal_mid_run_is_incomplete_not_a_result(fx):
    base = datetime.now(UTC)
    state = {"now": base}
    the_grant = grant(fx, now=base)

    def advance(job):
        if len(runtime.execute_jobs) == 3:
            state["now"] = base + timedelta(days=1, minutes=1)  # past the grant window
        return result_observation(reference(*(int(a) for a in job.args)))
    runtime = scripted(execute=advance)
    record = roundtrip(run(fx, runtime, the_grant=the_grant, now=lambda: state["now"]))
    out = record.result.outcome
    assert (out.status, out.stop_reason, out.refusal_reason) == ("incomplete", "core_refused", "grant_expired")
    classes = [c.classification for c in record.result.cases]
    assert classes[:3] == ["match"] * 3 and set(classes[3:]) == {"not_evaluated"}
    assert len(runtime.execute_jobs) == 3


def test_interruption_during_a_case_publishes_a_partial_record(fx):
    runtime = scripted(execute=per_case(result_observation(EXPECTED[0]), KeyboardInterrupt()))
    with pytest.raises(ScoringInterrupted) as caught:
        run(fx, runtime)
    record = roundtrip(caught.value.record)
    classes = [c.classification for c in record.result.cases]
    assert classes[0] == "match" and set(classes[1:]) == {"not_evaluated"}
    assert (record.result.outcome.status, record.result.outcome.stop_reason) == ("incomplete", "interrupted")
    assert runtime.closed == 1 and record.result.worker.cleanup == "completed"


def test_interruption_during_compilation(fx):
    def interrupt(job):
        raise KeyboardInterrupt
    runtime = scripted(compile=interrupt)
    with pytest.raises(ScoringInterrupted) as caught:
        run(fx, runtime)
    record = roundtrip(caught.value.record)
    assert record.result.compilation is None and runtime.closed == 1
    assert record.result.outcome.stop_reason == "interrupted"


def test_interruption_during_core_preflight_propagates_before_any_record(fx):
    runtime = scripted(preflight_error=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        run(fx, runtime)
    # Core releases the runtime before the interruption propagates; nothing was compiled.
    assert runtime.compile_jobs == [] and runtime.closed == 1


def test_interrupted_run_with_failed_cleanup_is_infrastructure_failure(fx):
    runtime = scripted(execute=per_case(KeyboardInterrupt()), close_error=RuntimeError("leak"))
    with pytest.raises(ScoringInterrupted) as caught:
        run(fx, runtime)
    record = roundtrip(caught.value.record)
    assert (record.result.outcome.status, record.result.outcome.stop_reason) == ("infrastructure_failure",
                                                                                 "interrupted")


# --- Not evaluated ---------------------------------------------------------------------------------

def test_no_candidate_is_not_evaluated_and_never_reaches_core(tmp_path):
    fx = experiment(tmp_path, providers=(FakeProvider(source="int x;"), FakeProvider(content="not json")))
    record = roundtrip(score_trial(prep(fx, "protected"), config=None, grant=None, runtime=None))
    out = record.result.outcome
    assert (out.status, out.stop_reason) == ("not_evaluated", "no_candidate")
    assert record.result.trial.candidate_origin == "none"
    assert record.result.trial.reconstruction.status == "invalid_candidate"
    assert {c.classification for c in record.result.cases} == {"not_evaluated"}
    assert record.result.grant is None and record.result.worker.kind == "none"


def test_missing_reconstruction_record_is_not_evaluated(fx):
    prepared = prepare_scoring(fx["manifests"]["baseline"], reconstruction_bytes=None,
                               evidence_bytes=fx["reports"]["baseline"], suite_bytes=fx["suite"], policy=fx["policy"])
    record = roundtrip(score_trial(prepared, config=None, grant=None))
    assert record.result.trial.reconstruction is None and record.result.outcome.status == "not_evaluated"
    assert record.result.interface.symbol is None


@pytest.mark.parametrize("interface,status,code", [
    ("pixel(int, int)->int", "unsupported", "unsupported_return_type"),
    ("pixel(uint32_t*)->uint32_t", "unsupported", "unsupported_parameter_type"),
    ("opaque(int,int)->int", "unsupported", "unsupported_return_type"),
])
def test_unsupported_interface_is_classified_before_anything_runs(tmp_path, interface, status, code):
    suite = b'{"opaque": "suite for an interface the ABI cannot express"}\n'
    fx = experiment(tmp_path, interface=interface, suite=suite)
    record = roundtrip(score_trial(prep(fx), config=None, grant=None))
    assert (record.result.interface.status, record.result.interface.code) == (status, code)
    assert record.result.outcome.status == "unsupported_interface"
    assert record.result.suite.parsed is False and record.result.cases == ()
    assert record.result.outcome.criterion_satisfied is False


# --- Input validation (nothing runs) --------------------------------------------------------------

def edited_record(fx, variant, mutate) -> bytes:
    doc = json.loads(reconstruction_bytes(fx, variant))
    mutate(doc)
    return json.dumps(doc).encode()


def test_tampered_candidate_source_is_rejected(fx):
    def mutate(doc):
        doc["candidate"]["source"] += "/* edited */"
    with pytest.raises(ScoringInputError) as caught:
        prep(fx, record=edited_record(fx, "baseline", mutate))
    assert any(i.startswith("reconstruction: candidate") for i in caught.value.issues)


def test_candidate_digest_tampering_is_rejected(fx):
    def mutate(doc):
        doc["candidate"]["sha256"] = "0" * 64
    with pytest.raises(ScoringInputError):
        prep(fx, record=edited_record(fx, "baseline", mutate))


def test_record_from_the_other_trial_is_rejected(fx):
    with pytest.raises(ScoringInputError) as caught:
        prep(fx, "baseline", record=reconstruction_bytes(fx, "protected"))
    assert {"reconstruction: trial_id: mismatch", "reconstruction: variant: mismatch",
            "reconstruction: inputs.artifact_sha256: mismatch"} <= set(caught.value.issues)


def test_swapped_evidence_is_rejected(fx):
    with pytest.raises(ScoringInputError) as caught:
        prep(fx, "baseline", report=fx["reports"]["protected"])
    assert any(i.startswith("evidence: binding: binary.sha256") for i in caught.value.issues)


def test_hidden_suite_digest_must_match_the_manifest(fx):
    other = suite_bytes(arguments=ARGUMENTS[:-1])
    with pytest.raises(ScoringInputError) as caught:
        prep(fx, suite=other)
    assert caught.value.issues == ["suite: hidden_test_suite_sha256: mismatch"]
    with pytest.raises(ScoringInputError):
        prep(fx, suite=fx["suite"] + b" ")


def test_scorer_identity_must_match_the_policy(fx):
    with pytest.raises(ScoringInputError) as caught:
        prep(fx, policy=make_policy(**{"execute.wall_ms": 1234}))
    assert caught.value.issues == ["manifest: scoring.scorer.configuration_sha256: mismatch"]


def test_suite_bound_to_the_manifest_must_also_be_valid_and_fit_the_policy(tmp_path):
    other_interface = "pixel(uint32_t, uint32_t, uint32_t, uint32_t)->uint32_t"
    wrong = suite_bytes(interface=other_interface, arguments=[(1, 2, 3, 4)], function=lambda *a: sum(a))
    fx = experiment(tmp_path / "a", suite=wrong)
    with pytest.raises(ScoringInputError) as caught:
        prep(fx)
    assert caught.value.issues == ["suite: interface: mismatch"]
    small = make_policy(max_cases=4)
    fx = experiment(tmp_path / "b", policy=small)
    with pytest.raises(ScoringInputError) as caught:
        prep(fx)
    assert caught.value.issues == ["suite: cases: exceeds_policy_max_cases"]
    broken = b'{"schema_version": "aegis.lab.hidden-suite.v1", "cases": []}'
    fx = experiment(tmp_path / "c", suite=broken)
    with pytest.raises(ScoringInputError) as caught:
        prep(fx)
    assert all(i.startswith("suite: ") for i in caught.value.issues)


# --- Grant binding (Lab) and Core's decision ------------------------------------------------------

def other_target(fx):
    return fx["manifests"]["protected"].target.final_artifact_sha256


@pytest.mark.parametrize("make,code,reasons", [
    (lambda fx: grant(fx, **{"candidates.0.candidate_sha256": "0" * 64}), "grant_candidate_mismatch", ()),
    (lambda fx: grant(fx, variants=("protected",)), "grant_candidate_not_listed", ()),
    (lambda fx: grant(fx, **{"authorization.reference": "UNRELATED-REF"}), "grant_reference_mismatch", ()),
    (lambda fx: grant(fx, **{"lab_bindings.hidden_test_suite_sha256": "0" * 64}), "grant_lab_bindings_mismatch",
     ("hidden_test_suite_sha256",)),
    (lambda fx: grant(fx, **{"lab_bindings.sandbox_policy_sha256": "0" * 64}), "grant_lab_bindings_mismatch",
     ("sandbox_policy_sha256",)),
    (lambda fx: grant(fx, **{"lab_bindings.pair_id": "e" * 32}), "grant_lab_bindings_mismatch", ("pair_id",)),
    (lambda fx: grant(fx, variants=("baseline",), **{"candidates.0.target_sha256": other_target(fx),
                                                     "permitted_targets": [other_target(fx)]}),
     "grant_target_mismatch", ()),
    (lambda fx: grant(fx, compile_flags=["-std=c11", "-O2", "-static"]), "grant_flags_mismatch", ()),
    (lambda fx: grant(fx, **{"execute_limits.cpu_ms": 500}), "grant_limits_mismatch", ()),
    (lambda fx: grant(fx, **{"compile_limits.memory_bytes": 256 * 2**20}), "grant_limits_mismatch", ()),
    (lambda fx: grant(fx, stages=["compile"], execute_limits=None, max_executions_per_candidate=0),
     "grant_stages_insufficient", ()),
    (lambda fx: grant(fx, max_executions_per_candidate=len(ARGUMENTS) - 1), "grant_budget_insufficient",
     ("max_executions_per_candidate",)),
    (lambda fx: grant(fx, max_total_wall_ms=10_000), "grant_budget_insufficient", ("max_total_wall_ms",)),
])
def test_grant_must_describe_the_lab_inputs(fx, make, code, reasons):
    runtime = scripted(behavior=reference)
    with pytest.raises(ExecutionRefused) as caught:
        run(fx, runtime, the_grant=make(fx))
    assert (caught.value.code, caught.value.reasons) == (code, reasons)
    assert runtime.preflights == [] and runtime.compile_jobs == []


def test_missing_grant_is_refused(fx):
    with pytest.raises(ExecutionRefused) as caught:
        score_trial(prep(fx), config=fx["config"], grant=None, runtime=scripted(behavior=reference))
    assert caught.value.code == "grant_missing"


@pytest.mark.parametrize("config_kwargs,reason", [
    ({"attack_lab": False}, "attack_lab_disabled"),
    ({"candidate_execution": False}, "candidate_execution_disabled"),
])
def test_core_gates_refuse(fx, tmp_path, config_kwargs, reason):
    runtime = scripted(behavior=reference)
    with pytest.raises(ExecutionRefused) as caught:
        run(fx, runtime, config=core_config(tmp_path, **config_kwargs))
    assert (caught.value.code, caught.value.reasons) == ("core_refused", (reason,))
    assert runtime.preflights == []


def test_expired_grant_is_refused_by_core(fx):
    old = datetime.now(UTC) - timedelta(days=3)
    with pytest.raises(ExecutionRefused) as caught:
        run(fx, the_grant=grant(fx, now=old))
    assert caught.value.code == "core_refused"
    assert caught.value.reasons[0] in ("authorization_expired", "grant_expired")


def test_operator_ceiling_is_enforced_by_core(fx, tmp_path):
    from aegis_core.config import config_from_mapping

    ceiling = {"wall_ms": 1000, "cpu_ms": 1000, "memory_bytes": 32 * 2**20, "max_processes": 1,
               "scratch_bytes": 2**20, "stdout_bytes": 4096, "stderr_bytes": 4096}
    config = config_from_mapping({"attack_lab": {"enabled": True, "candidate_execution": {
        "enabled": True, "execute_ceiling": ceiling}}}, base_dir=tmp_path)
    with pytest.raises(ExecutionRefused) as caught:
        run(fx, config=config)
    assert (caught.value.code, caught.value.reasons) == ("core_refused", ("grant_exceeds_operator_ceiling",))


def test_cores_configured_runtime_refuses_real_execution(fx):
    # runtime=None: Core's configured runtime. No isolation runtime exists in this revision.
    with pytest.raises(ExecutionRefused) as caught:
        score_trial(prep(fx), config=fx["config"], grant=grant(fx), runtime=None)
    assert caught.value.code == "sandbox_unavailable"
    assert {"isolation_adr_not_accepted", "isolated_runtime_not_implemented"} <= set(caught.value.reasons)


def test_isolated_policy_with_a_test_double_runtime_fails_preflight(tmp_path):
    fx = experiment(tmp_path, policy=gvisor_policy())
    fx["config"] = core_config(tmp_path)
    runtime = scripted(behavior=reference)
    record = run(fx, runtime)
    assert (record.result.worker.preflight, record.result.worker.preflight_code) == ("failed", "runtime_mismatch")
    assert runtime.compile_jobs == []
    with pytest.raises(ExecutionRefused) as caught:
        score_trial(prep(fx), config=fx["config"], grant=grant(fx), runtime=None)
    assert caught.value.code == "sandbox_unavailable"


def test_core_record_that_does_not_match_the_request_fails_closed(fx, monkeypatch):
    original = CandidateExecutionSession.execute

    def tampered(self, *args, **kwargs):
        record = original(self, *args, **kwargs)
        return record.model_copy(update={"args": ["1", "2", "3"]})
    monkeypatch.setattr(CandidateExecutionSession, "execute", tampered)
    record = run(fx, scripted(behavior=reference))
    assert record.result.cases[0].classification == "infrastructure_failure"
    assert record.result.cases[0].infrastructure_code == "core_record_mismatch"


# --- Confidentiality --------------------------------------------------------------------------------

def test_runtime_never_receives_expected_values_or_the_suite(fx):
    runtime = scripted(behavior=reference)
    record = run(fx, runtime)
    (job,) = runtime.compile_jobs
    assert job.candidate.name == "candidate.c"
    assert [f.name for f in job.support_files] == ["aegis_harness.c", "aegis_candidate_unit.c"]
    assert job.flags == ["-std=c11", "-O1", "-static"] and job.output_name == "candidate"
    sent = job.candidate.data + b"".join(f.data for f in job.support_files) + b"\0".join(
        a.encode() for j in runtime.execute_jobs for a in j.args)
    for executed, arguments in zip(runtime.execute_jobs, ARGUMENTS):
        assert executed.args == [str(v) for v in arguments]
        assert executed.binary == runtime.execute_jobs[0].binary
    distinctive = [str(v) for v in EXPECTED if all(str(v) != str(a) for args in ARGUMENTS for a in args)]
    assert len(distinctive) >= 6
    for value in distinctive:
        assert value.encode() not in sent
    assert fx["suite"] not in sent
    assert hashlib.sha256(fx["suite"]).hexdigest().encode() not in sent
    text = record.to_json_bytes()
    for value in distinctive:
        assert f": {value}".encode() not in text and f"[{value}".encode() not in text


def test_record_holds_no_case_inputs_or_expected_values(fx):
    record = run(fx, scripted(behavior=reference))
    for case in json.loads(record.to_json_bytes())["result"]["cases"]:
        assert set(case) == {"case_id", "classification", "exit_code", "signal", "limit", "infrastructure_code",
                             "detail", "stdout_bytes", "stderr_bytes"}


def test_unblinded_run_calls_the_declared_function_name(tmp_path):
    source = BASELINE_SOURCE.replace("target_function", "secret_add")
    fx = experiment(tmp_path, baseline_source=source, protected_source=source,
                    both={"access.access_to_symbols": True})
    fx["config"] = core_config(tmp_path)
    runtime = scripted(behavior=reference)
    record = run(fx, runtime)
    assert record.result.interface.symbol == "secret_add"
    harness = {f.name: f.data for f in runtime.compile_jobs[0].support_files}["aegis_harness.c"]
    assert b'__asm__("secret_add")' in harness
    assert record.result.outcome.status == "behavioral_match"


# --- Determinism and record integrity -----------------------------------------------------------

def test_scoring_is_deterministic(fx, tmp_path):
    # One reviewed grant, two logically independent scorings: each gets its own store, so Core's
    # grant-wide ledger is neither shared nor reset between them.
    the_grant = grant(fx)
    first = run(fx, scripted(behavior=reference), the_grant=the_grant, config=core_config(tmp_path / "one"))
    second = run(fx, scripted(behavior=reference), the_grant=the_grant, config=core_config(tmp_path / "two"))
    assert first.result == second.result and first.result_sha256 == second.result_sha256
    assert first.run.score_id != second.run.score_id
    assert first.run.core_session_id != second.run.core_session_id
    assert canonical_sha256(first.result.model_dump(mode="json")) == first.result_sha256
    # The grant is an input identity: a different grant is a different result.
    other = grant(fx)
    assert run(fx, scripted(behavior=reference), the_grant=other).result_sha256 != first.result_sha256


def tampered(record: BehaviorScoreRecord, mutate, *, rehash: bool = True) -> bytes:
    doc = json.loads(record.to_json_bytes())
    mutate(doc)
    if rehash:
        doc["result_sha256"] = canonical_sha256(doc["result"])
    return json.dumps(doc).encode()


@pytest.mark.parametrize("mutate", [
    lambda d: d["result"]["outcome"].__setitem__("criterion_satisfied", True),
    lambda d: d["result"]["outcome"].__setitem__("status", "behavioral_match"),
    lambda d: d["result"]["outcome"].__setitem__("behaviorally_successful_reconstruction", "established"),
    lambda d: d["result"]["outcome"].__setitem__("refusal_reason", "grant_expired"),
    lambda d: d["result"]["evidence"].update(counts_as_behavioral_evidence=True, reasons=[]),
    lambda d: d["result"]["cases"][0].__setitem__("classification", "match"),
    lambda d: d["result"]["summary"].__setitem__("matched_cases", 8),
    lambda d: d["result"]["worker"].__setitem__("kind", "isolated_sandbox"),
    lambda d: d["result"]["worker"].__setitem__("limits_enforcement", "verified_by_runtime"),
    lambda d: d["result"]["worker"].__setitem__("core_contract", None),
    lambda d: d["result"]["trial"].__setitem__("candidate_origin", "model_provider"),
    lambda d: d["result"]["configuration"]["policy"]["execute"].__setitem__("wall_ms", 9999),
    lambda d: d["result"]["configuration"].__setitem__("policy_sha256", "0" * 64),
    lambda d: d["result"]["scorer"].__setitem__("configuration_sha256", "0" * 64),
    lambda d: d["result"]["cases"].pop(),
    lambda d: d["result"]["cases"][0].__setitem__("case_id", "c0009"),
    lambda d: d["result"]["interface"].__setitem__("arity", 4),
    lambda d: d["result"]["suite"].__setitem__("case_count", 9),
    lambda d: d["result"]["grant"].__setitem__("grant_signed", True),
    lambda d: d["result"].__setitem__("grant", None),
    lambda d: d.__setitem__("attacker_visible", True),
    lambda d: d.__setitem__("record_signed", True),
    lambda d: d["run"]["case_seconds"].pop(),
    lambda d: d["run"]["core_records"].pop(),
    lambda d: d["run"]["core_records"].reverse(),
    lambda d: d["run"].__setitem__("core_session_id", None),
    lambda d: d["result"]["outcome"].__setitem__("stop_reason", "worker_failure"),
])
def test_record_invariants_are_enforced_on_reload(fx, mutate):
    def mostly_wrong(a, b, c):
        return 0
    record = run(fx, scripted(behavior=mostly_wrong))
    with pytest.raises(ValidationError):
        parse_behavior_score(tampered(record, mutate, rehash=True))


def test_result_digest_detects_any_change(fx):
    record = run(fx, scripted(behavior=reference))
    with pytest.raises(ValidationError):
        parse_behavior_score(tampered(record, lambda d: d["result"]["limitations"].append("edited"), rehash=False))


def test_strict_json_and_size_on_reload(fx):
    record = run(fx, scripted(behavior=reference))
    data = record.to_json_bytes()
    with pytest.raises(LoadError):
        parse_behavior_score(data[:-2] + b', "record_signed": false}')
    with pytest.raises(LoadError):
        parse_behavior_score(b" " * (8 * 2**20 + 1))
    with pytest.raises(ValidationError):
        parse_behavior_score(data.replace(b'"aegis.lab.behavior-score.v1"', b'"aegis.lab.behavior-score.v0"'))


def test_mask_helper_sanity():
    assert reference(MASK, MASK, MASK) == ((MASK * 3) + 0x9E3779B9) & MASK
    assert INTERFACE.count("uint32_t") == 4


# --- Grant-wide budgets (Core ledger), translation units, record binding ---------------------------

def ledger_for(config):
    from aegis_core.lab_ledger import GrantLedger

    return GrantLedger.for_config(config)


def test_a_used_grant_is_refused_before_anything_runs(fx):
    the_grant = grant(fx)
    assert run(fx, the_grant=the_grant).result.outcome.status == "behavioral_match"
    runtime = scripted(behavior=reference)
    with pytest.raises(ExecutionRefused) as caught:
        run(fx, runtime, the_grant=the_grant)
    assert (caught.value.code, caught.value.reasons) == ("grant_budget_insufficient", ("compilations_already_used",))
    assert runtime.preflights == [] and runtime.compile_jobs == []
    usage = ledger_for(fx["config"]).usage(the_grant.grant_id)
    assert usage.compilations == {fx["manifests"]["baseline"].trial_id: 1}
    assert usage.executions == {fx["manifests"]["baseline"].trial_id: len(ARGUMENTS)}


def test_a_reused_grant_id_with_other_contents_is_refused(fx):
    first = grant(fx)
    run(fx, the_grant=first)
    edited = grant(fx, grant_id=first.grant_id, max_total_wall_ms=first.max_total_wall_ms + 1000)
    runtime = scripted(behavior=reference)
    with pytest.raises(ExecutionRefused) as caught:
        run(fx, runtime, the_grant=edited)
    assert (caught.value.code, caught.value.reasons) == ("core_refused", ("grant_ledger_conflict",))
    assert runtime.preflights == []


@pytest.mark.parametrize("stage,reason", [("execute", "execution_budget_exhausted"),
                                          ("wall", "wall_budget_exhausted")])
def test_budget_exhausted_elsewhere_mid_run_stops_as_incomplete(fx, stage, reason):
    """Another holder of the same grant consumes its budget while this trial runs."""
    the_grant = grant(fx)
    trial = fx["manifests"]["baseline"].trial_id
    other = fx["manifests"]["protected"].trial_id
    ledger = ledger_for(fx["config"])
    from aegis_core.lab_authorization import grant_sha256

    def consume(job):
        if len(runtime.execute_jobs) == 2:
            if stage == "execute":
                for _ in range(the_grant.max_executions_per_candidate - 2):
                    ledger.reserve(the_grant, grant_sha256(the_grant), stage="execute", candidate_id=trial,
                                   wall_ms=1, now=datetime.now(UTC))
            else:
                usage = ledger.usage(the_grant.grant_id)
                ledger.reserve(the_grant, grant_sha256(the_grant), stage="compile", candidate_id=other,
                               wall_ms=the_grant.max_total_wall_ms - usage.wall_ms_reserved, now=datetime.now(UTC))
        return result_observation(reference(*(int(a) for a in job.args)))
    runtime = scripted(execute=consume)
    record = roundtrip(run(fx, runtime, the_grant=the_grant))
    out = record.result.outcome
    assert (out.status, out.stop_reason, out.refusal_reason) == ("incomplete", "core_refused", reason)
    classes = [c.classification for c in record.result.cases]
    assert classes[:2] == ["match", "match"] and set(classes[2:]) == {"not_evaluated"}
    assert len(runtime.execute_jobs) == 2 and out.criterion_satisfied is False


def test_interrupted_run_keeps_its_reserved_budget(fx):
    the_grant = grant(fx)
    runtime = scripted(execute=per_case(result_observation(EXPECTED[0]), KeyboardInterrupt()))
    with pytest.raises(ScoringInterrupted):
        run(fx, runtime, the_grant=the_grant)
    usage = ledger_for(fx["config"]).usage(the_grant.grant_id)
    trial = fx["manifests"]["baseline"].trial_id
    assert usage.compilations[trial] == 1 and usage.executions[trial] == 2  # the interrupted run counts
    with pytest.raises(ExecutionRefused) as caught:
        run(fx, the_grant=the_grant)
    assert caught.value.code == "grant_budget_insufficient"


def test_only_the_generated_units_are_compiled(fx):
    runtime = scripted(behavior=reference)
    record = run(fx, runtime)
    (job,) = runtime.compile_jobs
    assert job.translation_units == ["aegis_harness.c", "aegis_candidate_unit.c"]
    assert "candidate.c" not in job.translation_units and job.candidate.name == "candidate.c"
    assert job.compiler_arguments() == ["-std=c11", "-O1", "-static", "-o", "candidate", "aegis_harness.c",
                                        "aegis_candidate_unit.c"]
    unit = {f.name: f.data for f in job.support_files}["aegis_candidate_unit.c"]
    assert b'#include "candidate.c"' in unit
    assert record.result.outcome.status == "behavioral_match"


def test_compile_request_never_lists_the_candidate_as_a_unit():
    from aegis_lab.scoring_worker import CompileRequest

    limits = make_policy().compile
    support = (("aegis_harness.c", b""), ("aegis_candidate_unit.c", b""))
    for units in (("candidate.c",), ("aegis_harness.c", "candidate.c"), (), ("aegis_harness.c", "aegis_harness.c"),
                  ("other.c",)):
        with pytest.raises(ValueError):
            CompileRequest(candidate_name="candidate.c", candidate=b"x", support=support, translation_units=units,
                           limits=limits)


def tamper_records(monkeypatch, stage, update):
    method = "compile" if stage == "compile" else "execute"
    original = getattr(CandidateExecutionSession, method)

    def patched(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if stage == "compile":
            from aegis_core.lab_execution import CompileResult

            return CompileResult(record=result.record.model_copy(update=update(result.record)), binary=result.binary)
        return result.model_copy(update=update(result))
    monkeypatch.setattr(CandidateExecutionSession, method, patched)


@pytest.mark.parametrize("stage,update", [
    ("compile", lambda r: {"translation_units": ["candidate.c"]}),
    ("compile", lambda r: {"translation_units": ["aegis_harness.c", "aegis_candidate_unit.c", "candidate.c"]}),
    ("compile", lambda r: {"support_files_sha256": {}}),
    ("compile", lambda r: {"compile_flags": ["-std=c11", "-O2"]}),
    ("compile", lambda r: {"limits": {**r.limits, "memory_bytes": r.limits["memory_bytes"] * 2}}),
    ("compile", lambda r: {"candidate_sha256": "0" * 64}),
    ("compile", lambda r: {"grant_id": "e" * 32}),
    ("compile", lambda r: {"lab_bindings": r.lab_bindings.model_copy(update={"pair_id": "e" * 32})}),
    ("compile", lambda r: {"compilations_used": 99}),
    ("execute", lambda r: {"limits": {**r.limits, "wall_ms": r.limits["wall_ms"] + 1}}),
    ("execute", lambda r: {"session_id": "e" * 32}),
    ("execute", lambda r: {"translation_units": ["aegis_harness.c"]}),
    ("execute", lambda r: {"executions_used": 10_000}),
    ("execute", lambda r: {"candidate_id": "e" * 32}),
])
def test_any_core_record_outside_the_authorization_fails_closed(fx, monkeypatch, stage, update):
    tamper_records(monkeypatch, stage, update)
    runtime = scripted(behavior=reference)
    record = roundtrip(run(fx, runtime))
    if stage == "compile":
        assert record.result.compilation.status == "infrastructure_failure"
        assert record.result.compilation.infrastructure_code == "core_record_mismatch"
        assert runtime.execute_jobs == []
    else:
        assert record.result.cases[0].classification == "infrastructure_failure"
        assert record.result.cases[0].infrastructure_code == "core_record_mismatch"
    assert record.result.outcome.status == "infrastructure_failure"


# --- Firecracker attestations and host enforcement ---------------------------------------------------
# Classification tests only. A real Core session is opened over Core's scripted runtime with a
# Firecracker attestation and passed straight to the coordinator; nothing boots or runs. The Lab
# itself never accepts an isolating attestation from an injected runtime (tested above and below).

from scoring_fixtures import firecracker_attestation, firecracker_policy, host_enforcement_for  # noqa: E402

from aegis_lab.behavior_score import score_opened  # noqa: E402
from aegis_lab.core_execution import OpenedSession, lab_bindings  # noqa: E402


@pytest.fixture(scope="module")
def fc(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("firecracker")
    data = experiment(tmp, policy=firecracker_policy())
    data["config"] = core_config(tmp)
    return data


def default_enforcement(stage, job):
    return host_enforcement_for(job.limits)


def isolated(fc, *, enforcement=default_enforcement, attestation_changes=None, **script):
    from aegis_core.lab_execution import open_session

    prepared = prep(fc)
    the_grant = grant(fc)
    if not script:
        script = {"behavior": reference}
    runtime = scripted(attestation=firecracker_attestation(fc["policy"], **(attestation_changes or {})),
                       enforcement=enforcement, **script)
    session = open_session(fc["config"], the_grant, lab_bindings=lab_bindings(prepared), runtime=runtime)
    record = score_opened(prepared, OpenedSession(injected=False, session=session), grant=the_grant)
    return roundtrip(record), runtime


def test_firecracker_attestation_and_enforcement_are_recorded_separately_from_requests(fc):
    record, runtime = isolated(fc)
    worker = record.result.worker
    assert (worker.kind, worker.preflight, worker.limits_enforcement, worker.identity_observed) == (
        "isolated_sandbox", "passed", "verified_by_runtime", True)
    assert worker.runtime == fc["policy"].runtime and worker.runtime.name == "firecracker"
    granted, enforced = worker.granted_execute_limits, worker.enforced_execute_limits
    assert granted == fc["policy"].execute
    # Requested and enforced are different quantities and are kept apart.
    assert enforced.memory_max_bytes != granted.memory_bytes
    assert enforced.vm_memory_mib * 2**20 >= granted.memory_bytes + granted.scratch_bytes
    assert enforced.memory_swap_max_bytes == 0 and worker.enforced_compile_limits is not None
    # Measurements live in the run section, aligned with Core's records.
    assert [(a.stage, a.case_id) for a in record.run.host_accounting] == [
        (r.stage, r.case_id) for r in record.run.core_records]
    assert all(a.host_cpu_usec == 1234 and a.host_oom_kills == 0 for a in record.run.host_accounting)
    assert "host_cpu_usec" not in json.dumps(record.result.model_dump(mode="json"))
    # An isolating runtime does not make a scripted FakeOffline candidate evidence.
    assert record.result.evidence.reasons == ("candidate_scripted_by_offline_fake_provider",
                                              "guest_integrity_not_independently_verified")
    assert record.result.outcome.behaviorally_successful_reconstruction == "not_established"


@pytest.mark.parametrize("field", ["guest_kernel_sha256", "guest_agent_sha256", "containment_verification_sha256",
                                   "rootfs_sha256", "runtime_sha256"])
def test_every_firecracker_identity_must_match_the_policy(fc, field):
    record, runtime = isolated(fc, attestation_changes={field: "9" * 64})
    assert (record.result.worker.preflight, record.result.worker.preflight_code) == ("failed", "runtime_mismatch")
    assert runtime.compile_jobs == [] and record.run.host_accounting == ()


def test_firecracker_version_must_match_the_policy(fc):
    record, _ = isolated(fc, attestation_changes={"runtime_version": "firecracker-9.9.9"})
    assert record.result.worker.preflight_code == "runtime_mismatch"


def test_injected_firecracker_runtime_is_refused(fc):
    runtime = scripted(behavior=reference, attestation=firecracker_attestation(fc["policy"]),
                       enforcement=default_enforcement)
    with pytest.raises(ExecutionRefused) as caught:
        score_trial(prep(fc), config=fc["config"], grant=grant(fc), runtime=runtime)
    assert caught.value.code == "injected_runtime_not_test_double"
    assert runtime.compile_jobs == [] and runtime.closed == 1


def only(stage, **changes):
    def enforcement(current, job):
        data = host_enforcement_for(job.limits)
        if current == stage:
            data.update(changes)
        return data
    return enforcement


@pytest.mark.parametrize("enforcement", [
    lambda stage, job: None,  # an isolating runtime that reports nothing
    only("compile", memory_swap_max_bytes=1),
    only("compile", vm_memory_mib=1, memory_max_bytes=2**20, host_memory_peak_bytes=0),  # no room for the job
    only("compile", vm_memory_mib=64, memory_max_bytes=512 * 2**20),  # 64 MiB VM < 512 MiB granted compile memory
    only("compile", cpu_quota_us=300_000),  # more CPU than the configured vCPU
    only("compile", vcpu_count=65),  # outside the Lab's bounded vCPU range
    only("compile", memory_max_bytes=2**20),  # scope smaller than the microVM
])
def test_invalid_compile_enforcement_fails_closed(fc, enforcement):
    record, runtime = isolated(fc, enforcement=enforcement)
    assert record.result.compilation.status == "infrastructure_failure"
    assert record.result.compilation.infrastructure_code == "host_enforcement_invalid"
    assert record.result.outcome.status == "infrastructure_failure" and runtime.execute_jobs == []


def test_enforcement_that_changes_between_cases_fails_closed(fc):
    calls = []

    def drifting(stage, job):
        calls.append(stage)
        return host_enforcement_for(job.limits, **({"pids_max": 99} if calls.count("execute") == 3 else {}))
    record, _ = isolated(fc, enforcement=drifting)
    classes = [c.classification for c in record.result.cases]
    assert classes[:2] == ["match", "match"] and classes[2] == "infrastructure_failure"
    assert record.result.cases[2].infrastructure_code == "host_enforcement_invalid"


def test_test_double_must_not_claim_enforcement(fx):
    runtime = scripted(behavior=reference, enforcement=default_enforcement)
    record = run(fx, runtime)
    assert record.result.compilation.infrastructure_code == "host_enforcement_invalid"
    assert record.result.worker.enforced_compile_limits is None and record.run.host_accounting == ()


@pytest.mark.parametrize("observation,classification,limit", [
    (ExecuteObservation(status="timeout"), "timeout", None),
    (ExecuteObservation(status="limit_exceeded", limit="memory"), "resource_limit_exceeded", "memory"),
])
def test_host_observed_outcomes_keep_their_accounting(fc, observation, classification, limit):
    def enforcement(stage, job):
        return host_enforcement_for(job.limits, host_oom_kills=1 if limit == "memory" and stage == "execute" else 0)
    record, _ = isolated(fc, enforcement=enforcement, execute=per_case(observation))
    assert record.result.cases[0].classification == classification and record.result.cases[0].limit == limit
    executes = [a for a in record.run.host_accounting if a.stage == "execute"]
    assert executes[0].host_oom_kills == (1 if limit else 0)


@pytest.mark.parametrize("mutate", [
    lambda d: d["result"]["worker"]["enforced_execute_limits"].update(vm_memory_mib=1, memory_max_bytes=2**20),
    lambda d: d["result"]["worker"]["enforced_execute_limits"].update(memory_swap_max_bytes=1),
    # Claiming the requested memory as the enforced scope limit is rejected (scope < microVM).
    lambda d: d["result"]["worker"]["enforced_execute_limits"].update(
        memory_max_bytes=d["result"]["worker"]["granted_execute_limits"]["memory_bytes"]),
    lambda d: d["result"]["worker"].__setitem__("enforced_execute_limits", None),
    lambda d: d["run"]["host_accounting"].pop(),
    lambda d: d["run"]["host_accounting"][1].__setitem__("host_memory_peak_bytes", -1),
])
def test_enforcement_record_invariants_on_reload(fc, mutate):
    record, _ = isolated(fc)
    with pytest.raises(ValidationError):
        parse_behavior_score(tampered(record, mutate))


@pytest.mark.parametrize("oom", [0, 1])
def test_cgroup_peak_above_limit_is_valid_accounting(fc, oom):
    record, _ = isolated(fc, enforcement=only("execute", host_memory_peak_bytes=2**40, host_oom_kills=oom))
    assert record.result.outcome.status == "behavioral_match"
    assert all(a.host_memory_peak_bytes == 2**40 for a in record.run.host_accounting if a.stage == "execute")
    assert not record.result.evidence.counts_as_behavioral_evidence


def test_full_core_records_are_private_and_digest_checkable(fx):
    record = run(fx)
    private = record.private_core_records
    assert len(private) == len(record.run.core_records)
    for ref in record.run.core_records:
        raw = private[ref.record_sha256]
        assert hashlib.sha256(raw).hexdigest() == ref.record_sha256
        assert json.loads(raw)["record_id"] == ref.record_id
    assert "observation" not in json.loads(record.to_json_bytes())
    assert "_private_core_records" not in record.model_dump()


def test_test_double_record_cannot_carry_enforcement_or_accounting(fx):
    record = run(fx)
    isolated_limits = host_enforcement_for(fx["policy"].execute)
    enforced = {k: v for k, v in isolated_limits.items() if not k.startswith("host_")}
    with pytest.raises(ValidationError):
        parse_behavior_score(tampered(record, lambda d: d["result"]["worker"].__setitem__(
            "enforced_execute_limits", enforced)))
    with pytest.raises(ValidationError):
        parse_behavior_score(tampered(record, lambda d: d["run"].__setitem__("host_accounting", [
            {"stage": "compile", "case_id": None, "host_cpu_usec": 1, "host_memory_peak_bytes": 1,
             "host_oom_kills": 0}])))


def test_cores_configured_firecracker_runtime_refuses(fc, tmp_path):
    from aegis_core.config import config_from_mapping

    pins = {"firecracker_path": "/opt/aegis/firecracker", "firecracker_sha256": "1" * 64, "bwrap_sha256": "2" * 64,
            "kernel_path": "/opt/aegis/vmlinux", "kernel_sha256": "3" * 64, "rootfs_path": "/opt/aegis/rootfs.ext4",
            "rootfs_sha256": "4" * 64, "guest_agent_sha256": "5" * 64, "compiler_name": "gcc",
            "compiler_version": "16.2.1", "compiler_sha256": "6" * 64, "state_dir": str(tmp_path / "state")}
    config = config_from_mapping({"attack_lab": {"enabled": True, "candidate_execution": {
        "enabled": True, "runtime": "firecracker", "firecracker": pins}}}, base_dir=tmp_path)
    with pytest.raises(ExecutionRefused) as caught:
        score_trial(prep(fc), config=config, grant=grant(fc), runtime=None)
    assert caught.value.code == "sandbox_unavailable"
    assert {"isolation_adr_not_accepted", "containment_unverified"} <= set(caught.value.reasons)
