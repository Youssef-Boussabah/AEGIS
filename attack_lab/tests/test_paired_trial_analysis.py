"""Phase 3B: target-analysis failures in valid wildcard Ghidra evidence (offline).

A wildcard (``*``) Ghidra report may record that the trial's target function failed
to decompile while other functions succeeded. Phase 2 accepts and binds such a
report. Phase 3B must keep that observation (no model request, no provider call,
zero resources) instead of discarding the experiment, and must keep every invalid
input invalid. Reports come from the real Phase 2 worker code path driven by the
offline fake launcher; the opt-in test at the end uses a real Ghidra decompiler
timeout. Generated code is never compiled or executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_manifest import digest, manifest_data
from test_paired_trial import (
    ALPHA,
    BRAVO,
    FUNCTION,
    SEED_BASELINE_FIRST,
    SEED_PROTECTED_FIRST,
    Factory,
    build_pair,
    by_variant,
    cli_args,
    prepared,
    run,
    tamper,
    verify_args,
    write_inputs,
)

from aegis_lab import paired_trial
from aegis_lab.evidence import planned_ghidra_tool
from aegis_lab.fake_provider import FakeProvider
from aegis_lab.ghidra import WorkerError, analyze
from aegis_lab.manifest import TrialManifest
from aegis_lab.paired_trial import (
    PAIRED_RECORD_FILE,
    RECONSTRUCTION_FILES,
    ZERO_RESOURCES,
    ExperimentVerificationError,
    PairedTrialInputError,
    _diagnostic_text,
    execution_order,
    main,
    parse_paired_trial_record,
    prepare_pair,
    run_paired_trial,
    verify_experiment,
)
from aegis_lab.reconstruction import (
    EXIT_COMPLETED,
    EXIT_INTERRUPTED,
    EXIT_NOT_COMPLETED,
    EXIT_PUBLICATION_FAILED,
    planned_attack_digests,
)
from aegis_lab.safe_io import LoadError, PublishError

TIMEOUT_ERROR = "decompiler timed out after 30s"
PCODE_MESSAGE = "Low-level Error: pcode error at 00101130"


def wildcard_hook(failing=(), *, message="", status="timed_out", extra="", target_count=1, helpers=1) -> str:
    """Export the target plus helper functions; the target fails in binaries containing a ``failing`` marker.

    ``fn`` is the fake launcher's own helper for building one exported function.
    """
    return (
        "data = imported.read_bytes()\n"
        f"failed = any(m in data for m in {list(failing)!r})\n"
        f"body = {BRAVO!r} if b'variant-two' in data else {ALPHA!r}\n"
        f"targets = [fn(name={FUNCTION!r}, code=body, ok=not failed, entry='0010' + str(1120 + i),"
        f" error={TIMEOUT_ERROR!r} if failed else '', status={status!r} if failed else None,"
        f" message={message!r} if failed else '') for i in range({target_count})]\n"
        f"helpers = [fn(name='helper_' + str(i), code='int helper_' + str(i) + '(int a, int b) {{ return a - b; }}',"
        f" entry='0020' + str(2000 + i)) for i in range({helpers})]\n"
        "out['functions'] = targets + helpers\n"
        "out['matching_function_count'] = len(out['functions'])\n"
        + extra
    )


def wildcard_pair(tmp_path: Path, failing=(), **kwargs) -> dict:
    hook_options = {k: kwargs.pop(k) for k in ("message", "status", "extra", "target_count", "helpers")
                    if k in kwargs}
    return build_pair(tmp_path, selector="*", hook=wildcard_hook(failing, **hook_options), **kwargs)


BOTH = (b"variant-one", b"variant-two")
FAILING = {"baseline": (b"variant-one",), "protected": (b"variant-two",), "both": BOTH}


def failing_variants(case: str) -> set[str]:
    return {"baseline", "protected"} if case == "both" else {case}


# --- Preparation: an attributable target failure is an observation, not invalid input -----------

def test_wildcard_pair_with_both_targets_decompiled_runs_as_before(tmp_path):
    fx = wildcard_pair(tmp_path)
    pair = prepared(fx)
    assert set(pair.prepared) == {"baseline", "protected"} and pair.prompts_compared
    for observation in pair.analysis.values():
        assert (observation.selector, observation.status, observation.failure) == ("wildcard", "decompiled", None)
        assert (observation.report_function_count, observation.report_decompiled_count) == (2, 2)
    result = run(fx)
    assert result.exit_code == EXIT_COMPLETED
    assert result.record.outcome.pair_status == "candidates_received_for_both_trials"
    assert result.record.comparability.effective_request_settings == "identical"
    assert {t.outcome for t in result.record.trials} == {"candidate_received"}


def test_exact_selector_success_records_its_analysis_observation(tmp_path):
    fx = build_pair(tmp_path)
    result = run(fx)
    for trial in result.record.trials:
        assert (trial.analysis.selector, trial.analysis.status, trial.analysis.decompile_status) == (
            "exact", "decompiled", "completed")
        assert trial.analysis.report_function_count == 1


@pytest.mark.parametrize("case", ["baseline", "protected", "both"])
def test_failed_target_is_kept_as_an_observation_without_a_request(tmp_path, case):
    fx = wildcard_pair(tmp_path, FAILING[case])
    pair = prepared(fx)
    failed = failing_variants(case)
    assert set(pair.prepared) == {"baseline", "protected"} - failed
    assert pair.prompts_compared is False
    assert set(pair.cross_trial_value_findings) == set(pair.prepared)
    for variant in failed:
        observation = pair.analysis[variant]
        assert (observation.selector, observation.status, observation.decompile_status) == (
            "wildcard", "decompilation_failed", "timed_out")
        assert observation.failure.error.text == TIMEOUT_ERROR
        assert observation.failure.error.sha256 == hashlib.sha256(TIMEOUT_ERROR.encode()).hexdigest()
        assert observation.failure.decompiler_message is None
        assert (observation.report_function_count, observation.report_decompiled_count,
                observation.report_failed_count) == (2, 1, 1)


def test_decompiler_message_is_retained_with_its_digest(tmp_path):
    fx = wildcard_pair(tmp_path, FAILING["protected"], message=PCODE_MESSAGE, status="failed")
    failure = prepared(fx).analysis["protected"].failure
    assert failure.decompile_status == "failed"
    assert failure.decompiler_message.text == PCODE_MESSAGE
    assert failure.decompiler_message.chars == len(PCODE_MESSAGE)
    assert failure.decompiler_message_truncated is False


def test_invalid_diagnostic_text_is_withheld_but_digested():
    text = _diagnostic_text("bad \ud800 text")
    assert text.text is None and text.withheld == "invalid_text"
    assert text.sha256 == hashlib.sha256("bad \ud800 text".encode("utf-8", "surrogatepass")).hexdigest()
    assert _diagnostic_text("ok").text == "ok"


# --- Running: no request, no provider, zero resources; the other trial proceeds -------------------

@pytest.mark.parametrize("seed", [SEED_BASELINE_FIRST, SEED_PROTECTED_FIRST])
@pytest.mark.parametrize("case", ["baseline", "protected", "both"])
def test_failed_target_is_recorded_and_the_other_trial_proceeds(tmp_path, case, seed):
    fx = wildcard_pair(tmp_path, FAILING[case])
    out = tmp_path / "experiment"
    factory = Factory()
    result = run(fx, out, factory=factory, seed=seed)
    record, trials = result.record, by_variant(result.record)
    failed = failing_variants(case)
    attempted = {"baseline", "protected"} - failed

    # The provider is created only for trials with a request, and each is called exactly once.
    assert len(factory.made) == len(attempted)
    assert all(len(p.requests) == 1 for p in factory.made)
    sequence = execution_order(seed, pair_id="9" * 32, baseline_trial_id="1" * 32, protected_trial_id="2" * 32)
    assert record.order.sequence == sequence
    for variant in failed:
        trial = trials[variant]
        assert trial.state == "analysis_failure_recorded"
        assert trial.outcome == "not_attempted_target_analysis_failed"
        assert trial.prepared is None and trial.reconstruction is None and trial.error is None
        assert trial.runner_wall_seconds is None
        assert trial.resources == ZERO_RESOURCES
        assert trial.resources.attempts == 0 and trial.resources.charged_tokens == 0
        assert trial.analysis.failure.decompile_status == "timed_out"
        assert trial.execution_position == sequence.index(variant) + 1
        assert not (out / RECONSTRUCTION_FILES[variant]).exists()
    for variant in attempted:
        trial = trials[variant]
        assert (trial.state, trial.outcome) == ("record_produced", "candidate_received")
        assert trial.resources.attempts == 1 and trial.resources.charged_tokens == 160
        assert (out / RECONSTRUCTION_FILES[variant]).exists()
    assert record.totals.attempts == len(attempted)
    assert record.totals.charged_tokens == record.totals.reported_tokens == 160 * len(attempted)
    assert record.totals.submitted_attempts == len(attempted)

    out_ = record.outcome
    assert (out_.run_status, out_.workflow_complete) == ("finished", True)
    assert out_.pair_status == "target_analysis_failure_observed"
    assert out_.trials_not_attempted_analysis_failed == len(failed)
    assert out_.trials_completed == len(attempted)
    assert out_.interpretation == "not_evaluated"
    assert out_.reconstruction_success_established is False and out_.protection_effect_established is False
    assert out_.scoring == "not_performed"
    assert record.errors == ()
    comparability = record.comparability
    assert (comparability.effective_request_settings, comparability.model_facing_task) == (
        "not_compared", "not_compared")
    assert comparability.declared_settings == "verified_for_both_trials"
    assert any("not evaluated" in note for note in record.limitations)
    assert result.exit_code == EXIT_NOT_COMPLETED

    # Publication, reload and full revalidation against the inputs.
    assert parse_paired_trial_record((out / PAIRED_RECORD_FILE).read_bytes()) == record
    m, r = fx["manifests"], fx["reports"]
    assert verify_experiment(out, baseline_manifest=m["baseline"], protected_manifest=m["protected"],
                             baseline_report=r["baseline"], protected_report=r["protected"]) == record


def test_failed_target_never_reaches_the_provider_or_reconstruction(tmp_path, monkeypatch):
    fx = wildcard_pair(tmp_path, FAILING["protected"])
    calls = []
    original = paired_trial.run_reconstruction

    def tracking(prepared_request, provider, **kwargs):
        calls.append(prepared_request.variant)
        return original(prepared_request, provider, **kwargs)

    monkeypatch.setattr(paired_trial, "run_reconstruction", tracking)
    factory = Factory()
    run(fx, factory=factory)
    assert calls == ["baseline"]
    (provider,) = factory.made
    assert "bravo_mix" not in provider.requests[0].messages[1].content  # no protected evidence leaks over


def test_both_targets_failed_creates_no_provider(tmp_path):
    fx = wildcard_pair(tmp_path, BOTH)

    def refuse():
        raise AssertionError("a provider was created for a trial without a request")

    result = run_paired_trial(prepared(fx), tmp_path / "experiment", order_seed=1, provider_factory=refuse)
    assert result.record.totals.attempts == 0 and result.record.outcome.trials_with_record == 0
    assert sorted(p.name for p in (tmp_path / "experiment").iterdir()) == [PAIRED_RECORD_FILE]


@pytest.mark.parametrize("change", ["observation", "binding", "request_removed"])
def test_prepared_pair_facts_are_rebound_before_provider_creation(tmp_path, change):
    fx = wildcard_pair(tmp_path, FAILING["protected"])
    pair = prepared(fx)
    if change == "observation":
        observation = pair.analysis["protected"]
        pair.analysis["protected"] = observation.model_copy(update={
            "decompile_status": "cancelled",
            "failure": observation.failure.model_copy(update={"decompile_status": "cancelled"}),
        })
    elif change == "binding":
        import dataclasses

        pair.evidence["protected"] = dataclasses.replace(pair.evidence["protected"],
                                                        evidence_sha256=digest("different report"))
    else:
        # Turn the valid baseline into a fabricated analysis-failure observation.
        del pair.prepared["baseline"]
        pair.analysis["baseline"] = pair.analysis["protected"]
        pair.cross_trial_value_findings.clear()
    factory, out = Factory(), tmp_path / "experiment"
    with pytest.raises(PairedTrialInputError, match="inconsistent"):
        run_paired_trial(pair, out, provider_factory=factory)
    assert factory.made == [] and not out.exists()


def test_exact_analysis_observation_requires_one_successful_function(tmp_path):
    fx = build_pair(tmp_path)
    document = run(fx).record.model_dump(mode="json")
    document["trials"][0]["analysis"].update(report_function_count=2, report_decompiled_count=2)
    with pytest.raises(ValidationError):
        parse_paired_trial_record(json.dumps(document).encode())


def test_other_trial_failure_is_preserved_alongside_an_analysis_failure(tmp_path):
    fx = wildcard_pair(tmp_path, FAILING["protected"])
    result = run(fx, factory=Factory(FakeProvider(content="not a candidate")))
    trials = by_variant(result.record)
    assert trials["baseline"].outcome == "reconstruction_not_completed"
    assert trials["baseline"].reconstruction.status == "invalid_candidate"
    assert trials["protected"].outcome == "not_attempted_target_analysis_failed"
    assert result.record.outcome.pair_status == "target_analysis_failure_observed"


@pytest.mark.parametrize("seed", [SEED_BASELINE_FIRST, SEED_PROTECTED_FIRST])
def test_interruption_keeps_the_analysis_failure_observation(tmp_path, seed):
    fx = wildcard_pair(tmp_path, FAILING["protected"])

    def interrupt(_request, _timeout):
        raise KeyboardInterrupt

    out = tmp_path / "experiment"
    result = run(fx, out, seed=seed, factory=Factory(FakeProvider(on_call=interrupt)))
    trials = by_variant(result.record)
    assert trials["baseline"].state == "interrupted"
    assert trials["protected"].state == "analysis_failure_recorded"  # never depends on the run stopping
    assert result.record.outcome.run_status == "interrupted"
    assert result.record.outcome.pair_status == "incomplete"
    assert result.record.outcome.trials_not_attempted_analysis_failed == 1
    assert result.exit_code == EXIT_INTERRUPTED
    assert verify_experiment(out) == result.record


def test_partial_publication_keeps_the_analysis_failure_observation(tmp_path, monkeypatch):
    fx = wildcard_pair(tmp_path, FAILING["baseline"])
    original = paired_trial.publish_new_file

    def fail_protected(path, data, limit):
        if Path(path).name == RECONSTRUCTION_FILES["protected"]:
            raise PublishError("write_failed")
        original(path, data, limit)

    monkeypatch.setattr(paired_trial, "publish_new_file", fail_protected)
    out = tmp_path / "experiment"
    result = run(fx, out)
    trials = by_variant(result.record)
    assert trials["baseline"].state == "analysis_failure_recorded"
    assert trials["protected"].reconstruction.publication == "failed"
    assert result.record.outcome.run_status == "publication_failed"
    assert result.exit_code == EXIT_PUBLICATION_FAILED
    assert verify_experiment(out) == result.record


# --- Invalid inputs stay invalid ------------------------------------------------------------------

def _fail_function(report: bytes, index: int) -> bytes:
    """Edit a genuine worker report so that one function claims a failed decompilation."""
    document = json.loads(report)
    fn = document["analysis"]["functions"][index]
    fn.update(decompile_success=False, decompile_status="timed_out", decompiled_c="", decompiler_signature="",
              error=TIMEOUT_ERROR)
    document["decompiled_ok_count"] -= 1
    document["decompile_failed_count"] += 1
    return json.dumps(document).encode()


def test_exact_selector_failure_is_still_rejected_by_phase_2(tmp_path):
    with pytest.raises(WorkerError, match="selected_function_failed|decompilation of"):
        build_pair(tmp_path / "worker", hook=wildcard_hook(FAILING["protected"], helpers=0))  # worker refuses
    fx = build_pair(tmp_path / "binder")  # exact selector, genuine reports
    m = fx["manifests"]
    with pytest.raises(PairedTrialInputError) as exc:
        prepare_pair(m["baseline"], m["protected"], fx["reports"]["baseline"],
                     _fail_function(fx["reports"]["protected"], 0))
    # Phase 2 rejects it (here already by its schema); it never becomes an analysis observation.
    assert exc.value.issues and all(i.startswith("protected-evidence: ") for i in exc.value.issues)


def test_wildcard_report_where_nothing_decompiled_is_still_rejected(tmp_path):
    with pytest.raises(WorkerError):
        wildcard_pair(tmp_path / "worker", FAILING["protected"], helpers=0)  # worker refuses
    fx = wildcard_pair(tmp_path / "binder", FAILING["protected"])
    m = fx["manifests"]
    with pytest.raises(PairedTrialInputError) as exc:
        prepare_pair(m["baseline"], m["protected"], fx["reports"]["baseline"],
                     _fail_function(fx["reports"]["protected"], 1))
    # Phase 2 rejects it (here already by its schema); it never becomes an analysis observation.
    assert exc.value.issues and all(i.startswith("protected-evidence: ") for i in exc.value.issues)


def test_missing_target_is_invalid_input_not_an_analysis_failure(tmp_path):
    extra = ("out['functions'] = [f for f in out['functions']\n"
             "                    if f['name'] != 'secret_add' or b'variant-one' in data]\n"
             "out['matching_function_count'] = len(out['functions'])\n")
    fx = wildcard_pair(tmp_path, extra=extra)
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx)
    assert exc.value.issues == ("protected-preparation: input: function_not_found",)


def test_ambiguous_failed_target_is_invalid_input(tmp_path):
    fx = wildcard_pair(tmp_path, FAILING["protected"], target_count=2)
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx)
    assert "protected-preparation: input: ambiguous_function" in exc.value.issues


def test_swapped_evidence_with_a_failed_target_is_rejected(tmp_path):
    fx = wildcard_pair(tmp_path, FAILING["protected"])
    m, r = fx["manifests"], fx["reports"]
    with pytest.raises(PairedTrialInputError) as exc:
        prepare_pair(m["baseline"], m["protected"], r["protected"], r["baseline"])
    assert exc.value.issues == ("baseline-evidence: binding: binary.sha256: mismatch",
                                "protected-evidence: binding: binary.sha256: mismatch")


def test_incorrect_artifact_hash_with_a_failed_target_is_rejected(tmp_path):
    fx = wildcard_pair(tmp_path, FAILING["protected"],
                       protected={"target.final_artifact_sha256": digest("another artifact")})
    with pytest.raises(PairedTrialInputError, match="protected-evidence: binding: binary.sha256: mismatch"):
        prepared(fx)


def test_corrupted_report_with_a_failed_target_is_rejected(tmp_path):
    fx = wildcard_pair(tmp_path, FAILING["protected"])
    document = json.loads(fx["reports"]["protected"])
    document["decompile_failed_count"] = 0  # contradicts the recorded failure
    m = fx["manifests"]
    with pytest.raises(PairedTrialInputError) as exc:
        prepare_pair(m["baseline"], m["protected"], fx["reports"]["baseline"], json.dumps(document).encode())
    assert all(i.startswith("protected-evidence:") for i in exc.value.issues)


def test_failed_target_with_unverifiable_digests_is_invalid(tmp_path):
    fx = wildcard_pair(tmp_path, FAILING["protected"], both={"attack.prompt_sha256": digest("placeholder")})
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx)
    assert set(exc.value.issues) == {"baseline-preparation: configuration: prompt_template_mismatch",
                                     "protected-preparation: configuration: prompt_template_mismatch"}


@pytest.mark.parametrize("case", ["protected", "both"])
def test_failed_target_with_an_unenforceable_budget_is_invalid(tmp_path, case):
    fx = wildcard_pair(tmp_path, FAILING[case])
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx, max_output_tokens=5000)
    assert set(exc.value.issues) == {"baseline-preparation: budget: output_tokens_exceed_budget",
                                     "protected-preparation: budget: output_tokens_exceed_budget"}


def test_failed_target_with_an_invalid_language_is_invalid(tmp_path):
    fx = wildcard_pair(tmp_path, BOTH)
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx, language="python")
    assert set(exc.value.issues) == {"baseline-preparation: disclosure: language_not_allowed",
                                     "protected-preparation: disclosure: language_not_allowed"}


@pytest.mark.parametrize("case", ["protected", "both"])
def test_failed_target_with_a_live_provider_manifest_is_refused_before_output(tmp_path, case):
    fx = wildcard_pair(tmp_path, FAILING[case], both={"attack.provider": "Nebius"})
    factory, out = Factory(), tmp_path / "experiment"
    with pytest.raises(PairedTrialInputError) as exc:
        run(fx, out, factory=factory)
    assert set(exc.value.issues) == {"baseline-preparation: configuration: provider_mismatch",
                                     "protected-preparation: configuration: provider_mismatch"}
    assert all(not p.requests for p in factory.made) and not out.exists()


# --- Record contradictions and replaced observations ---------------------------------------------

@pytest.fixture
def failure_published(tmp_path):
    fx = wildcard_pair(tmp_path, FAILING["protected"], message=PCODE_MESSAGE)
    out = tmp_path / "experiment"
    run(fx, out)
    return fx, out, json.loads((out / PAIRED_RECORD_FILE).read_bytes())


def _set_resources(document, attempts):
    document["trials"][1]["resources"]["attempts"] = attempts
    document["totals"]["attempts"] += attempts
    return json.dumps(document).encode()


def _replace_status(document):
    analysis = document["trials"][1]["analysis"]
    analysis["decompile_status"] = analysis["failure"]["decompile_status"] = "completed"
    return json.dumps(document).encode()


CONTRADICTIONS = {
    "request invented for failed target": lambda d: tamper(d, "trials.1.prepared", d["trials"][0]["prepared"]),
    "failed target claimed as run": lambda d: tamper(d, "trials.1.state", "record_produced"),
    "failed target claimed not started": lambda d: tamper(d, "trials.1.state", "not_started"),
    "inference attempts invented": lambda d: _set_resources(d, 1),
    "resources dropped": lambda d: tamper(d, "trials.1.resources", None),
    "wall time invented": lambda d: tamper(d, "trials.1.runner_wall_seconds", 0.5),
    "failure relabelled as decompiled": lambda d: tamper(d, "trials.1.analysis.status", "decompiled"),
    "status replaced by success": _replace_status,
    "failure details dropped": lambda d: tamper(d, "trials.1.analysis.failure", None),
    "failure status disagrees": lambda d: tamper(d, "trials.1.analysis.failure.decompile_status", "cancelled"),
    "exact selector failure": lambda d: tamper(d, "trials.1.analysis.selector", "exact"),
    "counts do not add up": lambda d: tamper(d, "trials.1.analysis.report_failed_count", 0),
    "error text changed without digest": lambda d: tamper(d, "trials.1.analysis.failure.error.text", "other"),
    "message withheld and kept": lambda d: tamper(d, "trials.1.analysis.failure.decompiler_message.withheld",
                                                  "invalid_text"),
    "trial outcome claims a candidate": lambda d: tamper(d, "trials.1.outcome", "candidate_received"),
    "pair status hides the failure": lambda d: tamper(d, "outcome.pair_status", "trial_failures"),
    "failure count changed": lambda d: tamper(d, "outcome.trials_not_attempted_analysis_failed", 0),
    "interpretation evaluated": lambda d: tamper(d, "outcome.interpretation", "resisted"),
    "requests claimed compared": lambda d: tamper(d, "comparability.effective_request_settings", "identical"),
    "task claimed compared": lambda d: tamper(d, "comparability.model_facing_task", "identical"),
    "successful trial relabelled as failed": lambda d: tamper(d, "trials.0.analysis.status",
                                                              "decompilation_failed"),
}


@pytest.mark.parametrize("name", sorted(CONTRADICTIONS))
def test_contradictory_observation_is_rejected(failure_published, name):
    _fx, _out, document = failure_published
    with pytest.raises(ValidationError):
        parse_paired_trial_record(CONTRADICTIONS[name](document))


def test_retired_v1_record_is_rejected(failure_published):
    _fx, _out, document = failure_published
    with pytest.raises(LoadError) as exc:
        parse_paired_trial_record(tamper(document, "schema_version", "aegis.lab.paired-trial.v1"))
    assert exc.value.category == "retired_schema_version"


def _rewrite(out: Path, document: dict) -> None:
    path = out / PAIRED_RECORD_FILE
    path.unlink()
    path.write_bytes(json.dumps(document).encode())
    parse_paired_trial_record(path.read_bytes())  # internally consistent: only the inputs can tell


@pytest.mark.parametrize("change", ["status", "error_text", "counts"])
def test_replaced_observation_facts_are_detected_against_the_inputs(failure_published, change):
    fx, out, document = failure_published
    analysis = document["trials"][1]["analysis"]
    if change == "status":
        analysis["decompile_status"] = analysis["failure"]["decompile_status"] = "cancelled"
    elif change == "error_text":
        text = "decompiler timed out after 31s"
        analysis["failure"]["error"].update(text=text, chars=len(text),
                                            sha256=hashlib.sha256(text.encode()).hexdigest())
    else:
        analysis.update(report_function_count=3, report_decompiled_count=2)
    _rewrite(out, document)
    assert verify_experiment(out) is not None  # nothing without the inputs can detect this
    m, r = fx["manifests"], fx["reports"]
    with pytest.raises(ExperimentVerificationError) as exc:
        verify_experiment(out, baseline_manifest=m["baseline"], protected_manifest=m["protected"],
                          baseline_report=r["baseline"], protected_report=r["protected"])
    assert exc.value.issues == ("inputs: protected.analysis: mismatch",)


def test_observation_verified_against_a_report_where_the_target_decompiled_is_rejected(failure_published,
                                                                                         tmp_path):
    fx, out, _document = failure_published
    clean = wildcard_pair(tmp_path / "clean")  # same artifacts, target decompiled in both
    m = fx["manifests"]
    with pytest.raises(ExperimentVerificationError) as exc:
        verify_experiment(out, baseline_manifest=m["baseline"], protected_manifest=m["protected"],
                          baseline_report=fx["reports"]["baseline"], protected_report=clean["reports"]["protected"])
    assert any(i.startswith("inputs: protected-evidence: binding:") or i == "inputs: protected.analysis: mismatch"
               for i in exc.value.issues)


# --- CLI ------------------------------------------------------------------------------------------

def test_cli_records_a_target_analysis_failure(tmp_path, capsys):
    fx = wildcard_pair(tmp_path, FAILING["protected"])
    paths, out = write_inputs(fx), tmp_path / "experiment"
    assert main(cli_args(paths, out, "--order-seed", "5")) == EXIT_NOT_COMPLETED
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["pair_status"] == "target_analysis_failure_observed"
    assert summary["interpretation"] == "not_evaluated"
    assert summary["trials"]["protected"] == {
        "trial_id": "2" * 32, "target_analysis": "decompilation_failed", "state": "analysis_failure_recorded",
        "outcome": "not_attempted_target_analysis_failed", "status": None, "stop_reason": None,
        "publication": None}
    assert summary["trials"]["baseline"]["outcome"] == "candidate_received"
    assert TIMEOUT_ERROR not in captured.out + captured.err  # exporter text never reaches the terminal
    assert "finished, target_analysis_failure_observed" in captured.err
    assert main(verify_args(paths, out)) == EXIT_COMPLETED


def test_cli_publication_failure_never_prints_analysis_diagnostics(tmp_path, monkeypatch, capsys):
    marker = "PRIVATE_GHIDRA_DIAGNOSTIC_31"
    fx = wildcard_pair(tmp_path, FAILING["protected"], message=marker)
    paths, out = write_inputs(fx), tmp_path / "experiment"
    original = paired_trial.publish_new_file

    def fail_paired(path, data, limit):
        if Path(path).name == PAIRED_RECORD_FILE:
            raise PublishError("write_failed")
        original(path, data, limit)

    monkeypatch.setattr(paired_trial, "publish_new_file", fail_paired)
    assert main(cli_args(paths, out)) == EXIT_PUBLICATION_FAILED
    captured = capsys.readouterr()
    assert marker not in captured.out + captured.err
    assert TIMEOUT_ERROR not in captured.out + captured.err
    assert json.loads(captured.out)["pair_status"] == "target_analysis_failure_observed"
    assert (out / RECONSTRUCTION_FILES["baseline"]).exists()
    assert not (out / PAIRED_RECORD_FILE).exists()


# --- Real Ghidra (opt-in) -------------------------------------------------------------------------

HEADLESS = os.environ.get("AEGIS_GHIDRA_HEADLESS")
CC = shutil.which("cc")
HEAVY_STATEMENTS = 1200


def _heavy_source(variant: str) -> str:
    """An AEGIS-owned fixture whose target is large enough to exceed a 1 s decompile timeout.

    The protected variant is a stand-in (a different constant), NOT a Shield output.
    """
    salt = 7 if variant == "protected" else 5
    lines = ["__attribute__((noinline)) int aegis_heavy(int a, int b) {", "  int x = a, y = b, z = a ^ b;"]
    for i in range(HEAVY_STATEMENTS):
        lines.append(f"  if ((x + {i}) & {1 + i % salt}) {{ y = y * {3 + i % 11} + x; }} "
                     f"else {{ z = z ^ (y + {i}); x = x + z; }}")
    lines += ["  return x + y + z; }",
              "int main(int argc, char **argv) { (void)argv; return aegis_heavy(argc, 5); }"]
    return "\n".join(lines) + "\n"


@pytest.mark.skipif(not HEADLESS or not CC, reason="real Ghidra test needs AEGIS_GHIDRA_HEADLESS and a C compiler")
def test_real_ghidra_decompiler_timeout_is_recorded(tmp_path):
    """Both reports are genuine real-Ghidra wildcard reports; nothing is edited."""
    options = {"function": "*", "decompile_timeout_seconds": 1, "analysis_timeout_seconds": 600,
               "wall_timeout_seconds": 1200}
    tool = planned_ghidra_tool(Path(HEADLESS), **options).model_dump(mode="json")
    manifests, reports = {}, {}
    for variant in ("baseline", "protected"):
        (tmp_path / f"{variant}.c").write_text(_heavy_source(variant))
        binary = tmp_path / f"{variant}.elf"
        subprocess.run([CC, "-O0", "-o", str(binary), str(tmp_path / f"{variant}.c")], check=True, timeout=300)
        sha = hashlib.sha256(binary.read_bytes()).hexdigest()  # compiled for analysis only; never executed
        reports[variant] = analyze(binary, tmp_path / f"out-{variant}", Path(HEADLESS), **options,
                                   expected_sha256=sha).read_bytes()
        data = manifest_data(protected=variant == "protected")
        data["target"].update(function="aegis_heavy", final_artifact_sha256=sha)
        data["attack"].update(tools=[tool], provider="FakeOffline",
                              **planned_attack_digests(max_model_tokens=4000, blinded=True))
        data["scoring"]["expected_interface"] = "opaque(int,int)->int"
        manifests[variant] = TrialManifest.model_validate(data)
    pair = prepare_pair(manifests["baseline"], manifests["protected"], reports["baseline"], reports["protected"])
    if pair.prepared:  # the decompiler finished within 1 s on this machine: no failure to observe
        pytest.skip("real decompiler did not time out on this host; the failure case was not exercised")
    for observation in pair.analysis.values():
        assert observation.status == "decompilation_failed" and observation.decompile_status == "timed_out"
        assert observation.report_decompiled_count >= 1  # other functions in the same report decompiled
    out = tmp_path / "experiment"
    result = run_paired_trial(pair, out, order_seed=3, provider_factory=Factory())
    assert result.record.outcome.pair_status == "target_analysis_failure_observed"
    assert result.record.totals.attempts == 0
    assert verify_experiment(out, baseline_manifest=manifests["baseline"], protected_manifest=manifests["protected"],
                             baseline_report=reports["baseline"], protected_report=reports["protected"]) \
        == result.record
