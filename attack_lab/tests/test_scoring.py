"""Phase 4: paired scoring through Core, comparison records, reload verification and the CLI.

Experiments come from the real Phase 3B runner with ``FakeProvider``. Execution goes through
Core's real sessions and grants. The runtime is Core's non-executing
``ScriptedIsolationRuntime``, except in the CLI and refusal tests, which use Core's
configured runtime and show it refusing. Process creation is patched to fail during scoring
to show that nothing is compiled or executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("aegis_core.lab_execution", reason="needs Role A's Core candidate-execution contract")

from aegis_core.lab_execution import sandbox_failure  # noqa: E402
from pydantic import ValidationError  # noqa: E402
from scoring_fixtures import (  # noqa: E402
    MASK,
    core_config,
    experiment,
    grant,
    gvisor_policy,
    reference,
    scripted,
)

from aegis_lab.behavior_score import ScoringInputError, parse_behavior_score  # noqa: E402
from aegis_lab.fake_provider import FakeProvider  # noqa: E402
from aegis_lab.paired_trial import PAIRED_RECORD_FILE, RECONSTRUCTION_FILES, parse_paired_trial_record  # noqa: E402
from aegis_lab.scoring import (  # noqa: E402
    COMPARISON_FILE,
    EXIT_INVALID,
    EXIT_OK,
    EXIT_REFUSED,
    SCORE_FILES,
    PairScoringInterrupted,
    PairScoringPublicationError,
    ScoreVerificationError,
    main,
    parse_behavior_comparison,
    score_paired_experiment,
    verify_behavior_scores,
)
from aegis_lab.scoring_policy import ExecutionRefused  # noqa: E402
from test_manifest import SECRET  # noqa: E402


def wrong(a, b, c):
    return (a * 3 + (b | c)) & MASK


def runtimes(*items):
    """A runtime factory handing out scripted runtimes (or given runtime objects) in call order."""
    pending = list(items)
    made = []

    def factory():
        item = pending.pop(0)
        runtime = item if hasattr(item, "compile_jobs") else scripted(behavior=item)
        made.append(runtime)
        return runtime
    factory.made = made
    return factory


def score(fx, out: Path, factory, **kwargs):
    if "grant" not in kwargs:
        kwargs["grant"] = grant(fx)
    kwargs.setdefault("config", fx["config"])
    return score_paired_experiment(fx["experiment"], out, manifests=fx["manifests"], reports=fx["reports"],
                                   suite_bytes=fx["suite"], policy=fx["policy"], runtime_factory=factory, **kwargs)


def verify(fx, out: Path, **kwargs):
    options = {"manifests": fx["manifests"], "reports": fx["reports"], "suite_bytes": fx["suite"],
               "policy": fx["policy"], **kwargs}
    return verify_behavior_scores(out, fx["experiment"], **options)


def tree_digest(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def make_experiment(tmp_path, **kwargs):
    fx = experiment(tmp_path, **kwargs)
    fx["config"] = core_config(tmp_path)
    return fx


@pytest.fixture(scope="module")
def fx(tmp_path_factory):
    return make_experiment(tmp_path_factory.mktemp("pair"))


@pytest.fixture
def no_processes(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("scoring must not create processes")
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse)
    for name in ("fork", "forkpty", "execv", "execve", "execvp", "posix_spawn", "posix_spawnp", "system"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, refuse)


def test_pair_is_scored_published_and_verified(fx, tmp_path, no_processes):
    before = tree_digest(fx["experiment"])
    factory = runtimes(reference, wrong)
    result = score(fx, tmp_path / "scores", factory)
    assert sorted(os.listdir(tmp_path / "scores")) == sorted(
        [*SCORE_FILES.values(), COMPARISON_FILE, "baseline-core-records", "protected-core-records"])
    assert (tmp_path / "scores").stat().st_mode & 0o777 == 0o700
    comparison = result.comparison
    assert comparison.outcome.status == "completed" and comparison.outcome.pattern == "baseline_only_passed"
    assert comparison.distinctions.valid_candidate.model_dump() == {"baseline": True, "protected": True}
    assert comparison.distinctions.hidden_suite_passed.model_dump() == {"baseline": True, "protected": False}
    assert comparison.distinctions.behaviorally_successful_reconstruction.model_dump() == {
        "baseline": "not_established", "protected": "not_established"}
    assert comparison.distinctions.paired_comparison_completed is True
    assert comparison.distinctions.protection_effect_established is False
    assert set(comparison.distinctions.protection_effect_reasons) == {
        "single_pair_is_not_statistical_evidence", "candidates_scripted_by_offline_fake_provider",
        "worker_is_test_double_no_execution"}
    # The original experiment is untouched and still says it was not scored.
    assert tree_digest(fx["experiment"]) == before
    paired = parse_paired_trial_record((fx["experiment"] / PAIRED_RECORD_FILE).read_bytes())
    assert paired.outcome.scoring == "not_performed"
    assert comparison.experiment.paired_file_sha256 == hashlib.sha256(
        (fx["experiment"] / PAIRED_RECORD_FILE).read_bytes()).hexdigest()
    assert verify(fx, tmp_path / "scores") == comparison
    # Each variant had its own Core session and runtime; both ran the same cases in the same order.
    first, second = factory.made
    assert first is not second and first.closed == second.closed == 1
    assert [j.args for j in first.execute_jobs] == [j.args for j in second.execute_jobs]
    base, prot = result.records["baseline"], result.records["protected"]
    assert base.run.core_session_id != prot.run.core_session_id
    assert base.result.grant == prot.result.grant


@pytest.mark.parametrize("behaviors,pattern", [
    ((reference, reference), "both_passed"),
    ((wrong, wrong), "both_failed"),
    ((wrong, reference), "protected_only_passed"),
])
def test_comparison_patterns(fx, tmp_path, behaviors, pattern):
    result = score(fx, tmp_path / "s", runtimes(*behaviors))
    assert result.comparison.outcome.pattern == pattern
    verify(fx, tmp_path / "s")


def test_shared_controls_are_identical_for_both_variants(fx, tmp_path):
    result = score(fx, tmp_path / "s", runtimes(reference, wrong))
    base, prot = result.records["baseline"].result, result.records["protected"].result
    for name in ("suite", "interface", "scorer", "score_rule", "configuration", "grant"):
        assert getattr(base, name) == getattr(prot, name)
    assert base.experiment == prot.experiment == result.comparison.experiment


@pytest.mark.parametrize("missing", [False, True])
def test_private_core_archives_are_required_and_integrity_checked(fx, tmp_path, missing):
    result = score(fx, tmp_path / "s", runtimes(reference, wrong))
    ref = result.records["baseline"].run.core_records[0]
    path = tmp_path / "s" / "baseline-core-records" / (ref.record_sha256 + ".json")
    assert path.stat().st_mode & 0o077 == 0
    raw = json.loads(path.read_bytes())
    assert raw["record_id"] == ref.record_id and "expected" not in raw
    if missing:
        path.unlink()
    else:
        path.write_bytes(b"tampered")
    with pytest.raises(ScoreVerificationError):
        verify(fx, tmp_path / "s")


def test_deterministic_reproduction(fx, tmp_path):
    # Same grant and inputs, two logically independent scorings, each with its own store.
    the_grant = grant(fx)
    one = score(fx, tmp_path / "one", runtimes(reference, wrong), grant=the_grant,
                config=core_config(tmp_path / "store-one"))
    two = score(fx, tmp_path / "two", runtimes(reference, wrong), grant=the_grant,
                config=core_config(tmp_path / "store-two"))
    for variant in SCORE_FILES:
        assert one.records[variant].result_sha256 == two.records[variant].result_sha256
    assert one.comparison.outcome == two.comparison.outcome
    assert one.comparison.comparison_id != two.comparison.comparison_id


def test_missing_candidate_makes_the_pair_not_comparable(tmp_path):
    fx = make_experiment(tmp_path, providers=(FakeProvider(source="int x;"), FakeProvider(content="```c\n```")))
    factory = runtimes(reference)
    result = score(fx, tmp_path / "s", factory, grant=grant(fx, variants=("baseline",)))
    assert len(factory.made) == 1
    comparison = result.comparison
    assert comparison.outcome.status == "not_comparable"
    assert comparison.outcome.reasons == ("protected_not_evaluated",)
    assert comparison.distinctions.valid_candidate.protected is False
    assert "paired_comparison_not_completed" in comparison.distinctions.protection_effect_reasons
    verify(fx, tmp_path / "s")


def test_infrastructure_failure_is_never_read_as_resistance(fx, tmp_path):
    broken = scripted(behavior=reference, preflight_error=sandbox_failure("sandbox_start_failed", "x"))
    result = score(fx, tmp_path / "s", runtimes(reference, broken))
    assert result.records["protected"].result.outcome.status == "infrastructure_failure"
    assert result.comparison.outcome.status == "not_comparable"
    assert result.comparison.outcome.reasons == ("protected_infrastructure_failure",)
    assert result.comparison.outcome.pattern is None
    assert result.comparison.distinctions.hidden_suite_passed.protected is False
    verify(fx, tmp_path / "s")


def test_unsupported_interface_is_not_comparable_and_never_contacts_core(tmp_path):
    fx = make_experiment(tmp_path, interface="pixel(int)->int", suite=b"{}\n")
    factory = runtimes()
    result = score(fx, tmp_path / "s", factory, grant=None, config=None)
    assert factory.made == []
    assert result.comparison.outcome.reasons == ("baseline_unsupported_interface", "protected_unsupported_interface")
    verify(fx, tmp_path / "s")


def test_identical_final_artifacts_are_flagged(tmp_path):
    fx = make_experiment(tmp_path, protected_binary=b"\x7fELF AEGIS-owned fixture variant-one")
    result = score(fx, tmp_path / "s", runtimes(reference, reference))
    assert result.comparison.final_artifacts_identical is True
    assert "final_artifacts_identical" in result.comparison.distinctions.protection_effect_reasons


def test_reusing_one_runtime_for_both_variants_is_refused(fx, tmp_path):
    shared = scripted(behavior=reference)
    with pytest.raises(ExecutionRefused) as caught:
        score(fx, tmp_path / "s", lambda: shared)
    assert caught.value.code == "runtime_reused"
    assert not (tmp_path / "s").exists() and shared.closed == 1


def test_interruption_publishes_partial_records_and_comparison(fx, tmp_path):
    def interrupt(job):
        raise KeyboardInterrupt
    factory = runtimes(scripted(execute=interrupt), reference)
    with pytest.raises(PairScoringInterrupted) as caught:
        score(fx, tmp_path / "s", factory)
    result = caught.value.result
    assert result.records["baseline"].result.outcome.stop_reason == "interrupted"
    assert result.records["protected"].result.outcome.stop_reason == "not_started"
    assert result.comparison.outcome.reasons == ("baseline_incomplete", "protected_incomplete")
    assert verify(fx, tmp_path / "s") == result.comparison
    # The protected session was opened before the run and is released, never used.
    assert factory.made[1].closed == 1 and factory.made[1].compile_jobs == []


def test_grant_refusals_happen_before_any_output_or_runtime(fx, tmp_path):
    factory = runtimes(reference, reference)
    with pytest.raises(ExecutionRefused) as caught:
        score(fx, tmp_path / "s", factory, grant=grant(fx, variants=("baseline",)))
    assert caught.value.code == "grant_candidate_not_listed"
    assert not (tmp_path / "s").exists() and factory.made == []
    with pytest.raises(ExecutionRefused) as caught:
        score(fx, tmp_path / "s", factory, grant=None)
    assert caught.value.code == "grant_missing" and not (tmp_path / "s").exists()


def test_core_refusals_happen_before_any_output(fx, tmp_path):
    factory = runtimes(reference, reference)
    with pytest.raises(ExecutionRefused) as caught:
        score(fx, tmp_path / "s", factory, config=core_config(tmp_path, candidate_execution=False))
    assert (caught.value.code, caught.value.reasons) == ("core_refused", ("candidate_execution_disabled",))
    assert not (tmp_path / "s").exists() and factory.made == []


def test_second_session_refusal_releases_the_first(fx, tmp_path):
    first = scripted(behavior=reference)
    second = scripted(behavior=reference, preflight_error=OSError("no runtime"))
    with pytest.raises(ExecutionRefused) as caught:
        score(fx, tmp_path / "s", runtimes(first, second))
    assert caught.value.code == "sandbox_unavailable"
    assert first.closed == 1 and not (tmp_path / "s").exists()


def test_cores_configured_runtime_refuses_before_any_output(tmp_path):
    fx = make_experiment(tmp_path, policy=gvisor_policy())
    with pytest.raises(ExecutionRefused) as caught:
        score(fx, tmp_path / "s", None)
    assert caught.value.code == "sandbox_unavailable"
    assert "isolation_adr_not_accepted" in caught.value.reasons
    assert not (tmp_path / "s").exists()


def test_existing_output_directory_is_refused(fx, tmp_path):
    (tmp_path / "s").mkdir()
    factory = runtimes(reference, reference)
    with pytest.raises(PairScoringPublicationError) as caught:
        score(fx, tmp_path / "s", factory)
    assert caught.value.category == "already_exists"
    assert all(r.closed == 1 and r.compile_jobs == [] for r in factory.made)
    (tmp_path / "link").symlink_to(tmp_path / "s")
    with pytest.raises(PairScoringPublicationError):
        score(fx, tmp_path / "link", runtimes(reference, reference))


def copy_experiment(fx, tmp_path) -> dict:
    target = tmp_path / "copy"
    shutil.copytree(fx["experiment"], target)
    return {**fx, "experiment": target}


def test_tampered_experiment_is_rejected_before_scoring(fx, tmp_path):
    copy = copy_experiment(fx, tmp_path)
    the_grant = grant(fx)
    path = copy["experiment"] / RECONSTRUCTION_FILES["protected"]
    doc = json.loads(path.read_bytes())
    doc["candidate"]["source"] += "\n"
    path.write_text(json.dumps(doc))
    with pytest.raises(ScoringInputError) as caught:
        score(copy, tmp_path / "s", runtimes(reference, reference), grant=the_grant)
    assert all(i.startswith("experiment: ") for i in caught.value.issues)
    assert not (tmp_path / "s").exists()


def test_swapped_inputs_are_rejected(fx, tmp_path):
    swapped = {**fx, "reports": {"baseline": fx["reports"]["protected"], "protected": fx["reports"]["baseline"]}}
    with pytest.raises(ScoringInputError):
        score(swapped, tmp_path / "s", runtimes(reference, reference))
    with pytest.raises(ScoringInputError) as caught:
        score_paired_experiment(fx["experiment"], tmp_path / "s", manifests={}, reports={}, suite_bytes=fx["suite"],
                                policy=fx["policy"], config=fx["config"], grant=None)
    assert caught.value.issues == ["inputs: incomplete: both manifests and both reports are required"]


def test_replaced_output_directory_stops_publication(fx, tmp_path):
    out = tmp_path / "s"

    def replacing(job):
        if not (tmp_path / "moved").exists():
            os.rename(out, tmp_path / "moved")
            out.mkdir()
        return reference_result(job)
    with pytest.raises(PairScoringPublicationError) as caught:
        score(fx, out, runtimes(scripted(execute=replacing), reference))
    assert caught.value.category == "directory_replaced"
    assert os.listdir(out) == [] and os.listdir(tmp_path / "moved") == []


def reference_result(job):
    from scoring_fixtures import result_observation

    return result_observation(reference(*(int(a) for a in job.args)))


# --- Verification of published scores --------------------------------------------------------------

@pytest.fixture
def scored(fx, tmp_path):
    out = tmp_path / "scores"
    score(fx, out, runtimes(reference, wrong))
    return out


def edit_json(path: Path, mutate) -> None:
    os.chmod(path, 0o600)
    doc = json.loads(path.read_bytes())
    mutate(doc)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


def test_verify_detects_an_edited_score(fx, scored):
    edit_json(scored / SCORE_FILES["protected"], lambda d: d["result"]["limitations"].append("edited"))
    with pytest.raises(ScoreVerificationError) as caught:
        verify(fx, scored)
    assert any(i.startswith("protected-score: ") for i in caught.value.issues)


def test_verify_detects_a_consistently_rewritten_score(fx, scored):
    edit_json(scored / SCORE_FILES["baseline"], lambda d: d["run"].__setitem__("score_id", "f" * 32))
    with pytest.raises(ScoreVerificationError) as caught:
        verify(fx, scored)
    assert "baseline-score: reference: mismatch" in caught.value.issues


def test_verify_detects_swapped_score_files(fx, scored):
    a, b = scored / SCORE_FILES["baseline"], scored / SCORE_FILES["protected"]
    data_a, data_b = a.read_bytes(), b.read_bytes()
    os.chmod(a, 0o600)
    os.chmod(b, 0o600)
    a.write_bytes(data_b)
    b.write_bytes(data_a)
    with pytest.raises(ScoreVerificationError) as caught:
        verify(fx, scored)
    assert "baseline-score: trial_id: mismatch" in caught.value.issues


def test_verify_detects_a_missing_score_and_comparison(fx, scored):
    os.unlink(scored / SCORE_FILES["protected"])
    with pytest.raises(ScoreVerificationError) as caught:
        verify(fx, scored)
    assert "protected-score: not_found" in caught.value.issues
    os.unlink(scored / COMPARISON_FILE)
    with pytest.raises(ScoreVerificationError) as caught:
        verify(fx, scored)
    assert caught.value.issues == ["comparison: not_found"]


@pytest.mark.parametrize("mutate", [
    lambda d: d["outcome"].__setitem__("pattern", "both_passed"),
    lambda d: d["distinctions"].__setitem__("protection_effect_established", True),
    lambda d: d["distinctions"]["behaviorally_successful_reconstruction"].__setitem__("baseline", "established"),
    lambda d: d["scores"][1].__setitem__("criterion_satisfied", True),
    lambda d: d["scores"].reverse(),
    lambda d: d.__setitem__("attacker_visible", True),
])
def test_comparison_invariants_are_enforced(scored, mutate):
    path = scored / COMPARISON_FILE
    doc = json.loads(path.read_bytes())
    mutate(doc)
    with pytest.raises(ValidationError):
        parse_behavior_comparison(json.dumps(doc).encode())


def test_verify_detects_a_replaced_experiment(fx, scored, tmp_path):
    copy = copy_experiment(fx, tmp_path)
    edit_json(copy["experiment"] / PAIRED_RECORD_FILE, lambda d: d["limitations"].append("edited"))
    with pytest.raises(ScoreVerificationError) as caught:
        verify_behavior_scores(scored, copy["experiment"])
    assert "comparison: experiment: mismatch" in caught.value.issues


def test_verify_checks_suite_and_policy(fx, scored):
    with pytest.raises(ScoreVerificationError) as caught:
        verify(fx, scored, suite_bytes=fx["suite"] + b" ")
    assert caught.value.issues == ["inputs: suite: mismatch"]
    with pytest.raises(ScoreVerificationError) as caught:
        verify_behavior_scores(scored, fx["experiment"], policy=gvisor_policy())
    assert caught.value.issues == ["inputs: policy: mismatch"]
    assert verify_behavior_scores(scored, fx["experiment"]).outcome.status == "completed"


# --- CLI ---------------------------------------------------------------------------------------------

def write(tmp_path: Path, name: str, data: bytes | dict | str) -> Path:
    path = tmp_path / name
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
    return path


def pair_args(fx, tmp_path) -> list[str]:
    args = []
    for variant in SCORE_FILES:
        manifest = write(tmp_path, f"{variant}-manifest.json", fx["manifests"][variant].model_dump(mode="json"))
        report = write(tmp_path, f"{variant}-report.json", fx["reports"][variant])
        args += [f"--{variant}-manifest", str(manifest), f"--{variant}-evidence", str(report)]
    return args


CONFIG_ENABLED = "[attack_lab]\nenabled = true\n[attack_lab.candidate_execution]\nenabled = true\n"


def test_cli_plan_and_suite_digest(fx, tmp_path, capsys):
    policy = write(tmp_path, "policy.json", fx["policy"].model_dump(mode="json"))
    assert main(["plan", "--policy", str(policy)]) == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["scorer"] == fx["manifests"]["baseline"].scoring.scorer.model_dump(mode="json")
    assert out["sandbox_policy_sha256"] == fx["policy"].sha256()
    suite = write(tmp_path, "suite.json", fx["suite"])
    assert main(["suite-digest", str(suite)]) == EXIT_OK
    printed = capsys.readouterr().out
    assert json.loads(printed) == {"hidden_test_suite_sha256": hashlib.sha256(fx["suite"]).hexdigest(),
                                   "abi": "aegis.lab.c-abi.scalar-u32.v1", "case_count": 8}
    assert str(reference(1, 2, 3)) not in printed


def cli_score(fx, tmp_path, *, config=CONFIG_ENABLED, the_grant=None, out=None):
    policy = write(tmp_path, "policy.json", fx["policy"].model_dump(mode="json"))
    suite = write(tmp_path, "suite.json", fx["suite"])
    config_path = write(tmp_path, "aegis.toml", config)
    grant_path = write(tmp_path, "grant.json", (the_grant or grant(fx)).model_dump(mode="json"))
    return main(["score-pair", str(fx["experiment"]), *pair_args(fx, tmp_path), "--suite", str(suite),
                 "--policy", str(policy), "--config", str(config_path), "--grant", str(grant_path),
                 "--output-dir", str(out or tmp_path / "scores")])


def test_cli_score_pair_goes_through_core_which_refuses(fx, tmp_path, capsys):
    assert cli_score(fx, tmp_path) == EXIT_REFUSED
    err = capsys.readouterr().err
    assert "sandbox_unavailable" in err and "isolation_adr_not_accepted" in err
    assert not (tmp_path / "scores").exists()


def test_cli_score_pair_reports_core_gate_refusals(fx, tmp_path, capsys):
    assert cli_score(fx, tmp_path, config="[attack_lab]\nenabled = false\n") == EXIT_REFUSED
    assert "core_refused (attack_lab_disabled)" in capsys.readouterr().err
    assert cli_score(fx, tmp_path, the_grant=grant(fx, variants=("baseline",))) == EXIT_REFUSED
    assert "grant_candidate_not_listed" in capsys.readouterr().err
    assert not (tmp_path / "scores").exists()


def test_cli_score_pair_reports_invalid_input_without_leaking(fx, tmp_path, capsys):
    policy = write(tmp_path, "policy.json", {**fx["policy"].model_dump(mode="json"), "note": SECRET})
    suite = write(tmp_path, "suite.json", fx["suite"])
    code = main(["score-pair", str(fx["experiment"]), *pair_args(fx, tmp_path), "--suite", str(suite),
                 "--policy", str(policy), "--output-dir", str(tmp_path / "scores")])
    assert code == EXIT_INVALID
    err = capsys.readouterr().err
    assert "policy: <unknown>: unknown_field" in err and "config: missing" in err and "grant: missing" in err
    assert SECRET not in err and str(tmp_path) not in err
    bad_grant = write(tmp_path, "bad-grant.json", {"schema_version": SECRET})
    good_policy = write(tmp_path, "good.json", fx["policy"].model_dump(mode="json"))
    config = write(tmp_path, "aegis.toml", CONFIG_ENABLED)
    code = main(["score-pair", str(fx["experiment"]), *pair_args(fx, tmp_path), "--suite", str(suite),
                 "--policy", str(good_policy), "--config", str(config), "--grant", str(bad_grant),
                 "--output-dir", str(tmp_path / "scores")])
    assert code == EXIT_INVALID
    err = capsys.readouterr().err
    assert "grant: INVALID_REQUEST" in err and SECRET not in err
    wrong_suite = write(tmp_path, "wrong.json", fx["suite"] + b" ")
    good_grant = write(tmp_path, "grant.json", grant(fx).model_dump(mode="json"))
    code = main(["score-pair", str(fx["experiment"]), *pair_args(fx, tmp_path), "--suite", str(wrong_suite),
                 "--policy", str(good_policy), "--config", str(config), "--grant", str(good_grant),
                 "--output-dir", str(tmp_path / "scores")])
    assert code == EXIT_INVALID
    assert "baseline-suite: hidden_test_suite_sha256: mismatch" in capsys.readouterr().err


def test_cli_verify(fx, scored, tmp_path, capsys):
    suite = write(tmp_path, "suite.json", fx["suite"])
    assert main(["verify", str(scored), str(fx["experiment"]), *pair_args(fx, tmp_path), "--suite",
                 str(suite)]) == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["verification"] == "consistent" and out["protection_effect_established"] is False
    edit_json(scored / SCORE_FILES["baseline"], lambda d: d["result"]["limitations"].append(SECRET))
    assert main(["verify", str(scored), str(fx["experiment"])]) == EXIT_INVALID
    err = capsys.readouterr().err
    assert "baseline-score" in err and SECRET not in err


def test_published_records_parse_and_are_never_attacker_visible(fx, scored):
    for name in SCORE_FILES.values():
        record = parse_behavior_score((scored / name).read_bytes())
        assert record.attacker_visible is False and record.record_signed is False
    assert parse_behavior_comparison((scored / COMPARISON_FILE).read_bytes()).attacker_visible is False


def test_rescoring_a_pair_with_a_used_grant_is_refused_before_any_output(fx, tmp_path):
    the_grant = grant(fx)
    score(fx, tmp_path / "first", runtimes(reference, reference), grant=the_grant)
    factory = runtimes(reference, reference)
    with pytest.raises(ExecutionRefused) as caught:
        score(fx, tmp_path / "second", factory, grant=the_grant)
    assert caught.value.code == "grant_budget_insufficient"
    assert factory.made == [] and not (tmp_path / "second").exists()


def test_interrupted_pair_does_not_reset_the_grant_budget(fx, tmp_path):
    the_grant = grant(fx)

    def interrupt(job):
        raise KeyboardInterrupt
    with pytest.raises(PairScoringInterrupted):
        score(fx, tmp_path / "s", runtimes(scripted(execute=interrupt), reference), grant=the_grant)
    from aegis_core.lab_ledger import GrantLedger

    usage = GrantLedger.for_config(fx["config"]).usage(the_grant.grant_id)
    assert usage.sessions_opened == 2
    assert usage.compilations == {fx["manifests"]["baseline"].trial_id: 1}
    with pytest.raises(ExecutionRefused) as caught:
        score(fx, tmp_path / "again", runtimes(reference, reference), grant=the_grant)
    assert caught.value.code == "grant_budget_insufficient"


def test_pairs_with_different_enforced_limits_are_not_comparable(fx, tmp_path):
    from aegis_lab.scoring import _derive

    result = score(fx, tmp_path / "s", runtimes(reference, reference))
    base, prot = result.comparison.scores
    assert (base.enforced_execute_limits_sha256, prot.enforced_execute_limits_sha256) == (None, None)
    assert _derive((base, prot), False)[0].status == "completed"
    same = {"enforced_execute_limits_sha256": "a" * 64}
    assert _derive((base.model_copy(update=same), prot.model_copy(update=same)), False)[0].status == "completed"
    outcome, distinctions = _derive((base.model_copy(update=same),
                                     prot.model_copy(update={"enforced_execute_limits_sha256": "b" * 64})), False)
    assert (outcome.status, outcome.reasons) == ("not_comparable", ("enforced_execute_limits_differ",))
    assert distinctions.paired_comparison_completed is False
    # Only one side observed (e.g. the other failed to compile): nothing to compare, not a difference.
    one_sided = _derive((base.model_copy(update=same), prot), False)[0]
    assert one_sided.status == "completed"
