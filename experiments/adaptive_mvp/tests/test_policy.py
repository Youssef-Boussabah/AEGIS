"""Policy fixtures are measurements for tests, never security evidence."""
from copy import deepcopy

import pytest

from experiments.adaptive_mvp.evidence import resistance_for
from experiments.adaptive_mvp.policy import Constraints, POOL, next_configuration, select


def measured(candidate_id="c001", config=POOL[0], size=100, ratio=1.0, retained=True):
    return {"candidate_id": candidate_id, "configuration": config.__dict__,
            "status": "VERIFIED", "artifact": {"sha256": "a" * 64, "size_bytes": size},
            "correctness": {"status": "passed"}, "retention": {"any_observed": retained},
            "size_ratio": size / 100, "performance": {"median_ratio": ratio},
            "resistance": resistance_for("a" * 64, [])}


def test_unmeasured_is_explicit_and_size_is_the_primary_objective():
    small = measured("c001", size=102, ratio=2.0)
    fast = measured("c002", size=105, ratio=1.0)
    result = select([small, fast], Constraints())
    assert result["selected_candidate_id"] == "c001"
    assert result["resistance"] == "UNMEASURED"
    assert result["security_claim"] == "none"
    assert small["resistance"]["score"] is None


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("status", "FAILED", "candidate_not_verified"),
    ("correctness", {"status": "failed"}, "correctness_not_passed"),
    ("retention", {"any_observed": False}, "no_final_transformation_observed"),
    ("size_ratio", 1.2, "size_constraint_exceeded"),
    ("performance", {"median_ratio": 4.0}, "performance_constraint_exceeded"),
])
def test_each_constraint_rejects_the_candidate(field, value, reason):
    candidate = measured()
    candidate[field] = value
    result = select([candidate], Constraints())
    assert result["selected_candidate_id"] is None
    assert reason in result["decisions"][0]["reasons"]


def test_evidence_required_does_not_default_enable_or_invent_attacks():
    candidate = measured()
    result = select([candidate], Constraints(require_attack_evidence=True))
    assert result["selected_candidate_id"] is None
    assert result["decisions"][0]["reasons"] == ["attack_evidence_required_but_unmeasured"]


@pytest.mark.parametrize("outcome", ["unscored", "inconclusive"])
def test_unscored_or_inconclusive_does_not_measure_resistance(outcome):
    candidate = measured()
    candidate["resistance"] = resistance_for("a" * 64, [{"artifact_sha256": "a" * 64, "outcome": outcome}])
    assert candidate["resistance"]["status"] == "UNMEASURED"
    assert select([candidate], Constraints(require_attack_evidence=True))["selected_candidate_id"] is None


def test_verified_success_vetoes_and_changes_the_next_probe():
    candidate = measured(config=POOL[1])
    candidate["resistance"] = resistance_for("a" * 64, [
        {"artifact_sha256": "a" * 64, "outcome": "reconstruction_succeeded"}])
    result = select([candidate], Constraints())
    assert result["selected_candidate_id"] is None
    next_config, why = next_configuration([candidate], Constraints())
    assert next_config.name == "hybrid-6"
    assert "externally verified reconstruction succeeded" in why["reason"]
    assert "unproven hypothesis" in why["reason"]


def test_failed_attack_never_becomes_a_score_or_outweighs_measured_cost():
    cheap, costly = measured(), measured("c002", size=109)
    costly["resistance"] = resistance_for("a" * 64, [
        {"artifact_sha256": "a" * 64, "outcome": "reconstruction_failed"}])
    assert costly["resistance"]["score"] is None
    assert select([cheap, costly], Constraints())["selected_candidate_id"] == "c001"
    assert select([cheap, costly], Constraints(require_attack_evidence=True))["selected_candidate_id"] == "c002"


def test_wrong_artifact_hash_cannot_affect_selection():
    candidate = measured()
    candidate["resistance"] = resistance_for("a" * 64, [
        {"artifact_sha256": "b" * 64, "outcome": "reconstruction_succeeded"}])
    assert candidate["resistance"]["evidence"] == []
    assert select([candidate], Constraints())["selected_candidate_id"] == "c001"


def test_full_feedback_path_uses_observations_and_has_a_finite_stop():
    history = []
    expected = ["shield-2", "hybrid-3", "hybrid-1", "hybrid-1-site1"]
    for index, name in enumerate(expected):
        configuration, reason = next_configuration(history, Constraints())
        assert configuration.name == name
        assert reason["observed_candidate_id"] == (history[-1]["candidate_id"] if history else None)
        candidate = measured(f"c{index + 1:03d}", configuration, retained=index != 0)
        history.append(candidate)
    assert next_configuration(history, Constraints())[0] is None
    assert "matched the baseline" in next_configuration(history[:1], Constraints())[1]["reason"]


def test_failed_build_has_a_bounded_fallback_and_never_repeats():
    failed = measured()
    failed["status"] = "FAILED"
    config, reason = next_configuration([failed], Constraints())
    assert config.name == "hybrid-1"
    assert "failed" in reason["reason"]
    second = deepcopy(failed)
    second["configuration"] = config.__dict__
    assert next_configuration([failed, second], Constraints())[0] is None


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), True])
def test_invalid_constraints_fail_closed(value):
    with pytest.raises(ValueError):
        Constraints(max_time_ratio=value)
