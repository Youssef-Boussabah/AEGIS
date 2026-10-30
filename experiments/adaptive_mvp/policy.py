"""Small, explicit feedback policy. No model calls and no proxy security score."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math


@dataclass(frozen=True)
class Constraints:
    max_size_ratio: float = 1.10
    max_time_ratio: float = 3.0
    require_retention: bool = True
    require_attack_evidence: bool = False
    reject_successful_reconstruction: bool = True

    def __post_init__(self):
        for value in (self.max_size_ratio, self.max_time_ratio):
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError("ratios_must_be_positive_and_finite")
        for value in (self.require_retention, self.require_attack_evidence,
                      self.reject_successful_reconstruction):
            if type(value) is not bool:
                raise ValueError("constraints_require_booleans")


@dataclass(frozen=True)
class Configuration:
    name: str
    backend: str
    sites: int
    decoys: int = 0
    seed: str = "42"

    def options(self):
        result = {"seed": self.seed, "max-sites": self.sites}
        if self.decoys:
            result.update({"mirage-count": self.decoys, "mirage-seed": "42"})
        return result


POOL = (
    Configuration("shield-2", "llvm-shield", 2),
    Configuration("hybrid-3", "llvm-shield-mirage", 2, 3),
    Configuration("hybrid-1", "llvm-shield-mirage", 2, 1),
    Configuration("hybrid-6", "llvm-shield-mirage", 2, 6),
    Configuration("hybrid-1-site1", "llvm-shield-mirage", 1, 1),
)


def rejection_reasons(candidate: dict, constraints: Constraints) -> list[str]:
    reasons = []
    if candidate.get("status") != "VERIFIED":
        return ["candidate_not_verified"]
    if candidate.get("correctness", {}).get("status") != "passed":
        reasons.append("correctness_not_passed")
    if constraints.require_retention and not candidate["retention"]["any_observed"]:
        reasons.append("no_final_transformation_observed")
    if candidate["size_ratio"] > constraints.max_size_ratio:
        reasons.append("size_constraint_exceeded")
    if candidate["performance"]["median_ratio"] > constraints.max_time_ratio:
        reasons.append("performance_constraint_exceeded")
    attack = candidate["resistance"]
    if constraints.require_attack_evidence and attack["status"] == "UNMEASURED":
        reasons.append("attack_evidence_required_but_unmeasured")
    if constraints.reject_successful_reconstruction and any(
            item["outcome"] == "reconstruction_succeeded" for item in attack["evidence"]):
        reasons.append("verified_reconstruction_succeeded")
    return reasons


def select(candidates: list[dict], constraints: Constraints) -> dict:
    eligible = []
    decisions = []
    for candidate in candidates:
        reasons = rejection_reasons(candidate, constraints)
        decisions.append({"candidate_id": candidate["candidate_id"], "eligible": not reasons,
                          "reasons": reasons})
        if not reasons:
            eligible.append(candidate)
    # Evidence is a gate/veto, never an invented numeric resistance score. Do
    # not rank unscored, inconclusive and failed attacks as ordered numbers.
    eligible.sort(key=lambda item: (item["artifact"]["size_bytes"],
                                   item["performance"]["median_ratio"], item["candidate_id"]))
    winner = eligible[0] if eligible else None
    return {"selected_candidate_id": winner["candidate_id"] if winner else None,
            "status": "selected" if winner else "no_verified_candidate_satisfies_constraints",
            "objective": ["minimum_final_elf_bytes", "minimum_measured_median_time_ratio", "candidate_id"],
            "constraints": asdict(constraints), "decisions": decisions,
            "resistance": winner["resistance"]["status"] if winner else "UNMEASURED",
            "security_claim": "none"}


def next_configuration(history: list[dict], constraints: Constraints) -> tuple[Configuration | None, dict]:
    used = {item["configuration"]["name"] for item in history}
    last = history[-1] if history else None
    reason = "Initial bounded probe: measure Shield at two eligible sites before adding decoys."
    preferred = "shield-2"
    if last:
        name = last["configuration"]["name"]
        reasons = rejection_reasons(last, constraints)
        if "verified_reconstruction_succeeded" in reasons:
            preferred = "hybrid-6"
            reason = "An externally verified reconstruction succeeded; probe six retained decoys. This is an unproven hypothesis, not a resistance improvement."
        elif last["status"] != "VERIFIED":
            preferred = "hybrid-1"
            reason = "The previous build/check failed; try the bounded one-decoy configuration without accepting the failed artifact."
        elif name == "shield-2":
            preferred = "hybrid-3"
            reason = ("Shield machine code matched the baseline; probe three Mirage decoys for observable final retention."
                      if not last["retention"]["any_observed"] else
                      "Shield changed final code; probe three Mirage decoys to measure their additional size and runtime cost.")
        elif name in ("hybrid-3", "hybrid-6"):
            preferred = "hybrid-1"
            reason = "Reduce retained decoys to one and remeasure correctness, size and runtime; fewer bytes is the declared objective."
        elif name == "hybrid-1":
            preferred = "hybrid-1-site1"
            reason = "Probe one Shield site while keeping the same single Mirage decoy; measure whether reduced work changes the final artifact."
        else:
            return None, {"reason": "Bounded feedback plan completed; no justified next probe.",
                          "observed_candidate_id": last["candidate_id"]}
        if preferred in used:
            return None, {"reason": "Feedback would repeat a configuration already measured; stop without inventing new evidence.",
                          "observed_candidate_id": last["candidate_id"]}
    return next(item for item in POOL if item.name == preferred), {
        "reason": reason, "observed_candidate_id": last["candidate_id"] if last else None,
        "observed_rejections": rejection_reasons(last, constraints) if last else [],
        "incumbent_before_probe": select(history, constraints)["selected_candidate_id"],
    }
