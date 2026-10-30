"""Three-variant inference trial using existing strict baseline/protected validation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import sys

from pydantic import BaseModel, ConfigDict, Field, StrictInt
from typing import Literal

from .canonical import canonical_json_bytes
from .experiment import WorkflowConfig, run_experiment
from .inference import load_approval
from .live import preflight, record_failure
from .manifest import load_manifest, validate_pair
from .private_evidence import PrivateEvidence
from .reconstruction import prepare_reconstruction
from .safe_io import parse_strict_json, publish_new_file, read_regular_file

NAMES = ("baseline", "shield", "mirage")


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    manifest: Path
    report: Path
    artifact: Path
    approval: Path | None = None


class TrialPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["aegis.lab.live-trial-plan.v1"] = "aegis.lab.live-trial-plan.v1"
    baseline: Target
    shield: Target
    mirage: Target
    configuration: WorkflowConfig = WorkflowConfig(max_steps=1)
    max_output_tokens: StrictInt | None = Field(default=None, ge=1, le=100_000)
    order_seed: StrictInt = Field(ge=0, le=2**63 - 1, default=0)


def prepare_plan(plan):
    prepared, approvals, summaries = {}, {}, {}
    for name in NAMES:
        target = getattr(plan, name)
        prepared[name] = prepare_reconstruction(load_manifest(target.manifest), read_regular_file(target.report, 8 * 1024 * 1024),
                                                  max_output_tokens=plan.max_output_tokens)
        approval = None if target.approval is None else load_approval(target.approval)
        approvals[name] = approval
        summaries[name] = preflight(prepared[name], target.artifact, plan.configuration, approval)
    for name in NAMES[1:]:
        pair = validate_pair(prepared["baseline"].manifest, prepared[name].manifest)
        if pair.final_artifacts_identical:
            raise ValueError("transformed_final_artifact_required")
    if prepared["shield"].artifact_sha256 == prepared["mirage"].artifact_sha256:
        raise ValueError("distinct_mirage_artifact_required")
    if len({p.trial_id for p in prepared.values()}) != 3:
        raise ValueError("distinct_trial_ids_required")
    if any(approvals.values()):
        if not all(approvals.values()):
            raise ValueError("all_three_approvals_required")
        limits = [(a.max_requests, a.max_total_tokens, a.max_spend_microusd, a.context_tokens,
                   a.input_microusd_per_million, a.output_microusd_per_million, a.request_timeout_seconds)
                  for a in approvals.values()]
        if len(set(limits)) != 1:
            raise ValueError("equal_inference_budgets_required")
    return prepared, approvals, summaries


def run_trial(plan, output_dir, *, provider_factory=None):
    """Every target has a fresh provider; failures remain generation failures, never scores."""
    from .bounded_provider import BoundedNebiusProvider

    prepared, approvals, summaries = prepare_plan(plan)
    if not all(approvals.values()):
        raise ValueError("all_three_approvals_required")
    output_dir.mkdir(mode=0o700)
    archive = PrivateEvidence(output_dir / "private-plan")
    plan_sha = archive.put(canonical_json_bytes(plan.model_dump(mode="json")))
    order = list(NAMES)
    random.Random(plan.order_seed).shuffle(order)
    outcomes = {}
    made = []

    def fresh(sink):
        provider = (provider_factory(sink) if provider_factory else
                    BoundedNebiusProvider.from_environment(allow_live=True, evidence_sink=sink))
        if any(provider is previous for previous in made):
            raise ValueError("provider_session_reused")
        if made and provider.identity != made[0].identity:
            raise ValueError("provider_identity_changed")
        made.append(provider)
        return provider

    for name in order:
        target = getattr(plan, name)
        try:
            record = run_experiment(prepared[name], target.artifact, output_dir / name,
                configuration=plan.configuration, provider_factory=fresh, inference_approval=approvals[name],
                allow_live=True, approval_state_dir=target.approval.parent / ".inference-uses")
            outcomes[name] = {"generation_status": record.generation_status,
                              "record_sha256": hashlib.sha256((output_dir / name / "experiment.json").read_bytes()).hexdigest(),
                              "reported_models": sorted({s.reported_model for s in record.steps if s.reported_model}),
                              "reported_fingerprints": sorted({s.system_fingerprint for s in record.steps if s.system_fingerprint}),
                              "requests": len(record.steps), "charged_tokens": record.charged_tokens,
                              "reserved_spend_microusd": record.reserved_spend_microusd}
        except KeyboardInterrupt:
            outcomes[name] = {"generation_status": "interrupted"}
            break
        except Exception as exc:
            from .disclosure import AuthorizationError
            from .provider import ProviderError
            code = exc.code if isinstance(exc, AuthorizationError) else exc.category if isinstance(exc, ProviderError) else "infrastructure_failure"
            outcomes[name] = {"generation_status": code, "record_sha256": None}
    for name in NAMES:
        outcomes.setdefault(name, {"generation_status": "not_started"})
    identities = [(o.get("reported_models"), o.get("reported_fingerprints")) for o in outcomes.values()]
    result = {"schema_version": "aegis.lab.live-trial.v1", "private_plan_sha256": plan_sha,
              "order": order, "order_seed": plan.order_seed, "outcomes": outcomes,
              "reported_identity_comparable": all(x == identities[0] for x in identities)
                  and bool(identities[0][0]) and bool(identities[0][1]),
              "behavioral_scoring": "pending_authorized_core_runtime", "execution_performed": False,
              "protection_effect": "not_established"}
    publish_new_file(output_dir / "live-trial.json", canonical_json_bytes(result), 1024 * 1024)
    return result


def main(argv=None):
    from .diagnostics import SafeArgumentParser

    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "run"))
    parser.add_argument("plan", type=Path)
    parser.add_argument("--approve-live-inference", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        plan = TrialPlan.model_validate(parse_strict_json(read_regular_file(args.plan, 64 * 1024)))
        if args.command == "preflight":
            _, approvals, summaries = prepare_plan(plan)
            print(json.dumps({"targets": summaries, "network_requests": 0, "billable_requests": 0,
                "aggregate_max_spend_microusd": sum(a.max_spend_microusd for a in approvals.values()) if all(approvals.values()) else None}, indent=2))
            return 0
        if not args.approve_live_inference or args.output_dir is None:
            raise ValueError("explicit_live_opt_in_and_output_required")
        result = run_trial(plan, args.output_dir)
        print(json.dumps(result, sort_keys=True))
        return 0 if all(o["generation_status"] == "generated_but_behaviorally_unscored" for o in result["outcomes"].values()) else 1
    except Exception:
        record_failure(args.output_dir, "invalid_input_or_publication")
        print("live_trial_plan_failed: invalid_input_or_publication", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
