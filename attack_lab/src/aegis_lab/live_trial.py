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
from .experiment import WorkflowConfig, run_experiment, verify_experiment
from .inference import load_approval
from .live import preflight, record_failure
from .manifest import load_manifest, validate_pair
from .private_evidence import PrivateEvidence
from .reconstruction import prepare_reconstruction
from .safe_io import parse_strict_json, publish_new_file, read_regular_file

NAMES = ("baseline", "shield", "mirage")


def identity_comparable(outcomes):
    identities = [(o.get("reported_models"), o.get("reported_fingerprints")) for o in outcomes.values()]
    return (all(x == identities[0] for x in identities)
            and all(o.get("reported_identity_complete") is True for o in outcomes.values())
            and len(identities[0][0] or []) == len(identities[0][1] or []) == 1)


def experiment_outcome(record, digest):
    return {"generation_status": record.generation_status, "record_sha256": digest,
            "reported_models": sorted({s.reported_model for s in record.steps if s.reported_model}),
            "reported_fingerprints": sorted({s.system_fingerprint for s in record.steps if s.system_fingerprint}),
            "reported_identity_complete": bool(record.steps) and all(s.reported_model and s.system_fingerprint for s in record.steps),
            "requests": len(record.steps), "charged_tokens": record.charged_tokens,
            "reserved_spend_microusd": record.reserved_spend_microusd}


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
            outcomes[name] = experiment_outcome(record,
                hashlib.sha256((output_dir / name / "experiment.json").read_bytes()).hexdigest())
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
    result = {"schema_version": "aegis.lab.live-trial.v1", "private_plan_sha256": plan_sha,
              "order": order, "order_seed": plan.order_seed, "outcomes": outcomes,
              "reported_identity_comparable": identity_comparable(outcomes),
              "behavioral_scoring": "pending_authorized_core_runtime", "execution_performed": False,
              "protection_effect": "not_established"}
    publish_new_file(output_dir / "live-trial.json", canonical_json_bytes(result), 1024 * 1024)
    return result


def verify_trial(directory, *, expected_sha256=None):
    """Verify the three archives offline; never load paths from the archived plan."""
    from .manifest import TrialManifest

    data = read_regular_file(directory / "live-trial.json", 1024 * 1024)
    if expected_sha256 is not None and hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("trial_source_digest_mismatch")
    result = parse_strict_json(data)
    keys = {"schema_version", "private_plan_sha256", "order", "order_seed", "outcomes",
            "reported_identity_comparable", "behavioral_scoring", "execution_performed", "protection_effect"}
    if (set(result) != keys or result["schema_version"] != "aegis.lab.live-trial.v1"
            or result["behavioral_scoring"] != "pending_authorized_core_runtime"
            or result["execution_performed"] is not False or result["protection_effect"] != "not_established"
            or type(result["reported_identity_comparable"]) is not bool or set(result["outcomes"]) != set(NAMES)):
        raise ValueError("invalid_trial_record")
    plan_store = PrivateEvidence(directory / "private-plan", create=False)
    plan = TrialPlan.model_validate(parse_strict_json(plan_store.get(result["private_plan_sha256"])))
    order = list(NAMES)
    random.Random(plan.order_seed).shuffle(order)
    if result["order"] != order or result["order_seed"] != plan.order_seed:
        raise ValueError("trial_order_mismatch")
    records, manifests, approvals = {}, {}, []
    for name in NAMES:
        outcome = result["outcomes"][name]
        digest = outcome.get("record_sha256")
        if digest is None:
            # Operational failures lack a generation archive: retain the absence,
            # never turn one into a result or model-identity measurement.
            allowed = ({"generation_status"} if outcome.get("generation_status") in ("interrupted", "not_started")
                       else {"generation_status", "record_sha256"})
            if set(outcome) != allowed or (directory / name / "experiment.json").exists():
                raise ValueError("unbound_trial_outcome")
            continue
        record = records[name] = verify_experiment(directory / name, expected_sha256=digest)
        if outcome != experiment_outcome(record, digest) or record.configuration != plan.configuration:
            raise ValueError("trial_outcome_mismatch")
        store = PrivateEvidence(directory / name / "private-evidence", create=False)
        manifests[name] = TrialManifest.model_validate_json(store.get(record.manifest_sha256))
        if not record.provider.external_disclosure:
            raise ValueError("live_trial_requires_external_records")
        from .disclosure import InferenceApproval

        approval = InferenceApproval.model_validate_json(store.get(record.inference_approval_sha256))
        approvals.append((approval.max_requests, approval.max_total_tokens, approval.max_spend_microusd,
                          approval.context_tokens, approval.input_microusd_per_million,
                          approval.output_microusd_per_million, approval.request_timeout_seconds))
        if plan.max_output_tokens is not None:
            request = parse_strict_json(store.get(record.prepared_request_sha256))
            if request["max_tokens"] != plan.max_output_tokens:
                raise ValueError("trial_request_budget_mismatch")
    if len(set(approvals)) > 1 or len({r.provider for r in records.values()}) > 1:
        raise ValueError("trial_limits_or_provider_mismatch")
    if len({r.trial_id for r in records.values()}) != len(records):
        raise ValueError("distinct_trial_ids_required")
    if len({r.artifact_sha256 for r in records.values()}) != len(records):
        raise ValueError("distinct_final_artifacts_required")
    for name in NAMES[1:]:
        if "baseline" in manifests and name in manifests:
            validate_pair(manifests["baseline"], manifests[name])
    if result["reported_identity_comparable"] != identity_comparable(result["outcomes"]):
        raise ValueError("trial_identity_comparison_mismatch")
    return result, records


def main(argv=None):
    from .diagnostics import SafeArgumentParser

    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "run", "verify"))
    parser.add_argument("plan", type=Path)
    parser.add_argument("--approve-live-inference", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            result, records = verify_trial(args.plan)
            print(json.dumps({"schema_version": result["schema_version"], "verified_experiments": len(records),
                              "behavioral_scoring": result["behavioral_scoring"], "execution_performed": False,
                              "protection_effect": "not_established"}, sort_keys=True))
            return 0
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
