"""Prepare two unapproved continuation requests against a verified baseline, offline.

Only identities and the sampling digest are reissued in new manifests. All other
paired conditions must match the archived baseline. No runner/provider is invoked;
the existing draft command writes invalid operator-review drafts only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import secrets
import sys

from .canonical import canonical_json_bytes
from .disclosure import InferenceApproval
from .experiment import verify_experiment
from .inference import worst_request_cost
from .live import main as live_main
from .live_trial import TrialPlan
from .manifest import TrialManifest, load_manifest, validate_pair
from .private_evidence import PrivateEvidence
from .provider import NEBIUS_REASONING_COMPLETION_PARSER
from .bounded_provider import BoundedNebiusProvider
from .reconstruction import prepare_reconstruction, sampling_configuration_sha256
from .safe_io import parse_strict_json, publish_new_file, read_regular_file


def prepare_remaining(baseline_dir: Path, plan_path: Path, output_dir: Path):
    if BoundedNebiusProvider.completion_parser != NEBIUS_REASONING_COMPLETION_PARSER:
        raise ValueError("corrected_nebius_parser_required")
    baseline_bytes = read_regular_file(baseline_dir / "experiment.json", 2 * 1024 * 1024)
    baseline_digest = hashlib.sha256(baseline_bytes).hexdigest()
    record = verify_experiment(baseline_dir, expected_sha256=baseline_digest)
    if not record.provider.external_disclosure or record.provider.provider != "Nebius":
        raise ValueError("verified_nebius_baseline_required")
    store = PrivateEvidence(baseline_dir / "private-evidence", create=False)
    baseline = TrialManifest.model_validate_json(store.get(record.manifest_sha256))
    if baseline.variant.value != "baseline":
        raise ValueError("baseline_variant_required")
    approval = InferenceApproval.model_validate_json(store.get(record.inference_approval_sha256))
    request = parse_strict_json(store.get(record.prepared_request_sha256))
    plan_bytes = read_regular_file(plan_path, 64 * 1024)
    plan = TrialPlan.model_validate(parse_strict_json(plan_bytes))
    if any(getattr(plan, name).approval is not None for name in ("baseline", "shield", "mirage")):
        raise ValueError("preparation_plan_must_not_reuse_approvals")
    if plan.configuration != record.configuration:
        raise ValueError("workflow_configuration_mismatch")
    sampling = sampling_configuration_sha256(max_output_tokens=request["max_tokens"], top_p=request.get("top_p"))
    if sampling != baseline.attack.sampling_configuration_sha256:
        raise ValueError("baseline_sampling_not_reproducible")
    manifests, prepared = {}, {}
    for name in ("baseline", "shield", "mirage"):
        target = getattr(plan, name)
        data = load_manifest(target.manifest).model_dump(mode="json")
        # These are explicitly new declarations, never an edit of past evidence.
        data["pair_id"] = baseline.pair_id
        data["trial_id"] = baseline.trial_id if name == "baseline" else secrets.token_hex(16)
        data["attack"]["sampling_configuration_sha256"] = sampling
        manifest = manifests[name] = TrialManifest.model_validate(data)
        if name == "baseline":
            if manifest != baseline:
                raise ValueError("prepared_plan_baseline_mismatch")
        elif validate_pair(baseline, manifest).final_artifacts_identical:
            raise ValueError("distinct_final_artifacts_required")
        item = prepared[name] = prepare_reconstruction(manifest,
            read_regular_file(target.report, 8 * 1024 * 1024),
            max_output_tokens=request["max_tokens"], top_p=request.get("top_p"))
        if hashlib.sha256(read_regular_file(target.artifact, 64 * 1024 * 1024)).hexdigest() != item.artifact_sha256:
            raise ValueError("artifact_digest_mismatch")
    if len({p.artifact_sha256 for p in prepared.values()}) != 3:
        raise ValueError("three_distinct_artifacts_required")
    if len({m.trial_id for m in manifests.values()}) != 3:
        raise ValueError("three_distinct_trial_ids_required")
    if prepared["baseline"].request.to_body() != request:
        raise ValueError("baseline_request_mismatch")
    if min(plan.configuration.max_steps, prepared["baseline"].max_attempts) != approval.max_requests:
        raise ValueError("baseline_request_count_mismatch")
    # The public CLI currently reproduces the default top_p only; fail closed.
    if request.get("top_p") is not None:
        raise ValueError("operator_cli_top_p_not_supported")
    root = output_dir.resolve()
    if root.is_relative_to(baseline_dir.resolve()) or root.is_relative_to(plan_path.parent.resolve()):
        raise ValueError("original_evidence_is_read_only")
    root.mkdir(mode=0o700)
    commands, targets = {}, {}
    for name in ("shield", "mirage"):
        target = getattr(plan, name)
        child = root / name
        child.mkdir(mode=0o700)
        manifest_path = child / "manifest.json"
        draft_path = child / "approval.DRAFT.json"
        approved_path = child / "approval.json"
        publish_new_file(manifest_path, manifests[name].canonical_bytes(), 1024 * 1024)
        common = [str(manifest_path), str(target.report), str(target.artifact),
                  "--steps", str(plan.configuration.max_steps), "--max-output-tokens", str(request["max_tokens"])]
        draft = ["draft", *common, "--output", str(draft_path),
            "--context-tokens", str(approval.context_tokens),
            "--input-microusd-per-million", str(approval.input_microusd_per_million),
            "--output-microusd-per-million", str(approval.output_microusd_per_million),
            "--max-spend-microusd", str(approval.max_spend_microusd),
            "--request-timeout", str(approval.request_timeout_seconds)]
        if live_main(draft) != 0:
            raise ValueError("operator_draft_preparation_failed")
        base_argv = [sys.executable, "-m", "aegis_lab.live"]
        commands[name] = {
            "preflight_argv": [*base_argv, "preflight", *common, "--approval", str(approved_path)],
            "run_argv": [*base_argv, "run", *common, "--approval", str(approved_path),
                         "--output-dir", str(root / (name + "-live-run")), "--approve-live-inference"],
        }
        targets[name] = {"manifest_sha256": manifests[name].sha256(),
                         "artifact_sha256": prepared[name].artifact_sha256,
                         "evidence_sha256": prepared[name].evidence_sha256,
                         "prompt_sha256": prepared[name].rendered_prompt_sha256}
    summary = {"schema_version": "aegis.lab.remaining-inference-preparation.v1",
        "baseline_experiment_sha256": baseline_digest,
        "source_plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "request_conditions_comparable": True, "historical_outcomes_directly_comparable": False,
        "baseline_completion_parser": record.completion_parser,
        "remaining_completion_parser": NEBIUS_REASONING_COMPLETION_PARSER,
        "model": record.requested_model, "max_output_tokens": request["max_tokens"],
        "max_requests_per_target": approval.max_requests,
        "max_total_tokens_per_target": approval.max_total_tokens,
        "max_spend_microusd_per_target": approval.max_spend_microusd,
        "context_tokens": approval.context_tokens,
        "input_microusd_per_million": approval.input_microusd_per_million,
        "output_microusd_per_million": approval.output_microusd_per_million,
        "request_timeout_seconds": approval.request_timeout_seconds,
        "worst_request_reservation_microusd": worst_request_cost(approval, request["max_tokens"]),
        "shield_and_mirage_selected_prompts_identical": prepared["shield"].rendered_prompt_sha256 == prepared["mirage"].rendered_prompt_sha256,
        "targets": targets, "network_requests": 0, "approvals_granted": False,
        "limitations": ["Baseline was observed first, not a randomized prospective three-way trial.",
            "Baseline history uses v1; compare its separately labeled post-hoc v2 interpretation explicitly.",
            "Build provenance is operator-declared; provider weight identity is not verified.",
            "Only selected-function evidence is disclosed; no decoy-inventory effect can be measured.",
            "No candidate compilation, execution, behavioral score or protection effect is established."]}
    publish_new_file(root / "comparability.json", canonical_json_bytes(summary), 64 * 1024)
    publish_new_file(root / "operator-commands.json", canonical_json_bytes(commands), 64 * 1024)
    return summary


def main(argv=None):
    from .diagnostics import SafeArgumentParser

    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(prepare_remaining(args.baseline, args.plan, args.output_dir), sort_keys=True))
        return 0
    except Exception:
        print("remaining_inference_preparation_failed: invalid_input_or_publication", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
