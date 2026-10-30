"""Operator interface: local preflight/draft, or explicitly approved Nebius inference."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import sys

from .canonical import canonical_json_bytes
from .disclosure import InferenceApproval
from .experiment import WorkflowConfig, initial_messages, live_workflow_sha256
from .inference import check_inference_approval, load_approval
from .manifest import load_manifest
from .provider import NEBIUS_API_KEY_ENV, NEBIUS_BASE_URL, canonical_endpoint
from .reconstruction import prepare_reconstruction, run_live_reconstruction
from .safe_io import publish_new_file, read_regular_file


def execute_live(prepared, artifact, output_dir, approval, state_dir, *, configuration):
    try:
        return run_live_reconstruction(prepared, artifact, output_dir, inference_approval=approval,
                                        approval_state_dir=state_dir, allow_live=True, configuration=configuration)
    except Exception as exc:
        from .disclosure import AuthorizationError
        from .provider import ProviderError
        code = exc.code if isinstance(exc, AuthorizationError) else exc.category if isinstance(exc, ProviderError) else "invalid_input_or_publication"
        record_failure(output_dir, code)
        raise


def preflight(prepared, artifact, configuration, approval=None):
    """No networking, credential use, billable request or approval consumption."""
    data = read_regular_file(artifact, 64 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != prepared.artifact_sha256:
        raise ValueError("artifact_digest_mismatch")
    if approval is not None:
        check_inference_approval(prepared, configuration, approval, allow_live=True)
    return {"schema_version": "aegis.lab.live-preflight.v1", "network_requests": 0, "billable_requests": 0,
            "credentials_configured": NEBIUS_API_KEY_ENV in os.environ,
            "artifact_identity_verified": True, "artifact_readable": os.access(artifact, os.R_OK),
            "prepared": prepared.safe_metadata(), "workflow_sha256": live_workflow_sha256(configuration),
            "proposed_model": prepared.request.model, "proposed_endpoint": NEBIUS_BASE_URL,
            "max_requests": min(configuration.max_steps, prepared.max_attempts),
            "max_total_tokens": prepared.max_model_tokens,
            "approval_validated": approval is not None,
            "max_spend_microusd": None if approval is None else approval.max_spend_microusd,
            "context_tokens_reserved_per_request": None if approval is None else approval.context_tokens,
            "model_available_to_account": "not_checked_offline_fresh_check_required_before_inference",
            "candidate_execution_authorized": False}


def record_failure(output_dir, code):
    """Best-effort private operational failure report; never replace existing files."""
    from .private_evidence import PrivateEvidence

    if output_dir is None:
        return
    try:
        if not output_dir.exists():
            output_dir.mkdir(mode=0o700)
        PrivateEvidence(output_dir, create=False)
        publish_new_file(output_dir / "failure.json", canonical_json_bytes({
            "schema_version": "aegis.lab.live-operational-failure.v1", "status": code,
            "execution_performed": False, "behavioral_scoring": "unscored",
            "inference_outcome": "not_established_see_any_private_experiment_records"}), 64 * 1024)
    except Exception:
        pass  # Publication failures must not overwrite unrelated or unsafe output.


def main(argv=None):
    from .diagnostics import SafeArgumentParser

    parser = SafeArgumentParser(description="Authorized inference only; generated candidates never execute")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "draft", "run"):
        p = sub.add_parser(command)
        p.add_argument("manifest", type=Path)
        p.add_argument("report", type=Path)
        p.add_argument("artifact", type=Path)
        p.add_argument("--steps", type=int, default=1)
        p.add_argument("--max-output-tokens", type=int)
        p.add_argument("--disable-thinking", action="store_true",
                       help="explicit Nebius template control; requires a matching sampling digest and fresh approval")
        if command != "draft":
            p.add_argument("--approval", type=Path, required=command == "run")
        if command == "run":
            p.add_argument("--approve-live-inference", action="store_true", required=True)
            p.add_argument("--output-dir", type=Path, required=True)
        if command == "draft":
            p.add_argument("--output", type=Path, required=True)
            p.add_argument("--context-tokens", type=int, required=True)
            p.add_argument("--input-microusd-per-million", type=int, required=True)
            p.add_argument("--output-microusd-per-million", type=int, required=True)
            p.add_argument("--max-spend-microusd", type=int, required=True)
            p.add_argument("--request-timeout", type=int, default=120)
    args = parser.parse_args(argv)
    try:
        prepared = prepare_reconstruction(load_manifest(args.manifest), read_regular_file(args.report, 8 * 1024 * 1024),
                                          max_output_tokens=args.max_output_tokens,
                                          enable_thinking=False if args.disable_thinking else None)
        config = WorkflowConfig(max_steps=args.steps)
        approval = load_approval(args.approval) if getattr(args, "approval", None) else None
        summary = preflight(prepared, args.artifact, config, approval)
        if args.command == "preflight":
            print(json.dumps(summary, sort_keys=True, indent=2))
            return 0
        if args.command == "draft":
            now = datetime.now(UTC)
            draft = {"schema_version": "aegis.lab.inference-approval.v1", "operator_approved": False,
                     "purpose": "inference_only_no_candidate_execution",
                     "disclosure": {"reference": "OPERATOR_REVIEW_REQUIRED", "approved_by": "OPERATOR_REVIEW_REQUIRED",
                         "scope": "Owned artifact; exact reviewed Ghidra evidence and bounded model-reply continuation only",
                         "created_at": now.isoformat(), "valid_from": now.isoformat(),
                         "expires_at": (now + timedelta(hours=1)).isoformat(),
                         "artifact_sha256": prepared.artifact_sha256, "evidence_sha256": prepared.evidence_sha256,
                         "rendered_prompt_sha256": prepared.rendered_prompt_sha256,
                         "acknowledged_findings": sorted(dict(prepared.findings)), "provider": "Nebius",
                         "endpoint": canonical_endpoint(NEBIUS_BASE_URL), "model_id": prepared.request.model},
                     "manifest_sha256": prepared.manifest_sha256, "workflow_sha256": live_workflow_sha256(config),
                     "max_requests": min(config.max_steps, prepared.max_attempts),
                     "max_total_tokens": prepared.max_model_tokens, "max_spend_microusd": args.max_spend_microusd,
                     "context_tokens": args.context_tokens, "input_microusd_per_million": args.input_microusd_per_million,
                     "output_microusd_per_million": args.output_microusd_per_million,
                     "request_timeout_seconds": args.request_timeout,
                     "request_deadline": (now + timedelta(hours=1)).isoformat(),
                     "private_archive_delete_after": (now + timedelta(days=7)).isoformat(),
                     "provider_retention_policy": "OPERATOR MUST REVIEW Nebius retention and applicable account terms",
                     "provider_retention_reviewed": False}
            # An invalid draft cannot authorize any network request.
            publish_new_file(args.output, canonical_json_bytes(draft), 64 * 1024)
            from .provider import InferenceRequest
            review = InferenceRequest(**{**prepared.request.model_dump(), "messages": initial_messages(prepared), "store": False})
            publish_new_file(args.output.with_name(args.output.name + ".request-review.json"),
                             canonical_json_bytes(review.to_body()), 1024 * 1024)
            print("draft_created_not_authorized")
            return 0
        record = execute_live(prepared, args.artifact, args.output_dir, approval, args.approval.parent / ".inference-uses",
                              configuration=config)
        print(json.dumps({"generation_status": record.generation_status, "requests": len(record.steps),
                          "behavioral_scoring": record.behavioral_scoring, "execution_performed": False}))
        return 0 if record.generation_status == "generated_but_behaviorally_unscored" else 1
    except KeyboardInterrupt:
        print("live_trial_failed: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        # Never echo file names, arbitrary validator/provider messages or secrets.
        from .disclosure import AuthorizationError
        from .provider import ProviderError
        code = exc.code if isinstance(exc, AuthorizationError) else exc.category if isinstance(exc, ProviderError) else "invalid_input_or_publication"
        record_failure(getattr(args, "output_dir", None), code)
        print("live_trial_failed: " + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
