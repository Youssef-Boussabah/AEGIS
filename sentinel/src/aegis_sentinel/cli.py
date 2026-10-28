"""CLI for AEGIS Sentinel rights and usage policy records."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path

from aegis_sentinel.evaluator import _compute_sha256, evaluate_action
from aegis_sentinel.models import (
    ArtifactLinkage,
    EnforcementMode,
    PermissionAction,
    PolicyConstraint,
    PolicyPermission,
    SentinelPolicy,
    utcnow,
)
from aegis_sentinel.validator import validate_policy_data


def _cmd_validate(args: argparse.Namespace) -> int:
    policy_path = Path(args.policy).resolve()
    if not policy_path.is_file():
        sys.stderr.write(f"Error: policy file not found: {policy_path}\n")
        return 1

    content = policy_path.read_text(encoding="utf-8")
    policy, res = validate_policy_data(content)

    if res.valid:
        sys.stdout.write(f"VALID Sentinel Policy (ID: {policy.policy_id})\n")
        for warn in res.warnings:
            sys.stdout.write(f"NOTICE: {warn}\n")
        return 0
    else:
        sys.stderr.write("INVALID Sentinel Policy:\n")
        for err in res.errors:
            sys.stderr.write(f"  - {err}\n")
        return 1


def _cmd_evaluate(args: argparse.Namespace) -> int:
    policy_path = Path(args.policy).resolve()
    if not policy_path.is_file():
        sys.stderr.write(f"Error: policy file not found: {policy_path}\n")
        return 2

    policy, val_res = validate_policy_data(policy_path.read_text(encoding="utf-8"))
    if not val_res.valid or policy is None:
        sys.stderr.write("Error: invalid policy cannot be evaluated.\n")
        for err in val_res.errors:
            sys.stderr.write(f"  - {err}\n")
        return 2

    artifact_path = Path(args.artifact).resolve() if args.artifact else None
    action = PermissionAction(args.action)

    eval_res = evaluate_action(
        policy=policy,
        action=action,
        artifact_path=artifact_path,
        caller_id=args.caller_id,
        environment=args.environment,
        watermark_present=args.watermark_present,
    )

    if eval_res.permitted:
        sys.stdout.write(f"ACTION PERMITTED: [{eval_res.action}] {eval_res.reason}\n")
        sys.stdout.write(f"Enforcement Mode : {eval_res.enforcement_mode}\n")
        return 0
    else:
        sys.stderr.write(f"ACTION DENIED: [{eval_res.action}] {eval_res.reason}\n")
        sys.stderr.write(f"Enforcement Mode : {eval_res.enforcement_mode}\n")
        return 1


def _cmd_create(args: argparse.Namespace) -> int:
    artifact_path = Path(args.artifact).resolve()
    if not artifact_path.is_file():
        sys.stderr.write(f"Error: target artifact not found: {artifact_path}\n")
        return 1

    sha256_hex = _compute_sha256(artifact_path)
    policy_id = uuid.uuid4().hex

    permissions = [
        PolicyPermission(action=PermissionAction.EXECUTE, allowed=not args.deny_execute),
        PolicyPermission(action=PermissionAction.ANALYZE, allowed=args.allow_analyze),
        PolicyPermission(action=PermissionAction.REDISTRIBUTE, allowed=args.allow_redistribute),
    ]

    policy = SentinelPolicy(
        schema_version="1",
        policy_id=policy_id,
        issuer=args.issuer,
        issued_at=utcnow(),
        enforcement_mode=EnforcementMode(args.mode),
        target_artifact=ArtifactLinkage(
            artifact_name=artifact_path.name,
            artifact_sha256=sha256_hex,
            manifest_reference=args.manifest_reference or None,
        ),
        permissions=permissions,
        constraints=PolicyConstraint(
            watermark_required=args.require_watermark,
        ),
    )

    policy_json = policy.model_dump_json(indent=2)
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(policy_json, encoding="utf-8")
        sys.stdout.write(f"Sentinel policy written to: {out_path}\n")
    else:
        sys.stdout.write(policy_json + "\n")

    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    policy_path = Path(args.policy).resolve()
    if not policy_path.is_file():
        sys.stderr.write(f"Error: policy file not found: {policy_path}\n")
        return 1

    policy, val_res = validate_policy_data(policy_path.read_text(encoding="utf-8"))
    if not val_res.valid or policy is None:
        sys.stderr.write("Error: invalid policy document.\n")
        return 1

    sys.stdout.write("Sentinel Rights & Policy Document\n")
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.write(f"Policy ID        : {policy.policy_id}\n")
    sys.stdout.write(f"Issuer           : {policy.issuer}\n")
    sys.stdout.write(f"Enforcement Mode : {policy.enforcement_mode}\n")
    sys.stdout.write(f"Target Artifact  : {policy.target_artifact.artifact_name} ({policy.target_artifact.artifact_sha256[:16]}...)\n")
    if policy.target_artifact.manifest_reference:
        sys.stdout.write(f"Manifest Ref     : {policy.target_artifact.manifest_reference}\n")
    sys.stdout.write("Declared Permissions:\n")
    for p in policy.permissions:
        status = "ALLOWED" if p.allowed else "DENIED"
        scope = f" [Scope: {p.scope}]" if p.scope else ""
        sys.stdout.write(f"  - {p.action.value:<16}: {status}{scope}\n")
    sys.stdout.write(f"Notice / Disclaimer: {policy.disclaimer}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-sentinel",
        description="AEGIS Sentinel: machine-readable rights and usage policy records.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # validate
    p_val = sub.add_parser("validate", help="Validate a Sentinel policy file")
    p_val.add_argument("policy", help="Path to policy JSON file")
    p_val.set_defaults(func=_cmd_validate)

    # evaluate
    p_eval = sub.add_parser("evaluate", help="Evaluate an action against a policy")
    p_eval.add_argument("policy", help="Path to policy JSON file")
    p_eval.add_argument("--action", required=True, choices=[a.value for a in PermissionAction], help="Action to evaluate")
    p_eval.add_argument("--artifact", default=None, help="Path to artifact file for linkage check")
    p_eval.add_argument("--caller-id", default=None, help="Identifier of caller/agent")
    p_eval.add_argument("--environment", default=None, help="Current runtime environment")
    p_eval.add_argument("--watermark-present", action="store_true", help="Flag if watermark is present")
    p_eval.set_defaults(func=_cmd_evaluate)

    # create
    p_cr = sub.add_parser("create", help="Create a new policy record for an artifact")
    p_cr.add_argument("artifact", help="Path to target artifact")
    p_cr.add_argument("--issuer", required=True, help="Policy issuer name")
    p_cr.add_argument("--mode", choices=["advisory_notice", "cooperating_enforced"], default="advisory_notice")
    p_cr.add_argument("--manifest-reference", default=None, help="SHA-256 of provenance manifest")
    p_cr.add_argument("--deny-execute", action="store_true", help="Deny execution permission")
    p_cr.add_argument("--allow-analyze", action="store_true", help="Grant analysis permission")
    p_cr.add_argument("--allow-redistribute", action="store_true", help="Grant redistribution permission")
    p_cr.add_argument("--require-watermark", action="store_true", help="Require verified watermark")
    p_cr.add_argument("-o", "--output", default=None, help="Output path for policy JSON")
    p_cr.set_defaults(func=_cmd_create)

    # inspect
    p_insp = sub.add_parser("inspect", help="Inspect a policy file")
    p_insp.add_argument("policy", help="Path to policy JSON file")
    p_insp.set_defaults(func=_cmd_inspect)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

