"""Evaluation of actions and access requests against Sentinel policy records."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from aegis_sentinel.models import (
    EvaluationResult,
    PermissionAction,
    SentinelPolicy,
    utcnow,
)


def _compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def evaluate_action(
    policy: SentinelPolicy,
    action: PermissionAction,
    artifact_path: Path | None = None,
    caller_id: str | None = None,
    environment: str | None = None,
    watermark_present: bool = False,
    at_time: datetime | None = None,
) -> EvaluationResult:
    """Evaluate whether a cooperating tool is authorized to perform action under policy.

    Cooperating tools must check:
    - Target artifact hash linkage
    - Temporal validity window (not_before, expires_at)
    - Environment eligibility
    - Authorized caller IDs
    - Watermark requirement
    - Specific permission grant (default deny)
    """
    check_time = at_time or utcnow()

    # 1. Artifact linkage verification
    if artifact_path is not None:
        if not artifact_path.is_file():
            return EvaluationResult(
                action=action,
                permitted=False,
                enforcement_mode=policy.enforcement_mode,
                reason=f"Target artifact does not exist: {artifact_path}",
                evaluated_at=check_time,
            )
        actual_hash = _compute_sha256(artifact_path)
        if actual_hash != policy.target_artifact.artifact_sha256:
            return EvaluationResult(
                action=action,
                permitted=False,
                enforcement_mode=policy.enforcement_mode,
                reason=(
                    f"Artifact linkage failed: actual SHA-256 {actual_hash} does not match "
                    f"policy target {policy.target_artifact.artifact_sha256}"
                ),
                evaluated_at=check_time,
            )

    # 2. Temporal constraints
    c = policy.constraints
    if c.not_before and check_time < c.not_before:
        return EvaluationResult(
            action=action,
            permitted=False,
            enforcement_mode=policy.enforcement_mode,
            reason=f"Policy not yet active: check time {check_time.isoformat()} < not_before {c.not_before.isoformat()}",
            evaluated_at=check_time,
        )
    if c.expires_at and check_time > c.expires_at:
        return EvaluationResult(
            action=action,
            permitted=False,
            enforcement_mode=policy.enforcement_mode,
            reason=f"Policy expired: check time {check_time.isoformat()} > expires_at {c.expires_at.isoformat()}",
            evaluated_at=check_time,
        )

    # 3. Environment constraint
    if c.environments is not None and environment is not None:
        if environment not in c.environments:
            return EvaluationResult(
                action=action,
                permitted=False,
                enforcement_mode=policy.enforcement_mode,
                reason=f"Environment '{environment}' not in permitted environments: {c.environments}",
                evaluated_at=check_time,
            )

    # 4. Caller ID constraint
    if c.allowed_caller_ids is not None and caller_id is not None:
        if caller_id not in c.allowed_caller_ids:
            return EvaluationResult(
                action=action,
                permitted=False,
                enforcement_mode=policy.enforcement_mode,
                reason=f"Caller ID '{caller_id}' not in authorized callers: {c.allowed_caller_ids}",
                evaluated_at=check_time,
            )

    # 5. Watermark constraint
    if c.watermark_required and not watermark_present:
        return EvaluationResult(
            action=action,
            permitted=False,
            enforcement_mode=policy.enforcement_mode,
            reason="Policy requires verified watermark, but no valid watermark was detected.",
            evaluated_at=check_time,
        )

    # 6. Specific action permission (default deny)
    for perm in policy.permissions:
        if perm.action == action:
            if perm.allowed:
                scope_info = f" (Scope: {perm.scope})" if perm.scope else ""
                return EvaluationResult(
                    action=action,
                    permitted=True,
                    enforcement_mode=policy.enforcement_mode,
                    reason=f"Action '{action}' is permitted by policy issuer '{policy.issuer}'{scope_info}.",
                    evaluated_at=check_time,
                )
            else:
                return EvaluationResult(
                    action=action,
                    permitted=False,
                    enforcement_mode=policy.enforcement_mode,
                    reason=f"Action '{action}' is explicitly denied by policy issuer '{policy.issuer}'.",
                    evaluated_at=check_time,
                )

    return EvaluationResult(
        action=action,
        permitted=False,
        enforcement_mode=policy.enforcement_mode,
        reason=f"Action '{action}' is not listed in policy permissions (default deny).",
        evaluated_at=check_time,
    )

