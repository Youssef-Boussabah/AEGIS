"""Validation rules for Sentinel rights and usage policy records."""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from aegis_sentinel.models import (
    EnforcementMode,
    SentinelPolicy,
    ValidationResult,
)


def validate_policy_data(data: Any) -> tuple[SentinelPolicy | None, ValidationResult]:
    """Validate raw dictionary or JSON string against Sentinel policy specifications.

    Rejects:
    - Unsupported schema versions
    - Conflicting / ambiguous permissions for the same action
    - Invalid datetime ranges (not_before > expires_at)
    - Malformed structures or unknown fields
    """
    errors: list[str] = []
    warnings: list[str] = []

    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as exc:
            return None, ValidationResult(valid=False, errors=[f"Malformed JSON: {exc}"])

    if not isinstance(data, dict):
        return None, ValidationResult(valid=False, errors=["Policy data must be a JSON object."])

    # Check schema version
    version = data.get("schema_version")
    if version != "1":
        return None, ValidationResult(
            valid=False,
            errors=[f"Unsupported policy schema_version '{version}'. Supported: '1'."],
        )

    # Check for ambiguous permissions before/during validation
    raw_perms = data.get("permissions")
    if isinstance(raw_perms, list):
        seen_actions: set[str] = set()
        for p in raw_perms:
            if isinstance(p, dict) and "action" in p:
                act = str(p["action"])
                if act in seen_actions:
                    errors.append(f"Ambiguous policy: duplicate permission entry for action '{act}'.")
                seen_actions.add(act)

    try:
        policy = SentinelPolicy.model_validate(data)
    except ValidationError as exc:
        for err in exc.errors(include_input=False, include_url=False):
            loc = ".".join(str(p) for p in err["loc"])
            errors.append(f"{loc}: {err['msg']}")
        return None, ValidationResult(valid=False, errors=errors)

    if errors:
        return None, ValidationResult(valid=False, errors=errors)

    # Check temporal constraints
    c = policy.constraints
    if c.not_before and c.expires_at and c.not_before > c.expires_at:
        errors.append(f"Invalid temporal constraint: not_before ({c.not_before}) > expires_at ({c.expires_at}).")

    # Advisory notice warning
    if policy.enforcement_mode == EnforcementMode.ADVISORY_NOTICE:
        warnings.append(
            "Policy enforcement_mode is 'advisory_notice'. Publishing this JSON states rights "
            "but does not bind or compel non-cooperating third-party tools."
        )

    is_valid = len(errors) == 0
    return (policy if is_valid else None), ValidationResult(valid=is_valid, errors=errors, warnings=warnings)

