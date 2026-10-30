from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis_sentinel.evaluator import _compute_sha256, evaluate_action
from aegis_sentinel.models import (
    ArtifactLinkage,
    EnforcementMode,
    PermissionAction,
    PolicyConstraint,
    PolicyPermission,
    SentinelPolicy,
)


def create_test_policy(
    sha256_hex: str,
    permissions: list[PolicyPermission],
    constraints: PolicyConstraint | None = None,
) -> SentinelPolicy:
    return SentinelPolicy(
        schema_version="1",
        policy_id="0123456789abcdef0123456789abcdef",
        issuer="Test Org",
        issued_at=datetime.now(timezone.utc),
        enforcement_mode=EnforcementMode.COOPERATING_ENFORCED,
        target_artifact=ArtifactLinkage(
            artifact_name="kernel.bin",
            artifact_sha256=sha256_hex,
        ),
        permissions=permissions,
        constraints=constraints or PolicyConstraint(),
    )


def test_evaluate_action_permitted(tmp_path: Path):
    f = tmp_path / "kernel.bin"
    f.write_bytes(b"content-12345")
    sha = _compute_sha256(f)

    policy = create_test_policy(
        sha256_hex=sha,
        permissions=[PolicyPermission(action=PermissionAction.EXECUTE, allowed=True, scope="prod")],
    )

    res = evaluate_action(policy, PermissionAction.EXECUTE, artifact_path=f)
    assert res.permitted is True
    assert "is permitted" in res.reason


def test_evaluate_action_explicitly_denied(tmp_path: Path):
    f = tmp_path / "kernel.bin"
    f.write_bytes(b"content-12345")
    sha = _compute_sha256(f)

    policy = create_test_policy(
        sha256_hex=sha,
        permissions=[PolicyPermission(action=PermissionAction.ANALYZE, allowed=False)],
    )

    res = evaluate_action(policy, PermissionAction.ANALYZE, artifact_path=f)
    assert res.permitted is False
    assert "explicitly denied" in res.reason


def test_evaluate_action_default_deny(tmp_path: Path):
    f = tmp_path / "kernel.bin"
    f.write_bytes(b"content-12345")
    sha = _compute_sha256(f)

    policy = create_test_policy(sha256_hex=sha, permissions=[])
    res = evaluate_action(policy, PermissionAction.MODIFY, artifact_path=f)
    assert res.permitted is False
    assert "default deny" in res.reason


def test_evaluate_artifact_hash_mismatch(tmp_path: Path):
    f = tmp_path / "kernel.bin"
    f.write_bytes(b"content-12345")

    policy = create_test_policy(
        sha256_hex="f" * 64,  # mismatched hash
        permissions=[PolicyPermission(action=PermissionAction.EXECUTE, allowed=True)],
    )

    res = evaluate_action(policy, PermissionAction.EXECUTE, artifact_path=f)
    assert res.permitted is False
    assert "Artifact linkage failed" in res.reason


def test_evaluate_temporal_expired():
    now = datetime.now(timezone.utc)
    expired_time = now - timedelta(days=1)

    policy = create_test_policy(
        sha256_hex="0" * 64,
        permissions=[PolicyPermission(action=PermissionAction.EXECUTE, allowed=True)],
        constraints=PolicyConstraint(expires_at=expired_time),
    )

    res = evaluate_action(policy, PermissionAction.EXECUTE, at_time=now)
    assert res.permitted is False
    assert "Policy expired" in res.reason


def test_evaluate_watermark_constraint():
    policy = create_test_policy(
        sha256_hex="0" * 64,
        permissions=[PolicyPermission(action=PermissionAction.EXECUTE, allowed=True)],
        constraints=PolicyConstraint(watermark_required=True),
    )

    # Without watermark
    res = evaluate_action(policy, PermissionAction.EXECUTE, watermark_present=False)
    assert res.permitted is False
    assert "requires verified watermark" in res.reason

    # With watermark
    res2 = evaluate_action(policy, PermissionAction.EXECUTE, watermark_present=True)
    assert res2.permitted is True


def test_restricted_policy_fails_closed_without_caller_or_environment(tmp_path: Path):
    f = tmp_path / "kernel.bin"
    f.write_bytes(b"content")
    sha = _compute_sha256(f)
    allow = [PolicyPermission(action=PermissionAction.ANALYZE, allowed=True)]

    callers = create_test_policy(sha, allow, PolicyConstraint(allowed_caller_ids=["tool-a"]))
    missing = evaluate_action(callers, PermissionAction.ANALYZE, artifact_path=f)
    assert not missing.permitted and "none was supplied" in missing.reason
    assert evaluate_action(callers, PermissionAction.ANALYZE, caller_id="tool-a").permitted
    assert not evaluate_action(callers, PermissionAction.ANALYZE, caller_id="tool-b").permitted

    envs = create_test_policy(sha, allow, PolicyConstraint(environments=["ci"]))
    assert not evaluate_action(envs, PermissionAction.ANALYZE).permitted
    assert evaluate_action(envs, PermissionAction.ANALYZE, environment="ci").permitted
