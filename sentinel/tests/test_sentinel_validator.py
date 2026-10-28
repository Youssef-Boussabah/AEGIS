from datetime import datetime, timezone

from aegis_sentinel.models import (
    ArtifactLinkage,
    EnforcementMode,
    PermissionAction,
    PolicyConstraint,
    PolicyPermission,
    SentinelPolicy,
)
from aegis_sentinel.validator import validate_policy_data


def test_valid_policy_validation():
    policy = SentinelPolicy(
        schema_version="1",
        policy_id="a" * 32,
        issuer="AEGIS Authority",
        issued_at=datetime.now(timezone.utc),
        enforcement_mode=EnforcementMode.ADVISORY_NOTICE,
        target_artifact=ArtifactLinkage(
            artifact_name="app.bin",
            artifact_sha256="0" * 64,
        ),
        permissions=[
            PolicyPermission(action=PermissionAction.EXECUTE, allowed=True),
            PolicyPermission(action=PermissionAction.ANALYZE, allowed=False),
        ],
    )
    validated, res = validate_policy_data(policy.model_dump(mode="json"))
    assert res.valid is True
    assert validated is not None
    assert len(res.warnings) > 0  # advisory notice warning


def test_invalid_unsupported_version():
    data = {
        "schema_version": "99",
        "policy_id": "a" * 32,
        "issuer": "Test",
        "issued_at": "2026-10-28T12:00:00Z",
        "target_artifact": {"artifact_name": "app.bin", "artifact_sha256": "0" * 64},
        "permissions": [],
    }
    validated, res = validate_policy_data(data)
    assert res.valid is False
    assert any("Unsupported policy schema_version" in e for e in res.errors)


def test_ambiguous_duplicate_permission():
    data = {
        "schema_version": "1",
        "policy_id": "a" * 32,
        "issuer": "Test",
        "issued_at": "2026-10-28T12:00:00Z",
        "target_artifact": {"artifact_name": "app.bin", "artifact_sha256": "0" * 64},
        "permissions": [
            {"action": "execute", "allowed": True},
            {"action": "execute", "allowed": False},  # duplicate / ambiguous
        ],
    }
    validated, res = validate_policy_data(data)
    assert res.valid is False
    assert any("Ambiguous policy: duplicate permission" in e for e in res.errors)


def test_invalid_temporal_constraints():
    policy = SentinelPolicy(
        schema_version="1",
        policy_id="a" * 32,
        issuer="AEGIS Authority",
        issued_at=datetime.now(timezone.utc),
        target_artifact=ArtifactLinkage(
            artifact_name="app.bin",
            artifact_sha256="0" * 64,
        ),
        permissions=[],
        constraints=PolicyConstraint(
            not_before=datetime(2026, 12, 1, tzinfo=timezone.utc),
            expires_at=datetime(2026, 11, 1, tzinfo=timezone.utc),  # inverted!
        ),
    )
    validated, res = validate_policy_data(policy.model_dump(mode="json"))
    assert res.valid is False
    assert any("Invalid temporal constraint" in e for e in res.errors)
