"""AEGIS Adversarial Lab experiment records (no execution capability)."""

from .canonical import CANONICALIZATION, canonical_json_bytes
from .manifest import (
    SCHEMA_VERSION,
    AccessPolicy,
    AttackBudget,
    AttackConfig,
    AuthorizationReference,
    BuildConditions,
    BuildTarget,
    ManifestPairError,
    PairValidation,
    ProtectionStep,
    ScoringPlan,
    ToolIdentity,
    TrialManifest,
    TrialVariant,
    load_manifest,
    parse_manifest,
    validate_pair,
)
from .safe_io import LoadError

__all__ = [
    "CANONICALIZATION",
    "SCHEMA_VERSION",
    "AccessPolicy",
    "AttackBudget",
    "AttackConfig",
    "AuthorizationReference",
    "BuildConditions",
    "BuildTarget",
    "LoadError",
    "ManifestPairError",
    "PairValidation",
    "ProtectionStep",
    "ScoringPlan",
    "ToolIdentity",
    "TrialManifest",
    "TrialVariant",
    "canonical_json_bytes",
    "load_manifest",
    "parse_manifest",
    "validate_pair",
]
