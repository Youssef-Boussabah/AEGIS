"""Versioned experiment manifest for paired reconstruction trials.

This is a *local research schema*, not an aegis.adapter.v1 message or a Core
ProtectionPolicy. Validating a manifest cannot grant permission to run attacks:
Core's operator switch and per-job AttackLabAuthorization remain mandatory.

Nothing here invokes REA, Ghidra, model providers or generated code.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictFloat, model_validator

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
TrialId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
ShortText = Annotated[str, Field(min_length=1, max_length=200)]
LongText = Annotated[str, Field(min_length=1, max_length=2000)]


class StrictRecord(BaseModel):
    """Reject unknown fields; use strict types for security-critical numeric/boolean fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrialVariant(StrEnum):
    BASELINE = "baseline"
    PROTECTED = "protected"


class ToolIdentity(StrictRecord):
    name: ShortText
    version: ShortText
    executable_sha256: Hash | None = None


class BuildTarget(StrictRecord):
    """Identity of the *final* artifact the attacker receives, not intermediate IR."""

    name: ShortText
    function: ShortText
    source_revision: ShortText
    platform: ShortText
    artifact_format: ShortText
    final_artifact_sha256: Hash
    matched_build_profile: ShortText
    build_recipe_sha256: Hash
    transformation_report_sha256: Hash | None = None


class AccessPolicy(StrictRecord):
    """Explicit limits on evidence and oracle access for this trial."""

    access_to_original_source: StrictBool = False
    access_to_symbols: StrictBool = False
    runtime_oracle_enabled: StrictBool = False
    repository_retrieval_enabled: StrictBool = False
    network_enabled: StrictBool = False
    oracle_query_limit: Annotated[StrictInt, Field(ge=0, le=1_000_000)] = 0

    @model_validator(mode="after")
    def _oracle_consistency(self) -> AccessPolicy:
        if not self.runtime_oracle_enabled and self.oracle_query_limit:
            raise ValueError("oracle_query_limit must be 0 when oracle access is disabled")
        return self


class AttackBudget(StrictRecord):
    max_wall_seconds: Annotated[StrictInt, Field(ge=1, le=86_400)]
    max_model_tokens: Annotated[StrictInt, Field(ge=1, le=100_000_000)]
    max_tool_calls: Annotated[StrictInt, Field(ge=1, le=1_000_000)]
    max_attempts: Annotated[StrictInt, Field(ge=1, le=100_000)] = 1


class AttackConfig(StrictRecord):
    """A reproducible workflow; tools may include REA and/or Ghidra."""

    workflow: Literal["ghidra_model", "rea", "custom"]
    tools: Annotated[tuple[ToolIdentity, ...], Field(min_length=1, max_length=32)]
    provider: ShortText
    model_id: ShortText
    prompt_sha256: Hash
    sampling_seed: StrictInt | None = None
    temperature: Annotated[StrictFloat, Field(ge=0.0, le=2.0)] = 0.0

    @model_validator(mode="after")
    def _no_duplicate_tools(self) -> AttackConfig:
        names = [tool.name.casefold() for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool names must be unique within an attack configuration")
        return self


class ScoringPlan(StrictRecord):
    """Hidden test identity is public to the manifest; contents are not."""

    hidden_test_suite_sha256: Hash
    score_rule: Literal["all_hidden_tests_pass"] = "all_hidden_tests_pass"
    expected_interface: ShortText


class AuthorizationReference(StrictRecord):
    """Audit metadata only. NOT a grant of authority to execute any trial."""

    reference: ShortText
    authorized_scope: LongText


class TrialManifest(StrictRecord):
    schema_version: Literal["aegis.lab.trial.v1"] = "aegis.lab.trial.v1"
    trial_id: TrialId
    pair_id: TrialId
    variant: TrialVariant
    target: BuildTarget
    attack: AttackConfig
    access: AccessPolicy
    budget: AttackBudget
    scoring: ScoringPlan
    authorization: AuthorizationReference

    @model_validator(mode="after")
    def _variant_consistency(self) -> TrialManifest:
        has_report = self.target.transformation_report_sha256 is not None
        if self.variant == TrialVariant.BASELINE and has_report:
            raise ValueError("baseline must not reference a protection transformation report")
        return self

    def canonical_bytes(self) -> bytes:
        """Stable UTF-8 representation for manifest audit hashes; not a signature."""
        data = self.model_dump(mode="json")
        return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class ManifestPairError(ValueError):
    """Paired trials are incomparable; reasons are safe field names."""

    def __init__(self, fields: tuple[str, ...]):
        self.fields = fields
        super().__init__("incomparable paired trials: " + ", ".join(fields))


def validate_pair(a: TrialManifest, b: TrialManifest) -> tuple[TrialManifest, TrialManifest]:
    """Require equivalent adversary conditions before running a paired experiment.

    Returns baseline, protected in that order. It deliberately does *not*
    claim that an attack was executed or that protection was effective.
    """

    differences: list[str] = []
    if {a.variant, b.variant} != {TrialVariant.BASELINE, TrialVariant.PROTECTED}:
        differences.append("variant")
    if a.trial_id == b.trial_id:
        differences.append("trial_id")
    if a.pair_id != b.pair_id:
        differences.append("pair_id")
    for field in ("name", "function", "source_revision", "platform", "artifact_format", "matched_build_profile"):
        if getattr(a.target, field) != getattr(b.target, field):
            differences.append(f"target.{field}")
    if a.target.final_artifact_sha256 == b.target.final_artifact_sha256:
        differences.append("target.final_artifact_sha256")
    for field in ("attack", "access", "budget", "scoring", "authorization"):
        if getattr(a, field) != getattr(b, field):
            differences.append(field)
    if differences:
        raise ManifestPairError(tuple(differences))
    baseline, protected = (a, b) if a.variant == TrialVariant.BASELINE else (b, a)
    return baseline, protected
