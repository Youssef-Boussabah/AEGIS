"""Versioned experiment manifest for paired reconstruction trials.

This is a *local research schema*, not an aegis.adapter.v1 message or a Core
ProtectionPolicy. Validating a manifest cannot grant permission to run attacks:
Core's operator switch and per-job AttackLabAuthorization remain mandatory.

A manifest is a *declaration* made before a trial. Its digests are claims by the
author; the Lab does not verify them here. Independently checked evidence and
attack outcomes are separate records.

Nothing here invokes REA, Ghidra, model providers or generated code.
"""

from __future__ import annotations

import hashlib
import os
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    model_validator,
)
from pydantic_core import PydanticCustomError

from .canonical import CANONICALIZATION, canonical_json_bytes
from .safe_io import LoadError, parse_strict_json, read_regular_file

SCHEMA_VERSION = "aegis.lab.trial.v2"
RETIRED_SCHEMA_VERSIONS = ("aegis.lab.trial.v1",)
ATTACKER_VIEW_SCHEMA = "aegis.lab.attacker-view.v1"
MAX_MANIFEST_BYTES = 1_048_576

# Error types raised by this module's validators. Their codes are fixed strings
# and safe to show; the accompanying messages never contain input values.
MANIFEST_ERROR_TYPES = frozenset({
    "aegis_blank",
    "aegis_surrounding_whitespace",
    "aegis_forbidden_character",
    "aegis_not_nfc",
    "aegis_duplicate_tool",
    "aegis_tools_not_sorted",
    "aegis_workflow_tool_missing",
    "aegis_oracle_inconsistent",
    "aegis_baseline_has_protection",
    "aegis_protected_missing_protection",
})

# Control (Cc), format (Cf: bidi overrides, zero-width characters), surrogate,
# private-use and unassigned code points, and line/paragraph separators.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def _check_text(value: str) -> str:
    """Reject, never rewrite, values that are blank, padded, invisible or ambiguous.

    Legitimate values are returned unchanged: no stripping, case folding or
    Unicode normalization is applied. Values must already be in NFC so that
    canonically equivalent spellings cannot produce two different identities.
    """
    if not value.strip():
        raise PydanticCustomError("aegis_blank", "must not be blank")
    if value != value.strip():
        raise PydanticCustomError("aegis_surrounding_whitespace", "must not start or end with whitespace")
    if any(unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in value):
        raise PydanticCustomError("aegis_forbidden_character", "contains a control, format or unassigned character")
    if unicodedata.normalize("NFC", value) != value:
        raise PydanticCustomError("aegis_not_nfc", "must be Unicode NFC")
    return value


Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
TrialId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_check_text)]
Description = Annotated[str, Field(min_length=1, max_length=2000), AfterValidator(_check_text)]
Seed = Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]


class StrictRecord(BaseModel):
    """Reject unknown fields; use strict types for security-critical numeric/boolean fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrialVariant(StrEnum):
    BASELINE = "baseline"
    PROTECTED = "protected"


class ToolIdentity(StrictRecord):
    """A tool bound by digests, not only by its declared name and version.

    ``executable_sha256`` identifies the program that is run (for Ghidra, the
    ``analyzeHeadless`` launcher). ``configuration_sha256`` identifies every
    setting, script and limit that can change its output; how it is computed is
    tool-specific and must be documented with the tool's evidence format.
    """

    name: Identifier
    version: Identifier
    executable_sha256: Hash
    configuration_sha256: Hash


class BuildConditions(StrictRecord):
    """Declared build conditions that must be identical for both variants of a pair."""

    pipeline: Identifier
    compiler: ToolIdentity
    shared_recipe_sha256: Hash
    symbols: Literal["stripped", "present"]
    debug_info: StrictBool


class ProtectionStep(StrictRecord):
    """The only build difference a pair may declare: one protection step.

    The transformation report is the backend's own claim about what it changed.
    It does not show that the transformation survived optimization, linking or
    stripping into the final artifact.
    """

    backend: ToolIdentity
    seed: Seed | None = None
    transformation_report_sha256: Hash


class BuildTarget(StrictRecord):
    """Identity of the *final* artifact the attacker receives, not intermediate IR."""

    name: Identifier
    function: Identifier
    source_revision: Identifier
    platform: Identifier
    artifact_format: Identifier
    final_artifact_sha256: Hash
    build: BuildConditions
    protection: ProtectionStep | None = None


class AccessPolicy(StrictRecord):
    """Explicit limits on evidence and oracle access for this trial.

    ``workspace_policy_sha256`` identifies the rules for which files, besides the
    trial's final artifact, are placed in the attacker workspace.
    ``access_to_symbols`` means separate symbol or debug files; whether the
    artifact itself is stripped is ``target.build.symbols``.
    """

    workspace_policy_sha256: Hash
    access_to_original_source: StrictBool = False
    access_to_symbols: StrictBool = False
    repository_retrieval_enabled: StrictBool = False
    network_enabled: StrictBool = False
    runtime_oracle_enabled: StrictBool = False
    oracle_query_limit: Annotated[StrictInt, Field(ge=0, le=1_000_000)] = 0
    oracle_configuration_sha256: Hash | None = None

    @model_validator(mode="after")
    def _oracle_consistency(self) -> AccessPolicy:
        if self.runtime_oracle_enabled:
            if self.oracle_query_limit < 1 or self.oracle_configuration_sha256 is None:
                raise PydanticCustomError(
                    "aegis_oracle_inconsistent", "an enabled oracle needs a query limit and a configuration digest"
                )
        elif self.oracle_query_limit or self.oracle_configuration_sha256 is not None:
            raise PydanticCustomError(
                "aegis_oracle_inconsistent", "oracle limit and configuration must be unset when the oracle is disabled"
            )
        return self


class AttackBudget(StrictRecord):
    max_wall_seconds: Annotated[StrictInt, Field(ge=1, le=86_400)]
    max_model_tokens: Annotated[StrictInt, Field(ge=1, le=100_000_000)]
    max_tool_calls: Annotated[StrictInt, Field(ge=1, le=1_000_000)]
    max_attempts: Annotated[StrictInt, Field(ge=1, le=100_000)] = 1


_WORKFLOW_TOOL = {"ghidra_model": "ghidra", "rea": "rea"}


class AttackConfig(StrictRecord):
    """A reproducible workflow; tools may include REA and/or Ghidra.

    ``tools`` is a set: order carries no meaning, so it must be listed in
    ascending case-folded name order and names must be unique case-insensitively.
    ``sampling_configuration_sha256`` covers every model request parameter other
    than ``model_id``, ``temperature`` and ``sampling_seed``.
    """

    workflow: Literal["ghidra_model", "rea", "custom"]
    workflow_configuration_sha256: Hash
    tools: Annotated[tuple[ToolIdentity, ...], Field(min_length=1, max_length=32)]
    provider: Identifier
    model_id: Identifier
    prompt_sha256: Hash
    sampling_configuration_sha256: Hash
    sampling_seed: Seed | None = None
    temperature: Annotated[StrictFloat, Field(ge=0.0, le=2.0)] = 0.0
    session_isolation: Literal["fresh_session_and_workspace"]

    @model_validator(mode="after")
    def _tool_set(self) -> AttackConfig:
        keys = [tool.name.casefold() for tool in self.tools]
        if len(keys) != len(set(keys)):
            raise PydanticCustomError("aegis_duplicate_tool", "tool names must be unique, ignoring case")
        if keys != sorted(keys):
            raise PydanticCustomError("aegis_tools_not_sorted", "tools must be sorted by case-folded name")
        required = _WORKFLOW_TOOL.get(self.workflow)
        if required is not None and required not in keys:
            raise PydanticCustomError("aegis_workflow_tool_missing", "the workflow's primary tool is not listed")
        return self


class ScoringPlan(StrictRecord):
    """Identity of the hidden tests and scorer. Test contents never appear in a manifest.

    ``hidden_test_suite_sha256`` must be computed over the complete test-suite
    archive. A digest of a small or guessable answer could be brute-forced.
    """

    hidden_test_suite_sha256: Hash
    scorer: ToolIdentity
    score_rule: Literal["all_hidden_tests_pass"] = "all_hidden_tests_pass"
    expected_interface: Identifier


class AuthorizationReference(StrictRecord):
    """Audit metadata only. NOT a grant of authority to execute any trial."""

    reference: Identifier
    authorized_scope: Description


class TrialManifest(StrictRecord):
    schema_version: Literal["aegis.lab.trial.v2"] = SCHEMA_VERSION
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
        has_protection = self.target.protection is not None
        if self.variant == TrialVariant.BASELINE and has_protection:
            raise PydanticCustomError("aegis_baseline_has_protection", "a baseline must not declare a protection step")
        if self.variant == TrialVariant.PROTECTED and not has_protection:
            raise PydanticCustomError("aegis_protected_missing_protection", "a protected trial must declare its protection step")
        return self

    def canonical_bytes(self) -> bytes:
        """``aegis.lab.canonical-json.v1`` bytes of the full record; see ``aegis_lab.canonical``."""
        return canonical_json_bytes(self.model_dump(mode="json"))

    def sha256(self) -> str:
        """Record fingerprint for audit references. Not a signature."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def attacker_view(self) -> dict[str, Any]:
        """The only manifest content that may be placed in an attacker workspace.

        Allowlisted: the task (function, interface, platform, format), the artifact
        digest, access policy and budget. Excluded: variant, trial and pair ids,
        target name and source revision, build and protection details, the attack
        workflow configuration, hidden-test and scorer identities, and authorization.
        """
        return {
            "schema_version": ATTACKER_VIEW_SCHEMA,
            "task": {
                "function": self.target.function,
                "expected_interface": self.scoring.expected_interface,
                "platform": self.target.platform,
                "artifact_format": self.target.artifact_format,
            },
            "artifact_sha256": self.target.final_artifact_sha256,
            "access": self.access.model_dump(mode="json"),
            "budget": self.budget.model_dump(mode="json"),
        }


def parse_manifest(data: bytes) -> TrialManifest:
    """Parse untrusted manifest bytes. Raises LoadError or pydantic.ValidationError."""
    document = parse_strict_json(data)
    if isinstance(document, dict) and document.get("schema_version") in RETIRED_SCHEMA_VERSIONS:
        raise LoadError("retired_schema_version")
    return TrialManifest.model_validate_json(data)


def load_manifest(path: str | os.PathLike[str]) -> TrialManifest:
    return parse_manifest(read_regular_file(path, MAX_MANIFEST_BYTES))


class ManifestPairError(ValueError):
    """Paired trials are incomparable; reasons are schema field paths only."""

    def __init__(self, fields: tuple[str, ...]):
        self.fields = fields
        super().__init__("incomparable paired trials: " + ", ".join(fields))


@dataclass(frozen=True)
class PairValidation:
    """Declared configurations are comparable. This is not evidence of a fair or completed trial."""

    baseline: TrialManifest
    protected: TrialManifest

    @property
    def final_artifacts_identical(self) -> bool:
        return self.baseline.target.final_artifact_sha256 == self.protected.target.final_artifact_sha256

    def summary(self) -> dict[str, Any]:
        observations = []
        if self.final_artifacts_identical:
            observations.append(
                "final_artifacts_identical: the protected final artifact is byte-identical to the baseline; "
                "the protection step had no observable effect on it (for example, it was optimized away). "
                "Any outcome difference cannot be attributed to protection."
            )
        return {
            "validation": "declared_configuration_comparable",
            "pair_id": self.baseline.pair_id,
            "baseline_trial_id": self.baseline.trial_id,
            "protected_trial_id": self.protected.trial_id,
            "baseline_manifest_sha256": self.baseline.sha256(),
            "protected_manifest_sha256": self.protected.sha256(),
            "fingerprint": f"sha256 over {CANONICALIZATION}",
            "final_artifacts_identical": self.final_artifacts_identical,
            "observations": observations,
            "not_established": [
                "that declared digests match the actual tools, recipes, workspace or tests",
                "that both artifacts were built reproducibly from the shared recipe",
                "that the protection was retained in the final protected artifact",
                "that any attack was run, or any outcome",
            ],
            "attacks_executed": False,
            "authorizes_execution": False,
        }


def _differences(a: BaseModel, b: BaseModel, prefix: str, skip: frozenset[str] = frozenset()) -> list[str]:
    found: list[str] = []
    for name in type(a).model_fields:
        if name in skip:
            continue
        left, right = getattr(a, name), getattr(b, name)
        if isinstance(left, StrictRecord) and isinstance(right, StrictRecord) and type(left) is type(right):
            found.extend(_differences(left, right, f"{prefix}{name}."))
        elif left != right:
            found.append(f"{prefix}{name}")
    return found


def validate_pair(a: TrialManifest, b: TrialManifest) -> PairValidation:
    """Require equal declared adversary conditions before running a paired experiment.

    Accepts the two manifests in either order. Allowed differences: ``trial_id``
    and ``variant`` (which must differ), ``target.final_artifact_sha256`` (equal
    hashes are permitted and reported), and ``target.protection`` (present only
    on the protected variant). Everything else must be equal. This does *not*
    claim that an attack was executed or that protection was effective.
    """
    differences: list[str] = []
    if {a.variant, b.variant} != {TrialVariant.BASELINE, TrialVariant.PROTECTED}:
        differences.append("variant")
    if a.trial_id == b.trial_id:
        differences.append("trial_id")
    differences.extend(
        _differences(a, b, "", skip=frozenset({"trial_id", "variant", "target"}))
    )
    differences.extend(
        _differences(a.target, b.target, "target.", skip=frozenset({"final_artifact_sha256", "protection"}))
    )
    if differences:
        raise ManifestPairError(tuple(differences))
    baseline, protected = (a, b) if a.variant == TrialVariant.BASELINE else (b, a)
    return PairValidation(baseline=baseline, protected=protected)
