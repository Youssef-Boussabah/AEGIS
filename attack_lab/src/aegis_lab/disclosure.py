"""Disclosure policy for model-facing reconstruction prompts (``aegis.lab.disclosure-policy.v1``).

The policy answers two separate questions.

1. **What may the model see?** Exactly the fields in ``MODEL_FACING_FIELDS``:
   the function label (a fixed placeholder when blinded), the expected
   interface, platform, artifact format and language, plus the decompiler's
   output for the selected function (``decompiled_c``, ``decompiler_signature``)
   and, only when symbols are revealed, the symbol-table signature. Every other
   manifest, report, authorization and run field is structurally excluded: the
   prompt is rendered from this allowlist, not filtered from a larger document.

2. **Is the selected evidence safe to disclose?** It cannot be known in general.
   Decompiled code is untrusted binary-derived text: comments, string literals
   and identifiers can carry paths, names, secrets or instructions. The scanner
   here records *findings* (category counts only, never values) and does not
   rewrite evidence, because rewriting would change its meaning. A finding is
   not proof that something is sensitive, and the absence of findings is not
   proof that nothing is. Automatic secret detection and semantic
   declassification are not provided.

Hard failures (``DisclosurePolicyError``) stop preparation in every mode:
invalid task fields or language, an interface that reveals a withheld symbol,
a withheld symbol still present after blinding, a pre-existing placeholder
collision, or a privileged trial value (ids, hidden-test or scorer identity,
authorization text, recipe digests, source revision) in a pipeline-supplied
task field. The same values inside artifact-derived evidence are recorded as the
``privileged_trial_value`` finding.

External disclosure additionally needs an ``ExternalDisclosureApproval``: an
explicit, time-bounded review decision bound to the exact artifact, evidence
report bytes, rendered prompt digest, finding categories, provider, canonical
endpoint and (optionally) model. It is an unauthenticated local file: it records
a decision, it does not prove who made it, and it is **not** Core execution
authorization (``AttackLabAuthorization`` and ``[attack_lab] enabled``).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from .manifest import _check_text
from .provider import canonical_endpoint

DISCLOSURE_POLICY_VERSION = "aegis.lab.disclosure-policy.v1"
EXTERNAL_DISCLOSURE_APPROVAL_SCHEMA = "aegis.lab.external-disclosure-approval.v1"
ALLOWED_LANGUAGES = ("c",)
BLINDED_FUNCTION_PLACEHOLDER = "target_function"
MAX_APPROVAL_VALIDITY = timedelta(days=7)
MAX_EVIDENCE_CHARS = 200_000

# The complete set of model-facing fields. Anything else never reaches a prompt.
MODEL_FACING_FIELDS = (
    "task.function",
    "task.expected_interface",
    "task.platform",
    "task.artifact_format",
    "task.language",
    "task.symbol_names",
    "evidence.decompiler_signature",
    "evidence.database_signature",
    "evidence.decompiled_c",
)

# Finding categories: recorded as counts; must be acknowledged by an approval for
# external disclosure. They never block an offline run, which discloses nothing.
FINDING_CATEGORIES = (
    "absolute_path",
    "artifact_identity",
    "comment",
    "control_or_format_character",
    "email_address",
    "file_name",
    "high_entropy_token",
    "instruction_like_text",
    "other_function_name",
    "privileged_trial_value",
    "protection_hint",
    "string_literal",
    "url",
)
FindingCategory = Literal[
    "absolute_path", "artifact_identity", "comment", "control_or_format_character", "email_address",
    "file_name", "high_entropy_token", "instruction_like_text", "other_function_name", "privileged_trial_value",
    "protection_hint", "string_literal", "url",
]

POLICY_ERROR_CODES = frozenset({
    "language_not_allowed",
    "function_label_invalid",
    "task_field_invalid",
    "interface_invalid",
    "interface_reveals_withheld_symbol",
    "withheld_symbol_present",
    "placeholder_collision",
    "privileged_value_present",
    "evidence_too_large",
})

APPROVAL_ERROR_CODES = frozenset({
    "live_opt_in_required",
    "disclosure_approval_required",
    "approval_not_yet_valid",
    "approval_expired",
    "artifact_not_approved",
    "evidence_not_approved",
    "prompt_not_approved",
    "provider_not_approved",
    "endpoint_not_approved",
    "model_not_approved",
    "findings_not_acknowledged",
    "policy_version_not_approved",
    "live_inference_disabled",
})


class DisclosurePolicyError(ValueError):
    """The prompt would violate the disclosure policy. Fails closed; message is a fixed code."""

    def __init__(self, code: str) -> None:
        if code not in POLICY_ERROR_CODES:
            raise AssertionError(f"unregistered policy error code {code!r}")
        self.code = code
        super().__init__(f"disclosure policy not satisfied: {code}")


class AuthorizationError(ValueError):
    """A live provider call is not authorized. Fails closed before any network call.

    ``reasons`` lists every unmet precondition known at the point of refusal.
    """

    def __init__(self, code: str, reasons: tuple[str, ...] = ()) -> None:
        if code not in APPROVAL_ERROR_CODES:
            raise AssertionError(f"unregistered authorization error code {code!r}")
        self.code = code
        self.reasons = reasons
        detail = f" ({', '.join(reasons)})" if reasons else ""
        super().__init__(f"live inference not authorized: {code}{detail}")


# --- Task-field validation ------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
_FIELD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_TYPE = r"[A-Za-z_][A-Za-z0-9_ ]*(?:\*+|\[[0-9]*\])*"
_INTERFACE_RE = re.compile(rf"^[A-Za-z_][A-Za-z0-9_]*\((?:{_TYPE}(?:,\s?{_TYPE})*)?\)\s?->\s?{_TYPE}$")


def check_task_fields(*, function_label: str, expected_interface: str, platform: str, artifact_format: str,
                      language: str, withheld: Iterable[str]) -> None:
    if language not in ALLOWED_LANGUAGES:
        raise DisclosurePolicyError("language_not_allowed")
    if len(function_label) > 200 or not _LABEL_RE.match(function_label):
        raise DisclosurePolicyError("function_label_invalid")
    if not _FIELD_RE.match(platform) or not _FIELD_RE.match(artifact_format):
        raise DisclosurePolicyError("task_field_invalid")
    if len(expected_interface) > 200 or not _INTERFACE_RE.match(expected_interface):
        raise DisclosurePolicyError("interface_invalid")
    if any(contains_name(expected_interface, name) for name in withheld):
        raise DisclosurePolicyError("interface_reveals_withheld_symbol")


def contains_name(text: str, name: str) -> bool:
    """Case-insensitive identifier occurrence; names of 6+ characters also match as substrings."""
    if not name:
        return False
    lowered, needle = text.casefold(), name.casefold()
    if len(needle) >= 6 and needle in lowered:
        return True
    return re.search(rf"(?<![a-z0-9_]){re.escape(needle)}(?![a-z0-9_])", lowered) is not None


def neutralize(text: str, names: Iterable[str], placeholder: str) -> tuple[str, int]:
    """Replace exact whole-identifier occurrences of ``names`` with ``placeholder``.

    This is a declared, recorded renaming of the target symbol, not a redaction
    guarantee: case variants, substrings and encoded forms are *not* rewritten;
    they are caught afterwards by ``contains_name`` and fail closed.
    """
    count = 0
    for name in sorted({n for n in names if n}, key=len, reverse=True):
        text, n = re.subn(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", placeholder, text)
        count += n
    return text, count


# --- Evidence scanning ----------------------------------------------------------------------------

_PATTERNS: dict[str, re.Pattern[str]] = {
    "absolute_path": re.compile(
        r"(?<![A-Za-z0-9_.])(?:/(?:home|Users|root|tmp|var|etc|opt|usr|mnt|srv|private|build|workspace|nix|proc)"
        r"(?:/[^\s\"'*;,)]*)?|[A-Za-z]:\\[^\s\"']+|~/[^\s\"']+)"
    ),
    "url": re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s\"']+"),
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"),
    "file_name": re.compile(
        r"\b[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:elf|so|exe|dll|pdb|dylib|bin|cpp|hpp|cc|json|ll|bc|py|java|o|a)\b"
        r"|\b[A-Za-z0-9_-]{3,}\.[ch]\b"
    ),
    "string_literal": re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|L\"(?:[^\"\\\n]|\\.)*\""),
    "comment": re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL),
    "instruction_like_text": re.compile(
        r"(?i)\b(?:ignore|disregard|override|forget)\b[^\n]{0,40}\b(?:instruction|task|prompt|previous|above|rules?)"
        r"|\bsystem prompt\b|\byou are (?:now )?(?:an?|the)\b|\b(?:assistant|system|user)\s*:"
        r"|\bBEGIN_[A-Z_]+\b|\bEND_[A-Z_]+\b|<\|[a-z_]+\|>"
    ),
    "high_entropy_token": re.compile(r"\b[0-9A-Fa-f]{32,}\b|[A-Za-z0-9+/_-]{40,}={0,2}"),
    # Letter boundaries, not word boundaries, so identifiers such as protected_demo also match.
    "protection_hint": re.compile(r"(?i)(?<![a-z])(?:baseline|protected|obfuscat|aegis|shield|mirage)"),
}
_GHIDRA_DEFAULT_NAME = re.compile(r"^(?:FUN|thunk_FUN|LAB|DAT|PTR|SUB|switchD|caseD|code_r)_")


def _privileged(values: Iterable[str]) -> list[str]:
    return sorted({v.casefold() for v in values if v and len(v) >= 4})


def scan_findings(texts: Iterable[str], *, other_function_names: Iterable[str],
                  artifact_names: Iterable[str], privileged_values: Iterable[str] = ()) -> dict[str, int]:
    """Count findings per category over artifact-derived text. Returns only non-zero counts."""
    counts: dict[str, int] = {}
    others = sorted({n for n in other_function_names if n and not _GHIDRA_DEFAULT_NAME.match(n)})
    artifacts = sorted({n for n in artifact_names if n and len(n) >= 3})
    privileged = _privileged(privileged_values)
    for text in texts:
        hits = sum(1 for value in privileged if value in text.casefold())
        if hits:
            counts["privileged_trial_value"] = counts.get("privileged_trial_value", 0) + hits
        for category, pattern in _PATTERNS.items():
            found = len(pattern.findall(text))
            if found:
                counts[category] = counts.get(category, 0) + found
        controls = sum(1 for ch in text if ch not in "\n\t" and unicodedata.category(ch) in ("Cc", "Cf"))
        if controls:
            counts["control_or_format_character"] = counts.get("control_or_format_character", 0) + controls
        names = sum(1 for name in others if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text))
        if names:
            counts["other_function_name"] = counts.get("other_function_name", 0) + names
        identities = sum(1 for name in artifacts if name.casefold() in text.casefold())
        if identities:
            counts["artifact_identity"] = counts.get("artifact_identity", 0) + identities
    return dict(sorted(counts.items()))


def check_privileged_values(texts: Iterable[str], privileged: Iterable[str]) -> None:
    """Fail closed if a privileged trial value (4+ characters) occurs in pipeline-supplied task text.

    Task fields are added by the pipeline, so a privileged value there is an isolation
    failure. The same value inside artifact-derived evidence is a finding instead
    (``scan_findings``): the attacker holds the artifact, but sending it to a third
    party must be acknowledged.
    """
    values = _privileged(privileged)
    for text in texts:
        lowered = text.casefold()
        if any(v in lowered for v in values):
            raise DisclosurePolicyError("privileged_value_present")


# --- External-disclosure approval -----------------------------------------------------------------

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_check_text)]
Description = Annotated[str, Field(min_length=1, max_length=2000), AfterValidator(_check_text)]


def _canonical(value: str) -> str:
    if canonical_endpoint(value) != value:
        raise ValueError("endpoint must be in canonical form")
    return value


class ExternalDisclosureApproval(BaseModel):
    """A recorded, time-bounded review decision to send *exactly* this material to *exactly* this endpoint.

    Unauthenticated: a local file records a decision but does not prove who made
    it. It is not Core execution authorization and does not satisfy either Core
    gate. ``rendered_prompt_sha256`` binds the decision to the exact messages
    reviewed; ``acknowledged_findings`` must cover every finding category present.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["aegis.lab.external-disclosure-approval.v1"] = EXTERNAL_DISCLOSURE_APPROVAL_SCHEMA
    reference: Identifier
    scope: Description
    approved_by: Identifier
    created_at: AwareDatetime
    valid_from: AwareDatetime
    expires_at: AwareDatetime
    artifact_sha256: Hash
    evidence_sha256: Hash
    rendered_prompt_sha256: Hash
    disclosure_policy_version: Literal["aegis.lab.disclosure-policy.v1"] = DISCLOSURE_POLICY_VERSION
    acknowledged_findings: tuple[FindingCategory, ...] = ()
    provider: Identifier
    endpoint: Annotated[str, Field(min_length=1, max_length=2048), AfterValidator(_canonical)]
    model_id: Identifier | None = None

    @model_validator(mode="after")
    def _window(self) -> ExternalDisclosureApproval:
        if not self.created_at <= self.valid_from < self.expires_at:
            raise ValueError("requires created_at <= valid_from < expires_at")
        if self.expires_at - self.valid_from > MAX_APPROVAL_VALIDITY:
            raise ValueError("validity window exceeds the maximum")
        if list(self.acknowledged_findings) != sorted(set(self.acknowledged_findings)):
            raise ValueError("acknowledged_findings must be sorted and unique")
        return self


def check_disclosure_approval(
    approval: ExternalDisclosureApproval,
    *,
    provider: str,
    endpoint: str,
    model: str,
    artifact_sha256: str,
    evidence_sha256: str,
    rendered_prompt_sha256: str,
    findings: Mapping[str, int],
    now: datetime | None = None,
) -> None:
    """Fail closed unless the approval is currently valid and covers exactly this disclosure."""
    if now is not None and (now.tzinfo is None or now.utcoffset() is None):
        raise ValueError("now must be timezone-aware")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if current < approval.valid_from.astimezone(UTC) or current < approval.created_at.astimezone(UTC):
        raise AuthorizationError("approval_not_yet_valid")
    if current >= approval.expires_at.astimezone(UTC):
        raise AuthorizationError("approval_expired")
    if approval.disclosure_policy_version != DISCLOSURE_POLICY_VERSION:
        raise AuthorizationError("policy_version_not_approved")
    if approval.artifact_sha256 != artifact_sha256:
        raise AuthorizationError("artifact_not_approved")
    if approval.evidence_sha256 != evidence_sha256:
        raise AuthorizationError("evidence_not_approved")
    if approval.rendered_prompt_sha256 != rendered_prompt_sha256:
        raise AuthorizationError("prompt_not_approved")
    if approval.provider != provider:
        raise AuthorizationError("provider_not_approved")
    if approval.endpoint != endpoint:
        raise AuthorizationError("endpoint_not_approved")
    if approval.model_id is not None and approval.model_id != model:
        raise AuthorizationError("model_not_approved")
    if not set(findings) <= set(approval.acknowledged_findings):
        raise AuthorizationError("findings_not_acknowledged")
