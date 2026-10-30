"""Authorization for attack-lab work, including untrusted candidate execution.

Two gates protect every attack-lab task and are checked by one function,
``check_attack_lab_gates``, used by the orchestrator and by candidate execution:

1. ``[attack_lab] enabled = true`` in the operator's configuration;
2. a present, unexpired ``AttackLabAuthorization``.

Compiling or running a generated candidate additionally needs:

3. ``[attack_lab.candidate_execution] enabled = true`` (operator, off by default);
4. a ``CandidateExecutionGrant`` (``aegis.core.candidate-execution-grant.v1``)
   that embeds the gate-2 authorization and binds the permitted target artifacts,
   candidate digests, stages, compiler flags, resource limits, run budgets, the
   Lab's declared digests and a validity window.

A grant is an operator-attested record, not a cryptographic credential.
See docs/adr/0004-isolated-candidate-execution.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, Field, StrictInt, ValidationError, model_validator

from .config import AegisConfig
from .errors import AegisError
from .lab_limits import CompileLimits, SandboxLimits
from .models import AegisModel, AttackLabAuthorization, ErrorCode, ObjectId, Sha256

GRANT_SCHEMA = "aegis.core.candidate-execution-grant.v1"
MAX_GRANT_BYTES = 64 * 1024
MAX_GRANT_WINDOW = timedelta(days=7)
MAX_CANDIDATES = 64
MAX_TARGETS = 16

ExecutionStage = Literal["compile", "execute"]

# Compiler flags are an allowlist. None of them reads a path, loads a plugin or
# runs a program. Kept identical to the Lab's sandbox-policy allowlist.
COMPILER_FLAG_PATTERN = (
    r"^-(?:std=c11|O[0-3s]|static|fwrapv|fno-strict-aliasing|fno-builtin|fno-pie|no-pie|w|Wall|"
    r"Wextra|pedantic|Werror=[a-z][a-z-]{0,62})$"
)
CompilerFlag = Annotated[str, Field(pattern=COMPILER_FLAG_PATTERN)]

# Stable values of ``details["reason"]`` on AUTHORIZATION_REQUIRED errors.
REFUSAL_REASONS = frozenset(
    {
        # gates 1-3
        "attack_lab_disabled",
        "authorization_missing",
        "authorization_expired",
        "candidate_execution_disabled",
        # grant validity and operator ceilings
        "grant_not_yet_valid",
        "grant_expired",
        "grant_exceeds_operator_ceiling",
        # the grant id was first used by a grant with different contents
        "grant_ledger_conflict",
        # binding of one stage invocation to the grant
        "lab_bindings_mismatch",
        "stage_not_permitted",
        "candidate_not_permitted",
        "candidate_digest_mismatch",
        "compilation_bundle_required",
        "compilation_bundle_mismatch",
        "compile_flags_mismatch",
        "limits_exceed_grant",
        "binary_not_from_session",
        "compilation_budget_exhausted",
        "execution_budget_exhausted",
        "wall_budget_exhausted",
        # session state
        "session_closed",
        "session_failed",
    }
)


def refuse(reason: str, message: str, **details: Any) -> AegisError:
    """An AUTHORIZATION_REQUIRED error with a registered ``details.reason``."""
    if reason not in REFUSAL_REASONS:
        raise AssertionError(f"unregistered refusal reason {reason!r}")
    return AegisError(ErrorCode.AUTHORIZATION_REQUIRED, message, {"reason": reason, **details})


# --------------------------------------------------------------- gates 1 and 2


def check_attack_lab_gates(
    config: AegisConfig, authorization: AttackLabAuthorization | None, now: datetime
) -> None:
    """The two attack-lab gates. Raise AUTHORIZATION_REQUIRED unless both hold."""
    if not config.attack_lab.enabled:
        raise refuse(
            "attack_lab_disabled",
            "Attack-lab tasks are disabled in this AEGIS configuration "
            "([attack_lab] enabled = false).",
        )
    if authorization is None:
        raise refuse(
            "authorization_missing",
            "Attack-lab tasks require an explicit authorization record "
            "(authorized_by, reference, scope).",
        )
    if authorization.expires_at is not None and authorization.expires_at <= now:
        raise refuse(
            "authorization_expired",
            "The attack-lab authorization has expired.",
            expires_at=authorization.expires_at.isoformat(),
        )


# ----------------------------------------------------------------------- grant


class PermittedCandidate(AegisModel):
    candidate_id: ObjectId
    """The Lab's identifier for this candidate (its trial id). Opaque to Core."""
    candidate_sha256: Sha256
    """SHA-256 of the exact untrusted candidate source bytes."""
    target_sha256: Sha256
    """The final artifact this candidate reconstructs; one of ``permitted_targets``."""
    compilation_bundle_sha256: Sha256 | None = None
    """Digest of all named files and the ordered translation units. Missing means
    only candidate.c, compiled alone, is permitted (legacy single-source grant)."""


def compilation_bundle_sha256(files: dict[str, bytes], translation_units: list[str] | tuple[str, ...]) -> str:
    """Digest reviewed by the grant issuer, independently of the stage request.

    File order is immaterial; names, bytes and translation-unit order are bound.
    This hashes metadata only and neither parses nor compiles submitted code.
    """
    value = {"files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
             "translation_units": list(translation_units)}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")).hexdigest()


class LabBindings(AegisModel):
    """Digests declared by the Lab. Core binds and records them but cannot verify them."""

    pair_id: ObjectId
    hidden_test_suite_sha256: Sha256
    sandbox_policy_sha256: Sha256
    scorer_configuration_sha256: Sha256


class CandidateExecutionGrant(AegisModel):
    """A reviewed decision to compile and/or run exactly these candidates, within these limits."""

    schema_version: Literal["aegis.core.candidate-execution-grant.v1"]
    grant_id: ObjectId
    authorization: AttackLabAuthorization
    permitted_targets: Annotated[list[Sha256], Field(min_length=1, max_length=MAX_TARGETS)]
    candidates: Annotated[list[PermittedCandidate], Field(min_length=1, max_length=MAX_CANDIDATES)]
    stages: Annotated[list[ExecutionStage], Field(min_length=1, max_length=2)]
    compile_flags: Annotated[list[CompilerFlag], Field(max_length=32)] = Field(default_factory=list)
    compile_limits: CompileLimits | None = None
    execute_limits: SandboxLimits | None = None
    max_compilations_per_candidate: Annotated[StrictInt, Field(ge=1, le=16)] = 1
    max_executions_per_candidate: Annotated[StrictInt, Field(ge=0, le=4096)] = 0
    max_total_wall_ms: Annotated[StrictInt, Field(ge=1_000, le=86_400_000)]
    """Sum of the wall limits of all stage invocations under this grant."""
    lab_bindings: LabBindings
    valid_from: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def _consistent(self) -> CandidateExecutionGrant:
        if not self.valid_from < self.expires_at:
            raise ValueError("valid_from must be before expires_at")
        if self.expires_at - self.valid_from > MAX_GRANT_WINDOW:
            raise ValueError("the validity window must not exceed 7 days")
        auth = self.authorization
        if "attested_at" not in auth.model_fields_set:
            raise ValueError("authorization.attested_at must be stated explicitly in a grant")
        if auth.attested_at > self.valid_from:
            raise ValueError("a grant cannot become valid before its authorization was attested")
        if auth.expires_at is not None and self.expires_at > auth.expires_at:
            raise ValueError("a grant must not outlive its authorization")

        if len(set(self.permitted_targets)) != len(self.permitted_targets):
            raise ValueError("permitted_targets must be unique")
        ids = [c.candidate_id for c in self.candidates]
        if len(set(ids)) != len(ids):
            raise ValueError("candidate_id values must be unique")
        used = {c.target_sha256 for c in self.candidates}
        if not used <= set(self.permitted_targets):
            raise ValueError("every candidate target must be listed in permitted_targets")
        if used != set(self.permitted_targets):
            raise ValueError("every permitted target must be used by at least one candidate")

        stages = set(self.stages)
        if len(stages) != len(self.stages):
            raise ValueError("stages must be unique")
        if "execute" in stages and "compile" not in stages:
            raise ValueError("execute requires compile: only binaries compiled under the grant run")
        if "compile" in stages:
            if self.compile_limits is None or not self.compile_flags:
                raise ValueError("compile requires compile_limits and compile_flags")
        elif self.compile_limits is not None or self.compile_flags:
            raise ValueError("compile_limits and compile_flags require the compile stage")
        if len(set(self.compile_flags)) != len(self.compile_flags):
            raise ValueError("compile_flags must be unique")
        if "execute" in stages:
            if self.execute_limits is None or self.max_executions_per_candidate < 1:
                raise ValueError("execute requires execute_limits and max_executions_per_candidate >= 1")
        elif self.execute_limits is not None or self.max_executions_per_candidate != 0:
            raise ValueError("execute_limits and executions require the execute stage")
        return self

    def candidate(self, candidate_id: str) -> PermittedCandidate | None:
        for item in self.candidates:
            if item.candidate_id == candidate_id:
                return item
        return None


def grant_sha256(grant: CandidateExecutionGrant) -> str:
    """SHA-256 of the grant's canonical JSON (sorted keys, no whitespace, UTF-8).

    It identifies the record; it does not authenticate it.
    """
    value = grant.model_dump(mode="json")
    # Preserve the identity and persistent usage of pre-bundle v1 grants. Adding
    # a real bundle digest intentionally changes identity; absence does not.
    for candidate in value["candidates"]:
        if candidate["compilation_bundle_sha256"] is None:
            del candidate["compilation_bundle_sha256"]
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-finite number")


def _invalid_grant(message: str, **details: Any) -> AegisError:
    return AegisError(ErrorCode.INVALID_REQUEST, message, details)


def _safe_loc(err: Any) -> str:
    # An unknown key name can itself be a secret: never echo it.
    parts = [str(p) for p in err["loc"]]
    if err["type"] == "extra_forbidden" and parts:
        parts[-1] = "<unknown>"
    return ".".join(parts)


def parse_grant(data: bytes) -> CandidateExecutionGrant:
    """Strictly parse a grant: bounded, UTF-8 without BOM, no duplicate keys, no NaN."""
    if len(data) > MAX_GRANT_BYTES:
        raise _invalid_grant(f"Candidate execution grant exceeds {MAX_GRANT_BYTES} bytes.")
    if data.startswith(b"\xef\xbb\xbf"):
        raise _invalid_grant("Candidate execution grant must not start with a byte-order mark.")
    try:
        json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError):
        # Covers invalid UTF-8, malformed JSON, duplicate keys and NaN/Infinity.
        raise _invalid_grant("Candidate execution grant is not strict UTF-8 JSON.") from None
    try:
        return CandidateExecutionGrant.model_validate_json(data, strict=True)
    except ValidationError as exc:
        problems = [
            {"loc": _safe_loc(err), "msg": err["msg"]}
            for err in exc.errors(include_input=False, include_url=False, include_context=False)[:20]
        ]
        raise _invalid_grant("Candidate execution grant failed validation.", errors=problems) from None


def load_grant(path: str | os.PathLike[str]) -> CandidateExecutionGrant:
    """Read and parse a grant file: a regular file, not a symlink, at most MAX_GRANT_BYTES."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(Path(path), flags)
    except OSError:
        raise _invalid_grant("Candidate execution grant file cannot be opened.") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise _invalid_grant("Candidate execution grant must be a regular file.")
        if info.st_size > MAX_GRANT_BYTES:
            raise _invalid_grant(f"Candidate execution grant exceeds {MAX_GRANT_BYTES} bytes.")
        chunks: list[bytes] = []
        remaining = MAX_GRANT_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        raise _invalid_grant("Candidate execution grant file cannot be read.") from None
    finally:
        os.close(fd)
    return parse_grant(b"".join(chunks))


# --------------------------------------------------------------- authorization


def authorize_candidate_execution(
    config: AegisConfig, grant: CandidateExecutionGrant, now: datetime
) -> None:
    """Gates 1-3, the grant's window and the operator ceilings. Raise unless all hold.

    This decides whether execution *may* happen. It does not provide isolation;
    a runtime must still pass its own preflight.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    check_attack_lab_gates(config, grant.authorization, now)
    execution = config.attack_lab.candidate_execution
    if not execution.enabled:
        raise refuse(
            "candidate_execution_disabled",
            "Compiling or running Lab candidates is disabled in this AEGIS configuration "
            "([attack_lab.candidate_execution] enabled = false).",
        )
    if now < grant.valid_from:
        raise refuse(
            "grant_not_yet_valid",
            "The candidate execution grant is not valid yet.",
            valid_from=grant.valid_from.isoformat(),
        )
    if now >= grant.expires_at:
        raise refuse(
            "grant_expired",
            "The candidate execution grant has expired.",
            expires_at=grant.expires_at.isoformat(),
        )
    over: dict[str, list[str]] = {}
    if grant.compile_limits is not None:
        if fields := grant.compile_limits.exceeding(execution.compile_ceiling):
            over["compile"] = fields
    if grant.execute_limits is not None:
        if fields := grant.execute_limits.exceeding(execution.execute_ceiling):
            over["execute"] = fields
    if over:
        raise refuse(
            "grant_exceeds_operator_ceiling",
            "The grant's limits exceed the operator's configured ceilings.",
            exceeding=over,
        )
