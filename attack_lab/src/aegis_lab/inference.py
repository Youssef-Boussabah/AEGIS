"""Lab-local inference permission and one-use budget reservation; no Core grants."""
from __future__ import annotations

from datetime import UTC, datetime
import os
from pathlib import Path

from .canonical import canonical_json_bytes, canonical_sha256
from .disclosure import AuthorizationError, InferenceApproval, check_disclosure_approval
from .private_evidence import PrivateEvidence
from .safe_io import parse_strict_json, read_regular_file


def load_approval(path: Path) -> InferenceApproval:
    st = path.lstat()
    if path.is_symlink() or st.st_mode & 0o077 or st.st_uid != os.getuid():
        raise ValueError("private_approval_required")
    return InferenceApproval.model_validate(parse_strict_json(read_regular_file(path, 64 * 1024)))


def check_inference_approval(prepared, configuration, approval, *, allow_live, now=None):
    """Validate every limit before credentials, claims or network are touched."""
    from .experiment import live_workflow_sha256

    if not allow_live:
        raise AuthorizationError("live_opt_in_required")
    if not isinstance(approval, InferenceApproval):
        raise AuthorizationError("inference_approval_required")
    # Reparse even a model_construct or copied/mutated object.
    approval = InferenceApproval.model_validate(approval.model_dump(mode="json"))
    disclosure = approval.disclosure
    check_disclosure_approval(disclosure, provider=prepared.declared_provider, endpoint=disclosure.endpoint,
                              model=prepared.request.model, artifact_sha256=prepared.artifact_sha256,
                              evidence_sha256=prepared.evidence_sha256, rendered_prompt_sha256=prepared.rendered_prompt_sha256,
                              findings=dict(prepared.findings), now=now)
    current = now or datetime.now(UTC)
    requests = min(configuration.max_steps, prepared.max_attempts)
    reserve = approval.context_tokens + prepared.request.max_output_tokens
    if current >= approval.request_deadline:
        raise AuthorizationError("request_deadline_expired")
    if (approval.manifest_sha256 != prepared.manifest_sha256
            or approval.workflow_sha256 != live_workflow_sha256(configuration)):
        raise AuthorizationError("inference_scope_mismatch")
    if (approval.max_requests != requests or reserve * requests > approval.max_total_tokens
            or approval.max_total_tokens > prepared.max_model_tokens
            or prepared.request.max_output_tokens > approval.context_tokens):
        raise AuthorizationError("inference_budget_not_approved")
    if worst_request_cost(approval, prepared.request.max_output_tokens) * requests > approval.max_spend_microusd:
        raise AuthorizationError("inference_budget_not_approved")
    # Retain the base pipeline's privacy policy; it never gains oracle/source access.
    access = prepared.manifest.access
    if access.access_to_original_source or access.repository_retrieval_enabled or access.network_enabled or access.runtime_oracle_enabled:
        raise AuthorizationError("inference_scope_mismatch")
    return approval


def worst_request_cost(approval, max_output_tokens):
    return (approval.context_tokens * approval.input_microusd_per_million
            + max_output_tokens * approval.output_microusd_per_million + 999_999) // 1_000_000


def claim_approval(approval, state_dir: Path):
    """O_EXCL whole-experiment reservation; never release after uncertain failure.

    The CLI fixes this to a private sibling of the approval file. Operator approval
    files are local attestations, not tamper-resistant capabilities or bank limits.
    """
    state_dir = Path(state_dir)
    if not state_dir.exists():
        state_dir.mkdir(mode=0o700)
    store = PrivateEvidence(state_dir, create=False)
    digest = canonical_sha256(approval.model_dump(mode="json"))
    store._check()
    try:
        fd = os.open(state_dir / digest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise AuthorizationError("inference_approval_already_used") from None
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical_json_bytes({"approval_sha256": digest, "state": "whole_budget_reserved_no_automatic_retry"}))
        stream.flush()
        os.fsync(stream.fileno())
    return digest
