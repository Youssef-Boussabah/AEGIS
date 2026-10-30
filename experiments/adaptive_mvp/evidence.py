"""Import an operator-pinned receipt from a separate evidence verifier.

This module never executes evidence or reconstruction code. A digest pin is an
explicit trust decision by the operator, not a signature or a behavioral proof.
The external verifier remains responsible for the truth of its attestation.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

MAX_BYTES = 8 * 1024 * 1024
OUTCOMES = {"reconstruction_succeeded", "reconstruction_failed", "inconclusive", "unscored"}
FIELDS = {
    "schema_version", "artifact_sha256", "evidence_sha256", "attack_id",
    "protocol_sha256", "suite_sha256", "outcome", "verification_kind",
    "runtime_attestation_sha256", "verifier", "verified_at", "limitations",
}


class EvidenceError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_value(value) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def read_bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise EvidenceError("unsafe_or_oversized_evidence")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise EvidenceError("oversized_evidence")
    return data


def strict_json(data: bytes):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise EvidenceError("duplicate_json_key")
            obj[key] = value
        return obj

    def constant(_):
        raise EvidenceError("nonfinite_json")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError) as exc:
        raise EvidenceError("invalid_json") from exc


def verify_receipt(receipt_bytes: bytes, evidence_bytes: bytes, trusted_sha256: str) -> dict:
    if not hash_value(trusted_sha256) or digest(receipt_bytes) != trusted_sha256:
        raise EvidenceError("receipt_not_operator_pinned")
    receipt = strict_json(receipt_bytes)
    if type(receipt) is not dict or set(receipt) != FIELDS:
        raise EvidenceError("invalid_receipt_fields")
    if receipt["schema_version"] != "aegis.adaptive.attack-receipt.v1":
        raise EvidenceError("unsupported_receipt_schema")
    for key in ("artifact_sha256", "evidence_sha256", "protocol_sha256", "suite_sha256"):
        if not hash_value(receipt[key]):
            raise EvidenceError("invalid_receipt_digest")
    if receipt["evidence_sha256"] != digest(evidence_bytes):
        raise EvidenceError("evidence_digest_mismatch")
    for key in ("attack_id", "verifier"):
        value = receipt[key]
        if type(value) is not str or not value.strip() or len(value) > 200:
            raise EvidenceError("invalid_verifier_or_attack")
    if type(receipt["outcome"]) is not str or receipt["outcome"] not in OUTCOMES:
        raise EvidenceError("invalid_attack_outcome")
    kind = receipt["verification_kind"]
    if kind not in ("independent_behavioral", "structural_only", "unscored"):
        raise EvidenceError("invalid_verification_kind")
    decisive = receipt["outcome"] in ("reconstruction_succeeded", "reconstruction_failed")
    if decisive and (kind != "independent_behavioral" or not hash_value(
            receipt["runtime_attestation_sha256"])):
        raise EvidenceError("behavioral_outcome_requires_verified_isolation")
    if not decisive and receipt["runtime_attestation_sha256"] is not None and not hash_value(
            receipt["runtime_attestation_sha256"]):
        raise EvidenceError("invalid_runtime_attestation")
    limitations = receipt["limitations"]
    if (type(limitations) is not list or not 1 <= len(limitations) <= 32
            or any(type(item) is not str or not item.strip() or len(item) > 2000 for item in limitations)):
        raise EvidenceError("limitations_required")
    try:
        timestamp = datetime.fromisoformat(receipt["verified_at"])
        if timestamp.tzinfo is None:
            raise ValueError()
    except (TypeError, ValueError):
        raise EvidenceError("invalid_verification_timestamp") from None
    return {**receipt, "receipt_sha256": trusted_sha256,
            "trust": "operator_pinned_external_verifier_attestation"}


def load_index(path: Path | None, archive: Path) -> list[dict]:
    if path is None:
        return []
    index = strict_json(read_bounded(path))
    if (type(index) is not dict or set(index) != {"schema_version", "entries"}
            or index["schema_version"] != "aegis.adaptive.evidence-index.v1"
            or type(index["entries"]) is not list or len(index["entries"]) > 128):
        raise EvidenceError("invalid_evidence_index")
    archive.mkdir(mode=0o700)
    results = []
    identities = set()
    for i, entry in enumerate(index["entries"]):
        if type(entry) is not dict or set(entry) != {"receipt", "evidence", "trusted_receipt_sha256"}:
            raise EvidenceError("invalid_index_entry")
        files = []
        for key in ("receipt", "evidence"):
            if type(entry[key]) is not str:
                raise EvidenceError("invalid_index_path")
            relative = Path(entry[key])
            if relative.is_absolute() or ".." in relative.parts:
                raise EvidenceError("evidence_path_escape")
            candidate = path.parent / relative
            if not candidate.resolve().is_relative_to(path.parent.resolve()):
                raise EvidenceError("evidence_path_escape")
            files.append(read_bounded(candidate))
        receipt = verify_receipt(*files, entry["trusted_receipt_sha256"])
        # One result per artifact/attack/protocol/suite. Conflicts and duplicates
        # require external reconciliation, rather than cherry-picking outcomes.
        identity = tuple(receipt[key] for key in (
            "artifact_sha256", "attack_id", "protocol_sha256", "suite_sha256"))
        if identity in identities:
            raise EvidenceError("duplicate_or_conflicting_attack_evidence")
        identities.add(identity)
        for key, data in zip(("receipt", "evidence"), files):
            (archive / f"{i:03d}-{key}.json").write_bytes(data)
        results.append(receipt)
    (archive / "index.json").write_bytes(read_bounded(path))
    return results


def resistance_for(artifact_sha256: str, receipts: list[dict]) -> dict:
    matching = [item for item in receipts if item["artifact_sha256"] == artifact_sha256]
    decisive = [item for item in matching if item["outcome"] in (
        "reconstruction_succeeded", "reconstruction_failed")]
    return {
        "status": "MEASURED_FOR_DECLARED_ATTACKS" if decisive else "UNMEASURED",
        "score": None,
        "evidence": matching,
        "limitation": "A failed reconstruction is limited to the named attack, suite and budget; no security guarantee.",
    }
