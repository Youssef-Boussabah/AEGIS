"""Synthetic receipts exercise validation only; they attest to no actual attack."""
import json

import pytest

from experiments.adaptive_mvp.evidence import EvidenceError, digest, load_index, verify_receipt


def receipt(outcome="unscored"):
    decisive = outcome in ("reconstruction_succeeded", "reconstruction_failed")
    return {"schema_version": "aegis.adaptive.attack-receipt.v1", "artifact_sha256": "a" * 64,
            "evidence_sha256": digest(b"synthetic test evidence; not an attack result"),
            "attack_id": "test-only", "protocol_sha256": "b" * 64, "suite_sha256": "c" * 64,
            "outcome": outcome, "verification_kind": "independent_behavioral" if decisive else "unscored",
            "runtime_attestation_sha256": "d" * 64 if decisive else None,
            "verifier": "test-only-no-execution", "verified_at": "2026-10-30T08:00:00-04:00",
            "limitations": ["Synthetic test fixture, never real behavioral evidence."]}


def encode(value):
    return json.dumps(value).encode()


def verify(value, evidence=b"synthetic test evidence; not an attack result"):
    data = encode(value)
    return verify_receipt(data, evidence, digest(data))


@pytest.mark.parametrize("outcome", ["reconstruction_succeeded", "reconstruction_failed", "inconclusive", "unscored"])
def test_all_explicit_outcomes_are_preserved(outcome):
    result = verify(receipt(outcome))
    assert result["outcome"] == outcome
    assert result["trust"] == "operator_pinned_external_verifier_attestation"


def test_receipt_requires_an_explicit_matching_operator_pin():
    data = encode(receipt())
    with pytest.raises(EvidenceError, match="not_operator_pinned"):
        verify_receipt(data, b"", "0" * 64)


def test_modified_evidence_is_rejected():
    with pytest.raises(EvidenceError, match="evidence_digest_mismatch"):
        verify(receipt(), b"tampered")


@pytest.mark.parametrize(("field", "value"), [
    ("outcome", "resisted"), ("outcome", []), ("artifact_sha256", "invalid"),
    ("verification_kind", "test_double"), ("verifier", " "), ("verified_at", "2026-10-30"),
    ("limitations", []), ("suite_sha256", True), ("runtime_attestation_sha256", "invalid"),
])
def test_invalid_receipts_are_rejected(field, value):
    item = receipt()
    item[field] = value
    with pytest.raises(EvidenceError):
        verify(item)


@pytest.mark.parametrize("outcome", ["reconstruction_succeeded", "reconstruction_failed"])
@pytest.mark.parametrize(("kind", "runtime"), [("structural_only", None), ("unscored", "d" * 64), ("independent_behavioral", None)])
def test_decisive_behavior_requires_external_isolation_attestation(outcome, kind, runtime):
    item = receipt(outcome)
    item.update({"verification_kind": kind, "runtime_attestation_sha256": runtime})
    with pytest.raises(EvidenceError, match="requires_verified_isolation"):
        verify(item)


def test_duplicate_unknown_and_nonfinite_json_are_rejected():
    item = receipt()
    item["score"] = 99
    with pytest.raises(EvidenceError, match="fields"):
        verify(item)
    for data in (b'{"outcome":"unscored","outcome":"reconstruction_failed"}', b'{"x":NaN}'):
        with pytest.raises(EvidenceError):
            verify_receipt(data, b"", digest(data))


def index_fixture(tmp_path):
    data = encode(receipt())
    (tmp_path / "receipt.json").write_bytes(data)
    (tmp_path / "evidence.json").write_bytes(b"synthetic test evidence; not an attack result")
    entry = {"receipt": "receipt.json", "evidence": "evidence.json", "trusted_receipt_sha256": digest(data)}
    index = {"schema_version": "aegis.adaptive.evidence-index.v1", "entries": [entry]}
    path = tmp_path / "index.json"
    path.write_bytes(encode(index))
    return path, index


def test_index_archives_exact_bytes_without_executing_them(tmp_path):
    path, _ = index_fixture(tmp_path)
    result = load_index(path, tmp_path / "archive")
    assert len(result) == 1
    assert (tmp_path / "archive/000-evidence.json").read_bytes() == (tmp_path / "evidence.json").read_bytes()
    assert (tmp_path / "archive/000-receipt.json").read_bytes() == (tmp_path / "receipt.json").read_bytes()


def test_conflicting_or_duplicate_attacks_are_rejected(tmp_path):
    path, index = index_fixture(tmp_path)
    index["entries"] *= 2
    path.write_bytes(encode(index))
    with pytest.raises(EvidenceError, match="duplicate_or_conflicting"):
        load_index(path, tmp_path / "archive")


@pytest.mark.parametrize("unsafe", ["../receipt.json", "/tmp/receipt.json"])
def test_index_path_escape_is_rejected(tmp_path, unsafe):
    path, index = index_fixture(tmp_path)
    index["entries"][0]["receipt"] = unsafe
    path.write_bytes(encode(index))
    with pytest.raises(EvidenceError, match="path_escape"):
        load_index(path, tmp_path / "archive")


def test_index_symlink_is_rejected(tmp_path):
    path, index = index_fixture(tmp_path)
    (tmp_path / "alias.json").symlink_to(tmp_path / "receipt.json")
    index["entries"][0]["receipt"] = "alias.json"
    path.write_bytes(encode(index))
    with pytest.raises(EvidenceError, match="unsafe"):
        load_index(path, tmp_path / "archive")
