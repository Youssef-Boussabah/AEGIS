"""Phase 4: aegis.lab.hidden-suite.v1 integrity, strictness and reference self-checks."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from scoring_fixtures import ARGUMENTS, INTERFACE, reference, suite_bytes

from aegis_lab.hidden_suite import (
    MAX_SUITE_BYTES,
    MAX_SUITE_CASES,
    audit_suite,
    load_hidden_suite,
    parse_hidden_suite,
    serialize_suite,
    suite_sha256,
)
from aegis_lab.safe_io import LoadError


def document() -> dict:
    return json.loads(suite_bytes())


def encode(doc: dict) -> bytes:
    return json.dumps(doc).encode()


def error_types(exc: ValidationError) -> set[str]:
    return {e["type"] for e in exc.errors()}


def test_round_trip_and_digest_cover_every_byte():
    data = suite_bytes()
    suite = parse_hidden_suite(data)
    assert suite.arity == 3 and len(suite.cases) == len(ARGUMENTS)
    assert [c.case_id for c in suite.cases] == [f"c{i:04d}" for i in range(1, len(ARGUMENTS) + 1)]
    assert serialize_suite(suite) == data
    digest = suite_sha256(data)
    assert digest == suite_sha256(serialize_suite(parse_hidden_suite(data)))
    for position in (0, len(data) // 2, len(data) - 2):
        changed = data[:position] + bytes([data[position] ^ 1]) + data[position + 1:]
        assert suite_sha256(changed) != digest


def test_load_uses_bounded_regular_file_policy(tmp_path):
    path = tmp_path / "suite.json"
    path.write_bytes(suite_bytes())
    suite, data = load_hidden_suite(path)
    assert data == path.read_bytes() and suite.suite_id == "5" * 32
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(LoadError) as caught:
        load_hidden_suite(link)
    assert caught.value.category == "symlink_rejected"


@pytest.mark.parametrize("raw,category", [
    (b'{"a": 1, "a": 2}', "duplicate_key"),
    (b'{"x": NaN}', "non_finite_number"),
    (b"\xff\xfe", "invalid_utf8"),
    (b"[", "malformed_json"),
])
def test_strict_json(raw, category):
    with pytest.raises(LoadError) as caught:
        parse_hidden_suite(raw)
    assert caught.value.category == category


def test_oversized_suite_rejected_before_parsing():
    with pytest.raises(LoadError) as caught:
        parse_hidden_suite(b" " * (MAX_SUITE_BYTES + 1))
    assert caught.value.category == "too_large"


@pytest.mark.parametrize("mutate", [
    lambda d: d["cases"][0].__setitem__("expected", True),
    lambda d: d["cases"][0].__setitem__("expected", 1.0),
    lambda d: d["cases"][0].__setitem__("expected", "1"),
    lambda d: d["cases"][0].__setitem__("expected", -1),
    lambda d: d["cases"][0].__setitem__("expected", 2**32),
    lambda d: d["cases"][0]["arguments"].__setitem__(0, False),
    lambda d: d["cases"][0]["arguments"].__setitem__(0, 2**32),
    lambda d: d["cases"][0].__setitem__("note", "x"),
    lambda d: d.__setitem__("extra", 1),
    lambda d: d.__setitem__("schema_version", "aegis.lab.hidden-suite.v0"),
    lambda d: d.__setitem__("abi", "aegis.lab.c-abi.scalar-u64.v1"),
    lambda d: d.__setitem__("cases", []),
    lambda d: d["reference"].__setitem__("method", "computed_from_candidate"),
    lambda d: d["reference"].pop("reference_implementation_sha256"),
    lambda d: d["reference"].__setitem__("frozen_at", "2026-10-01T00:00:00"),
    lambda d: d.__setitem__("suite_id", "not-hex"),
])
def test_schema_is_strict(mutate):
    doc = document()
    mutate(doc)
    with pytest.raises(ValidationError):
        parse_hidden_suite(encode(doc))


@pytest.mark.parametrize("mutate,error", [
    (lambda d: d["cases"][1].__setitem__("case_id", "c0005"), "aegis_case_ids_not_sequential"),
    (lambda d: d["cases"][0].__setitem__("case_id", "c0000"), "aegis_case_ids_not_sequential"),
    (lambda d: d["cases"][0]["arguments"].pop(), "aegis_arity_mismatch"),
    (lambda d: d.__setitem__("interface", "pixel(int, int, int)->int"), "aegis_interface_not_supported"),
    (lambda d: d["cases"][1].__setitem__("arguments", list(d["cases"][0]["arguments"])),
     "aegis_contradictory_expectations"),
    (lambda d: d["cases"][1].update(arguments=list(d["cases"][0]["arguments"]),
                                    expected=d["cases"][0]["expected"]), "aegis_duplicate_case_arguments"),
])
def test_semantic_rules(mutate, error):
    doc = document()
    mutate(doc)
    with pytest.raises(ValidationError) as caught:
        parse_hidden_suite(encode(doc))
    assert error in error_types(caught.value)


def test_case_limit():
    doc = document()
    base = doc["cases"][0]
    doc["cases"] = [{"case_id": f"c{i:04d}", "arguments": [i, 0, 0], "expected": 0}
                    for i in range(1, MAX_SUITE_CASES + 2)]
    assert base
    with pytest.raises(ValidationError):
        parse_hidden_suite(encode(doc))


def test_audit_detects_incorrect_reference_expectations():
    suite = parse_hidden_suite(suite_bytes())
    assert audit_suite(suite, reference) == ()
    doc = document()
    doc["cases"][2]["expected"] ^= 1
    doc["cases"][5]["expected"] = 0
    wrong = parse_hidden_suite(encode(doc))
    assert audit_suite(wrong, reference) == ("c0003", "c0006")


def test_audit_rejects_non_integer_reference_results():
    suite = parse_hidden_suite(suite_bytes())
    assert audit_suite(suite, lambda *a: float(reference(*a))) == tuple(c.case_id for c in suite.cases)


def test_suite_never_holds_unsupported_interface():
    with pytest.raises(ValidationError):
        suite_bytes(interface="pixel(uint32_t*)->uint32_t")
    assert parse_hidden_suite(suite_bytes(interface=INTERFACE)).interface == INTERFACE
