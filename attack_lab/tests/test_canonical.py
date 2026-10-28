"""Fixed vectors for aegis.lab.canonical-json.v1."""

from __future__ import annotations

import hashlib
import math

import pytest

from aegis_lab.canonical import CANONICALIZATION, canonical_json_bytes, canonical_sha256

# Hand-written expected bytes. The digest was computed with coreutils sha256sum over
# exactly these bytes, independently of Python's hashlib.
VECTOR_INPUT = {"c": {"é": 1.5, "z": -1}, "b": -0.0, "a": (1, "é", None, True)}
VECTOR_BYTES = b'{"a":[1,"\xc3\xa9",null,true],"b":0.0,"c":{"z":-1,"\xc3\xa9":1.5}}'
VECTOR_SHA256 = "411669153d74117e6389cc53505d81fef00ec5456efc203f38774890a5ad48c0"


def test_identifier():
    assert CANONICALIZATION == "aegis.lab.canonical-json.v1"


def test_fixed_vector_bytes_and_digest():
    assert canonical_json_bytes(VECTOR_INPUT) == VECTOR_BYTES
    assert canonical_sha256(VECTOR_INPUT) == VECTOR_SHA256
    assert hashlib.sha256(VECTOR_BYTES).hexdigest() == VECTOR_SHA256


def test_negative_zero_is_canonicalized_to_zero():
    assert canonical_json_bytes({"t": -0.0}) == canonical_json_bytes({"t": 0.0}) == b'{"t":0.0}'
    assert canonical_json_bytes([-0.0, [{"x": -0.0}]]) == b'[0.0,[{"x":0.0}]]'


def test_floats_use_shortest_round_trip_form():
    assert canonical_json_bytes([0.1, 1.0, 2.0, 1e-7, 1e21, 0.7]) == b"[0.1,1.0,2.0,1e-07,1e+21,0.7]"


def test_integers_and_floats_remain_distinct_types():
    # Schemas fix each field's type, so a float field always serializes as a float.
    assert canonical_json_bytes([1, 1.0, True]) == b"[1,1.0,true]"
    assert canonical_json_bytes(2**63 - 1) == b"9223372036854775807"


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_are_rejected(value):
    with pytest.raises(ValueError):
        canonical_json_bytes({"x": value})


@pytest.mark.parametrize("value", [{1: "x"}, {"x": object()}, {"x": {1, 2}}, b"bytes"])
def test_unsupported_types_are_rejected_not_stringified(value):
    with pytest.raises(TypeError):
        canonical_json_bytes(value)


def test_lone_surrogates_cannot_be_encoded():
    with pytest.raises(UnicodeEncodeError):
        canonical_json_bytes({"x": "\ud800"})


def test_non_ascii_is_utf8_and_not_escaped():
    assert canonical_json_bytes("画像") == '"画像"'.encode()
    assert canonical_json_bytes('quote"backslash\\') == b'"quote\\"backslash\\\\"'
