"""Canonical JSON bytes for Lab record fingerprints (``aegis.lab.canonical-json.v1``).

Rules:

- UTF-8 output, no insignificant whitespace, object keys sorted by Unicode code point.
- Non-ASCII characters are emitted as UTF-8, never as ``\\u`` escapes.
- Strings containing lone surrogates cannot be encoded and are rejected.
- Integers are exact decimal. Booleans and null are JSON literals.
- Floats must be finite. ``-0.0`` is written as ``0.0`` because it compares
  equal to ``0.0``: two records that compare equal must have equal bytes.
  Other floats use Python's shortest round-trip representation (``repr``).
- Only dict (with string keys), list/tuple, str, int, float, bool and None are
  accepted; any other type raises instead of being silently stringified.

A fingerprint is SHA-256 over these bytes. It identifies a record; it is not a
signature and does not authenticate who produced the record.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

CANONICALIZATION = "aegis.lab.canonical-json.v1"


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON forbids non-finite numbers")
        return 0.0 if value == 0.0 else value
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        return {key: _normalize(item) for key, item in value.items()}
    raise TypeError(f"canonical JSON cannot encode {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    text = json.dumps(_normalize(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return text.encode("utf-8")  # strict: lone surrogates raise UnicodeEncodeError


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
