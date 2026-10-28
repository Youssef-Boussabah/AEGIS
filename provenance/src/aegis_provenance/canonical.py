"""Deterministic canonical JSON serialization adhering to RFC 8785 (JCS principles)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel


def _normalize_value(val: Any) -> Any:
    if isinstance(val, BaseModel):
        return _normalize_value(val.model_dump(mode="json"))
    if isinstance(val, dict):
        return {str(k): _normalize_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_normalize_value(item) for item in val]
    if isinstance(val, datetime):
        # Normalize to UTC ISO 8601 format ending with Z
        utc_dt = val.astimezone(timezone.utc)
        iso = utc_dt.strftime("%Y-%m-%dT%H:%M:%S")
        if utc_dt.microsecond:
            iso += f".{utc_dt.microsecond:06d}"
        return iso + "Z"
    return val


def canonical_json(data: Any) -> bytes:
    """Serialize a dict, model, or primitive into deterministic canonical UTF-8 bytes.

    Characteristics:
    - Object keys sorted lexicographically
    - Compact separators (no whitespace: ',', ':')
    - UTF-8 encoded with ensure_ascii=False
    - Normalized datetime strings in UTC ISO-8601
    """
    normalized = _normalize_value(data)
    json_str = json.dumps(
        normalized,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return json_str.encode("utf-8")

