from datetime import datetime, timezone

from aegis_provenance.canonical import canonical_json
from pydantic import BaseModel


class SampleModel(BaseModel):
    name: str
    count: int
    created: datetime


def test_canonical_json_key_order():
    d1 = {"z": 1, "a": 2, "m": 3}
    d2 = {"a": 2, "m": 3, "z": 1}
    assert canonical_json(d1) == canonical_json(d2)
    assert canonical_json(d1) == b'{"a":2,"m":3,"z":1}'


def test_canonical_json_no_whitespace():
    d = {"key": "value", "list": [1, 2, 3]}
    raw = canonical_json(d)
    assert b" " not in raw
    assert b"\n" not in raw


def test_canonical_json_datetime_normalization():
    dt1 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
    model1 = SampleModel(name="test", count=42, created=dt1)
    raw = canonical_json(model1)
    assert b'"created":"2026-10-28T12:00:00Z"' in raw


def test_canonical_json_nested():
    nested = {
        "b": {"y": 2, "x": 1},
        "a": [3, 2, 1],
    }
    assert canonical_json(nested) == b'{"a":[3,2,1],"b":{"x":1,"y":2}}'
