"""Validate Shield's local v1 report without importing a protection backend.

Only the JSON Schema vocabulary used by the checked-in report schema is
implemented here. Unknown vocabulary fails closed rather than being ignored.
"""

import json
import re
from pathlib import Path


class InvalidReport(ValueError):
    pass


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite JSON value")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _validate(value, schema, root):
    known = {"$schema", "$id", "$defs", "title", "$ref", "type", "const", "enum",
             "additionalProperties", "required", "properties", "propertyNames",
             "items", "minimum", "maximum", "pattern"}
    if schema.keys() - known:
        raise InvalidReport("Unsupported report schema vocabulary")
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise InvalidReport("Unsupported report schema reference")
        _validate(value, root["$defs"][ref.removeprefix("#/$defs/")], root)
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}
    if "type" in schema and type(value) is not types[schema["type"]]:
        raise InvalidReport("Wrong report field type")
    if "const" in schema and (type(value) is not type(schema["const"])
                              or value != schema["const"]):
        raise InvalidReport("Wrong report constant")
    if "enum" in schema and value not in schema["enum"]:
        raise InvalidReport("Unknown report field value")
    if "minimum" in schema and value < schema["minimum"]:
        raise InvalidReport("Report value below minimum")
    if "maximum" in schema and value > schema["maximum"]:
        raise InvalidReport("Report value above maximum")
    if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
        raise InvalidReport("Invalid report string")
    if type(value) is dict:
        if set(schema.get("required", [])) - value.keys():
            raise InvalidReport("Missing report field")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if "propertyNames" in schema:
                _validate(key, schema["propertyNames"], root)
            if key in properties:
                _validate(item, properties[key], root)
            elif additional is False:
                raise InvalidReport("Unknown report field")
            elif type(additional) is dict:
                _validate(item, additional, root)
    if type(value) is list and "items" in schema:
        for item in value:
            _validate(item, schema["items"], root)


def validate_report(raw, config, llvm_version):
    schema = strict_json((Path(__file__).parent.parent / "schemas/report.schema.json").read_bytes())
    try:
        report = strict_json(raw)
        _validate(report, schema, schema)
        # Both contracts keep their existing versions and names. Config is the
        # explicitly converted Shield config, without its schema_version field.
        expected = {key: value for key, value in config.items() if key != "schema_version"}
        if report["config"] != expected or report["llvm_version"] != llvm_version:
            raise InvalidReport("Report configuration or LLVM version does not match invocation")
        if report["module"] != "shield-input.ll":
            raise InvalidReport("Report module does not match invocation")
        total = 0
        names = set()
        for row in report["functions"]:
            if row["name"] in names:
                raise InvalidReport("Duplicate function in report")
            names.add(row["name"])
            sites = row["transformed_sites"]
            transformed = bool(sites)
            if (row["status"] == "transformed") != transformed:
                raise InvalidReport("Inconsistent function status")
            if (row["reason"] == "expanded") != transformed:
                raise InvalidReport("Inconsistent transformation reason")
            if transformed and (not row["annotated"] or not config["enabled"]):
                raise InvalidReport("Transformation of an unselected function")
            if len(sites) > config["max_sites_per_function"]:
                raise InvalidReport("Transformation budget exceeded")
            indices = [site["add_index"] for site in sites]
            if indices != sorted(set(indices)):
                raise InvalidReport("Site indices are not unique and ordered")
            total += len(sites)
        if total != report["transformed_sites"]:
            raise InvalidReport("Report transformation total does not match sites")
        return report
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise InvalidReport("Invalid Shield report") from exc
