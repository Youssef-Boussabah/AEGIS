"""Safe, bounded descriptions of rejected records.

Validation errors are reported as ``<field path>: <category>`` only. Rejected
values, Pydantic messages, validator contexts and documentation URLs are never
included. A path component is printed only if it is a field name of the
schema being validated, or a list index; anything else (for example an unknown
key, which may itself be a secret) becomes ``<unknown>``.

Command-line errors follow the same rule: ``SafeArgumentParser`` names the
option that was rejected but never repeats the rejected value, and
``terminal_text`` escapes and bounds any text before it reaches a terminal.
"""

from __future__ import annotations

import argparse
import re
import sys
import types
import typing
from collections.abc import Iterable

from pydantic import BaseModel, ValidationError

MAX_REPORTED_ISSUES = 20

_CATEGORIES = {
    "missing": "missing",
    "extra_forbidden": "unknown_field",
    "string_pattern_mismatch": "invalid_format",
    "string_too_short": "invalid_length",
    "string_too_long": "invalid_length",
    "too_short": "invalid_length",
    "too_long": "invalid_length",
    "literal_error": "invalid_choice",
    "enum": "invalid_choice",
    "greater_than": "out_of_range",
    "greater_than_equal": "out_of_range",
    "less_than": "out_of_range",
    "less_than_equal": "out_of_range",
    "finite_number": "out_of_range",
    "json_invalid": "malformed_json",
    "json_type": "malformed_json",
}
_TYPE_SUFFIXES = ("_type", "_parsing", "_from_float")


def model_field_names(*models: type[BaseModel]) -> frozenset[str]:
    """All field names reachable from the given models, recursively."""
    names: set[str] = set()
    seen: set[type] = set()

    def visit_annotation(annotation: object) -> None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            visit_model(annotation)
        for arg in typing.get_args(annotation):
            visit_annotation(arg)
        if isinstance(annotation, types.UnionType):
            for arg in annotation.__args__:
                visit_annotation(arg)

    def visit_model(model: type[BaseModel]) -> None:
        if model in seen:
            return
        seen.add(model)
        for name, info in model.model_fields.items():
            names.add(name)
            visit_annotation(info.annotation)

    for model in models:
        visit_model(model)
    return frozenset(names)


def _category(error_type: str, custom_types: frozenset[str]) -> str:
    if error_type in custom_types:
        return error_type
    if error_type in _CATEGORIES:
        return _CATEGORIES[error_type]
    if error_type.endswith(_TYPE_SUFFIXES):
        return "invalid_type"
    return "invalid_value"


def _path(loc: Iterable[object], allowed: frozenset[str]) -> str:
    parts: list[str] = []
    for part in loc:
        if isinstance(part, int) and not isinstance(part, bool) and 0 <= part < 1_000_000:
            parts.append(str(part))
        elif isinstance(part, str) and part in allowed:
            parts.append(part)
        else:
            parts.append("<unknown>")
            break  # nothing below an unknown component is meaningful or safe
    return ".".join(parts) or "<record>"


def validation_issues(
    exc: ValidationError, allowed_fields: frozenset[str], custom_types: frozenset[str] = frozenset()
) -> list[str]:
    """Return at most MAX_REPORTED_ISSUES distinct ``path: category`` strings."""
    issues: list[str] = []
    for error in exc.errors(include_url=False, include_context=False, include_input=False):
        issue = f"{_path(error['loc'], allowed_fields)}: {_category(error['type'], custom_types)}"
        if issue not in issues:
            issues.append(issue)
    if len(issues) > MAX_REPORTED_ISSUES:
        hidden = len(issues) - MAX_REPORTED_ISSUES
        issues = issues[:MAX_REPORTED_ISSUES] + [f"<{hidden} more issues not shown>"]
    return issues


MAX_TERMINAL_TEXT = 500


def terminal_text(text: str, limit: int = MAX_TERMINAL_TEXT) -> str:
    """Defense in depth for messages that are already built from safe parts.

    Escapes every non-printable character (control, format, bidi override,
    separators) so a value can never move the cursor or reorder the line, and bounds
    the length.
    """
    escaped = "".join(ch if ch.isprintable() else f"\\u{ord(ch):04x}" for ch in text)
    return escaped if len(escaped) <= limit else escaped[:limit] + "...<truncated>"


# argparse names options as "argument --name", "argument --a/-b" or "argument dest".
_ARGUMENT_PREFIX = re.compile(r"^argument ([A-Za-z0-9_/-]{1,64}): ")
_REQUIRED = re.compile(r"^the following arguments are required: [A-Za-z0-9_/, -]{1,300}$")


class SafeArgumentParser(argparse.ArgumentParser):
    """``argparse`` echoes rejected values (``invalid int value: '<value>'``) and
    unrecognized arguments. This parser reports only the option name, which comes from
    the parser's own definition, or a fixed message.
    """

    def error(self, message: str) -> typing.NoReturn:
        match = _ARGUMENT_PREFIX.match(message)
        if match:
            detail = f"invalid value for {match.group(1)}"
        elif _REQUIRED.match(message):  # lists only option names defined by the parser
            detail = message
        else:
            detail = "invalid command-line arguments"
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {detail}\n")
