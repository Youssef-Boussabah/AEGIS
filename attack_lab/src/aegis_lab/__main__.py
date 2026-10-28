"""Local manifest validation only; never invokes an attacker or scorer.

Error output names the argument role, a schema field path and a fixed error
category. It never repeats rejected values, file contents, unknown key names,
paths or operating-system messages.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from .diagnostics import SafeArgumentParser, model_field_names, validation_issues
from .manifest import MANIFEST_ERROR_TYPES, ManifestPairError, TrialManifest, load_manifest, validate_pair
from .safe_io import LoadError

MANIFEST_FIELDS = model_field_names(TrialManifest)


def describe_manifest_failure(role: str, exc: Exception) -> list[str]:
    if isinstance(exc, LoadError):
        return [f"{role}: {exc.category}"]
    if isinstance(exc, ValidationError):
        return [f"{role}: {issue}" for issue in validation_issues(exc, MANIFEST_FIELDS, MANIFEST_ERROR_TYPES)]
    raise TypeError("unsupported failure type")


def load_role(role: str, path: Path) -> tuple[TrialManifest | None, list[str]]:
    try:
        return load_manifest(path), []
    except (LoadError, ValidationError) as exc:
        return None, describe_manifest_failure(role, exc)


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(prog="python -m aegis_lab", description="Inspect trial manifests without running an attack")
    parser.add_argument("command", choices=["validate-pair"])
    parser.add_argument("baseline", type=Path)
    parser.add_argument("protected", type=Path)
    args = parser.parse_args(argv)
    try:
        first, first_issues = load_role("baseline-file", args.baseline)
        second, second_issues = load_role("protected-file", args.protected)
        issues = first_issues + second_issues
        summary = None
        if first is not None and second is not None:
            try:
                summary = validate_pair(first, second).summary()
            except ManifestPairError as exc:
                issues.extend(f"pair: {field}: differs" for field in exc.fields)
    except Exception as exc:  # never let an unexpected message reach the terminal
        print(f"invalid trial pair: internal_error ({type(exc).__name__})", file=sys.stderr)
        return 3
    if summary is None:
        print("invalid trial pair:", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
