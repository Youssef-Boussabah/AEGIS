"""Local manifest validation only; never invokes an attacker or scorer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from .manifest import ManifestPairError, TrialManifest, validate_pair

MAX_MANIFEST_BYTES = 1_048_576


def _load(path: Path) -> TrialManifest:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes: {path.name}")
    data = path.read_bytes()
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes: {path.name}")
    return TrialManifest.model_validate_json(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis_lab", description="Inspect trial manifests without running an attack")
    parser.add_argument("command", choices=["validate-pair"])
    parser.add_argument("baseline", type=Path)
    parser.add_argument("protected", type=Path)
    args = parser.parse_args(argv)
    try:
        baseline, protected = validate_pair(_load(args.baseline), _load(args.protected))
    except (FileNotFoundError, OSError, ValueError, ValidationError, ManifestPairError) as exc:
        print(f"invalid trial pair: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "validation": "comparable_configuration_only",
        "pair_id": baseline.pair_id,
        "baseline_trial_id": baseline.trial_id,
        "protected_trial_id": protected.trial_id,
        "baseline_manifest_sha256": baseline.sha256(),
        "protected_manifest_sha256": protected.sha256(),
        "attacks_executed": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
