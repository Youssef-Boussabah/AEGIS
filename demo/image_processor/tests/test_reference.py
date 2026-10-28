#!/usr/bin/env python3
"""Compare imagelab-cli output with the independent Python reference model.

For every fixture in --fixtures and every parameter set in
imagelab_reference.PARAMETER_SETS this test:

1. runs the CLI and reads its output file;
2. requires the output bytes to equal the reference model's encoded output;
3. requires the SHA-256 of those bytes to equal the checked-in manifest
   (expected.sha256.json, produced by the reference model only).

--update-manifest rewrites the manifest from the reference model (never from
the CLI) and runs no CLI. Use it only after a deliberate semantics change,
and review the diff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True  # keep the source tree free of __pycache__
sys.path.insert(0, str(Path(__file__).resolve().parent))
import imagelab_reference as ref  # noqa: E402

MANIFEST = "expected.sha256.json"


def fixture_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if p.suffix in (".pam", ".ppm"))


def cli_args(op: str, params: dict[str, int]) -> list[str]:
    args = [op]
    for key, value in params.items():
        args += [f"--{key}", str(value)]
    return args


def expected_outputs(fixtures: Path) -> dict[str, dict[str, bytes]]:
    result: dict[str, dict[str, bytes]] = {}
    for path in fixture_files(fixtures):
        image = ref.decode(path.read_bytes())
        result[path.name] = {
            ref.case_id(op, params): ref.encode_pam(ref.apply(op, params, image))
            for op, params in ref.PARAMETER_SETS
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--update-manifest", action="store_true")
    args = parser.parse_args()

    expected = expected_outputs(args.fixtures)
    hashes = {name: {case: hashlib.sha256(data).hexdigest() for case, data in cases.items()}
              for name, cases in expected.items()}
    manifest_path = args.fixtures / MANIFEST
    if args.update_manifest:
        manifest_path.write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n")
        print(f"wrote {manifest_path}")
        return 0
    if args.cli is None:
        parser.error("--cli is required unless --update-manifest is given")

    failures = 0
    manifest = json.loads(manifest_path.read_text())
    if manifest != hashes:
        print("FAIL reference model output differs from the checked-in manifest")
        failures += 1

    checked = 0
    with tempfile.TemporaryDirectory(prefix="imagelab-ref-") as tmp:
        out = Path(tmp) / "out.pam"
        for path in fixture_files(args.fixtures):
            for op, params in ref.PARAMETER_SETS:
                case = ref.case_id(op, params)
                proc = subprocess.run(
                    [str(args.cli), *cli_args(op, params), str(path), str(out)],
                    capture_output=True, text=True, timeout=60, check=False)
                checked += 1
                if proc.returncode != 0:
                    print(f"FAIL {path.name} {case}: exit {proc.returncode}: {proc.stderr.strip()}")
                    failures += 1
                    continue
                got = out.read_bytes()
                if got != expected[path.name][case]:
                    got_img = ref.decode(got)
                    want_img = ref.decode(expected[path.name][case])
                    diff = [i for i, (a, b) in enumerate(zip(got_img.pixels, want_img.pixels))
                            if a != b]
                    first = diff[0] if diff else -1
                    print(f"FAIL {path.name} {case}: {len(diff)} pixel(s) differ; first index "
                          f"{first}: got {got_img.pixels[first] if diff else '-'} "
                          f"want {want_img.pixels[first] if diff else '-'}")
                    failures += 1
    print(f"{checked} CLI runs over {len(expected)} fixtures; {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
