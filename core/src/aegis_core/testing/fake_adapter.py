"""Protocol test double for `aegis.adapter.v1`. Performs NO protection.

Behaviour is selected by the policy option `mode`:

    ok (default)  write outputs/protected.bin and succeed
    attack        write outputs/protected.bin and return one attack evaluation
    fail          report status "failed"
    crash         write to stderr and exit 3
    garbage       print non-JSON
    sleep         sleep for option `seconds` (default 60)
    escape        claim an output path outside output_dir
    no-output     succeed without outputs
    mutate-input  modify the input file, then succeed
    env           write the environment variable names to outputs/env.txt
    argv          write sys.argv as JSON to outputs/argv.json
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def _emit(result: dict) -> None:
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()


def _ok(outputs: list[str], **extra) -> dict:
    return {
        "protocol": "aegis.adapter.v1",
        "status": "succeeded",
        "outputs": [{"path": p} for p in outputs],
        "evidence": [{"summary": "fake adapter ran (no protection applied)", "data": {"fake": True}}],
        **extra,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "--aegis-request":
        sys.stderr.write("usage: fake_adapter --aegis-request <path>\n")
        return 2
    request = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    mode = request["options"].get("mode", "ok")
    input_path = Path(request["input_path"])
    out_dir = Path(request["output_dir"])

    def write_protected() -> str:
        (out_dir / "protected.bin").write_bytes(b"FAKE-AEGIS\n" + input_path.read_bytes())
        return "protected.bin"

    if mode == "ok":
        _emit(_ok([write_protected()]))
    elif mode == "attack":
        name = write_protected()
        _emit(
            _ok(
                [name],
                attack_evaluations=[
                    {
                        "attack": "fake-static-analysis",
                        "outcome": "resisted",
                        "target": name,
                        "metrics": {"attempts": 1},
                    }
                ],
            )
        )
    elif mode == "fail":
        _emit(
            {
                "protocol": "aegis.adapter.v1",
                "status": "failed",
                "error": {"code": "FAKE_FAILURE", "message": "fake adapter was asked to fail"},
            }
        )
    elif mode == "crash":
        sys.stderr.write("fake adapter crashed on purpose\n")
        return 3
    elif mode == "garbage":
        sys.stdout.write("this is not json")
    elif mode == "sleep":
        time.sleep(float(request["options"].get("seconds", 60)))
        _emit(_ok([write_protected()]))
    elif mode == "escape":
        _emit(_ok(["../../escape.bin"]))
    elif mode == "no-output":
        _emit(_ok([]))
    elif mode == "mutate-input":
        with open(input_path, "ab") as handle:
            handle.write(b"tampered")
        _emit(_ok([write_protected()]))
    elif mode == "env":
        (out_dir / "env.txt").write_text("\n".join(sorted(os.environ)), encoding="utf-8")
        _emit(_ok(["env.txt"]))
    elif mode == "argv":
        (out_dir / "argv.json").write_text(json.dumps(sys.argv), encoding="utf-8")
        _emit(_ok(["argv.json"]))
    else:
        sys.stderr.write(f"unknown mode {mode!r}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
