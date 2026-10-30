#!/usr/bin/env python3
"""Build trusted native projects through the existing AEGIS LLVM adapters."""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys

from runner import Failure
from workflow import build, load_manifest, verify_report


def positive(value):
    result = int(value)
    if not 1 <= result <= 4 * 1024**3:
        raise argparse.ArgumentTypeError("Expected 1..4294967296")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="validate manifest and resolve compile database without compiling")
    plan.add_argument("manifest")
    run = commands.add_parser("build", help="build verified objects and optionally link/run declared cases")
    run.add_argument("manifest")
    run.add_argument("--output", required=True, help="new private directory outside source trees")
    run.add_argument("--plugin", required=True, help="existing trusted LLVM 22 Shield plugin")
    run.add_argument("--backend", choices=("llvm-shield", "llvm-shield-mirage"))
    run.add_argument("--execute", action="store_true", help="execute trusted built programs on the host")
    run.add_argument("--timeout", type=int, default=60, help="wall seconds per command, including entire adapter job")
    run.add_argument("--max-input-bytes", type=positive, default=64 * 1024**2)
    run.add_argument("--max-output-bytes", type=positive, default=128 * 1024**2)
    for name in ("clang", "clang++", "opt", "llvm-link"):
        run.add_argument("--" + name, default=name)
    verify = commands.add_parser("verify", help="rehash a report and every inventoried artifact")
    verify.add_argument("report")
    args = parser.parse_args(argv)
    os.umask(0o077)

    def interrupt(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    try:
        if args.command == "verify":
            result = verify_report(args.report)
        else:
            result = load_manifest(args.manifest)
            if args.command == "build":
                if not 1 <= args.timeout <= 3600:
                    raise Failure("INVALID_CONFIGURATION", "timeout must be 1..3600 seconds.")
                if args.backend:
                    result["backend"] = args.backend
                report = build(result, args.output, plugin=args.plugin, execute=args.execute,
                               tool_paths={name: getattr(args, name.replace("-", "_"))
                                           for name in ("clang", "clang++", "opt", "llvm-link")},
                               timeout=args.timeout, input_limit=args.max_input_bytes, output_limit=args.max_output_bytes)
                result = {"status": report["status"], "report": str(os.path.abspath(args.output)) + "/report.json",
                          "coverage": report.get("coverage"), "execution": report["execution"]["status"],
                          "error": report.get("error")}
        print(json.dumps(result, indent=2, allow_nan=False))
        return 1 if result.get("status") == "failed" else 0
    except (Failure, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        error = exc.record() if isinstance(exc, Failure) else {
            "code": "INVALID_INPUT", "message": "Unable to process manifest, output directory or report.",
            "details": {"type": type(exc).__name__}}
        print(json.dumps({"status": "failed", "error": error}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
