#!/usr/bin/env python3
"""Opt-in Cargo RUSTC_WRAPPER: record one successful library-test invocation.

This wrapper does not transform code. Run protect.py on the resulting private JSON.
Only AEGIS_RUST_CRATE and AEGIS_RUST_CAPTURE control capture; neither affects rustc.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


# Cargo's documented compile-time metadata, not the caller's arbitrary environment.
COMPILE_ENV = {
    "OUT_DIR", "CARGO_MANIFEST_DIR", "CARGO_MANIFEST_PATH", "CARGO_CRATE_NAME",
    "CARGO_PKG_NAME", "CARGO_PKG_VERSION", "CARGO_PKG_VERSION_MAJOR",
    "CARGO_PKG_VERSION_MINOR", "CARGO_PKG_VERSION_PATCH", "CARGO_PKG_VERSION_PRE",
    "CARGO_PKG_AUTHORS", "CARGO_PKG_DESCRIPTION", "CARGO_PKG_HOMEPAGE",
    "CARGO_PKG_REPOSITORY", "CARGO_PKG_LICENSE", "CARGO_PKG_LICENSE_FILE",
    "CARGO_PKG_README", "CARGO_PKG_RUST_VERSION", "CARGO_PRIMARY_PACKAGE",
}


def main() -> int:
    compiler, *args = sys.argv[1:]
    crate = os.environ.get("AEGIS_RUST_CRATE", "")
    matches = ("--test" in args and "--crate-name" in args
               and args[args.index("--crate-name") + 1] == crate)
    destination = Path(os.environ.get("AEGIS_RUST_CAPTURE", ""))
    if matches and (not destination.is_absolute() or destination.exists()
                    or not destination.parent.is_dir()):
        print("Rust capture requires a new absolute AEGIS_RUST_CAPTURE file in an existing directory.",
              file=sys.stderr)
        return 2
    # Cargo supervises its ordinary compiler. The protection runner separately bounds
    # all replayed compiler/backend/linker/test processes and minimizes their env.
    # Preserve Cargo's already-inherited jobserver descriptors, as direct rustc
    # execution would; otherwise every wrapped build warns about closed fds.
    result = subprocess.run([compiler, *args], check=False, close_fds=False)
    if matches and result.returncode == 0:
        record = {"schema_version": 1, "rustc": os.path.abspath(compiler),
                  "cwd": os.getcwd(), "argv": args,
                  "compile_env": {k: os.environ[k] for k in sorted(COMPILE_ENV) if k in os.environ}}
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(record, stream, indent=2)
            stream.write("\n")
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
