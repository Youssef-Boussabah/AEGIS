#!/usr/bin/env python3
"""Error-path and contract tests for imagelab-cli (exit codes, no partial output)."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True  # keep the source tree free of __pycache__
sys.path.insert(0, str(Path(__file__).resolve().parent))
import imagelab_reference as ref  # noqa: E402

OK, INTERNAL, USAGE, IO, FORMAT, PARAMETER, LIMITS = 0, 1, 2, 3, 4, 5, 6

GOOD = ref.encode_pam(ref.Image(2, 2, [(10, 20, 30, 40), (50, 60, 70, 80),
                                        (90, 100, 110, 120), (130, 140, 150, 160)]))


def header(width: int, height: int, depth: int = 4, maxval: int = 255) -> bytes:
    return (f"P7\nWIDTH {width}\nHEIGHT {height}\nDEPTH {depth}\nMAXVAL {maxval}\n"
            "ENDHDR\n").encode()


class Runner:
    def __init__(self, cli: Path, tmp: Path) -> None:
        self.cli = cli
        self.tmp = tmp
        self.failures = 0
        self.count = 0

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.cli), *args], capture_output=True, text=True,
                              timeout=30, check=False)

    def expect(self, name: str, code: int, *args: str, output: Path | None = None) -> None:
        """Run the CLI; require exit `code`, and no output file on failure."""
        self.count += 1
        if output is not None and output.exists():
            output.unlink()
        proc = self.run(*args)
        problems = []
        if proc.returncode != code:
            problems.append(f"exit {proc.returncode}, want {code}; stderr: {proc.stderr.strip()}")
        if code != OK and output is not None and output.exists():
            problems.append("an output file was written on failure")
        if code != OK and not proc.stderr.strip():
            problems.append("no diagnostic on stderr")
        leftovers = [p.name for p in self.tmp.iterdir() if ".tmp-" in p.name]
        if leftovers:
            problems.append(f"temporary files left behind: {leftovers}")
        if problems:
            self.failures += 1
            print(f"FAIL {name}: " + "; ".join(problems))

    def file(self, name: str, data: bytes) -> Path:
        path = self.tmp / name
        path.write_bytes(data)
        return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="imagelab-cli-") as tmp_name:
        tmp = Path(tmp_name)
        r = Runner(args.cli, tmp)
        good = r.file("good.pam", GOOD)
        out = tmp / "out.pam"
        s = str

        # Help, version, usage errors.
        r.expect("help", OK, "--help")
        r.expect("no args", USAGE)
        r.expect("unknown command", USAGE, "blur", s(good), s(out), output=out)
        r.expect("missing output", USAGE, "tone", s(good), output=out)
        r.expect("extra positional", USAGE, "tone", s(good), s(out), "x", output=out)
        r.expect("unknown option", USAGE, "tone", "--gamma", "2", s(good), s(out), output=out)
        r.expect("option of other op", USAGE, "tone", "--threshold", "2", s(good), s(out),
                 output=out)
        r.expect("duplicate option", USAGE, "tone", "--knee", "5", "--knee", "6", s(good),
                 s(out), output=out)
        r.expect("missing value", USAGE, "tone", s(good), s(out), "--knee", output=out)
        r.expect("info with option", USAGE, "info", "--knee", "1", s(good))
        for bad in ["abc", "1.5", "+5", "", "0x10", "99999999999999999999", "--"]:
            r.expect(f"malformed number {bad!r}", USAGE, "tone", "--knee", bad, s(good), s(out),
                     output=out)
        r.expect("output is input", USAGE, "tone", s(good), s(good))
        if good.read_bytes() != GOOD:
            r.failures += 1
            print("FAIL output-is-input modified the input")

        # Parameter range errors: just outside each documented bound.
        for op, key, value in [
            ("tone", "exposure-q8", "0"), ("tone", "exposure-q8", "4097"),
            ("tone", "knee", "0"), ("tone", "knee", str((1 << 20) + 1)),
            ("tone", "knee", "4294967296"),
            ("color", "saturation-q8", "1025"), ("color", "contrast-q8", "1025"),
            ("color", "brightness", "256"), ("color", "brightness", "-256"),
            ("color", "saturation-q8", "-1"),
            ("enhance", "amount-q8", "1025"), ("enhance", "threshold", "256"),
        ]:
            r.expect(f"{op} --{key} {value}", PARAMETER, op, f"--{key}", value, s(good), s(out),
                     output=out)
        # The bounds themselves are accepted.
        for op, opts in [
            ("tone", ["--exposure-q8", "1", "--knee", "1"]),
            ("tone", ["--exposure-q8", "4096", "--knee", str(1 << 20)]),
            ("color", ["--saturation-q8", "0", "--contrast-q8", "1024", "--brightness", "-255"]),
            ("color", ["--saturation-q8", "1024", "--contrast-q8", "0", "--brightness", "255"]),
            ("enhance", ["--amount-q8", "1024", "--threshold", "255"]),
            ("enhance", ["--amount-q8", "0", "--threshold", "0"]),
        ]:
            r.expect(f"{op} bounds {opts}", OK, op, *opts, s(good), s(out), output=out)

        # I/O errors.
        r.expect("missing input", IO, "tone", s(tmp / "nope.pam"), s(out), output=out)
        r.expect("input is a directory", IO, "tone", s(tmp), s(out), output=out)
        r.expect("output dir missing", IO, "tone", s(good), s(tmp / "no" / "out.pam"))

        # Invalid images: format errors and limits.
        px = bytes(16)
        cases = {
            "empty": b"",
            "garbage": b"hello world",
            "p5": b"P5\n1 1\n255\n\x00",
            "truncated": header(2, 2) + px[:15],
            "trailing": header(2, 2) + px + b"\x00",
            "maxval16": header(2, 2, maxval=65535) + px * 2,
            "depth1": header(2, 2, depth=1) + px[:4],
            "zero width": header(0, 2),
            "no endhdr": b"P7\nWIDTH 1\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\n",
            "bad p6": b"P6\n1 1\n255\n\x01\x02",
        }
        for name, data in cases.items():
            r.expect(f"format: {name}", FORMAT, "color", s(r.file("bad.pam", data)), s(out),
                     output=out)
        r.expect("limits: width", LIMITS, "enhance", s(r.file("big.pam", header(40000, 1))),
                 s(out), output=out)
        r.expect("limits: pixels", LIMITS, "enhance",
                 s(r.file("big.pam", header(30000, 30000))), s(out), output=out)
        r.expect("info on invalid", FORMAT, "info", s(r.file("bad.pam", b"P7\n")))

        # Success paths: output replaces an existing file atomically and
        # matches the reference model.
        out.write_bytes(b"old")
        r.expect("overwrite existing output", OK, "enhance", s(good), s(out))
        want = ref.encode_pam(ref.apply("enhance", {}, ref.decode(GOOD)))
        if out.read_bytes() != want:
            r.failures += 1
            print("FAIL enhance output differs from the reference model")
        mode = out.stat().st_mode & 0o777
        umask = os.umask(0)
        os.umask(umask)
        if mode != (0o666 & ~umask):
            r.failures += 1
            print(f"FAIL output mode {oct(mode)} != 0666 & ~umask")

        proc = r.run("info", s(good))
        want_info = f"width=2 height=2 fingerprint={ref.fingerprint(ref.decode(GOOD)):016x}"
        r.count += 1
        if proc.returncode != OK or proc.stdout.strip() != want_info:
            r.failures += 1
            print(f"FAIL info: {proc.stdout.strip()!r} != {want_info!r}")
        proc = r.run("--version")
        r.count += 1
        if proc.returncode != OK or "kernels:" not in proc.stdout:
            r.failures += 1
            print(f"FAIL --version: {proc.stdout!r}")

        print(f"{r.count} CLI checks; {r.failures} failure(s)")
        return 1 if r.failures else 0


if __name__ == "__main__":
    sys.exit(main())
