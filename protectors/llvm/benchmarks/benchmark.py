#!/usr/bin/env python3
"""Build and time actual baseline/transformed executables; no dependencies."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from common import load_report, run, transform  # noqa: E402


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--opt", default="opt")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--objcopy", default="llvm-objcopy")
    parser.add_argument("--iterations", type=positive, default=20000000)
    parser.add_argument("--samples", type=positive, default=9)
    parser.add_argument("--seed", default="42")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="aegis-shield-bench-") as tmp:
        root = Path(tmp)
        source = root / "input.ll"
        protected = root / "transformed.ll"
        report = root / "report.json"
        run(args.clang, "-O1", "-S", "-emit-llvm", here / "kernel.c", "-o", source)
        transform(args.opt, args.plugin.resolve(), source, protected, f"seed={args.seed}", report)
        transformation = load_report(report)
        if not transformation["transformed_sites"]:
            raise AssertionError("benchmark did not transform any instructions")
        if source.read_bytes() == protected.read_bytes():
            raise AssertionError("IR did not change")
        results = {}
        for name, module in (("baseline", source), ("transformed", protected)):
            obj = root / f"{name}.o"
            exe = root / name
            text = root / f"{name}.text"
            run(args.clang, "-O2", "-c", module, "-o", obj)
            run(args.clang, "-O2", here / "runner.c", obj, "-o", exe)
            run(args.objcopy, f"--dump-section=.text={text}", obj)
            # Warm each executable once before collecting alternating samples.
            warmup = json.loads(run(exe, args.iterations).stdout)
            results[name] = {"seconds": [], "checksum": warmup["checksum"],
                             "executable_bytes": exe.stat().st_size,
                             "kernel_text_bytes": text.stat().st_size,
                             "kernel_text_sha256": hashlib.sha256(text.read_bytes()).hexdigest(),
                             "ir_bytes": module.stat().st_size}
        for index in range(args.samples):
            names = ("baseline", "transformed") if index % 2 == 0 else ("transformed", "baseline")
            for name in names:
                sample = json.loads(run(root / name, args.iterations).stdout)
                if sample["checksum"] != results[name]["checksum"]:
                    raise AssertionError("nondeterministic benchmark result")
                results[name]["seconds"].append(sample["seconds"])
        if results["baseline"]["checksum"] != results["transformed"]["checksum"]:
            raise AssertionError("baseline/transformed checksum mismatch")
        for value in results.values():
            value["median_seconds"] = statistics.median(value["seconds"])
            value["min_seconds"] = min(value["seconds"])
            value["max_seconds"] = max(value["seconds"])
        cpu = "unknown"
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.exists():
            cpu = next((line.split(":", 1)[1].strip() for line in cpuinfo.read_text().splitlines()
                        if line.startswith("model name")), cpu)
        result = {
            "schema_version": 1,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(), "cpu": cpu,
            "clang": run(args.clang, "--version").stdout.splitlines()[0],
            "opt": next(line.strip() for line in run(args.opt, "--version").stdout.splitlines()
                        if "LLVM version" in line),
            "pipeline": "clang -O1 -> aegis-shield (transformed only) -> clang -O2 object -> clang -O2 link",
            "iterations_per_sample": args.iterations, "samples": args.samples,
            "warmups_per_executable": 1, "seed": str(int(args.seed)),
            "transformed_sites": transformation["transformed_sites"],
            "results": results,
            "transformed_to_baseline_median_ratio": results["transformed"]["median_seconds"] /
                                                     results["baseline"]["median_seconds"],
            "kernel_machine_code_identical": results["baseline"]["kernel_text_sha256"] ==
                                             results["transformed"]["kernel_text_sha256"],
            "limitations": ["Single dependency-chain integer kernel, not an application workload",
                            "Unpinned shared host; timings include scheduling and frequency noise",
                            "Matching checksums are a regression check, not a proof",
                            "IR expansion and overhead do not establish security"],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
