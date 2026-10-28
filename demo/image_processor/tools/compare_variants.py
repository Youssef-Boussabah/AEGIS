#!/usr/bin/env python3
"""Compare ImageLab kernel variants (baseline vs transformed) in one build tree.

    compare_variants.py --build BUILD_DIR [--baseline ir-baseline] [--quick]
                        [--rounds N] [--width N] [--height N] [--samples N]
                        [--warmup N] [--repeat N] [--seed N] [--output FILE]

Reads BUILD_DIR/imagelab-variants.json (written by CMake) and, for every
variant:

1. Output equivalence: runs the variant's CLI on every fixture and parameter
   set and requires byte-identical output to the baseline variant's CLI.
2. Benchmark: runs imagelab-bench for all variants in rotating order for
   --rounds rounds and requires identical output fingerprints everywhere.
3. Artifacts: SHA-256 and size of the kernel object, kernel IR, CLI and
   benchmark executables; executable-section and per-kernel symbol sizes
   from the kernel object (ELF only).

Writes one JSON record (schema imagelab.compare.v1) and prints a summary.
Exits 1 if any output or fingerprint differs. Timing is a local measurement
on this machine only; see README.md "Benchmarks" for its limitations.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import statistics
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

LIMITATIONS = [
    "Single machine, single process at a time, no CPU pinning or frequency control.",
    "Times one synthetic image per operation; other images, sizes, seeds, compilers, "
    "flags or hardware may behave differently.",
    "Identical outputs on the tested fixtures and benchmark image are regression evidence, "
    "not a proof of equivalence for all inputs.",
    "Differences in code size or speed say nothing about resistance to reverse engineering "
    "or tampering; no security property is measured here.",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def file_info(path: str | None) -> dict | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return {"path": path, "missing": True}
    return {"path": path, "size_bytes": p.stat().st_size, "sha256": sha256_file(p)}


def elf_code_info(path: Path, symbols: list[str]) -> dict:
    """Executable-section bytes and function symbol sizes of an ELF64 LE object."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return {"available": False, "reason": "not an ELF64 little-endian object"}
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    sections = []
    for i in range(shnum):
        name, stype, flags, _addr, offset, size, link, _info, _align, entsize = \
            struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
        sections.append((name, stype, flags, offset, size, link, entsize))
    _, _, _, stroff, _, _, _ = sections[shstrndx]

    def cstr(base: int, index: int) -> str:
        end = data.index(b"\0", base + index)
        return data[base + index:end].decode()

    exec_bytes = sum(s[4] for s in sections if s[2] & 0x4)
    sizes: dict[str, int] = {}
    for _name, stype, _flags, offset, size, link, entsize in sections:
        if stype != 2 or entsize == 0:  # SHT_SYMTAB
            continue
        strtab = sections[link][3]
        for j in range(size // entsize):
            st_name, st_info, _other, _shndx, _value, st_size = \
                struct.unpack_from("<IBBHQQ", data, offset + j * entsize)
            sym = cstr(strtab, st_name)
            if sym in symbols and (st_info & 0xF) == 2:  # STT_FUNC
                sizes[sym] = st_size
    return {"available": True, "executable_section_bytes": exec_bytes,
            "function_bytes": {s: sizes.get(s) for s in symbols}}


def read_allowlist(path: Path) -> list[str]:
    return [line.split("#", 1)[0].strip() for line in path.read_text().splitlines()
            if line.split("#", 1)[0].strip()]


def environment(manifest: dict) -> dict:
    cpu = None
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    governor = None
    try:
        governor = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text().strip()
    except OSError:
        pass
    return {
        "utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_model": cpu,
        "logical_cpus": os.cpu_count(),
        "cpu0_governor": governor,
        "python": platform.python_version(),
        "compiler": f"{manifest['compiler_id']} {manifest['compiler_version']}",
        "build_type": manifest["build_type"],
        "ir_backend_flags": manifest["ir_backend_flags"],
        "sanitize": manifest["sanitize"],
        "shield": manifest["shield"],
    }


def check_outputs(variants: list[dict], baseline: str, source_dir: Path) -> tuple[dict, int]:
    sys.dont_write_bytecode = True  # keep the source tree free of __pycache__
    sys.path.insert(0, str(source_dir / "tests"))
    import imagelab_reference as ref  # noqa: PLC0415

    fixtures = sorted(p for p in (source_dir / "tests" / "fixtures").iterdir()
                      if p.suffix in (".pam", ".ppm"))
    hashes: dict[str, dict[str, str]] = {v["name"]: {} for v in variants}
    errors = 0
    with tempfile.TemporaryDirectory(prefix="imagelab-compare-") as tmp:
        out = Path(tmp) / "out.pam"
        for variant in variants:
            for fixture in fixtures:
                for op, params in ref.PARAMETER_SETS:
                    argv = [variant["cli"], op]
                    for key, value in params.items():
                        argv += [f"--{key}", str(value)]
                    proc = subprocess.run([*argv, str(fixture), str(out)], capture_output=True,
                                          text=True, timeout=60, check=False)
                    case = f"{fixture.name} {ref.case_id(op, params)}"
                    if proc.returncode != 0:
                        print(f"FAIL {variant['name']}: {case}: exit {proc.returncode}")
                        errors += 1
                        continue
                    hashes[variant["name"]][case] = sha256_file(out)
    summary = {}
    for variant in variants:
        diff = sorted(case for case, h in hashes[variant["name"]].items()
                      if hashes[baseline].get(case) != h)
        for case in diff[:10]:
            print(f"FAIL {variant['name']} differs from {baseline}: {case}")
        errors += len(diff)
        summary[variant["name"]] = {"cases": len(hashes[variant["name"]]),
                                    "differ_from_baseline": len(diff)}
    return summary, errors


def run_benchmarks(variants: list[dict], args: argparse.Namespace) -> tuple[dict, int]:
    bench_args = ["--width", str(args.width), "--height", str(args.height),
                  "--samples", str(args.samples), "--warmup", str(args.warmup),
                  "--repeat", str(args.repeat), "--seed", str(args.seed)]
    samples: dict[str, dict[str, list[int]]] = {v["name"]: {} for v in variants}
    fingerprints: dict[str, set[str]] = {}
    for rnd in range(args.rounds):
        order = variants[rnd % len(variants):] + variants[:rnd % len(variants)]
        for variant in order:
            proc = subprocess.run([variant["bench"], *bench_args], capture_output=True,
                                  text=True, timeout=3600, check=True)
            result = json.loads(proc.stdout)
            for op in result["operations"]:
                samples[variant["name"]].setdefault(op["name"], []).extend(op["samples_ns"])
                fingerprints.setdefault(op["name"], set()).add(op["fingerprint"])
    errors = 0
    for op, prints in fingerprints.items():
        if len(prints) != 1:
            print(f"FAIL benchmark fingerprints differ for {op}: {sorted(prints)}")
            errors += 1
    pixels = args.width * args.height * args.repeat
    summary: dict[str, dict] = {}
    for name, ops in samples.items():
        summary[name] = {}
        for op, values in ops.items():
            median = statistics.median(values)
            summary[name][op] = {
                "samples": len(values), "median_ns": median, "min_ns": min(values),
                "max_ns": max(values), "median_ns_per_pixel": median / pixels,
                "fingerprint": next(iter(fingerprints[op])) if len(fingerprints[op]) == 1
                else None,
                "samples_ns": values,
            }
    return summary, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--baseline", help="variant to compare against "
                        "(default: ir-baseline if built, else native)")
    parser.add_argument("--quick", action="store_true",
                        help="tiny benchmark settings, for smoke tests only")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--width", type=int, default=1024)
    parser.add_argument("--height", type=int, default=768)
    parser.add_argument("--samples", type=int, default=9)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--repeat", type=int, default=4)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.quick:
        args.rounds, args.width, args.height = 1, 64, 48
        args.samples, args.warmup, args.repeat = 2, 0, 1

    manifest = json.loads((args.build / "imagelab-variants.json").read_text())
    variants = manifest["variants"]
    names = [v["name"] for v in variants]
    baseline = args.baseline or ("ir-baseline" if "ir-baseline" in names else names[0])
    if baseline not in names:
        parser.error(f"unknown baseline {baseline}; built variants: {names}")
    source_dir = Path(manifest["source_dir"])
    allow = read_allowlist(source_dir / "protect.allowlist")

    outputs, output_errors = check_outputs(variants, baseline, source_dir)
    bench, bench_errors = run_benchmarks(variants, args)

    artifacts = {}
    for v in variants:
        obj = v["kernel_object"]
        artifacts[v["name"]] = {
            "kernel_object": file_info(obj),
            "kernel_object_code": elf_code_info(Path(obj), allow) if obj else None,
            "kernel_ir": file_info(v["kernel_ir"]),
            "cli": file_info(v["cli"]),
            "bench": file_info(v["bench"]),
        }
    shield_report = None
    if manifest["shield"]:
        report = json.loads(Path(manifest["shield"]["report"]).read_text())
        shield_report = {
            "transformed_sites": report["transformed_sites"],
            "llvm_version": report.get("llvm_version"),
            "functions": {f["name"]: len(f.get("transformed_sites", []))
                          for f in report["functions"] if f.get("annotated")},
        }

    record = {
        "schema": "imagelab.compare.v1",
        "baseline": baseline,
        "settings": {k: getattr(args, k) for k in
                     ("quick", "rounds", "width", "height", "samples", "warmup", "repeat", "seed")},
        "environment": environment(manifest),
        "outputs": outputs,
        "benchmark": bench,
        "artifacts": artifacts,
        "shield_report": shield_report,
        "limitations": LIMITATIONS,
        "ok": output_errors == 0 and bench_errors == 0,
    }
    if args.output:
        args.output.write_text(json.dumps(record, indent=2) + "\n")

    print(f"baseline: {baseline}; outputs identical: "
          f"{all(o['differ_from_baseline'] == 0 for o in outputs.values())}")
    print(f"{'variant':<12} {'op':<8} {'median ms':>10} {'vs base':>8} {'ns/px':>8}")
    for name in names:
        for op, stats in bench[name].items():
            base = bench[baseline][op]["median_ns"]
            print(f"{name:<12} {op:<8} {stats['median_ns'] / 1e6:>10.3f} "
                  f"{stats['median_ns'] / base:>8.3f} {stats['median_ns_per_pixel']:>8.3f}")
    for name in names:
        code = artifacts[name]["kernel_object_code"]
        if code and code.get("available"):
            print(f"{name:<12} kernel code bytes: {code['executable_section_bytes']} "
                  f"{code['function_bytes']}")
    return 0 if record["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
