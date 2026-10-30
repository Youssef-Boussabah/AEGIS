#!/usr/bin/env python3
"""Verify local research bindings and export an allowlisted, private-data-free summary."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mirage(directory, original):
    report_path = directory / "report.json"
    report = json.loads(report_path.read_bytes())
    if report["schema_version"] != "aegis.mirage.report.v1":
        raise ValueError("Unsupported Mirage schema")
    if sha(original) != report["input_sha256"] or sha(directory / "module.ll") != report["output_sha256"]:
        raise ValueError("Mirage input/output digest mismatch")
    count = report["inserted_count"]
    if type(count) is not int or count < 0 or count != len(report["inserted_functions"]):
        raise ValueError("Invalid decoy count")
    return report_path, {"input_sha256": report["input_sha256"], "output_sha256": report["output_sha256"],
                         "inserted_count": count, "security_property": "not_established",
                         "final_artifact_retention": "requires_independent_check"}


def benchmark(path):
    record = json.loads(path.read_bytes())
    if record["schema"] != "imagelab.compare.v1":
        raise ValueError("Unsupported ImageLab schema")
    # Check all recorded artifact bytes. This verifies bindings, not the timing measurement.
    for variant in record["artifacts"].values():
        for key in ("kernel_object", "kernel_ir", "cli", "bench"):
            artifact = variant.get(key)
            if artifact and (artifact.get("missing") or sha(Path(artifact["path"])) != artifact["sha256"]):
                raise ValueError("ImageLab artifact digest mismatch or missing artifact")
    rows = []
    for variant, operations in record["benchmark"].items():
        for operation, stats in operations.items():
            rows.append({"variant": variant, "operation": operation, "samples": stats["samples"],
                         "median_ns": stats["median_ns"], "min_ns": stats["min_ns"], "max_ns": stats["max_ns"]})
    conditions = {k: record["environment"].get(k) for k in
                  ("utc", "platform", "cpu_model", "cpu0_governor", "compiler", "build_type", "ir_backend_flags")}
    return path, {"baseline": record["baseline"], "outputs_match": record["ok"],
                  "conditions": conditions, "settings": record["settings"], "measurements": rows,
                  "security_property": "not_measured"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("reconstruction", "reconstruction_comparison", "mirage", "benchmark"))
    parser.add_argument("source", type=Path, help="Experiment/Mirage directory, or ImageLab compare JSON")
    parser.add_argument("--original-ir", type=Path, help="Required for Mirage input binding verification")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--post-hoc-report", type=Path, help="Recompute and bind a separate reconstruction parser review")
    args = parser.parse_args()
    try:
        if args.post_hoc_report is not None and args.kind != "reconstruction":
            raise ValueError("post_hoc_report_requires_reconstruction")
        if args.kind in ("reconstruction", "reconstruction_comparison") and args.output.resolve().is_relative_to(args.source.resolve()):
            raise ValueError("original_evidence_is_read_only")
        if args.kind in ("reconstruction", "reconstruction_comparison"):
            from aegis_lab.public_summary import export_comparison, export_experiment

            record = (export_experiment(args.source, post_hoc_report=args.post_hoc_report) if args.kind == "reconstruction"
                      else export_comparison(args.source)).model_dump(mode="json", by_alias=True)
        elif args.kind == "mirage":
            if args.original_ir is None:
                parser.error("Mirage requires --original-ir")
            source, summary = mirage(args.source, args.original_ir)
        else:
            source, summary = benchmark(args.source)
        if args.kind in ("mirage", "benchmark"):
            record = {"schema": "aegis.product.evidence.v1", "kind": args.kind, "source_sha256": sha(source),
                      "verification": "offline_hash_bindings_checked", "summary": summary}
        data = (json.dumps(record, indent=2, allow_nan=False) + "\n").encode()
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        print(f"{hashlib.sha256(data).hexdigest()}  {args.output}")
    except Exception:
        # Never print input JSON, provider bodies, paths from private records or diagnostics.
        print("error: evidence verification/export failed; check schema, dependencies and bound files locally", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
