"""Read-only experiment consistency checks. Never executes an artifact.

These are unsigned local records. Rechecking bindings cannot authenticate their
author or independently remeasure timings or an external attacker's behavior.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import statistics
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.adaptive_mvp.controller import (  # noqa: E402
    ExperimentError, SCHEMA, TARGET_SHA256, contained, retention, sha256_file,
)
from experiments.adaptive_mvp.evidence import (  # noqa: E402
    EvidenceError, read_bounded, resistance_for, strict_json, verify_receipt,
)
from experiments.adaptive_mvp.policy import Constraints, next_configuration, select  # noqa: E402


def verify_report(path: Path, expected_sha256: str | None = None) -> dict:
    root = path.absolute().parent
    report_bytes = read_bounded(path)
    import hashlib
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    if expected_sha256 is not None and report_hash != expected_sha256:
        raise ExperimentError("REPORT_DIGEST_MISMATCH")
    report = strict_json(report_bytes)
    if report.get("schema_version") != SCHEMA:
        raise ExperimentError("UNSUPPORTED_EXPERIMENT_SCHEMA")
    checked = 0

    def check(item):
        nonlocal checked
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ExperimentError("UNSAFE_PATH")
        file = contained(root, root / relative)
        if (not file.is_file() or sha256_file(file) != item["sha256"]
                or ("size_bytes" in item and file.stat().st_size != item["size_bytes"])):
            raise ExperimentError("ARTIFACT_INTEGRITY_ERROR")
        checked += 1
        return file

    inputs = report.get("inputs")
    if inputs:
        check(inputs["target"])
        if inputs["target"]["sha256"] != TARGET_SHA256:
            raise ExperimentError("TARGET_SOURCE_NOT_TRUSTED")
        check(inputs["plugin"])
        for entry in inputs["dependency_sources"]:
            check({"path": "inputs/repository/" + entry["repository_path"], "sha256": entry["sha256"]})
    for command in report["commands"]:
        for key in ("stdout", "stderr"):
            if key in command:
                check(command[key])

    receipts = []
    for index, claimed in enumerate(report["external_evidence"]):
        archive = root / "external-evidence"
        receipt = verify_receipt(read_bounded(archive / f"{index:03d}-receipt.json"),
                                 read_bounded(archive / f"{index:03d}-evidence.json"), claimed["receipt_sha256"])
        if receipt != claimed:
            raise ExperimentError("EVIDENCE_RECORD_MISMATCH")
        receipts.append(receipt)
        checked += 2

    baseline = report["baseline"]
    baseline_path = check(baseline["artifact"]) if baseline else None
    if baseline:
        check(baseline["input_ir"])
    constraints = Constraints(**report["constraints"])
    history = []
    for index, candidate in enumerate(report["candidates"]):
        if candidate["candidate_id"] != f"c{index + 1:03d}":
            raise ExperimentError("CANDIDATE_ORDER_MISMATCH")
        if candidate["parent_candidate_id"] != (history[-1]["candidate_id"] if history else "baseline"):
            raise ExperimentError("LINEAGE_MISMATCH")
        config, decision = next_configuration(history, constraints)
        if config is None or candidate["configuration"] != asdict(config) or candidate["decision"] != decision:
            raise ExperimentError("FEEDBACK_DECISION_MISMATCH")
        if candidate["options"] != config.options():
            raise ExperimentError("CONFIGURATION_OPTIONS_MISMATCH")
        if "artifact" in candidate:
            check(candidate["artifact"])
        for item in candidate.get("protection_artifacts", {}).values():
            check(item)
        if "core_report_artifact" in candidate:
            check(candidate["core_report_artifact"])
        if candidate["status"] == "VERIFIED":
            if baseline_path is None:
                raise ExperimentError("BASELINE_REQUIRED")
            decoys = []
            if config.decoys:
                mirage = strict_json(read_bounded(root / candidate["protection_artifacts"]["mirage-report.json"]["path"]))
                decoys = mirage["inserted_functions"]
            observation = retention(root / candidate["artifact"]["path"], baseline_path, decoys)
            if observation != candidate["retention"]:
                raise ExperimentError("RETENTION_RECORD_MISMATCH")
            if resistance_for(candidate["artifact"]["sha256"], receipts) != candidate["resistance"]:
                raise ExperimentError("RESISTANCE_RECORD_MISMATCH")
            performance = candidate["performance"]
            samples, controls = performance["process_wall_ns"], performance["paired_baseline_wall_ns"]
            if (len(samples) != report["budgets"]["samples"] or len(controls) != len(samples)
                    or any(type(value) is not int or value <= 0 for value in samples + controls)
                    or statistics.median(samples) != performance["median_ns"]
                    or statistics.median(samples) / statistics.median(controls) != performance["median_ratio"]):
                raise ExperimentError("PERFORMANCE_RECORD_MISMATCH")
            if candidate["size_ratio"] != candidate["artifact"]["size_bytes"] / baseline["artifact"]["size_bytes"]:
                raise ExperimentError("SIZE_RECORD_MISMATCH")
            # Check observed stdout, rather than just the report's pass label.
            native_commands = [item for item in report["commands"] if item["argv"] == [str(root / candidate["artifact"]["path"])]]
            if len(native_commands) != 1 + len(samples):
                raise ExperimentError("CORRECTNESS_RUN_COUNT_MISMATCH")
            for command in native_commands:
                if (command["exit_code"] != 0 or command["timed_out"]
                        or (root / command["stdout"]["path"]).read_bytes() != inputs["oracle"]["expected_stdout"].encode()):
                    raise ExperimentError("CORRECTNESS_RECORD_MISMATCH")
            if candidate["correctness"]["status"] != "passed":
                raise ExperimentError("CORRECTNESS_RECORD_MISMATCH")
        history.append(candidate)
    if select(history, constraints) != report["selection"]:
        raise ExperimentError("SELECTION_RECORD_MISMATCH")
    return {"status": "passed", "report_sha256": report_hash, "artifact_hashes_checked": checked,
            "candidate_count": len(history), "selection_recomputed": True,
            "scope": "Unsigned local consistency, final ELF bytes, logged checks and selection; no artifact execution or independent timing/attack remeasurement."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify_report(args.report, args.expected_sha256), sort_keys=True))
        return 0
    except (ExperimentError, EvidenceError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Experiment verification failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
