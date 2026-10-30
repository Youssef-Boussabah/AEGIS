"""Prepare fresh Lab requests or import verified generation records as UNSCORED.

No credential access, networking, approval creation, candidate compilation or
candidate execution. Actual inference stays in the production Lab pipeline and
the designated credential-enabled runtime.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.adaptive_mvp.controller import ROOT, ExperimentError, sha256_file, write_json  # noqa: E402
from experiments.adaptive_mvp.evidence import digest, read_bounded, strict_json  # noqa: E402
from experiments.adaptive_mvp.verify import verify_report  # noqa: E402


def load_lab():
    sys.path.insert(0, str(ROOT / "attack_lab/src"))


def prepare(report_path: Path, output: Path, ghidra: Path, model: str, *, max_output_tokens=8192):
    verify_report(report_path)
    if not model.startswith("nvidia/"):
        raise ValueError("explicit_nvidia_model_required")
    load_lab()
    from aegis_lab.canonical import canonical_sha256
    from aegis_lab.evidence import planned_ghidra_tool, parse_ghidra_report
    from aegis_lab.ghidra import analyze
    from aegis_lab.live import main as live_main
    from aegis_lab.manifest import TrialManifest
    from aegis_lab.reconstruction import planned_attack_digests

    report = strict_json(read_bounded(report_path))
    root = report_path.absolute().parent
    if output.resolve().is_relative_to(ROOT):
        raise ValueError("output_must_be_outside_source_tree")
    output.mkdir(mode=0o700)
    if not report["baseline"]:
        raise ValueError("verified_baseline_required")
    unique = {}
    for name, item in [("baseline", report["baseline"]), *[
            (item["candidate_id"], item) for item in report["candidates"] if item["status"] == "VERIFIED"]]:
        key = item["artifact"]["sha256"]
        if key in unique:
            unique[key]["aliases"].append(name)
        else:
            unique[key] = {"aliases": [name], "candidate": item}
    tool = planned_ghidra_tool(ghidra, function="*", max_functions=512)
    flags = report["inputs"]["compile_flags"] + report["inputs"]["final_flags"]
    compiler = report["inputs"]["tools"]["clang"]
    build = {"pipeline": "clang22-O1-IR-production-adapter-O2-ELF-GC",
             "compiler": {"name": "clang", "version": re.search(r"version (\d+\.\d+\.\d+)", compiler["version"]).group(1),
                          "executable_sha256": compiler["sha256"],
                          "configuration_sha256": canonical_sha256(flags)},
             "shared_recipe_sha256": canonical_sha256({"flags": flags, "source": report["inputs"]["target"]["sha256"]}),
             "symbols": "present", "debug_info": False}
    targets = []
    pair_id = uuid.uuid4().hex
    for index, (artifact_hash, entry) in enumerate(unique.items()):
        item = entry["candidate"]
        target_root = output / f"target-{index:02d}"
        target_root.mkdir(mode=0o700)
        binary = root / item["artifact"]["path"]
        analysis_path = analyze(binary, target_root / "ghidra", ghidra, function="*", max_functions=512,
                                expected_sha256=artifact_hash, expected_ghidra_version="12.1.4")
        analysis = parse_ghidra_report(read_bounded(analysis_path))
        function = next(fn for fn in analysis.analysis.functions if fn.name == "signal_mix")
        protection = None
        if index:
            protection = {"backend": {"name": item["configuration"]["backend"], "version": "captured-production-adapter",
                                      "executable_sha256": report["inputs"]["plugin"]["sha256"],
                                      "configuration_sha256": canonical_sha256(item["options"])},
                          "seed": int(item["configuration"]["seed"]),
                          "transformation_report_sha256": item["protection_artifacts"][
                              "mirage-report.json" if item["configuration"]["decoys"] else "shield-report.json"]["sha256"]}
        manifest = TrialManifest.model_validate({
            "trial_id": uuid.uuid4().hex, "pair_id": pair_id, "variant": "baseline" if index == 0 else "protected",
            "target": {"name": "adaptive-owned-signal", "function": "signal_mix",
                       "source_revision": report["inputs"]["target"]["sha256"], "platform": "linux-x86_64",
                       "artifact_format": "ELF", "final_artifact_sha256": artifact_hash,
                       "build": build, "protection": protection},
            "attack": {"workflow": "ghidra_model", "tools": [tool.model_dump(mode="json")], "provider": "Nebius",
                       "model_id": model, "sampling_seed": None, "temperature": 0.0,
                       "session_isolation": "fresh_session_and_workspace",
                       **planned_attack_digests(max_model_tokens=2_000_000, blinded=True, max_output_tokens=max_output_tokens)},
            "access": {"workspace_policy_sha256": canonical_sha256({"scope": "bound decompilation only; no original source, hidden tests or oracle"})},
            "budget": {"max_wall_seconds": 240, "max_model_tokens": 2_000_000, "max_tool_calls": 8, "max_attempts": 1},
            "scoring": {"hidden_test_suite_sha256": canonical_sha256({"status": "no_hidden_suite_configured"}),
                        "scorer": {"name": "not-configured", "version": "behavioral-execution-unavailable",
                                   "executable_sha256": digest(b"no scorer configured"),
                                   "configuration_sha256": digest(b"no candidate execution")},
                        "expected_interface": "opaque(uint32_t,uint32_t,uint32_t)->uint32_t"},
            "authorization": {"reference": "owner-authorized-adaptive-owned-fixture-2026-10-30",
                              "authorized_scope": "local static analysis; NVIDIA inference requires a separate exact single-use approval"},
        })
        manifest_path = target_root / "manifest.json"
        write_json(manifest_path, manifest.model_dump(mode="json"))
        common = [str(manifest_path), str(analysis_path), str(binary), "--steps", "1", "--max-output-tokens", str(max_output_tokens)]
        draft = target_root / "approval.DRAFT.json"
        draft_argv = ["draft", *common, "--context-tokens", "1048576", "--input-microusd-per-million", "60000",
                      "--output-microusd-per-million", "240000", "--max-spend-microusd", "100000",
                      "--request-timeout", "120", "--output", str(draft)]
        if live_main(draft_argv) != 0:
            raise ValueError("production_approval_draft_failed")
        prefix = [sys.executable, "-m", "aegis_lab.live"]
        targets.append({"artifact_sha256": artifact_hash, "aliases": entry["aliases"],
                        "selected_decompilation_sha256": digest(function.decompiled_c.encode()),
                        "function_count": len(analysis.analysis.functions),
                        "manifest": str(manifest_path), "report": str(analysis_path), "artifact": str(binary),
                        "approval_draft": str(draft), "approval_draft_sha256": sha256_file(draft),
                        "preflight_argv": [*prefix, "preflight", *common, "--approval", str(target_root / "approval.json")],
                        "run_argv": [*prefix, "run", *common, "--approval", str(target_root / "approval.json"),
                                     "--output-dir", str(target_root / "live-run"), "--approve-live-inference"]})
    result = {"schema_version": "aegis.adaptive.lab-preparation.v1", "experiment_report_sha256": sha256_file(report_path),
              "prepared_at": datetime.now(timezone.utc).isoformat(), "targets": targets,
              "network_requests": 0, "candidate_execution": False, "approvals_granted": False,
              "shared_budget_usd": 20, "proposed_aggregate_cap_microusd": 100000 * len(targets),
              "shared_spend_state": "must_be_reserved_in_designated_runtime_ledger_before_any_request",
              "limitations": ["Model/context/pricing are review proposals; the production runner must check fresh catalogue/account data.",
                              "The operator must independently review exact disclosure, retention, request and spending drafts.",
                              "Duplicate final artifacts share one request; a byte-identical Shield build is not a distinct transformed control.",
                              "Selected-function prompts do not expose Mirage's decoy inventory; this comparison cannot measure decoy target-selection effects.",
                              "Inference alone produces unscored text. No behavioral success, failure or resistance is established."]}
    write_json(output / "preparation.json", result)
    return result


def import_generation(directory: Path, output: Path):
    """Use Lab's verifier; generated text remains unscored regardless of validity."""
    if output.resolve().is_relative_to(ROOT):
        raise ValueError("output_must_be_outside_source_tree")
    load_lab()
    from aegis_lab.experiment import verify_experiment
    from aegis_lab.manifest import TrialManifest
    from aegis_lab.private_evidence import PrivateEvidence
    record = verify_experiment(directory)
    store = PrivateEvidence(directory / "private-evidence", create=False)
    manifest = TrialManifest.model_validate_json(store.get(record.manifest_sha256))
    source = read_bounded(directory / "experiment.json")
    receipt = {"schema_version": "aegis.adaptive.attack-receipt.v1", "artifact_sha256": record.artifact_sha256,
               "evidence_sha256": digest(source), "attack_id": "lab-REA-style-reconstruction-generation",
               "protocol_sha256": manifest.attack.workflow_configuration_sha256,
               "suite_sha256": manifest.scoring.hidden_test_suite_sha256,
               "outcome": "unscored", "verification_kind": "structural_only", "runtime_attestation_sha256": None,
               "verifier": "production-aegis_lab.experiment.verify_experiment",
               "verified_at": datetime.now(timezone.utc).isoformat(),
               "limitations": ["Lab archive consistency checked offline; unsigned records cannot authenticate provider origin.",
                               "Generation is not a behavioral result. No generated source is compiled or executed.",
                               "Scorer/suite identities may be placeholders; this receipt remains unscored."]}
    output.mkdir(mode=0o700)
    (output / "evidence.json").write_bytes(source)
    write_json(output / "receipt.json", receipt)
    receipt_hash = sha256_file(output / "receipt.json")
    write_json(output / "index.json", {"schema_version": "aegis.adaptive.evidence-index.v1", "entries": [
        {"receipt": "receipt.json", "evidence": "evidence.json", "trusted_receipt_sha256": receipt_hash}]})
    summary = {"artifact_sha256": record.artifact_sha256, "generation_status": record.generation_status,
               "reported_tokens": record.reported_tokens, "reserved_spend_microusd": record.reserved_spend_microusd,
               "estimated_reported_cost_microusd": record.estimated_reported_cost_microusd,
               "actual_billed_cost": record.cost_microusd, "resistance": "UNMEASURED", "execution_performed": False,
               "source_archive": str(directory.absolute()), "receipt_sha256": receipt_hash}
    write_json(output / "import-summary.json", summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare")
    p.add_argument("report", type=Path)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--ghidra-headless", type=Path, required=True)
    p.add_argument("--model", required=True)
    p = commands.add_parser("import-generation")
    p.add_argument("directory", type=Path)
    p.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = (prepare(args.report, args.output_dir.absolute(), args.ghidra_headless.absolute(), args.model)
                  if args.command == "prepare" else import_generation(args.directory, args.output_dir.absolute()))
        print(json.dumps({key: value for key, value in result.items() if key != "targets"}, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"Lab bridge refused: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
