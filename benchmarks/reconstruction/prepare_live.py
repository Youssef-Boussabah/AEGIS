#!/usr/bin/env python3
"""Prepare, but never approve or send, a fresh three-way production-Lab experiment."""
from __future__ import annotations

import argparse
from copy import deepcopy
import os
from pathlib import Path
import secrets
import sys

import benchmark as b


def prepare(measurements, output_dir, headless, *, reports=None, analyze_owned=False,
            model="nvidia/Nemotron-3_5-Lightning", output_tokens=8192):
    """No provider construction, credentials, approval consumption or candidate execution."""
    import evidence
    evidence.lab_modules()
    from aegis_lab.evidence import planned_ghidra_tool, bind_ghidra_evidence, parse_ghidra_report
    from aegis_lab.ghidra import analyze
    from aegis_lab.manifest import TrialManifest
    from aegis_lab.reconstruction import planned_attack_digests, prepare_reconstruction
    from aegis_lab.experiment import WorkflowConfig, initial_messages, live_workflow_sha256
    from aegis_lab.provider import InferenceRequest
    from aegis_lab.live_trial import TrialPlan, prepare_plan
    from aegis_lab.safe_io import publish_new_file

    original = b.report_archive(measurements)
    m, root = deepcopy(original["manifest"]), Path(measurements).parent
    b.require(len(m["targets"]) == 1, "production_pipeline_requires_one_selected_function")
    b.require({s["sha256"] for s in m["sources"]} == {b.PINNED["target.c"], b.PINNED["runner.c"]},
              "only_pinned_owned_sources_may_be_disclosed")
    b.require(len(m["artifacts"]) == 3 and {a["variant"] for a in m["artifacts"]} == set(b.VARIANTS),
              "three_unique_variants_required")
    b.require(len({a["file"]["sha256"] for a in m["artifacts"]}) == 3, "distinct_final_artifacts_required")
    b.require(bool(reports) != bool(analyze_owned), "supply_completed_reports_or_explicit_owned_analysis")
    b.integer(output_tokens, 1, 16384)
    output_dir = Path(output_dir).absolute()
    b.require(not output_dir.resolve().is_relative_to(b.ROOT), "build_output_must_be_outside_source_tree")
    b.require(not output_dir.exists(), "output_directory_exists")
    output_dir.mkdir(mode=0o700, parents=True)
    # Only hash-bound files from this run; no scanning of other analysis jobs.
    refs = m["sources"] + [m["oracle"]]
    for a in m["artifacts"]:
        refs += [a[k] for k in ("file", "ir", "shield_report", "mirage_report") if a[k] is not None]
    for ref in refs:
        target = b.contained(output_dir, ref["path"])
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        data = b.checked(root, ref)
        if not target.exists():
            target.write_bytes(data)
        else:
            b.require(b.read_file(target) == data, "archive_copy_collision")
        if ref in [a["file"] for a in m["artifacts"]]:
            target.chmod(0o600)  # Static analysis only; preparation never runs these copies.
    if reports:
        export = parse_ghidra_report(b.read_file(reports["baseline"], b.MAX_JSON)).export
        tool = planned_ghidra_tool(headless, function=export.selected_function, max_functions=export.max_functions,
            max_c_chars=export.max_c_chars, decompile_timeout_seconds=export.decompile_timeout_seconds,
            analysis_timeout_seconds=export.analysis_timeout_seconds, wall_timeout_seconds=export.wall_timeout_seconds)
    else:
        tool = planned_ghidra_tool(headless, function="*", max_functions=64, max_c_chars=20000)
    workflow = WorkflowConfig(max_steps=1)
    build = m["build_conditions"]
    clang = build["tools"]["clang"]
    conditions = {"pipeline": "reconstruction-owned-llvm22-build", "compiler": {"name": "clang",
        "version": clang["version"], "executable_sha256": clang["sha256"],
        "configuration_sha256": b.identity({k: build[k] for k in ("target_triple", "frontend_flags", "final_flags")})},
        "shared_recipe_sha256": b.identity(build), "symbols": "present", "debug_info": False}
    pair_id, plan, prompts, observations = secrets.token_hex(16), {}, {}, {}
    derived_controls = []
    for a in m["artifacts"]:
        label = "mirage" if a["variant"] == "shield_mirage" else a["variant"]
        folder = output_dir / label
        folder.mkdir(mode=0o700, exist_ok=True)
        artifact = b.contained(output_dir, a["file"]["path"])
        if analyze_owned:
            report_path = analyze(artifact, folder / "ghidra", headless, function="*", max_functions=64,
                max_c_chars=20000, expected_sha256=a["file"]["sha256"], expected_ghidra_version=tool.version)
        else:
            (folder / "ghidra").mkdir(mode=0o700)
            report_path = folder / "ghidra/ghidra-analysis.json"
            report_path.write_bytes(b.read_file(reports[a["variant"]], b.MAX_JSON))
        protection = None
        if a["variant"] != "baseline":
            protector = build["tools"]["shield-plugin" if a["variant"] == "shield" else "mirage-source"]
            protection = {"backend": {"name": a["variant"], "version": protector["version"],
                "executable_sha256": protector["sha256"], "configuration_sha256": b.identity(a["protection"])},
                "seed": 42, "transformation_report_sha256": a["mirage_report" if a["variant"] == "shield_mirage" else "shield_report"]["sha256"]}
        lm = TrialManifest.model_validate({"trial_id": secrets.token_hex(16), "pair_id": pair_id,
            "variant": "baseline" if a["variant"] == "baseline" else "protected",
            "target": {"name": "aegis-owned-reconstruction-u32", "function": m["targets"][0],
                "source_revision": "sha256:" + b.PINNED["target.c"], "platform": "linux-x86_64",
                "artifact_format": "ELF", "final_artifact_sha256": a["file"]["sha256"], "build": conditions,
                "protection": protection},
            "attack": {"workflow": "ghidra_model", "tools": [tool.model_dump(mode="json")], "provider": "Nebius",
                "model_id": model, "sampling_seed": None, "temperature": 0.0,
                "session_isolation": "fresh_session_and_workspace",
                **planned_attack_digests(max_model_tokens=2000000, blinded=True, max_output_tokens=output_tokens)},
            "access": {"workspace_policy_sha256": b.identity({"scope": "selected bound decompilation only; no oracle or source"})},
            "budget": {"max_wall_seconds": 240, "max_model_tokens": 2000000, "max_tool_calls": 8, "max_attempts": 1},
            "scoring": {"hidden_test_suite_sha256": b.identity({"status": "no-hidden-suite-candidate-execution-unavailable"}),
                "scorer": {"name": "unavailable", "version": "not-implemented-no-validated-isolation",
                    "executable_sha256": b.digest(b"absent-scorer"), "configuration_sha256": b.digest(b"no-execution")},
                "expected_interface": "opaque(uint32_t,uint32_t)->uint32_t"},
            "authorization": {"reference": "owned-reconstruction-benchmark-20261030",
                "authorized_scope": "owned static analysis; inference requires single-use approval; no candidate execution"}})
        manifest_path = folder / "manifest.json"
        publish_new_file(manifest_path, lm.canonical_bytes(), b.MAX_JSON)
        report_bytes = b.read_file(report_path, b.MAX_JSON)
        bind_ghidra_evidence(lm, report_bytes)
        prepared = prepare_reconstruction(lm, report_bytes, max_output_tokens=output_tokens)
        request = InferenceRequest(**{**prepared.request.model_dump(), "messages": initial_messages(prepared), "store": False}).to_body()
        controls = {"capabilities": ["ghidra_decompilation", "rea_reasoning"],
            "analysis_tools": {"Ghidra": {k: v for k, v in tool.model_dump(mode="json").items() if k != "name"}},
            "prompt_template_sha256": lm.attack.prompt_sha256,
            "system_prompt_sha256": b.digest(request["messages"][0]["content"].encode()),
            "workflow_sha256": live_workflow_sha256(workflow),
            "request_parameters_sha256": b.identity({k: v for k, v in request.items() if k != "messages"}),
            "model_identity": model, "max_attempts": 1, "max_input_tokens": 1048576,
            "max_output_tokens": output_tokens, "max_total_tokens": 2000000, "max_spend_microusd": 100000,
            "time_budget_seconds": 240, "random_seed": None, "context_policy": "selected_functions_only",
            "oracle_access": "none", "source_access": "none"}
        b.validate_controls(controls)
        derived_controls.append(controls)
        draft = folder / "approval.DRAFT.json"
        argv = [sys.executable, "-B", "-m", "aegis_lab.live", "draft", manifest_path, report_path, artifact,
            "--max-output-tokens", str(output_tokens), "--steps", "1", "--context-tokens", "1048576",
            "--input-microusd-per-million", "60000", "--output-microusd-per-million", "240000",
            "--max-spend-microusd", "100000", "--request-timeout", "120", "--output", draft]
        b.run(argv, output_dir, env_extra={"PYTHONPATH": str(b.ROOT / "attack_lab/src")})
        prompt = {"format": "aegis_lab", "manifest": b.reference(output_dir, manifest_path),
            "report": b.reference(output_dir, report_path),
            "request": b.reference(output_dir, Path(str(draft) + ".request-review.json")),
            "configuration": workflow.model_dump(mode="json")}
        b.write_json(folder / "prompt-bindings.json", prompt)
        plan[label] = {"manifest": str(manifest_path), "report": str(report_path), "artifact": str(artifact), "approval": None}
        prompts[a["id"]] = str(folder / "prompt-bindings.json")
        observations[a["id"]] = {"artifact_sha256": a["file"]["sha256"], "ghidra_report_sha256": b.digest(report_bytes),
            "rendered_prompt_sha256": prepared.rendered_prompt_sha256,
            "request_review_sha256": prompt["request"]["sha256"], "draft": str(draft)}
    b.require(all(c == derived_controls[0] for c in derived_controls), "noncomparable_production_requests")
    m["attacker_controls"] = derived_controls[0]
    original["manifest"], original["comparison_sha256"] = m, b.identity(m)
    original["limitations"] += ["Fresh Ghidra inputs and production inference drafts prepared separately; not an inference result.",
        "Selected-function prompts omit Mirage decoy inventory; this design cannot measure analyst distraction."]
    b.validate_manifest(m, output_dir)
    b.write_json(output_dir / "comparison.json", m)
    b.write_json(output_dir / "measurements.json", original)
    b.write_json(output_dir / "controls.json", m["attacker_controls"])
    plan.update(configuration=workflow.model_dump(mode="json"), max_output_tokens=output_tokens, order_seed=42)
    parsed_plan = TrialPlan.model_validate(plan)
    prepare_plan(parsed_plan)  # Read-only production validation; no approval/network.
    b.write_json(output_dir / "plan.DRAFT.json", parsed_plan.model_dump(mode="json"))
    command = [sys.executable, "-B", "-m", "aegis_lab.live_trial"]
    handoff = {"schema": "aegis.reconstruction.live-handoff.v1", "prepared_at": b.stamp(),
        "comparison_sha256": b.identity(m), "artifacts": observations, "prompt_bindings": prompts,
        "plan": str(output_dir / "plan.DRAFT.json"), "network_requests": 0, "candidate_execution": False,
        "approvals_granted": False, "proposed_requests": 3, "proposed_max_spend_microusd": 300000,
        "shared_remaining_budget": "unknown_requires_runtime_coordinator_confirmation",
        "catalogue_and_prices": "proposals_only_live_pipeline_rechecks_before_inference",
        "preflight_argv": command + ["preflight", str(output_dir / "plan.APPROVED.json")],
        "run_argv": command + ["run", str(output_dir / "plan.APPROVED.json"), "--output-dir",
                                 str(output_dir / "live-results"), "--approve-live-inference"]}
    b.write_json(output_dir / "handoff.json", handoff)
    return handoff


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("measurements", type=Path)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--ghidra-headless", type=Path, required=True)
    p.add_argument("--analyze-owned", action="store_true", help="explicitly permit new static analysis of this owned fixture")
    p.add_argument("--reports", nargs=3, type=Path, metavar=("BASELINE", "SHIELD", "COMBINED"))
    p.add_argument("--model", default="nvidia/Nemotron-3_5-Lightning")
    a = p.parse_args(argv)
    try:
        if a.analyze_owned:
            os.nice(10)  # Lower priority for our new jobs; never alter another analysis process.
        h = prepare(a.measurements, a.output_dir, a.ghidra_headless,
            reports=dict(zip(b.VARIANTS, a.reports)) if a.reports else None, analyze_owned=a.analyze_owned, model=a.model)
        print("prepared_not_approved " + h["comparison_sha256"])
    except Exception as exc:
        print(str(exc) if isinstance(exc, b.Invalid) else "live_preparation_failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
