"""Prepare an inference-only ImageLab trial from existing trusted build artifacts.

Runs real Ghidra only. Does not build/run binaries, invoke models, consume approval,
read reference source/hidden tests, or manufacture a scoring result. Source/build
provenance is operator-declared and remains unverified by this preparation tool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
from datetime import UTC, datetime
import platform

from aegis_lab.canonical import canonical_json_bytes, canonical_sha256
from aegis_lab.evidence import planned_ghidra_tool, parse_ghidra_report
from aegis_lab.ghidra import analyze
from aegis_lab.live_trial import TrialPlan, prepare_plan
from aegis_lab.manifest import TrialManifest
from aegis_lab.reconstruction import planned_attack_digests
from aegis_lab.safe_io import publish_new_file, read_regular_file


def sha(path, limit=64 * 1024 * 1024):
    return hashlib.sha256(read_regular_file(path, limit)).hexdigest()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build-dir", required=True, type=Path)
    p.add_argument("--mirage-report", required=True, type=Path)
    p.add_argument("--ghidra-headless", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--source-revision", required=True, help="operator-declared revision of the existing build")
    p.add_argument("--model", required=True, help="explicit NVIDIA model proposal; account availability checked only after approval")
    p.add_argument("--max-model-tokens", required=True, type=int)
    p.add_argument("--max-output-tokens", type=int, default=2048)
    p.add_argument("--steps", type=int, default=1)
    p.add_argument("--function", default="imagelab_color_adjust_pixel")
    p.add_argument("--interface", default="opaque(uint32_t,uint32_t,uint32_t,uint32_t)->uint32_t")
    p.add_argument("--authorized-owned-artifacts", action="store_true", required=True)
    a = p.parse_args(argv)
    root = a.output_dir.resolve()
    root.mkdir(mode=0o700)
    try:
        build = json.loads(read_regular_file(a.build_dir / "imagelab-variants.json", 64 * 1024))
        shield_report_path = Path(build["shield"]["report"])
        shield_report = json.loads(read_regular_file(shield_report_path, 1024 * 1024))
        if shield_report["transformed_sites"] < 1:
            raise ValueError("no_shield_transformations")
        mirage_report = json.loads(read_regular_file(a.mirage_report, 1024 * 1024))
        if mirage_report["inserted_count"] < 1:
            raise ValueError("no_mirage_decoys")
        if sha(a.build_dir / "ir/kernels.shield.ll") != mirage_report["input_sha256"]:
            raise ValueError("mirage_input_not_bound_to_shield")
        external_ir = next(Path(v["kernel_ir"]) for v in build["variants"] if v["name"] == "external")
        if sha(external_ir) != mirage_report["output_sha256"]:
            raise ValueError("mirage_output_digest_mismatch")
        publish_new_file(root / "shield-report.private.json", read_regular_file(shield_report_path, 1024 * 1024), 1024 * 1024)
        publish_new_file(root / "mirage-report.private.json", read_regular_file(a.mirage_report, 1024 * 1024), 1024 * 1024)
        compiler = Path(build["compiler"]).resolve()
        tool = planned_ghidra_tool(a.ghidra_headless, function="*", max_functions=512)
        conditions = {"pipeline": "operator-declared-existing-imagelab-ir-build",
            "compiler": {"name": "clang", "version": build["compiler_version"],
                "executable_sha256": sha(compiler, 256 * 1024 * 1024),
                "configuration_sha256": canonical_sha256({"flags": build["ir_backend_flags"], "build_type": build["build_type"]})},
            "shared_recipe_sha256": canonical_sha256({"compiler": build["compiler_version"],
                "ir_backend_flags": build["ir_backend_flags"], "build_type": build["build_type"],
                "recipe": "ImageLab existing IR variant build; provenance not independently verified"}),
            "symbols": "present", "debug_info": False}
        pair_id = secrets.token_hex(16)
        plan = {"configuration": {"max_steps": a.steps}, "max_output_tokens": a.max_output_tokens, "order_seed": 42}
        summaries = {}
        mirage_module = Path(__file__).resolve().parents[2] / "protectors/mirage/src/aegis_mirage/transform.py"
        for name, directory in (("baseline", "ir-baseline"), ("shield", "shield"), ("mirage", "external")):
            target_root = root / name
            target_root.mkdir(mode=0o700)
            artifact = a.build_dir.resolve() / directory / "imagelab-cli"
            digest = sha(artifact)
            report_path = analyze(artifact, target_root / "ghidra", a.ghidra_headless,
                function="*", max_functions=512, expected_sha256=digest, expected_ghidra_version="12.1.4")
            report_path.parent.chmod(0o700)
            report = parse_ghidra_report(read_regular_file(report_path, 8 * 1024 * 1024))
            protection = None
            if name != "baseline":
                backend = Path(build["shield"]["plugin"]).resolve() if name == "shield" else mirage_module
                protection = {"backend": {"name": "llvm-shield" if name == "shield" else "mirage-after-shield",
                    "version": "operator-declared-existing-build", "executable_sha256": sha(backend),
                    "configuration_sha256": canonical_sha256({"shield": shield_report["config"],
                        "mirage": None if name == "shield" else mirage_report["configuration"]})}, "seed": 42,
                    "transformation_report_sha256": sha(shield_report_path if name == "shield" else a.mirage_report)}
            m = TrialManifest.model_validate({"trial_id": secrets.token_hex(16), "pair_id": pair_id,
                "variant": "baseline" if name == "baseline" else "protected",
                "target": {"name": "operator-owned-imagelab", "function": a.function, "source_revision": a.source_revision,
                    "platform": "linux-x86_64", "artifact_format": "ELF", "final_artifact_sha256": digest,
                    "build": conditions, "protection": protection},
                "attack": {"workflow": "ghidra_model", "tools": [tool.model_dump(mode="json")], "provider": "Nebius",
                    "model_id": a.model, "sampling_seed": None, "temperature": 0.0,
                    "session_isolation": "fresh_session_and_workspace",
                    **planned_attack_digests(max_model_tokens=a.max_model_tokens, blinded=True, max_output_tokens=a.max_output_tokens)},
                "access": {"workspace_policy_sha256": canonical_sha256({"scope": "bound decompilation only; no source, hidden tests or oracle"})},
                "budget": {"max_wall_seconds": 240, "max_model_tokens": a.max_model_tokens, "max_tool_calls": 8, "max_attempts": a.steps},
                "scoring": {"hidden_test_suite_sha256": canonical_sha256({"status": "no_hidden_suite_supplied_scoring_unavailable"}),
                    "scorer": {"name": "not-configured", "version": "not-implemented-for-this-trial",
                        "executable_sha256": canonical_sha256({"scorer": "absent"}),
                        "configuration_sha256": canonical_sha256({"execution": False})}, "expected_interface": a.interface},
                "authorization": {"reference": "operator-owned-artifact-static-analysis",
                    "authorized_scope": "local Ghidra preparation only; external inference requires separate operator approval"}})
            manifest_path = target_root / "manifest.json"
            publish_new_file(manifest_path, m.canonical_bytes(), 1024 * 1024)
            plan[name] = {"manifest": str(manifest_path), "report": str(report_path), "artifact": str(artifact)}
            target_function = next(f for f in report.analysis.functions if f.name == a.function)
            summaries[name] = {"artifact_sha256": digest, "ghidra_version": report.analysis.ghidra_version,
                "function_decompiled": target_function.decompile_success,
                "selected_decompilation_sha256": hashlib.sha256(target_function.decompiled_c.encode()).hexdigest(),
                "function_count": len(report.analysis.functions),
                "ghidra_retained_decoys": [f.name for f in report.analysis.functions if f.name in mirage_report["inserted_functions"]]}
        if summaries["baseline"]["selected_decompilation_sha256"] == summaries["shield"]["selected_decompilation_sha256"]:
            raise ValueError("selected_shield_decompilation_unchanged")
        if len(summaries["mirage"]["ghidra_retained_decoys"]) != mirage_report["inserted_count"]:
            raise ValueError("mirage_decoys_not_retained_in_ghidra")
        prepared_plan = TrialPlan.model_validate(plan)
        prepare_plan(prepared_plan)  # Fail before publication if evidence/configuration do not bind.
        publish_new_file(root / "plan.json", canonical_json_bytes(prepared_plan.model_dump(mode="json")), 64 * 1024)
        publish_new_file(root / "preparation.json", canonical_json_bytes({"targets": summaries,
            "command": sys_argv(argv), "prepared_at": datetime.now(UTC).isoformat(),
            "host_platform": platform.platform(), "compiler": conditions["compiler"],
            "live_requests": 0, "candidate_execution": False,
            "scoring": "not_configured_placeholder_identities_cannot_be_scored",
            "build_provenance": "operator_declared_not_independently_verified",
            "shield_report_sha256": sha(shield_report_path), "mirage_report_sha256": sha(a.mirage_report)}), 1024 * 1024)
        return 0
    except Exception:
        publish_new_file(root / "preparation-failure.json", canonical_json_bytes({"status": "preparation_failed",
            "live_requests": 0, "candidate_execution": False}), 1024)
        import sys
        print("imagelab_preparation_failed: see_private_report", file=sys.stderr)
        return 1


def sys_argv(argv):
    import sys
    return [sys.executable, *sys.argv] if argv is None else list(argv)


if __name__ == "__main__":
    raise SystemExit(main())
