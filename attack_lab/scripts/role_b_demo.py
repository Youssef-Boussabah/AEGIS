"""Reproducible owned-fixture demo. Executes only the checked-in trusted fixture.

Fake-provider candidates are stored as text and are NEVER compiled or executed.
All generated reports/artifacts remain in a new private directory outside Git.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path

from aegis_lab.canonical import canonical_json_bytes
from aegis_lab.evidence import planned_ghidra_tool, parse_ghidra_report
from aegis_lab.experiment import WorkflowConfig, run_controlled_pair, verify_experiment
from aegis_lab.fake_provider import FakeProvider
from aegis_lab.ghidra import analyze
from aegis_lab.manifest import TrialManifest
from aegis_lab.paired_trial import prepare_pair, run_paired_trial
from aegis_lab.provider import InferenceRequest
from aegis_lab.reconstruction import planned_attack_digests
from aegis_lab.safe_io import publish_new_file
from aegis_mirage import MirageConfig, transform
from aegis_mirage.transform import digest, run

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "protectors/mirage/tests/fixtures/signal.c"
SOURCE = "#include <stdint.h>\nuint32_t target_function(uint32_t a,uint32_t b,uint32_t c){return 0;}\n"
INTERFACE = "opaque(uint32_t,uint32_t,uint32_t)->uint32_t"


def write_json(path, value):
    publish_new_file(path, canonical_json_bytes(value), 16 * 1024 * 1024)


def tool_identity(name, sha, config):
    return dict(name=name, version="1", executable_sha256=sha,
                configuration_sha256=digest(canonical_json_bytes(config)))


def manifest(*, trial, pair, variant, artifact, protection, ghidra, compiler_sha, source_sha):
    budget = dict(max_wall_seconds=240, max_model_tokens=200000, max_tool_calls=8, max_attempts=4)
    return TrialManifest.model_validate(dict(
        trial_id=trial, pair_id=pair, variant=variant,
        target=dict(name="owned-signal-fixture", function="signal_mix", source_revision=source_sha,
                    platform="linux-x86_64", artifact_format="ELF", final_artifact_sha256=digest(artifact.read_bytes()),
                    build=dict(pipeline="clang22-ir-o2-elf-gc", compiler=tool_identity("clang", compiler_sha, {"frontend": "O1", "backend": "O2"}),
                               shared_recipe_sha256=digest(b"O1 emit-llvm; optional transform; O2; link gc"), symbols="present", debug_info=False),
                    protection=protection),
        attack=dict(workflow="ghidra_model", tools=[ghidra.model_dump(mode="json")], provider="FakeOffline", model_id="offline-scripted-v1",
                    sampling_seed=42, temperature=0.0, session_isolation="fresh_session_and_workspace",
                    **planned_attack_digests(max_model_tokens=budget["max_model_tokens"], blinded=True)),
        access=dict(workspace_policy_sha256=digest(b"bound decompilation only; no original source; no expected outputs")),
        budget=budget,
        scoring=dict(hidden_test_suite_sha256=digest(b"no hidden suite supplied: scoring pending; no execution"),
                     scorer=tool_identity("pending-core-runtime", digest(b"unavailable"), {"implemented": False}), expected_interface=INTERFACE),
        authorization=dict(reference="operator-authorized-aegis-owned-fixture", authorized_scope="local static analysis and offline scripted reconstruction of checked-in fixture"),
    ))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--ghidra-headless", required=True, type=Path)
    parser.add_argument("--shield-plugin", required=True, type=Path)
    parser.add_argument("--authorized-owned-fixture", action="store_true", required=True)
    parser.add_argument("--samples", type=int, default=9)
    args = parser.parse_args(argv)
    if not 3 <= args.samples <= 100:
        parser.error("samples must be in [3,100]")
    root = args.output_dir.resolve()
    root.mkdir(mode=0o700)
    commands = []

    def execute(argv):
        commands.append(argv)
        return run(argv, root, timeout=120)

    execute(["/usr/bin/clang", "-O1", "-S", "-emit-llvm", str(FIXTURE), "-o", "baseline.ll"])
    plugin = args.shield_plugin.resolve()
    execute(["/usr/bin/opt", "-load-pass-plugin", str(plugin),
             "-passes=aegis-shield<seed=42;max-sites=16;report=shield-report.json>,verify", "-S", "baseline.ll", "-o", "shield.ll"])
    shield_report = json.loads((root / "shield-report.json").read_bytes())
    # A successful opt invocation alone is insufficient: require actual insertions.
    if shield_report.get("totals", {}).get("transformed_sites", shield_report.get("transformed_sites", 0)) < 1:
        raise ValueError("shield_report_has_no_transformations")
    mirage = transform(root / "shield.ll", root / "mirage", MirageConfig(seed=42))
    control = transform(root / "shield.ll", root / "no-decoy", MirageConfig(seed=42, enabled=False))
    inputs = {"baseline": root / "baseline.ll", "shield": root / "shield.ll", "mirage": root / "mirage/module.ll"}
    observations, reports, artifacts = {}, {}, {}
    ghidra = planned_ghidra_tool(args.ghidra_headless, function="*")
    for name, ir in inputs.items():
        execute(["/usr/bin/opt", "-passes=default<O2>,verify", "-S", str(ir), "-o", name + ".optimized.ll"])
        execute(["/usr/bin/clang", "-O2", "-ffunction-sections", "-fdata-sections", name + ".optimized.ll",
                 "-Wl,--gc-sections", "-o", name + ".elf"])
        binary = artifacts[name] = root / (name + ".elf")
        outputs, durations = [], []
        execute([str(binary)])  # warmup, trusted fixture only
        for _ in range(args.samples):
            start = time.perf_counter_ns()
            outputs.append(execute([str(binary)]).decode().strip())
            durations.append(time.perf_counter_ns() - start)
        symbols = execute(["/usr/bin/llvm-nm", "--defined-only", str(binary)]).decode()
        retained = [fn for fn in mirage["inserted_functions"] if fn in symbols]
        reports[name] = analyze(binary, root / (name + "-analysis"), args.ghidra_headless, function="*",
                                 expected_sha256=digest(binary.read_bytes())).read_bytes()
        analysis = parse_ghidra_report(reports[name])
        observations[name] = dict(sha256=digest(binary.read_bytes()), size_bytes=binary.stat().st_size,
            outputs=outputs, process_wall_ns=durations, median_process_wall_ns=statistics.median(durations),
            retained_decoys=retained, ghidra_functions=[fn.name for fn in analysis.analysis.functions],
            ghidra_decoys=[fn.name for fn in analysis.analysis.functions if fn.name in mirage["inserted_functions"]])
    if len({o for x in observations.values() for o in x["outputs"]}) != 1:
        raise ValueError("trusted_fixture_correctness_mismatch")
    if len(observations["mirage"]["retained_decoys"]) != mirage["inserted_count"]:
        raise ValueError("final_artifact_decoy_retention_failed")
    source_sha = digest(FIXTURE.read_bytes())
    shield_sha = digest(plugin.read_bytes())
    shield_step = dict(backend=tool_identity("llvm-shield", shield_sha, {"seed": 42, "max_sites": 16}), seed=42,
                       transformation_report_sha256=digest((root / "shield-report.json").read_bytes()))
    mirage_step = dict(backend=tool_identity("mirage", digest((REPO / "protectors/mirage/src/aegis_mirage/transform.py").read_bytes()), {"seed": 42, "count": 3}),
                       seed=42, transformation_report_sha256=digest((root / "mirage/report.json").read_bytes()))
    pair_reports = []
    for index, (left, right, step) in enumerate((("baseline", "shield", shield_step), ("shield", "mirage", mirage_step)), 1):
        pair_id = f"{index:032x}"
        manifests = {}
        for variant, name, pstep in (("baseline", left, None), ("protected", right, step)):
            manifests[variant] = manifest(trial=f"{index * 10 + (variant == 'protected'):032x}", pair=pair_id, variant=variant,
                artifact=artifacts[name], protection=pstep, ghidra=ghidra, compiler_sha=mirage["toolchain"]["clang"]["sha256"], source_sha=source_sha)
        pair_root = root / (left + "-vs-" + right)
        pair_root.mkdir(mode=0o700)
        for variant, m in manifests.items():
            write_json(pair_root / (variant + "-manifest.json"), m.model_dump(mode="json"))
        pair_evidence = {"baseline": reports[left], "protected": reports[right]}
        pair_artifacts = {"baseline": artifacts[left], "protected": artifacts[right]}
        def factory(sink):
            class DemoProvider(FakeProvider):
                def _body(self, request):
                    self._content = (json.dumps({"action": "revise_candidate", "source": SOURCE,
                                     "analysis": "Scripted offline revision, no model inference."})
                                     if len(self.requests) == 1 else '{"action":"finish"}')
                    return super()._body(request)
            return DemoProvider(evidence_sink=sink)
        # The one-shot runner produces the Phase 4-compatible candidate record too.
        original = run_paired_trial(prepare_pair(manifests["baseline"], manifests["protected"], pair_evidence["baseline"], pair_evidence["protected"]),
                                     pair_root / "one-shot", order_seed=42, provider_factory=lambda: FakeProvider(source=SOURCE))
        controlled = run_controlled_pair(manifests, pair_evidence, pair_artifacts, pair_root / "controlled", order_seed=42,
                                          configuration=WorkflowConfig(max_steps=2), provider_factory=factory)
        for variant in ("baseline", "protected"):
            verify_experiment(pair_root / "controlled" / variant)
        if original.exit_code != 0 or any(state != "generated_but_behaviorally_unscored" for state in controlled.generation_outcomes):
            raise ValueError("offline_reconstruction_demo_incomplete")
        pair_reports.append(dict(left=left, right=right, one_shot_record_sha256=original.record.sha256(),
                                 controlled=controlled.model_dump(mode="json")))
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), "unknown")
    report = dict(schema_version="aegis.lab.mirage-analysis-comparison.v1", measured_at=datetime.now(UTC).isoformat(),
        fixture_sha256=source_sha, hardware=dict(cpu=cpu, platform=platform.platform()), samples=args.samples,
        inputs_per_process=1_000_000, toolchain=mirage["toolchain"], shield_plugin_sha256=shield_sha,
        commands=commands, observations=observations, pairs=pair_reports,
        no_decoy_control=dict(input_sha256=control["input_sha256"], output_sha256=control["output_sha256"],
                              byte_identical=control["input_sha256"] == control["output_sha256"]),
        mirage_overhead=dict(size_bytes=observations["mirage"]["size_bytes"] - observations["shield"]["size_bytes"],
            median_process_wall_ratio=observations["mirage"]["median_process_wall_ns"] / observations["shield"]["median_process_wall_ns"]),
        shield_final_identical_to_baseline=observations["baseline"]["sha256"] == observations["shield"]["sha256"],
        behavioral_scoring="pending_authorized_core_runtime", ai_target_selection="not_measured_fake_provider",
        protection_effect="not_established", limitations=[
            "Correctness: one million deterministic inputs via one output digest, not a universal proof.",
            "Process wall times include startup and host scheduling; these samples do not establish a performance benefit.",
            "Static retention and decompiler visibility are not evidence of attack resistance.",
            "Shield insertions may be optimized away: compare final artifact digests; changed input IR is insufficient.",
            "No live inference; candidates are deliberately scripted placeholders and never compiled or run.",
            "Second pair uses Shield as its baseline; this isolates the added Mirage step, not an unprotected baseline.",
            "Hidden suite and scorer digests are declared pending placeholders, not behavioral evidence.",
            "The reconstruction objective is fixed; decoy inventory is measured statically but is not disclosed in target-only model prompts.",
        ])
    write_json(root / "analysis-comparison.json", report)
    print(json.dumps(dict(output_dir=str(root), retained_decoys=len(observations["mirage"]["retained_decoys"]),
                          size_overhead_bytes=report["mirage_overhead"]["size_bytes"], behavioral_scoring=report["behavioral_scoring"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
