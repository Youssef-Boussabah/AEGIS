"""Real LLVM / Core / production-adapter regression. No fake protection backend.

Requires matching LLVM 22 and an already built plugin. Missing prerequisites
fail explicitly. Set AEGIS_ADAPTIVE_PLUGIN to use a different existing build.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from experiments.adaptive_mvp.controller import ROOT, ExperimentError, elf_function_bytes, sha256_file
from experiments.adaptive_mvp.verify import verify_report


def run_native(output, *options, plugin=None):
    plugin = plugin or os.environ.get("AEGIS_ADAPTIVE_PLUGIN", "/tmp/aegis-shield-build/AegisShield.so")
    assert Path(plugin).is_file(), "NOT RUN: build the real Shield plugin, then set AEGIS_ADAPTIVE_PLUGIN"
    process = subprocess.run([sys.executable, str(ROOT / "experiments/adaptive_mvp/controller.py"),
                              "--output-dir", str(output), "--plugin", str(plugin), *options],
                             cwd=ROOT, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    assert (output / "report.json").is_file(), process.stderr.decode()
    return process, json.loads((output / "report.json").read_bytes())


@pytest.fixture(scope="module")
def real_run(tmp_path_factory):
    output = tmp_path_factory.mktemp("adaptive-real") / "run"
    process, report = run_native(output, "--samples", "5")
    assert process.returncode == 0, process.stderr.decode() + process.stdout.decode()
    return output, report


def test_real_adapters_correctness_feedback_and_retention(real_run):
    output, report = real_run
    assert report["baseline"]["correctness"]["expected_stdout"] == "bf283ea0\n"
    assert report["stop_reason"] == "FEEDBACK_PLAN_COMPLETE"
    assert report["final_verification"]["status"] == "passed"
    assert len(report["candidates"]) == 4
    first, three, one, reduced = report["candidates"]
    assert first["artifact"]["sha256"] == report["baseline"]["artifact"]["sha256"]
    assert first["constraint_rejections"] == ["no_final_transformation_observed"]
    assert "matched the baseline" in three["decision"]["reason"]
    assert [item["retention"]["mirage_retained_count"] for item in report["candidates"]] == [0, 3, 1, 1]
    assert one["artifact"]["size_bytes"] < three["artifact"]["size_bytes"]
    assert reduced["artifact"]["sha256"] == one["artifact"]["sha256"]
    assert report["selection"]["selected_candidate_id"] in ("c003", "c004")
    assert report["selection"]["resistance"] == "UNMEASURED"
    assert report["usage"]["native_runs"] == 50
    for candidate in report["candidates"]:
        assert candidate["status"] == "VERIFIED"
        assert candidate["adapter_claims"]["shield_transformed_sites"] > 0
        assert candidate["correctness"]["status"] == "passed"
        assert candidate["resistance"]["score"] is None
        core_report = json.loads((output / candidate["core_report"]).read_bytes())
        assert core_report["status"] == "succeeded"
    for candidate in (three, one, reduced):
        final = output / candidate["artifact"]["path"]
        nm = subprocess.check_output(["/usr/bin/llvm-nm", "--defined-only", "--just-symbol-name", final]).decode().split()
        for name in candidate["retention"]["mirage_code"]:
            assert name in nm
            disassembly = subprocess.check_output(["/usr/bin/llvm-objdump", "-d", "--disassemble-symbols=" + name, final])
            assert ("<" + name + ">:").encode() in disassembly
            assert len(elf_function_bytes(final, [name])[name]) > 0


def test_real_results_and_inputs_are_reproducible(real_run, tmp_path):
    _, first = real_run
    process, second = run_native(tmp_path / "rerun", "--samples", "1")
    assert process.returncode == 0, process.stderr.decode() + process.stdout.decode()
    assert first["baseline"]["artifact"]["sha256"] == second["baseline"]["artifact"]["sha256"]
    assert [item["artifact"]["sha256"] for item in first["candidates"]] == [
        item["artifact"]["sha256"] for item in second["candidates"]]
    assert first["inputs"]["target"]["sha256"] == second["inputs"]["target"]["sha256"]


def test_captured_inputs_can_reproduce_without_reading_mutable_production_source(real_run, tmp_path):
    original, report = real_run
    script = original / "inputs/repository/experiments/adaptive_mvp/controller.py"
    output = tmp_path / "captured-reproduction"
    process = subprocess.run([sys.executable, script, "--output-dir", output,
                              "--plugin", original / "inputs/AegisShield.so", "--samples", "1"],
                             cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    assert process.returncode == 0, process.stderr.decode() + process.stdout.decode()
    reproduced = json.loads((output / "report.json").read_bytes())
    assert [item["artifact"]["sha256"] for item in reproduced["candidates"]] == [
        item["artifact"]["sha256"] for item in report["candidates"]]


def test_real_verifier_recomputes_every_final_binding(real_run):
    output, report = real_run
    result = verify_report(output / "report.json", sha256_file(output / "report.json"))
    assert result["status"] == "passed"
    assert result["candidate_count"] == 4
    assert result["artifact_hashes_checked"] > 100


@pytest.mark.parametrize("tamper", ["hash", "decision", "lineage", "performance", "selection", "resistance", "retention", "options"])
def test_real_verifier_detects_record_tampering(real_run, tamper):
    output, report = real_run
    altered = json.loads(json.dumps(report))
    if tamper == "hash":
        altered["candidates"][0]["artifact"]["sha256"] = "0" * 64
    elif tamper == "decision":
        altered["candidates"][1]["decision"]["reason"] = "invented history"
    elif tamper == "lineage":
        altered["candidates"][1]["parent_candidate_id"] = "baseline"
    elif tamper == "performance":
        altered["candidates"][1]["performance"]["median_ratio"] = 0.001
    elif tamper == "selection":
        altered["selection"]["selected_candidate_id"] = "c001"
    elif tamper == "resistance":
        altered["candidates"][1]["resistance"]["status"] = "PROVEN_RESISTANCE"
    elif tamper == "retention":
        altered["candidates"][1]["retention"]["mirage_retained_count"] = 32
    elif tamper == "options":
        altered["candidates"][1]["options"]["seed"] = "1"
    path = output / f"tampered-{tamper}.json"
    path.write_text(json.dumps(altered))
    with pytest.raises(ExperimentError):
        verify_report(path)


def test_real_budget_exhaustion_preserves_completed_candidate(tmp_path):
    process, report = run_native(tmp_path / "budget", "--samples", "1", "--max-native-runs", "9")
    assert process.returncode == 0  # A verified earlier artifact remains selectable.
    assert report["stop_reason"] == "NATIVE_RUN_BUDGET_EXHAUSTED"
    assert report["usage"]["native_runs"] == 9
    assert report["selection"]["selected_candidate_id"] == "c002"
    assert report["candidates"][2]["status"] == "FAILED"
    assert report["candidates"][2]["build_status"] == "succeeded"
    assert report["candidates"][2]["phase"] == "measurement"
    assert report["final_verification"]["status"] == "passed"


def test_real_invalid_plugin_surfaces_production_adapter_errors(tmp_path):
    invalid_plugin = tmp_path / "invalid-plugin.so"
    invalid_plugin.write_bytes(b"invalid plugin bytes: not executable code")
    process, report = run_native(tmp_path / "failure", "--samples", "1", plugin=invalid_plugin)
    assert process.returncode == 2
    assert report["selection"]["selected_candidate_id"] is None
    assert report["baseline"]["status"] == "VERIFIED"
    assert len(report["candidates"]) == 2
    for candidate in report["candidates"]:
        assert candidate["status"] == "FAILED"
        assert candidate["adapter_status"] == "failed"
        assert candidate["error"]["code"] == "ADAPTER_FAILED"
        assert candidate["error"]["details"]["adapter_error"]["code"] == "LLVM_FAILED"


def test_requiring_attack_evidence_does_not_accept_static_metrics(tmp_path):
    process, report = run_native(tmp_path / "unmeasured", "--samples", "1", "--require-attack-evidence")
    assert process.returncode == 2
    assert report["selection"]["selected_candidate_id"] is None
    assert all(item["resistance"]["status"] == "UNMEASURED" for item in report["candidates"])
    assert all("attack_evidence_required_but_unmeasured" in item["constraint_rejections"]
               for item in report["candidates"])
