"""Real static analysis and production archive validation; inference is a test double.

No test sends requests, approves inference or executes reconstruction code.
"""
import json
import os
from pathlib import Path
import subprocess

import pytest

from experiments.adaptive_mvp.controller import ROOT
from experiments.adaptive_mvp.evidence import load_index, resistance_for
from experiments.adaptive_mvp.lab_bridge import import_generation, load_lab, prepare
from experiments.adaptive_mvp.tests.test_native import real_run  # noqa: F401 - shared pytest fixture


@pytest.fixture(scope="module")
def prepared_lab(real_run, tmp_path_factory):
    ghidra = Path(os.environ.get("AEGIS_GHIDRA_HEADLESS", "/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"))
    assert ghidra.is_file(), "NOT RUN: real Ghidra 12.1.4 required; set AEGIS_GHIDRA_HEADLESS"
    output = tmp_path_factory.mktemp("adaptive-lab") / "prepared"
    result = prepare(real_run[0] / "report.json", output, ghidra, "nvidia/Nemotron-3_5-Lightning")
    return result, output


def test_fresh_lab_preparation_deduplicates_real_artifacts_and_cannot_approve(prepared_lab):
    prepared, _ = prepared_lab
    assert len(prepared["targets"]) == 3
    assert prepared["targets"][0]["aliases"] == ["baseline", "c001"]
    assert prepared["targets"][2]["aliases"] == ["c003", "c004"]
    assert prepared["network_requests"] == 0
    assert prepared["candidate_execution"] is False
    assert prepared["approvals_granted"] is False
    assert prepared["proposed_aggregate_cap_microusd"] == 300000
    for target in prepared["targets"]:
        draft = json.loads(Path(target["approval_draft"]).read_bytes())
        assert draft["operator_approved"] is False
        assert draft["provider_retention_reviewed"] is False
        assert draft["disclosure"]["artifact_sha256"] == target["artifact_sha256"]
        assert Path(target["approval_draft"]).stat().st_mode & 0o077 == 0
        assert target["run_argv"][1:4] == ["-m", "aegis_lab.live", "run"]


def test_real_decompilation_is_unchanged_and_does_not_support_resistance(prepared_lab):
    prepared, _ = prepared_lab
    assert len({target["selected_decompilation_sha256"] for target in prepared["targets"]}) == 1
    counts = [target["function_count"] for target in prepared["targets"]]
    assert counts[1] == counts[0] + 3
    assert counts[2] == counts[0] + 1
    assert any("cannot measure decoy" in item for item in prepared["limitations"])


@pytest.fixture
def offline_archive(prepared_lab, tmp_path):
    """Production Lab archive with an explicitly fake provider, never attack evidence."""
    load_lab()
    from aegis_lab.experiment import WorkflowConfig, run_experiment
    from aegis_lab.fake_provider import FakeProvider
    from aegis_lab.manifest import TrialManifest
    from aegis_lab.reconstruction import prepare_reconstruction
    target = prepared_lab[0]["targets"][2]
    raw = json.loads(Path(target["manifest"]).read_bytes())
    raw["attack"]["provider"] = "FakeOffline"
    raw["attack"]["model_id"] = "offline-scripted-v1"
    manifest = TrialManifest.model_validate(raw)
    prepared = prepare_reconstruction(manifest, Path(target["report"]).read_bytes(), max_output_tokens=8192)
    directory = tmp_path / "fake-generation"
    run_experiment(prepared, Path(target["artifact"]), directory, configuration=WorkflowConfig(max_steps=1),
                   provider_factory=lambda sink: FakeProvider(evidence_sink=sink))
    return directory


def test_production_generation_verifier_connects_to_controller_without_execution(offline_archive, tmp_path, monkeypatch):
    def refuse_process(*args, **kwargs):
        raise AssertionError("generation import must not start a subprocess")
    monkeypatch.setattr(subprocess, "Popen", refuse_process)
    output = tmp_path / "import"
    summary = import_generation(offline_archive, output)
    assert summary["resistance"] == "UNMEASURED"
    assert summary["execution_performed"] is False
    assert summary["actual_billed_cost"] == 0
    receipts = load_index(output / "index.json", tmp_path / "archive")
    resistance = resistance_for(summary["artifact_sha256"], receipts)
    assert resistance["status"] == "UNMEASURED"
    assert resistance["evidence"][0]["outcome"] == "unscored"


def test_import_refuses_a_tampered_lab_archive(offline_archive, tmp_path):
    record = offline_archive / "experiment.json"
    raw = json.loads(record.read_bytes())
    raw["artifact_sha256"] = "0" * 64
    record.write_text(json.dumps(raw))
    with pytest.raises((ValueError, OSError)):
        import_generation(offline_archive, tmp_path / "import")


def test_bridge_refuses_generation_artifacts_inside_repository():
    with pytest.raises(ValueError, match="outside_source_tree"):
        import_generation(Path("/tmp/unused"), ROOT / "experiments/adaptive_mvp/refused-import")
