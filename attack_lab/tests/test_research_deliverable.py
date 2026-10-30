"""Post-hoc public evidence and unapproved continuation preparation, entirely offline."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError
from test_live_inference import triple
from test_nebius_reasoning import archive, tree_digest

from aegis_lab.canonical import canonical_json_bytes
from aegis_lab.completion_review import verify_review, write_review
from aegis_lab.experiment import verify_experiment
from aegis_lab.inference import load_approval
from aegis_lab.manifest import load_manifest, validate_pair
from aegis_lab.private_evidence import PrivateEvidence
from aegis_lab.public_summary import ReconstructionEvidence, ComparisonEvidence, export_experiment
from aegis_lab.reconstruction import prepare_reconstruction
from aegis_lab.remaining_inference import prepare_remaining


@pytest.fixture
def inputs(triple, tmp_path):
    target = triple.baseline
    prepared = prepare_reconstruction(load_manifest(target.manifest), target.report.read_bytes())
    root = archive((prepared, target.artifact, load_approval(target.approval)), tmp_path, unversioned=True)
    report = tmp_path / "post-hoc.json"
    write_review(root, report)
    plan = triple.model_copy(update={name: getattr(triple, name).model_copy(update={"approval": None})
                                    for name in ("baseline", "shield", "mirage")})
    plan_root = tmp_path / "prepared-plan"
    plan_root.mkdir(mode=0o700)
    path = plan_root / "original-plan.json"
    path.write_bytes(canonical_json_bytes(plan.model_dump(mode="json")))
    return root, report, path, plan


def test_post_hoc_verification_recomputes_every_field(inputs):
    root, path, _, _ = inputs
    report, digest = verify_review(root, path)
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert report.historical_experiment_sha256 == hashlib.sha256((root / "experiment.json").read_bytes()).hexdigest()
    assert report.post_hoc_status == "candidate_text_revalidated_but_behaviorally_unscored"


@pytest.mark.parametrize("field,value", [
    ("historical_experiment_sha256", "0" * 64), ("response_sha256", "0" * 64),
    ("candidate_sha256", "0" * 64), ("post_hoc_status", "rejected"),
    ("candidate_envelope_valid", False), ("requested_model", "nvidia/other-model"),
    ("limitations", ["changed prose"]), ("execution_performed", 0),
    ("prompt", "PRIVATE_TEST_SENTINEL"),
])
def test_changed_or_private_sidecar_fields_are_rejected(inputs, field, value):
    root, path, _, _ = inputs
    data = json.loads(path.read_bytes())
    data[field] = value
    path.write_bytes(canonical_json_bytes(data))
    with pytest.raises(ValueError):
        verify_review(root, path)


def test_verified_public_projection_preserves_both_states_and_cost(inputs):
    root, path, _, _ = inputs
    before = tree_digest(root)
    record = verify_experiment(root)
    evidence = export_experiment(root, post_hoc_report=path)
    summary, review = evidence.summary, evidence.summary.post_hoc_review
    assert summary.generation_status == "invalid_output" and summary.candidate_sha256 is None
    assert summary.completion_parser == "aegis.lab.completion-parser.v1"
    assert review.candidate_sha256 and review.candidate_envelope_valid
    assert review.revalidation_completion_parser == "aegis.lab.nebius-reasoning-text.v2"
    assert review.historical_experiment_sha256 == evidence.source_sha256
    assert summary.estimated_reported_cost_microusd == record.estimated_reported_cost_microusd
    assert summary.cost_microusd is None and summary.reported_tokens == 9825
    assert tree_digest(root) == before
    encoded = evidence.model_dump_json(by_alias=True)
    for private in (str(root), "Synthetic placeholder", "fixture_add", "request-review", "messages", "provider_retention_policy"):
        assert private not in encoded


@pytest.mark.parametrize("mutation", [
    lambda d: d["summary"].update(candidate_sha256="1" * 64),
    lambda d: d["summary"].update(completion_parser="aegis.lab.nebius-reasoning-text.v2"),
    lambda d: d["summary"].update(generation_status="generated_but_behaviorally_unscored"),
    lambda d: d.update(source_sha256="0" * 64),
    lambda d: d["summary"]["post_hoc_review"].update(candidate_sha256=None),
    lambda d: d["summary"]["post_hoc_review"].update(candidate_envelope_valid=False),
    lambda d: d["summary"]["post_hoc_review"].update(generated_source="PRIVATE_TEST_SENTINEL"),
])
def test_public_projection_rejects_conflated_or_private_claims(inputs, mutation):
    root, report, _, _ = inputs
    data = export_experiment(root, post_hoc_report=report).model_dump(mode="json", by_alias=True)
    mutation(data)
    with pytest.raises(ValidationError):
        ReconstructionEvidence.model_validate(data)


def test_synthetic_fixture_is_valid_and_comparison_row_source_is_bound():
    fixtures = Path(__file__).parent / "fixtures" / "public-summary"
    sample = ReconstructionEvidence.model_validate_json((fixtures / "synthetic-post-hoc.json").read_bytes())
    assert sample.summary.evidence_label == "synthetic_fixture"
    comparison = json.loads((fixtures / "synthetic-comparison.json").read_bytes())
    row = comparison["summary"]["experiments"][0]
    row.update(source_sha256=sample.source_sha256, generation_status="invalid_output", summary=sample.summary.model_dump(mode="json"))
    # Preserve other comparison rows but deliberately break this review's source.
    row["source_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="comparison_post_hoc_source_mismatch"):
        ComparisonEvidence.model_validate(comparison)


def test_remaining_preparation_is_offline_and_preserves_original_evidence(inputs, tmp_path, monkeypatch):
    from aegis_lab.bounded_provider import BoundedNebiusProvider

    root, _, plan_path, plan = inputs
    before, plan_before = tree_digest(root), plan_path.read_bytes()
    monkeypatch.setattr(BoundedNebiusProvider, "from_environment", lambda *a, **kw: pytest.fail("provider touched"))
    output = tmp_path / "remaining"
    result = prepare_remaining(root, plan_path, output)
    assert result["request_conditions_comparable"] and not result["historical_outcomes_directly_comparable"]
    assert result["max_output_tokens"] == 8192 and result["network_requests"] == 0
    assert not result["approvals_granted"]
    record = verify_experiment(root)
    store = PrivateEvidence(root / "private-evidence", create=False)
    original_approval = json.loads(store.get(record.inference_approval_sha256))
    # The archived baseline uses the changed output cap, so read that declaration.
    from aegis_lab.manifest import TrialManifest
    baseline = TrialManifest.model_validate_json(store.get(record.manifest_sha256))
    commands = json.loads((output / "operator-commands.json").read_bytes())
    assert set(commands) == {"shield", "mirage"}
    for name in ("shield", "mirage"):
        manifest = load_manifest(output / name / "manifest.json")
        assert not validate_pair(baseline, manifest).final_artifacts_identical
        draft = json.loads((output / name / "approval.DRAFT.json").read_bytes())
        assert draft["operator_approved"] is draft["provider_retention_reviewed"] is False
        for key in ("max_requests", "max_total_tokens", "max_spend_microusd", "context_tokens",
                    "input_microusd_per_million", "output_microusd_per_million", "request_timeout_seconds"):
            assert draft[key] == original_approval[key]
        assert not (output / name / "approval.json").exists()
        assert not (output / name / ".inference-uses").exists()
        assert commands[name]["run_argv"][-1] == "--approve-live-inference"
        assert (output / name / "approval.DRAFT.json.request-review.json").stat().st_mode & 0o077 == 0
    assert tree_digest(root) == before and plan_path.read_bytes() == plan_before


@pytest.mark.parametrize("change", ["workflow", "artifact", "compiler", "approval"])
def test_incomparable_continuations_fail_before_output(inputs, tmp_path, change):
    root, _, path, plan = inputs
    data = json.loads(path.read_bytes())
    if change == "workflow":
        data["configuration"]["tools"] = []
    elif change == "artifact":
        plan.shield.artifact.write_bytes(b"tampered owned fixture")
    elif change == "compiler":
        manifest = json.loads(plan.shield.manifest.read_bytes())
        manifest["target"]["build"]["compiler"]["version"] = "different-version"
        plan.shield.manifest.write_bytes(canonical_json_bytes(manifest))
    else:
        data["shield"]["approval"] = str(tmp_path / "unused-approval.json")
    path.write_bytes(canonical_json_bytes(data))
    output = tmp_path / "must-not-exist"
    with pytest.raises(ValueError):
        prepare_remaining(root, path, output)
    assert not output.exists()


def test_remaining_preparation_refuses_writes_inside_baseline(inputs):
    root, _, path, _ = inputs
    before = tree_digest(root)
    with pytest.raises(ValueError, match="original_evidence_is_read_only"):
        prepare_remaining(root, path, root / "must-not-exist")
    assert tree_digest(root) == before


def test_exporter_cli_binds_post_hoc_and_refuses_writing_inside_archive(inputs, tmp_path):
    root, report, _, _ = inputs
    exporter = Path(__file__).resolve().parents[2] / "scripts" / "export-product-evidence.py"
    output = tmp_path / "public.json"
    common = [sys.executable, str(exporter), "reconstruction", str(root), "--post-hoc-report", str(report), "--output"]
    result = subprocess.run([*common, str(output)], capture_output=True, check=False, timeout=20)
    assert result.returncode == 0
    data = output.read_bytes()
    assert hashlib.sha256(data).hexdigest().encode() in result.stdout
    assert json.loads(data)["summary"]["generation_status"] == "invalid_output"
    assert output.stat().st_mode & 0o077 == 0
    before = tree_digest(root)
    refused = subprocess.run([*common, str(root / "must-not-exist.json")], capture_output=True, check=False, timeout=20)
    assert refused.returncode == 1 and tree_digest(root) == before
    assert b"fixture_add" not in refused.stderr and b"Synthetic placeholder" not in refused.stderr
