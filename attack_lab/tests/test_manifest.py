"""No external tools, requests, models, keys or generated code are executed."""

from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from aegis_lab.manifest import ManifestPairError, TrialManifest, TrialVariant, validate_pair


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def manifest_data(*, protected: bool = False) -> dict:
    return {
        "trial_id": "2" * 32 if protected else "1" * 32,
        "pair_id": "9" * 32,
        "variant": "protected" if protected else "baseline",
        "target": {
            "name": "controlled-module",
            "function": "sample_transform",
            "source_revision": "a5efcd6",
            "platform": "linux-x86_64",
            "artifact_format": "ELF",
            "final_artifact_sha256": digest("compiled protected" if protected else "compiled original"),
            "matched_build_profile": "clang22-release-matched",
            "build_recipe_sha256": digest("protected build recipe" if protected else "baseline build recipe"),
            "transformation_report_sha256": digest("report") if protected else None,
        },
        "attack": {
            "workflow": "ghidra_model",
            "tools": [{"name": "Ghidra", "version": "local-version-pinned"}],
            "provider": "Nebius",
            "model_id": "model-identity-pinned-at-run",
            "prompt_sha256": digest("same prompt"),
            "sampling_seed": 42,
        },
        "access": {"network_enabled": False},
        "budget": {"max_wall_seconds": 240, "max_model_tokens": 4000, "max_tool_calls": 20},
        "scoring": {"hidden_test_suite_sha256": digest("hidden-suite-id"), "expected_interface": "sample_transform(uint32,uint32)->uint32"},
        "authorization": {"reference": "AUTHORIZED-LOCAL-001", "authorized_scope": "owned local fixtures"},
    }


def test_valid_manifest_pair_roundtrip():
    baseline = TrialManifest.model_validate(manifest_data())
    protected = TrialManifest.model_validate(manifest_data(protected=True))
    assert validate_pair(protected, baseline) == (baseline, protected)
    assert TrialManifest.model_validate_json(baseline.model_dump_json()) == baseline
    assert baseline.variant == TrialVariant.BASELINE
    assert len(baseline.sha256()) == 64


def test_canonical_hash_is_independent_of_input_key_order():
    data = manifest_data()
    reversed_top_level = dict(reversed(list(data.items())))
    assert TrialManifest.model_validate(data).sha256() == TrialManifest.model_validate(reversed_top_level).sha256()
    assert json.loads(TrialManifest.model_validate(data).canonical_bytes())["schema_version"] == "aegis.lab.trial.v1"


@pytest.mark.parametrize("field", ["attack", "access", "budget", "scoring", "authorization"])
def test_pair_rejects_different_conditions(field):
    a = TrialManifest.model_validate(manifest_data())
    data = manifest_data(protected=True)
    value = data[field]
    if field == "attack":
        value["prompt_sha256"] = digest("different")
    elif field == "access":
        value["access_to_symbols"] = True
    elif field == "budget":
        value["max_model_tokens"] = 20
    elif field == "scoring":
        value["hidden_test_suite_sha256"] = digest("different tests")
    else:
        value["reference"] = "DIFFERENT-AUTH"
    with pytest.raises(ManifestPairError) as exc:
        validate_pair(a, TrialManifest.model_validate(data))
    assert field in exc.value.fields


@pytest.mark.parametrize("target_field", ["name", "function", "source_revision", "platform", "artifact_format", "matched_build_profile"])
def test_pair_rejects_different_targets(target_field):
    a = TrialManifest.model_validate(manifest_data())
    data = manifest_data(protected=True)
    data["target"][target_field] = "wrong"
    with pytest.raises(ManifestPairError) as exc:
        validate_pair(a, TrialManifest.model_validate(data))
    assert "target." + target_field in exc.value.fields


def test_pair_rejects_same_artifact_hash():
    data = manifest_data(protected=True)
    data["target"]["final_artifact_sha256"] = manifest_data()["target"]["final_artifact_sha256"]
    with pytest.raises(ManifestPairError) as exc:
        validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))
    assert "target.final_artifact_sha256" in exc.value.fields


def test_pair_rejects_duplicate_trial_ids():
    data = manifest_data(protected=True)
    data["trial_id"] = manifest_data()["trial_id"]
    with pytest.raises(ManifestPairError, match="trial_id"):
        validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))


def test_pair_rejects_two_baselines():
    data = manifest_data()
    data["trial_id"] = "2" * 32
    with pytest.raises(ManifestPairError, match="variant"):
        validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))


def test_pair_rejects_different_pair_id():
    data = manifest_data(protected=True)
    data["pair_id"] = "8" * 32
    with pytest.raises(ManifestPairError, match="pair_id"):
        validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version="unknown"),
    lambda d: d.update(api_key="secret"),
    lambda d: d["attack"].update(token="should-not-be-stored"),
    lambda d: d["attack"].update(workflow="magic"),
    lambda d: d["target"].update(final_artifact_sha256="not-a-hash"),
    lambda d: d["budget"].update(max_wall_seconds=0),
    lambda d: d["budget"].update(max_tool_calls=1.5),
    lambda d: d["budget"].update(max_model_tokens="100"),
    lambda d: d["access"].update(oracle_query_limit=3),
    lambda d: d["scoring"].update(score_rule="unverified-score"),
])
def test_manifest_rejects_invalid_or_secret_fields(mutate):
    data = manifest_data()
    mutate(data)
    with pytest.raises(ValidationError):
        TrialManifest.model_validate(data)


def test_rea_workflow_is_supported_without_ghidra_dependency():
    data = manifest_data()
    data["attack"].update(workflow="rea",tools=[{"name":"REA","version":"pin-at-run"}],provider="coding-agent")
    assert TrialManifest.model_validate(data).attack.workflow == "rea"


def test_baseline_cannot_claim_protection_report():
    data = manifest_data()
    data["target"]["transformation_report_sha256"] = digest("unjustified")
    with pytest.raises(ValidationError):
        TrialManifest.model_validate(data)


def test_runtime_oracle_policy_requires_explicit_enablement():
    data = manifest_data()
    data["access"].update(runtime_oracle_enabled=True,oracle_query_limit=8)
    assert TrialManifest.model_validate(data).access.oracle_query_limit == 8


def test_paired_trials_allow_different_build_recipes():
    a = TrialManifest.model_validate(manifest_data())
    b = TrialManifest.model_validate(manifest_data(protected=True))
    assert a.target.build_recipe_sha256 != b.target.build_recipe_sha256
    assert validate_pair(a,b) == (a,b)


def test_validation_cli_accepts_comparable_pair(tmp_path, capsys):
    from aegis_lab.__main__ import main
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(manifest_data()), encoding="utf-8")
    b.write_text(json.dumps(manifest_data(protected=True)), encoding="utf-8")
    assert main(["validate-pair", str(a), str(b)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["validation"] == "comparable_configuration_only"
    assert output["attacks_executed"] is False


def test_validation_cli_rejects_budget_mismatch(tmp_path, capsys):
    from aegis_lab.__main__ import main
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(manifest_data()), encoding="utf-8")
    changed = manifest_data(protected=True)
    changed["budget"]["max_model_tokens"] += 1
    b.write_text(json.dumps(changed), encoding="utf-8")
    assert main(["validate-pair", str(a), str(b)]) == 2
    assert "budget" in capsys.readouterr().err


def test_validation_cli_rejects_missing_file(tmp_path, capsys):
    from aegis_lab.__main__ import main
    assert main(["validate-pair", str(tmp_path / "missing"), str(tmp_path / "absent")]) == 2
    assert "invalid trial pair" in capsys.readouterr().err
