"""No external tools, requests, models, keys or generated code are executed."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest
from pydantic import ValidationError

from aegis_lab.canonical import canonical_json_bytes
from aegis_lab.manifest import (
    MANIFEST_ERROR_TYPES,
    ManifestPairError,
    PairValidation,
    TrialManifest,
    TrialVariant,
    parse_manifest,
    validate_pair,
)
from aegis_lab.safe_io import LoadError

SECRET = "AEGIS-SYNTHETIC-SECRET-7f3a9c"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def tool(name: str, version: str) -> dict:
    return {
        "name": name,
        "version": version,
        "executable_sha256": digest(f"{name} executable"),
        "configuration_sha256": digest(f"{name} configuration"),
    }


def manifest_data(*, protected: bool = False) -> dict:
    return {
        "schema_version": "aegis.lab.trial.v2",
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
            "build": {
                "pipeline": "clang22-ir-matched",
                "compiler": tool("clang", "22.1.8"),
                "shared_recipe_sha256": digest("shared build recipe"),
                "symbols": "stripped",
                "debug_info": False,
            },
            "protection": {
                "backend": tool("aegis-shield", "0.1.0"),
                "seed": 7,
                "transformation_report_sha256": digest("report"),
            } if protected else None,
        },
        "attack": {
            "workflow": "ghidra_model",
            "workflow_configuration_sha256": digest("workflow"),
            "tools": [tool("Ghidra", "12.1.4")],
            "provider": "Nebius",
            "model_id": "model-identity-pinned-at-run",
            "prompt_sha256": digest("same prompt"),
            "sampling_configuration_sha256": digest("sampling"),
            "sampling_seed": 42,
            "session_isolation": "fresh_session_and_workspace",
        },
        "access": {"workspace_policy_sha256": digest("workspace policy"), "network_enabled": False},
        "budget": {"max_wall_seconds": 240, "max_model_tokens": 4000, "max_tool_calls": 20},
        "scoring": {
            "hidden_test_suite_sha256": digest("hidden-suite-archive"),
            "scorer": tool("aegis-scorer", "0.0.1"),
            "expected_interface": "sample_transform(uint32,uint32)->uint32",
        },
        "authorization": {"reference": "AUTHORIZED-LOCAL-001", "authorized_scope": "owned local fixtures"},
    }


def pair() -> tuple[TrialManifest, TrialManifest]:
    return TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(manifest_data(protected=True))


def set_path(data: dict, path: str, value: object) -> None:
    *parents, last = path.split(".")
    for part in parents:
        data = data[int(part)] if part.isdigit() else data[part]
    data[int(last) if last.isdigit() else last] = value


def error_types(exc: ValidationError) -> set[str]:
    return {error["type"] for error in exc.errors()}


# --- Valid records, pairing and fingerprints ------------------------------------------------------

def test_valid_manifest_pair_roundtrip():
    baseline, protected = pair()
    result = validate_pair(protected, baseline)
    assert isinstance(result, PairValidation)
    assert (result.baseline, result.protected) == (baseline, protected)
    assert result.final_artifacts_identical is False
    assert TrialManifest.model_validate_json(baseline.model_dump_json()) == baseline
    assert baseline.variant == TrialVariant.BASELINE
    assert len(baseline.sha256()) == 64


def test_canonical_hash_is_independent_of_input_key_order():
    data = manifest_data()
    reversed_top_level = dict(reversed(list(data.items())))
    reversed_top_level["attack"] = dict(reversed(list(data["attack"].items())))
    assert TrialManifest.model_validate(data).sha256() == TrialManifest.model_validate(reversed_top_level).sha256()
    assert json.loads(TrialManifest.model_validate(data).canonical_bytes())["schema_version"] == "aegis.lab.trial.v2"


def test_canonical_hash_includes_defaults_whether_explicit_or_omitted():
    explicit = manifest_data()
    explicit["access"].update(access_to_symbols=False, oracle_query_limit=0, oracle_configuration_sha256=None)
    explicit["attack"]["temperature"] = 0.0
    assert TrialManifest.model_validate(explicit).sha256() == TrialManifest.model_validate(manifest_data()).sha256()


# A fixed regression vector: if this changes, the canonical form or the v2 schema changed and
# every recorded fingerprint is invalidated. Do not update it without a schema version bump.
BASELINE_V2_SHA256 = "2750c921a5547d496674c0bc644c9aff1f14244a735b6d5515a93f9ae432b3d0"


def test_fixed_manifest_fingerprint_vector():
    manifest = TrialManifest.model_validate(manifest_data())
    assert hashlib.sha256(manifest.canonical_bytes()).hexdigest() == manifest.sha256()
    assert manifest.sha256() == BASELINE_V2_SHA256


def test_negative_zero_and_integer_temperature_have_one_fingerprint():
    values = []
    for raw in ("0.0", "-0.0", "0", "-0", "0e0", "-0E+00"):
        text = json.dumps(manifest_data()).replace('"sampling_seed": 42', f'"sampling_seed": 42, "temperature": {raw}')
        manifest = parse_manifest(text.encode())
        values.append((manifest.canonical_bytes(), manifest.sha256()))
    assert len(set(values)) == 1
    assert b'"temperature":0.0' in values[0][0]
    assert TrialManifest.model_validate(manifest_data()).sha256() == values[0][1]


def test_negative_zero_pair_is_consistent_with_equality():
    a, b = pair()
    data = manifest_data(protected=True)
    data["attack"]["temperature"] = -0.0
    negative = TrialManifest.model_validate(data)
    assert negative.attack == a.attack
    assert validate_pair(a, negative).protected.attack == validate_pair(a, b).protected.attack
    assert negative.sha256() == b.sha256()


def test_distinct_temperatures_have_distinct_fingerprints():
    data = manifest_data()
    data["attack"]["temperature"] = 0.7
    assert TrialManifest.model_validate(data).sha256() != TrialManifest.model_validate(manifest_data()).sha256()


# --- A1: identical final artifacts are a valid, explicitly reported no-op ----------------------

def test_pair_accepts_identical_final_artifacts_and_reports_it():
    data = manifest_data(protected=True)
    data["target"]["final_artifact_sha256"] = manifest_data()["target"]["final_artifact_sha256"]
    result = validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))
    assert result.final_artifacts_identical is True
    summary = result.summary()
    assert summary["final_artifacts_identical"] is True
    assert any("no observable effect" in note for note in summary["observations"])
    assert summary["attacks_executed"] is False and summary["authorizes_execution"] is False


def test_identical_final_artifacts_do_not_hide_other_differences():
    data = manifest_data(protected=True)
    data["target"]["final_artifact_sha256"] = manifest_data()["target"]["final_artifact_sha256"]
    data["budget"]["max_tool_calls"] = 21
    with pytest.raises(ManifestPairError) as exc:
        validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))
    assert exc.value.fields == ("budget.max_tool_calls",)


def test_distinct_final_artifacts_have_no_identity_observation():
    summary = validate_pair(*pair()).summary()
    assert summary["final_artifacts_identical"] is False
    assert summary["observations"] == []


# --- Pair comparability ------------------------------------------------------------------------

@pytest.mark.parametrize(("path", "value"), [
    ("attack.prompt_sha256", digest("different")),
    ("attack.workflow_configuration_sha256", digest("different workflow")),
    ("attack.sampling_configuration_sha256", digest("different sampling")),
    ("attack.sampling_seed", 43),
    ("attack.temperature", 0.5),
    ("attack.model_id", "other-model"),
    ("attack.provider", "other-provider"),
    ("attack.tools", [tool("Ghidra", "12.1.3")]),
    ("access.access_to_symbols", True),
    ("access.workspace_policy_sha256", digest("different workspace")),
    ("budget.max_model_tokens", 20),
    ("budget.max_attempts", 2),
    ("scoring.hidden_test_suite_sha256", digest("different tests")),
    ("scoring.scorer.version", "0.0.2"),
    ("scoring.scorer.configuration_sha256", digest("other scorer configuration")),
    ("scoring.expected_interface", "other(uint32)->uint32"),
    ("authorization.reference", "DIFFERENT-AUTH"),
    ("authorization.authorized_scope", "different scope"),
    ("pair_id", "8" * 32),
])
def test_pair_rejects_different_conditions(path, value):
    data = manifest_data(protected=True)
    set_path(data, path, value)
    with pytest.raises(ManifestPairError) as exc:
        validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))
    assert exc.value.fields == (path,)


@pytest.mark.parametrize(("path", "value"), [
    ("target.name", "wrong"),
    ("target.function", "wrong"),
    ("target.source_revision", "wrong"),
    ("target.platform", "wrong"),
    ("target.artifact_format", "wrong"),
    ("target.build.pipeline", "ordinary-release"),
    ("target.build.compiler.version", "21.1.0"),
    ("target.build.compiler.executable_sha256", digest("other clang")),
    ("target.build.shared_recipe_sha256", digest("other recipe")),
    ("target.build.symbols", "present"),
    ("target.build.debug_info", True),
])
def test_pair_rejects_different_targets(path, value):
    data = manifest_data(protected=True)
    set_path(data, path, value)
    with pytest.raises(ManifestPairError) as exc:
        validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))
    assert exc.value.fields == (path,)


def test_pair_reports_every_difference():
    data = manifest_data(protected=True)
    data["budget"]["max_tool_calls"] = 21
    data["access"]["network_enabled"] = True
    with pytest.raises(ManifestPairError) as exc:
        validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))
    assert set(exc.value.fields) == {"budget.max_tool_calls", "access.network_enabled"}


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


def test_pair_rejects_two_protected_trials():
    data = manifest_data(protected=True)
    data["trial_id"] = "3" * 32
    with pytest.raises(ManifestPairError, match="variant"):
        validate_pair(TrialManifest.model_validate(manifest_data(protected=True)), TrialManifest.model_validate(data))


def test_pair_rejects_different_pair_id():
    data = manifest_data(protected=True)
    data["pair_id"] = "8" * 32
    with pytest.raises(ManifestPairError, match="pair_id"):
        validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))


def test_paired_trials_differ_only_in_declared_protection_step():
    a, b = pair()
    assert a.target.protection is None and b.target.protection is not None
    assert a.target.build == b.target.build
    assert validate_pair(a, b).protected is b


def test_protection_step_contents_may_vary_between_pairs():
    data = manifest_data(protected=True)
    data["target"]["protection"].update(seed=None, backend=tool("aegis-mirage", "0.0.1"))
    assert validate_pair(TrialManifest.model_validate(manifest_data()), TrialManifest.model_validate(data))


# --- Field validation --------------------------------------------------------------------------

@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version="unknown"),
    lambda d: d.update(api_key="secret"),
    lambda d: d["attack"].update(token="should-not-be-stored"),
    lambda d: d["attack"].update(workflow="magic"),
    lambda d: d["attack"].update(session_isolation="reuse_previous_session"),
    lambda d: d["attack"].pop("session_isolation"),
    lambda d: d["attack"].pop("sampling_configuration_sha256"),
    lambda d: d["attack"].pop("workflow_configuration_sha256"),
    lambda d: d["attack"].update(sampling_seed=-1),
    lambda d: d["attack"].update(sampling_seed=2**63),
    lambda d: d["attack"].update(temperature=2.5),
    lambda d: d["attack"]["tools"][0].pop("executable_sha256"),
    lambda d: d["attack"]["tools"][0].pop("configuration_sha256"),
    lambda d: d["attack"].update(tools=[]),
    lambda d: d["target"].update(final_artifact_sha256="not-a-hash"),
    lambda d: d["target"].update(final_artifact_sha256="A" * 64),
    lambda d: d["target"].update(final_artifact_sha256="a" * 64 + "\n"),
    lambda d: d["target"].pop("build"),
    lambda d: d["target"].update(matched_build_profile="free text is no longer accepted"),
    lambda d: d["target"]["build"].update(symbols="partially"),
    lambda d: d["target"]["build"].update(debug_info="false"),
    lambda d: d["target"]["build"]["compiler"].pop("executable_sha256"),
    lambda d: d["budget"].update(max_wall_seconds=0),
    lambda d: d["budget"].update(max_tool_calls=1.5),
    lambda d: d["budget"].update(max_model_tokens="100"),
    lambda d: d["access"].update(oracle_query_limit=3),
    lambda d: d["access"].update(oracle_configuration_sha256=digest("oracle")),
    lambda d: d["access"].update(runtime_oracle_enabled=True, oracle_query_limit=8),
    lambda d: d["access"].update(runtime_oracle_enabled=True, oracle_configuration_sha256=digest("oracle")),
    lambda d: d["access"].pop("workspace_policy_sha256"),
    lambda d: d["access"].update(network_enabled="no"),
    lambda d: d["scoring"].update(score_rule="unverified-score"),
    lambda d: d["scoring"].pop("scorer"),
    lambda d: d["scoring"].update(hidden_tests=["expected answer"]),
    lambda d: d.update(trial_id="1" * 31),
])
def test_manifest_rejects_invalid_or_secret_fields(mutate):
    data = manifest_data()
    mutate(data)
    with pytest.raises(ValidationError):
        TrialManifest.model_validate(data)


def test_rea_workflow_is_supported_without_ghidra_dependency():
    data = manifest_data()
    data["attack"].update(workflow="rea", tools=[tool("REA", "pin-at-run")], provider="coding-agent")
    assert TrialManifest.model_validate(data).attack.workflow == "rea"


@pytest.mark.parametrize(("workflow", "tools"), [
    ("ghidra_model", [tool("REA", "1")]),
    ("rea", [tool("Ghidra", "12.1.4")]),
])
def test_workflow_requires_its_primary_tool(workflow, tools):
    data = manifest_data()
    data["attack"].update(workflow=workflow, tools=tools)
    with pytest.raises(ValidationError) as exc:
        TrialManifest.model_validate(data)
    assert "aegis_workflow_tool_missing" in error_types(exc.value)


def test_custom_workflow_accepts_any_tool_set():
    data = manifest_data()
    data["attack"].update(workflow="custom", tools=[tool("objdump", "2.45")])
    assert TrialManifest.model_validate(data).attack.workflow == "custom"


def test_tool_order_is_not_significant_and_must_be_canonical():
    data = manifest_data()
    data["attack"]["tools"] = [tool("Ghidra", "12.1.4"), tool("objdump", "2.45"), tool("REA", "1")]
    assert TrialManifest.model_validate(data)
    data["attack"]["tools"] = [tool("REA", "1"), tool("Ghidra", "12.1.4")]
    with pytest.raises(ValidationError) as exc:
        TrialManifest.model_validate(data)
    assert "aegis_tools_not_sorted" in error_types(exc.value)


def test_tool_names_are_unique_ignoring_case():
    data = manifest_data()
    data["attack"]["tools"] = [tool("Ghidra", "12.1.4"), tool("GHIDRA", "12.1.3")]
    with pytest.raises(ValidationError) as exc:
        TrialManifest.model_validate(data)
    assert "aegis_duplicate_tool" in error_types(exc.value)


def test_baseline_cannot_claim_protection_step():
    data = manifest_data()
    data["target"]["protection"] = manifest_data(protected=True)["target"]["protection"]
    with pytest.raises(ValidationError) as exc:
        TrialManifest.model_validate(data)
    assert "aegis_baseline_has_protection" in error_types(exc.value)


def test_protected_trial_must_declare_protection_step():
    data = manifest_data(protected=True)
    data["target"]["protection"] = None
    with pytest.raises(ValidationError) as exc:
        TrialManifest.model_validate(data)
    assert "aegis_protected_missing_protection" in error_types(exc.value)


def test_runtime_oracle_policy_requires_explicit_enablement_and_configuration():
    data = manifest_data()
    data["access"].update(runtime_oracle_enabled=True, oracle_query_limit=8, oracle_configuration_sha256=digest("oracle"))
    access = TrialManifest.model_validate(data).access
    assert access.oracle_query_limit == 8 and access.oracle_configuration_sha256 == digest("oracle")


def test_all_custom_error_types_are_registered():
    # Every validator error code in manifest.py must be in the allowlist shown to users.
    import inspect

    import aegis_lab.manifest as module
    source = inspect.getsource(module)
    used = {part.split('"')[1] for part in source.split("PydanticCustomError(")[1:]}
    assert used <= MANIFEST_ERROR_TYPES


# --- A4: identity and audit-reference text rules -----------------------------------------------

IDENTITY_PATHS = [
    "target.name",
    "target.function",
    "target.source_revision",
    "target.platform",
    "target.artifact_format",
    "target.build.pipeline",
    "target.build.compiler.name",
    "target.build.compiler.version",
    "attack.tools.0.name",
    "attack.tools.0.version",
    "attack.provider",
    "attack.model_id",
    "scoring.expected_interface",
    "scoring.scorer.name",
    "scoring.scorer.version",
    "authorization.reference",
    "authorization.authorized_scope",
]
PROTECTED_IDENTITY_PATHS = ["target.protection.backend.name", "target.protection.backend.version"]

BAD_TEXT = {
    "": "string_too_short",
    " ": "aegis_blank",
    "   ": "aegis_blank",
    "\t\n": "aegis_blank",
    "  　": "aegis_blank",
    " leading": "aegis_surrounding_whitespace",
    "trailing ": "aegis_surrounding_whitespace",
    "trailing ": "aegis_surrounding_whitespace",
    "line\nbreak": "aegis_forbidden_character",
    "nul\x00byte": "aegis_forbidden_character",
    "escape\x1b[31m": "aegis_forbidden_character",
    "delete\x7f": "aegis_forbidden_character",
    "c1\x85control": "aegis_forbidden_character",
    "bidi‮override": "aegis_forbidden_character",
    "zero​width": "aegis_forbidden_character",
    "bom﻿inside": "aegis_forbidden_character",
    "line separator": "aegis_forbidden_character",
    "privateuse": "aegis_forbidden_character",
    "lone\ud800surrogate": "string_unicode",  # rejected by Pydantic before our validator
    "unassigned\U000e0080": "aegis_forbidden_character",
    "nfd-é": "aegis_not_nfc",
}


@pytest.mark.parametrize("path", IDENTITY_PATHS + PROTECTED_IDENTITY_PATHS)
@pytest.mark.parametrize("bad", list(BAD_TEXT))
def test_identity_fields_reject_blank_padded_and_invisible_text(path, bad):
    data = manifest_data(protected=path in PROTECTED_IDENTITY_PATHS)
    set_path(data, path, bad)
    with pytest.raises(ValidationError) as exc:
        TrialManifest.model_validate(data)
    assert BAD_TEXT[bad] in error_types(exc.value)


@pytest.mark.parametrize("good", [
    "x",
    "Ghidra 12.1.4",
    "bildverarbeitung-modul-ä",  # precomposed (NFC) non-ASCII is accepted unchanged
    "meta-llama/Llama-3.3-70B-Instruct",
    "sample_transform(uint32,uint32)->uint32",
    "画像処理",
    "a" * 200,
])
@pytest.mark.parametrize("path", IDENTITY_PATHS)
def test_identity_fields_accept_legitimate_values_unchanged(path, good):
    data = manifest_data()
    data["attack"]["workflow"] = "custom"  # the tool name itself is under test
    set_path(data, path, good)
    manifest = TrialManifest.model_validate(data)
    value = manifest.model_dump()
    for part in path.split("."):
        value = value[int(part)] if part.isdigit() else value[part]
    assert value == good


def test_identity_length_limits():
    data = manifest_data()
    data["target"]["name"] = "a" * 201
    with pytest.raises(ValidationError):
        TrialManifest.model_validate(data)
    data = manifest_data()
    data["authorization"]["authorized_scope"] = "owned local fixtures, " * 90
    data["authorization"]["authorized_scope"] = data["authorization"]["authorized_scope"].strip()
    assert len(data["authorization"]["authorized_scope"]) <= 2000
    assert TrialManifest.model_validate(data)


# --- Parsing untrusted bytes -------------------------------------------------------------------

def test_parse_manifest_accepts_valid_bytes():
    assert parse_manifest(json.dumps(manifest_data()).encode()) == TrialManifest.model_validate(manifest_data())


@pytest.mark.parametrize(("original", "ambiguous"), [
    ('"trial_id": "' + "1" * 32 + '"', '"trial_id": "' + "1" * 32 + '", "trial_id": "' + "3" * 32 + '"'),
    ('"max_tool_calls": 20', '"max_tool_calls": 20, "max_tool_calls": 2'),
    ('"debug_info": false', '"debug_info": false, "debug_info": false'),
])
def test_duplicate_keys_are_rejected_even_when_otherwise_valid(original, ambiguous):
    data = json.dumps(manifest_data())
    assert original in data
    with pytest.raises(LoadError) as exc:
        parse_manifest(data.replace(original, ambiguous).encode())
    assert exc.value.category == "duplicate_key"


def test_retired_v1_manifest_is_rejected_explicitly():
    data = manifest_data()
    data["schema_version"] = "aegis.lab.trial.v1"
    with pytest.raises(LoadError) as exc:
        parse_manifest(json.dumps(data).encode())
    assert exc.value.category == "retired_schema_version"


@pytest.mark.parametrize("raw", [b"", b"{", b"[]", b"null", b"\xff\xfe{}", b"\xef\xbb\xbf{}", b'{"a": NaN}', b"[" * 50000 + b"]" * 50000])
def test_parse_manifest_rejects_malformed_bytes(raw):
    with pytest.raises((LoadError, ValidationError)):
        parse_manifest(raw)


# --- Attacker-visible projection ---------------------------------------------------------------

def test_attacker_view_excludes_hidden_and_variant_information():
    a, b = pair()
    for manifest in (a, b):
        view = manifest.attacker_view()
        text = canonical_json_bytes(view).decode()
        assert set(view) == {"schema_version", "task", "artifact_sha256", "access", "budget"}
        for hidden in (
            manifest.variant.value, manifest.trial_id, manifest.pair_id, manifest.target.source_revision,
            manifest.target.name, manifest.target.build.shared_recipe_sha256, manifest.scoring.hidden_test_suite_sha256,
            manifest.scoring.scorer.configuration_sha256, manifest.attack.prompt_sha256,
            manifest.authorization.reference, "transformation_report", "protection",
        ):
            assert hidden not in text
    assert a.attacker_view()["task"] == b.attacker_view()["task"]
    assert {k: v for k, v in a.attacker_view().items() if k != "artifact_sha256"} == {
        k: v for k, v in b.attacker_view().items() if k != "artifact_sha256"
    }


# --- CLI ---------------------------------------------------------------------------------------

def write_pair(tmp_path, first: dict | str | bytes, second: dict | str | bytes):
    paths = []
    for name, value in (("a.json", first), ("b.json", second)):
        path = tmp_path / name
        if isinstance(value, dict):
            value = json.dumps(value)
        path.write_bytes(value if isinstance(value, bytes) else value.encode())
        paths.append(str(path))
    return paths


def test_validation_cli_accepts_comparable_pair(tmp_path, capsys):
    from aegis_lab.__main__ import main
    assert main(["validate-pair", *write_pair(tmp_path, manifest_data(), manifest_data(protected=True))]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["validation"] == "declared_configuration_comparable"
    assert output["attacks_executed"] is False
    assert output["authorizes_execution"] is False
    assert output["final_artifacts_identical"] is False
    baseline, protected = pair()
    assert output["baseline_manifest_sha256"] == baseline.sha256()
    assert output["protected_manifest_sha256"] == protected.sha256()


def test_validation_cli_reports_identical_artifacts(tmp_path, capsys):
    from aegis_lab.__main__ import main
    data = manifest_data(protected=True)
    data["target"]["final_artifact_sha256"] = manifest_data()["target"]["final_artifact_sha256"]
    assert main(["validate-pair", *write_pair(tmp_path, manifest_data(), data)]) == 0
    assert json.loads(capsys.readouterr().out)["final_artifacts_identical"] is True


def test_validation_cli_rejects_budget_mismatch(tmp_path, capsys):
    from aegis_lab.__main__ import main
    changed = manifest_data(protected=True)
    changed["budget"]["max_model_tokens"] += 1
    assert main(["validate-pair", *write_pair(tmp_path, manifest_data(), changed)]) == 2
    captured = capsys.readouterr()
    assert "pair: budget.max_model_tokens: differs" in captured.err
    assert captured.out == ""


def test_validation_cli_rejects_missing_file(tmp_path, capsys):
    from aegis_lab.__main__ import main
    assert main(["validate-pair", str(tmp_path / "missing"), str(tmp_path / "absent")]) == 2
    err = capsys.readouterr().err
    assert "invalid trial pair" in err
    assert "baseline-file: not_found" in err and "protected-file: not_found" in err
    assert str(tmp_path) not in err


def _secret_cases() -> list[tuple[str, bytes]]:
    cases: list[tuple[str, dict | bytes]] = []
    unknown_top = manifest_data()
    unknown_top[f"api_key_{SECRET}"] = SECRET
    cases.append(("unknown top-level key", unknown_top))
    unknown_nested = manifest_data()
    unknown_nested["attack"]["tools"][0][f"token-{SECRET}"] = {"nested": SECRET}
    cases.append(("unknown nested key", unknown_nested))
    for path in ("target.name", "attack.model_id", "authorization.reference", "authorization.authorized_scope"):
        for bad in (f" {SECRET}", f"{SECRET}\x1b[2J", f"{SECRET}‮", f"{SECRET}\n"):
            data = manifest_data()
            set_path(data, path, bad)
            cases.append((f"bad text at {path}", data))
    for path in ("target.final_artifact_sha256", "trial_id", "attack.prompt_sha256"):
        data = manifest_data()
        set_path(data, path, SECRET)
        cases.append((f"bad hash at {path}", data))
    for path, value in (("budget.max_tool_calls", SECRET), ("attack.workflow", SECRET), ("variant", SECRET),
                        ("schema_version", SECRET), ("access.network_enabled", SECRET), ("attack.tools", SECRET)):
        data = manifest_data()
        set_path(data, path, value)
        cases.append((f"bad type at {path}", data))
    text = json.dumps(manifest_data())
    cases.append(("duplicate key", text.replace('"network_enabled": false', f'"network_enabled": false, "network_enabled": "{SECRET}"').encode()))
    cases.append(("malformed json", (text[:-1] + f', "{SECRET}"').encode()))
    cases.append(("invalid utf-8", text.encode() + SECRET.encode() + b"\xff"))
    cases.append(("non-finite", text.replace('"sampling_seed": 42', f'"sampling_seed": 42, "{SECRET}": NaN').encode()))
    return [(label, data if isinstance(data, bytes) else json.dumps(data).encode()) for label, data in cases]


@pytest.mark.parametrize(("label", "payload"), _secret_cases(), ids=lambda v: v if isinstance(v, str) else "")
def test_validation_cli_never_echoes_rejected_input(tmp_path, capsys, label, payload):
    from aegis_lab.__main__ import main
    for first, second in ((payload, manifest_data(protected=True)), (manifest_data(), payload)):
        assert main(["validate-pair", *write_pair(tmp_path, first, second)]) == 2, label
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert SECRET not in combined, label
        assert captured.out == ""
        for leak in ("input_value", "errors.pydantic.dev", "Traceback", "\x1b", "‮", str(tmp_path)):
            assert leak not in combined, (label, leak)
        assert "invalid trial pair:" in captured.err


def test_validation_cli_secret_in_file_name_is_not_echoed(tmp_path, capsys):
    from aegis_lab.__main__ import main
    secret_dir = tmp_path / SECRET
    secret_dir.mkdir()
    bad = secret_dir / f"{SECRET}.json"
    bad.write_text("{", encoding="utf-8")
    assert main(["validate-pair", str(bad), str(secret_dir / "missing.json")]) == 2
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert "baseline-file: malformed_json" in captured.err
    assert "protected-file: not_found" in captured.err


def test_validation_cli_issue_output_is_bounded(tmp_path, capsys):
    from aegis_lab.__main__ import main
    data = manifest_data()
    data["attack"]["workflow"] = "custom"
    data["attack"]["tools"] = [
        {"name": f"t{i:02}", "version": "1", "executable_sha256": "bad", "configuration_sha256": "bad"} for i in range(32)
    ]
    data.update({f"unknown{i}": i for i in range(500)})
    assert main(["validate-pair", *write_pair(tmp_path, data, data)]) == 2
    err = capsys.readouterr().err
    assert err.count("\n") <= 1 + 2 * 21
    assert "more issues not shown" in err


def test_validation_cli_reports_field_paths_and_categories(tmp_path, capsys):
    from aegis_lab.__main__ import main
    data = manifest_data()
    data["target"]["name"] = "   "
    data["budget"]["max_wall_seconds"] = 0
    data["extra"] = 1
    other = copy.deepcopy(manifest_data(protected=True))
    del other["attack"]["prompt_sha256"]
    assert main(["validate-pair", *write_pair(tmp_path, data, other)]) == 2
    err = capsys.readouterr().err
    assert "baseline-file: target.name: aegis_blank" in err
    assert "baseline-file: budget.max_wall_seconds: out_of_range" in err
    assert "baseline-file: <unknown>: unknown_field" in err
    assert "protected-file: attack.prompt_sha256: missing" in err


def test_validation_cli_unexpected_failure_is_contained(tmp_path, capsys, monkeypatch):
    import aegis_lab.__main__ as cli

    def explode(_path):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(cli, "load_manifest", explode)
    assert cli.main(["validate-pair", str(tmp_path / "a"), str(tmp_path / "b")]) == 3
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert "internal_error (RuntimeError)" in captured.err


@pytest.mark.parametrize("argv", [[SECRET, "a", "b"], ["validate-pair", "a", "b", f"{SECRET}\x1b[2J"]])
def test_cli_argument_errors_do_not_echo_values(capsys, argv):
    from aegis_lab.__main__ import main

    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err and "\x1b" not in captured.err
