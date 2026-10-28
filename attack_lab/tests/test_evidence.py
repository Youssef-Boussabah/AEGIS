"""Binding Ghidra reports to manifests.

Reports are produced by the real Phase 2 worker code path (``aegis_lab.ghidra.analyze``)
driven by the offline fake launcher from test_ghidra.py, so the binding is checked
against the worker's actual output format. The opt-in test at the end uses real Ghidra.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_ghidra import fake_ghidra
from test_manifest import SECRET, digest, manifest_data

from aegis_lab.canonical import canonical_json_bytes
from aegis_lab.evidence import (
    GHIDRA_CONFIGURATION_FIELDS,
    EvidenceBindingError,
    bind_ghidra_evidence,
    bind_ghidra_pair,
    ghidra_configuration_sha256,
    main,
    parse_ghidra_report,
    planned_ghidra_tool,
)
from aegis_lab.ghidra import AnalysisReport, analyze
from aegis_lab.manifest import TrialManifest, validate_pair
from aegis_lab.safe_io import LoadError


def make_binary(directory: Path, content: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "sample.elf"
    path.write_bytes(content)
    return path


def manifests_for(baseline_sha: str, protected_sha: str, ghidra_tool: dict) -> tuple[TrialManifest, TrialManifest]:
    result = []
    for protected, sha in ((False, baseline_sha), (True, protected_sha)):
        data = manifest_data(protected=protected)
        data["target"]["final_artifact_sha256"] = sha
        data["attack"]["tools"] = [ghidra_tool]
        result.append(TrialManifest.model_validate(data))
    return result[0], result[1]


@pytest.fixture
def setup(tmp_path):
    launcher = fake_ghidra(tmp_path)
    baseline_bin = make_binary(tmp_path / "b", b"\x7fELF baseline AEGIS-owned")
    protected_bin = make_binary(tmp_path / "p", b"\x7fELF protected AEGIS-owned")
    tool = planned_ghidra_tool(launcher).model_dump(mode="json")
    reports = []
    for name, binary in (("rb", baseline_bin), ("rp", protected_bin)):
        reports.append(analyze(binary, tmp_path / name, launcher).read_bytes())
    baseline, protected = manifests_for(
        hashlib.sha256(baseline_bin.read_bytes()).hexdigest(), hashlib.sha256(protected_bin.read_bytes()).hexdigest(), tool
    )
    return {"launcher": launcher, "tool": tool, "baseline": baseline, "protected": protected,
            "reports": reports, "tmp": tmp_path, "bins": (baseline_bin, protected_bin)}


def edit_report(data: bytes, mutate) -> bytes:
    document = json.loads(data)
    mutate(document)
    return json.dumps(document, indent=2).encode()


# --- Configuration digest -------------------------------------------------------------------------

CONFIG = {
    "ghidra_application_properties_sha256": "a" * 64,
    "ghidra_revision": "rev",
    "exporter_name": "AegisExportFunctions.java",
    "exporter_script_sha256": "b" * 64,
    "selected_function": "*",
    "max_functions": 64,
    "max_c_chars": 12000,
    "decompile_timeout_seconds": 30,
    "analysis_timeout_seconds": 120,
    "wall_timeout_seconds": 300,
}


# Expected bytes written out by hand; the digest was computed with coreutils sha256sum.
CONFIG_BYTES = (
    b'{"analysis_timeout_seconds":120,"decompile_timeout_seconds":30,"exporter_name":"AegisExportFunctions.java",'
    b'"exporter_script_sha256":"' + b"b" * 64 + b'","ghidra_application_properties_sha256":"' + b"a" * 64 + b'",'
    b'"ghidra_revision":"rev","max_c_chars":12000,"max_functions":64,"schema":"aegis.lab.ghidra-configuration.v1",'
    b'"selected_function":"*","wall_timeout_seconds":300}'
)
CONFIG_SHA256 = "7fb9cc63b0a024801f2b32824beef51e1289f05e4d93f8f6070a9675f1e43cb8"


def test_configuration_digest_fixed_vector():
    assert canonical_json_bytes({"schema": "aegis.lab.ghidra-configuration.v1", **CONFIG}) == CONFIG_BYTES
    assert hashlib.sha256(CONFIG_BYTES).hexdigest() == CONFIG_SHA256
    assert ghidra_configuration_sha256(CONFIG) == CONFIG_SHA256


@pytest.mark.parametrize("field", GHIDRA_CONFIGURATION_FIELDS)
def test_every_configuration_field_changes_the_digest(field):
    changed = dict(CONFIG)
    changed[field] = changed[field] + 1 if isinstance(changed[field], int) else changed[field] + "x"
    assert ghidra_configuration_sha256(changed) != ghidra_configuration_sha256(CONFIG)


def test_configuration_digest_requires_every_field():
    partial = dict(CONFIG)
    del partial["wall_timeout_seconds"]
    with pytest.raises(ValueError):
        ghidra_configuration_sha256(partial)


def test_planned_tool_matches_what_the_worker_records(setup):
    report = AnalysisReport.model_validate_json(setup["reports"][0])
    tool = setup["tool"]
    assert tool["name"] == "Ghidra"
    assert tool["version"] == report.export.ghidra_version
    assert tool["executable_sha256"] == report.export.ghidra_launcher_sha256
    assert tool["configuration_sha256"] == ghidra_configuration_sha256(report.export)


# --- Single-trial binding ----------------------------------------------------------------------

def test_binds_report_to_its_manifest(setup):
    evidence = bind_ghidra_evidence(setup["baseline"], setup["reports"][0])
    assert evidence.trial_id == setup["baseline"].trial_id
    assert evidence.manifest_sha256 == setup["baseline"].sha256()
    assert evidence.artifact_sha256 == setup["baseline"].target.final_artifact_sha256
    assert evidence.evidence_sha256 == hashlib.sha256(setup["reports"][0]).hexdigest()
    assert evidence.evidence_size_bytes == len(setup["reports"][0])
    assert evidence.observed["decompiled_ok_count"] == 1
    record = json.dumps(evidence.record())
    assert "decompiled_c" not in record and "warnings_and_logs" not in record


def test_report_for_other_artifact_is_rejected(setup):
    with pytest.raises(EvidenceBindingError) as exc:
        bind_ghidra_evidence(setup["baseline"], setup["reports"][1])
    assert exc.value.fields == ("binary.sha256",)


def test_report_with_other_configuration_is_rejected(setup):
    tmp = setup["tmp"]
    other = analyze(setup["bins"][0], tmp / "other", setup["launcher"], function="add").read_bytes()
    with pytest.raises(EvidenceBindingError) as exc:
        bind_ghidra_evidence(setup["baseline"], other)
    assert exc.value.fields == ("export.configuration",)
    declared = planned_ghidra_tool(setup["launcher"], function="add").model_dump(mode="json")
    baseline, _ = manifests_for(setup["baseline"].target.final_artifact_sha256, "c" * 64, declared)
    assert bind_ghidra_evidence(baseline, other)


@pytest.mark.parametrize(("field", "value", "expected"), [
    ("version", "12.1.3", "export.ghidra_version"),
    ("executable_sha256", "d" * 64, "export.ghidra_launcher_sha256"),
    ("configuration_sha256", "e" * 64, "export.configuration"),
])
def test_declared_tool_identity_must_match(setup, field, value, expected):
    tool = dict(setup["tool"], **{field: value})
    baseline, _ = manifests_for(setup["baseline"].target.final_artifact_sha256, "c" * 64, tool)
    with pytest.raises(EvidenceBindingError) as exc:
        bind_ghidra_evidence(baseline, setup["reports"][0])
    assert exc.value.fields == (expected,)


def test_manifest_without_ghidra_tool_cannot_bind(setup):
    data = manifest_data()
    data["target"]["final_artifact_sha256"] = setup["baseline"].target.final_artifact_sha256
    data["attack"].update(workflow="custom", tools=[{**setup["tool"], "name": "objdump"}])
    with pytest.raises(EvidenceBindingError) as exc:
        bind_ghidra_evidence(TrialManifest.model_validate(data), setup["reports"][0])
    assert exc.value.fields == ("attack.tools",)


@pytest.mark.parametrize(("mutate", "expected"), [
    (lambda d: d.update(decompiled_ok_count=2), "decompiled_ok_count"),
    (lambda d: d["analysis"].update(java_version="17.0.1"), "analysis.java_version"),
    (lambda d: d["analysis"].update(ghidra_version="12.1.3"), "analysis.ghidra_version"),
])
def test_internally_inconsistent_report_is_rejected(setup, mutate, expected):
    with pytest.raises(EvidenceBindingError) as exc:
        bind_ghidra_evidence(setup["baseline"], edit_report(setup["reports"][0], mutate))
    assert expected in exc.value.fields


def test_report_with_duplicate_key_is_rejected(setup):
    text = setup["reports"][0].decode()
    sha = setup["baseline"].target.final_artifact_sha256
    ambiguous = text.replace(f'"sha256": "{sha}"', f'"sha256": "{"f" * 64}", "sha256": "{sha}"', 1)
    assert ambiguous != text
    with pytest.raises(LoadError) as exc:
        bind_ghidra_evidence(setup["baseline"], ambiguous.encode())
    assert exc.value.category == "duplicate_key"


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version="aegis.lab.ghidra.v0"),
    lambda d: d.update(extra_field=1),
    lambda d: d["binary"].update(sha256="not-a-hash"),
    lambda d: d.update(decompiled_ok_count=0),
    lambda d: d["analysis"]["functions"][0].update(decompile_success="true"),
])
def test_schema_invalid_report_is_rejected(setup, mutate):
    with pytest.raises(ValidationError):
        parse_ghidra_report(edit_report(setup["reports"][0], mutate))


def test_report_with_non_finite_number_is_rejected(setup):
    text = setup["reports"][0].decode()
    tampered = text.replace('"duration_seconds": ', '"duration_seconds": 1e999, "x": ', 1)
    with pytest.raises(LoadError) as exc:
        parse_ghidra_report(tampered.encode())
    assert exc.value.category == "non_finite_number"


# --- Pair binding ------------------------------------------------------------------------------

def test_pair_binding_records_independent_evidence_hashes(setup):
    pair = validate_pair(setup["baseline"], setup["protected"])
    record = bind_ghidra_pair(pair, *setup["reports"])
    assert record["schema_version"] == "aegis.lab.evidence-binding.v1"
    assert record["baseline"]["evidence_sha256"] == hashlib.sha256(setup["reports"][0]).hexdigest()
    assert record["protected"]["evidence_sha256"] == hashlib.sha256(setup["reports"][1]).hexdigest()
    assert record["baseline"]["evidence_sha256"] != record["protected"]["evidence_sha256"]
    assert record["baseline"]["artifact_sha256"] == setup["baseline"].target.final_artifact_sha256
    assert record["protected"]["artifact_sha256"] == setup["protected"].target.final_artifact_sha256
    assert record["baseline"]["manifest_sha256"] == setup["baseline"].sha256()
    assert record["final_artifacts_identical"] is False
    assert record["attacks_executed"] is False and record["authorizes_execution"] is False


def test_pair_binding_rejects_swapped_reports(setup):
    pair = validate_pair(setup["baseline"], setup["protected"])
    with pytest.raises(EvidenceBindingError) as exc:
        bind_ghidra_pair(pair, setup["reports"][1], setup["reports"][0])
    assert exc.value.fields == ("binary.sha256",)


def test_pair_binding_with_identical_artifacts(setup):
    tmp = setup["tmp"]
    same = make_binary(tmp / "same", setup["bins"][0].read_bytes())
    second = analyze(same, tmp / "r-same", setup["launcher"]).read_bytes()
    sha = setup["baseline"].target.final_artifact_sha256
    baseline, protected = manifests_for(sha, sha, setup["tool"])
    record = bind_ghidra_pair(validate_pair(baseline, protected), setup["reports"][0], second)
    assert record["final_artifacts_identical"] is True
    assert record["baseline"]["artifact_sha256"] == record["protected"]["artifact_sha256"] == sha
    assert record["baseline"]["evidence_sha256"] == hashlib.sha256(setup["reports"][0]).hexdigest()
    assert record["protected"]["evidence_sha256"] == hashlib.sha256(second).hexdigest()


def test_pair_binding_rejects_different_observed_runtime(setup):
    def other_java(document):
        document["analysis"]["java_version"] = "17.0.99"
        document["export"]["java_version"] = "17.0.99"

    pair = validate_pair(setup["baseline"], setup["protected"])
    with pytest.raises(EvidenceBindingError) as exc:
        bind_ghidra_pair(pair, setup["reports"][0], edit_report(setup["reports"][1], other_java))
    assert exc.value.fields == ("observed.java_version",)


# --- CLI ---------------------------------------------------------------------------------------

def write_inputs(setup, *, baseline_report: bytes | None = None, protected_report: bytes | None = None,
                 baseline: TrialManifest | bytes | None = None) -> list[str]:
    tmp = setup["tmp"] / "cli"
    tmp.mkdir(exist_ok=True)
    values = [
        baseline if baseline is not None else setup["baseline"],
        setup["protected"],
        baseline_report if baseline_report is not None else setup["reports"][0],
        protected_report if protected_report is not None else setup["reports"][1],
    ]
    paths = []
    for index, value in enumerate(values):
        path = tmp / f"{index}.json"
        path.write_bytes(value.model_dump_json().encode() if isinstance(value, TrialManifest) else value)
        paths.append(str(path))
    return paths


def test_cli_bind_pair_succeeds(setup, capsys):
    assert main(["bind-pair", *write_inputs(setup)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["baseline"]["evidence_sha256"] == hashlib.sha256(setup["reports"][0]).hexdigest()
    assert output["protected"]["evidence_sha256"] == hashlib.sha256(setup["reports"][1]).hexdigest()
    assert output["authorizes_execution"] is False


def test_cli_bind_pair_rejects_swapped_manifest_roles(setup, capsys):
    paths = write_inputs(setup)
    paths[0], paths[1] = paths[1], paths[0]
    assert main(["bind-pair", *paths]) == 2
    assert "baseline-manifest: variant: not_baseline" in capsys.readouterr().err


def test_cli_bind_pair_names_the_failing_side(setup, capsys):
    assert main(["bind-pair", *write_inputs(setup, protected_report=setup["reports"][0])]) == 2
    err = capsys.readouterr().err
    assert "protected-report: binary.sha256: mismatch" in err
    assert "baseline-report" not in err


@pytest.mark.parametrize("which", ["report", "manifest"])
def test_cli_bind_pair_never_echoes_rejected_input(setup, capsys, which):
    if which == "report":
        bad = edit_report(setup["reports"][0], lambda d: d.update({f"key-{SECRET}": SECRET, "binary": {"name": SECRET}}))
        paths = write_inputs(setup, baseline_report=bad)
    else:
        data = json.loads(setup["baseline"].model_dump_json())
        data["target"]["name"] = f"{SECRET}\x1b[2J"
        paths = write_inputs(setup, baseline=json.dumps(data).encode())
    assert main(["bind-pair", *paths]) == 2
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert "\x1b" not in captured.err and "input_value" not in captured.err
    assert str(setup["tmp"]) not in captured.err


def test_cli_ghidra_tool_prints_planned_identity(setup, capsys):
    assert main(["ghidra-tool", "--headless", str(setup["launcher"])]) == 0
    assert json.loads(capsys.readouterr().out) == setup["tool"]


def test_cli_ghidra_tool_rejects_invalid_installation(tmp_path, capsys):
    launcher = tmp_path / SECRET / "analyzeHeadless"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\n")
    assert main(["ghidra-tool", "--headless", str(launcher)]) == 2
    err = capsys.readouterr().err
    assert "launcher_or_installation_invalid" in err and SECRET not in err


# --- Real Ghidra (opt-in) ------------------------------------------------------------------------

HEADLESS = os.environ.get("AEGIS_GHIDRA_HEADLESS")
CC = shutil.which("cc")


@pytest.mark.skipif(not HEADLESS or not CC, reason="real Ghidra test needs AEGIS_GHIDRA_HEADLESS and a C compiler")
def test_real_ghidra_report_binds_to_planned_manifest(tmp_path):
    source = tmp_path / "fixture.c"
    source.write_text("__attribute__((noinline)) int aegis_bind(int a) { return a * 11 + 4; }\n"
                      "int main(int argc, char **argv) { (void)argv; return aegis_bind(argc); }\n")
    binary = tmp_path / "fixture"
    subprocess.run([CC, "-O1", "-fno-inline", "-o", str(binary), str(source)], check=True, timeout=120)
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    tool = planned_ghidra_tool(Path(HEADLESS), function="aegis_bind").model_dump(mode="json")
    baseline, _ = manifests_for(sha, digest("unused protected artifact"), tool)
    report = analyze(binary, tmp_path / "out", Path(HEADLESS), function="aegis_bind", expected_sha256=sha)
    evidence = bind_ghidra_evidence(baseline, report.read_bytes())
    assert evidence.artifact_sha256 == sha
    assert evidence.observed["decompiled_ok_count"] == 1
    other = analyze(binary, tmp_path / "out2", Path(HEADLESS), function="*", max_functions=4)
    with pytest.raises(EvidenceBindingError, match="export.configuration"):
        bind_ghidra_evidence(baseline, other.read_bytes())


# --- Audit hardening: the binder applies the worker's report invariants ---------------------------
# Each manipulation changes one aspect of a genuine worker report. They are written
# independently of aegis_lab.ghidra.report_violations and applied to offline reports
# and, opt-in, to reports produced by real Ghidra.

def _first(document):
    return document["analysis"]["functions"][0]


def _duplicate_selected(document):
    document["analysis"]["functions"].append(dict(_first(document)))
    document["analysis"]["matching_function_count"] = 2
    document["decompiled_ok_count"] = 2


def _second_match(document):
    other = dict(_first(document), entry_point="00ffff00")
    document["analysis"]["functions"].append(other)
    document["analysis"]["matching_function_count"] = 2
    document["decompiled_ok_count"] = 2


def _selected_failed(document):
    _first(document).update(decompile_success=False, decompile_status="failed", decompiled_c="",
                            decompiler_signature="", decompiled_c_truncated=False, error="pcode error")


MANIPULATIONS = {
    "analysis_timed_out": (lambda d: d["analysis"].update(analysis_timed_out=True),
                           ("analysis.analysis_timed_out", "analysis_incomplete")),
    "program_name": (lambda d: d["analysis"].update(program_name="libc.so.6"),
                     ("analysis.program_name", "not_analyzed_input")),
    "binary_name": (lambda d: d["binary"].update(name="other.elf"),
                    ("analysis.program_name", "not_analyzed_input")),
    "executable_sha256": (lambda d: d["analysis"].update(executable_sha256="f" * 64),
                          ("analysis.executable_sha256", "not_analyzed_input")),
    "non_matching_function": (lambda d: _first(d).update(name="main", qualified_name="main"),
                              ("analysis.functions.0.name", "not_selected")),
    "exceeds_max_c_chars": (lambda d: _first(d).update(decompiled_c="x" * (d["export"]["max_c_chars"] + 1)),
                            ("analysis.functions.0.decompiled_c", "exceeds_max_c_chars")),
    "duplicate_entry_point": (_duplicate_selected, ("analysis.functions.1.entry_point", "duplicate")),
    "duplicate_is_ambiguous": (_duplicate_selected, ("analysis.matching_function_count", "ambiguous_selector")),
    "second_match": (_second_match, ("analysis.matching_function_count", "ambiguous_selector")),
    "hidden_matches": (lambda d: d["analysis"].update(matching_function_count=3, functions_limited=True),
                       ("analysis.matching_function_count", "ambiguous_selector")),
    "selected_failed": (_selected_failed, ("analysis.functions.0.decompile_status", "selected_function_failed")),
    "false_truncation": (lambda d: _first(d).update(decompiled_c_truncated=True),
                         ("analysis.functions.0.decompiled_c_truncated", "truncation_inconsistent")),
    "log_truncated": (lambda d: d.update(log_truncated=not d["log_truncated"]), ("log_truncated", "inconsistent")),
    "ghidra_version": (lambda d: d["analysis"].update(ghidra_version="12.1.3"), ("analysis.ghidra_version", "mismatch")),
}


@pytest.fixture
def exact(tmp_path):
    launcher = fake_ghidra(tmp_path)
    binary = make_binary(tmp_path / "b", b"\x7fELF exact AEGIS-owned")
    tool = planned_ghidra_tool(launcher, function="add").model_dump(mode="json")
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    baseline, protected = manifests_for(sha, digest("protected artifact"), tool)
    report = analyze(binary, tmp_path / "r", launcher, function="add").read_bytes()
    return baseline, report


def assert_manipulation_rejected(manifest, report: bytes, name: str) -> None:
    mutate, (field, reason) = MANIPULATIONS[name]
    assert bind_ghidra_evidence(manifest, report)  # control: the genuine report binds
    with pytest.raises(EvidenceBindingError) as exc:
        bind_ghidra_evidence(manifest, edit_report(report, mutate))
    assert (field, reason) in tuple(zip(exc.value.fields, exc.value.reasons))


@pytest.mark.parametrize("name", sorted(MANIPULATIONS))
def test_binder_rejects_manipulated_exact_selector_report(exact, name):
    assert_manipulation_rejected(*exact, name)


def test_binder_rejects_duplicate_entry_points_in_wildcard_report(setup):
    def duplicate(document):
        document["analysis"]["functions"].append(dict(_first(document), name="other", qualified_name="other"))
        document["analysis"]["matching_function_count"] = 2
        document["decompiled_ok_count"] = 2

    with pytest.raises(EvidenceBindingError) as exc:
        bind_ghidra_evidence(setup["baseline"], edit_report(setup["reports"][0], duplicate))
    assert exc.value.fields == ("analysis.functions.1.entry_point",)
    assert exc.value.reasons == ("duplicate",)


def test_binder_keeps_legitimate_wildcard_partial_failure_and_warnings(tmp_path):
    from test_ghidra import hooked_ghidra

    launcher = hooked_ghidra(tmp_path, "out['functions'] = [fn(message='jump table warning'), "
                                       "fn(name='b', entry='2', ok=False, error='e')]; "
                                       "out['matching_function_count'] = 2")
    binary = make_binary(tmp_path / "bin", b"\x7fELF partial AEGIS-owned")
    tool = planned_ghidra_tool(launcher).model_dump(mode="json")
    baseline, _ = manifests_for(hashlib.sha256(binary.read_bytes()).hexdigest(), "c" * 64, tool)
    evidence = bind_ghidra_evidence(baseline, analyze(binary, tmp_path / "r", launcher).read_bytes())
    assert evidence.observed["decompiled_ok_count"] == 1
    assert evidence.observed["decompile_failed_count"] == 1
    assert evidence.observed["decompiled_with_warnings_count"] == 1


def test_binder_rejects_duplicate_timeout_key(exact):
    manifest, report = exact
    tampered = report.decode().replace('"analysis_timed_out": false',
                                       '"analysis_timed_out": true, "analysis_timed_out": false', 1)
    assert tampered != report.decode()
    with pytest.raises(LoadError) as exc:
        bind_ghidra_evidence(manifest, tampered.encode())
    assert exc.value.category == "duplicate_key"


def test_cli_reports_invariant_violation_by_code_only(setup, capsys):
    bad = edit_report(setup["reports"][0], lambda d: d["analysis"].update(analysis_timed_out=True,
                                                                          program_name=f"{SECRET}\x1b[2J"))
    assert main(["bind-pair", *write_inputs(setup, baseline_report=bad)]) == 2
    err = capsys.readouterr().err
    assert "baseline-report: analysis.analysis_timed_out: analysis_incomplete" in err
    assert "baseline-report: analysis.program_name: not_analyzed_input" in err
    assert SECRET not in err and "\x1b" not in err


@pytest.mark.parametrize("argv", [
    ["ghidra-tool", "--headless", "h", "--max-functions", SECRET],
    ["bind-pair", "a", "b", "c", "d", SECRET],
    [SECRET],
])
def test_cli_argument_errors_do_not_echo_values(capsys, argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err


# --- Audit hardening: stale, swapped and cached evidence ----------------------------------------

def _revise(manifest: TrialManifest, change) -> TrialManifest:
    data = json.loads(manifest.model_dump_json())
    change(data)
    return TrialManifest.model_validate(data)


def test_stale_evidence_is_rejected_after_artifact_revision(setup):
    from aegis_lab.evidence import compare_pair_evidence

    old_baseline = bind_ghidra_evidence(setup["baseline"], setup["reports"][0])
    protected = bind_ghidra_evidence(setup["protected"], setup["reports"][1])
    # Codex's reproduction: same trial ids, different artifact hash.
    revised = _revise(setup["baseline"], lambda d: d["target"].update(final_artifact_sha256="d" * 64))
    assert revised.trial_id == old_baseline.trial_id
    with pytest.raises(EvidenceBindingError) as exc:
        compare_pair_evidence(validate_pair(revised, setup["protected"]), old_baseline, protected)
    assert exc.value.fields == ("baseline.manifest_sha256", "baseline.artifact_sha256")
    assert set(exc.value.reasons) == {"stale_or_swapped"}


def test_stale_evidence_is_rejected_after_any_manifest_revision(setup):
    from aegis_lab.evidence import compare_pair_evidence

    baseline = bind_ghidra_evidence(setup["baseline"], setup["reports"][0])
    protected = bind_ghidra_evidence(setup["protected"], setup["reports"][1])

    def budget(data):
        data["budget"]["max_tool_calls"] += 1

    pair = validate_pair(_revise(setup["baseline"], budget), _revise(setup["protected"], budget))
    with pytest.raises(EvidenceBindingError) as exc:
        compare_pair_evidence(pair, baseline, protected)
    assert exc.value.fields == ("baseline.manifest_sha256", "protected.manifest_sha256")


def test_swapped_evidence_is_rejected(setup):
    from aegis_lab.evidence import compare_pair_evidence

    pair = validate_pair(setup["baseline"], setup["protected"])
    baseline = bind_ghidra_evidence(setup["baseline"], setup["reports"][0])
    protected = bind_ghidra_evidence(setup["protected"], setup["reports"][1])
    with pytest.raises(EvidenceBindingError) as exc:
        compare_pair_evidence(pair, protected, baseline)
    assert "baseline.trial_id" in exc.value.fields and "protected.trial_id" in exc.value.fields


def test_forged_binding_with_other_artifact_is_rejected(setup):
    from dataclasses import replace

    from aegis_lab.evidence import compare_pair_evidence

    pair = validate_pair(setup["baseline"], setup["protected"])
    baseline = bind_ghidra_evidence(setup["baseline"], setup["reports"][0])
    protected = bind_ghidra_evidence(setup["protected"], setup["reports"][1])
    with pytest.raises(EvidenceBindingError) as exc:
        compare_pair_evidence(pair, replace(baseline, artifact_sha256=protected.artifact_sha256), protected)
    assert exc.value.fields == ("baseline.artifact_sha256",)


def test_cached_evidence_for_unchanged_manifests_is_accepted(setup):
    from aegis_lab.evidence import compare_pair_evidence

    baseline = bind_ghidra_evidence(setup["baseline"], setup["reports"][0])
    protected = bind_ghidra_evidence(setup["protected"], setup["reports"][1])
    # Equal (not identical) manifest objects, e.g. reloaded from disk later.
    reloaded = [TrialManifest.model_validate_json(m.model_dump_json()) for m in (setup["baseline"], setup["protected"])]
    record = compare_pair_evidence(validate_pair(*reloaded), baseline, protected)
    assert record["baseline"]["manifest_sha256"] == setup["baseline"].sha256()


def test_identical_artifacts_remain_valid_through_the_stale_check(setup):
    from aegis_lab.evidence import compare_pair_evidence

    tmp = setup["tmp"]
    same = make_binary(tmp / "same2", setup["bins"][0].read_bytes())
    second = analyze(same, tmp / "r-same2", setup["launcher"]).read_bytes()
    sha = setup["baseline"].target.final_artifact_sha256
    baseline, protected = manifests_for(sha, sha, setup["tool"])
    pair = validate_pair(baseline, protected)
    record = compare_pair_evidence(pair, bind_ghidra_evidence(baseline, setup["reports"][0]),
                                   bind_ghidra_evidence(protected, second))
    assert record["final_artifacts_identical"] is True
    # Byte-identical artifacts still need each binding made against its own manifest.
    with pytest.raises(EvidenceBindingError):
        compare_pair_evidence(pair, bind_ghidra_evidence(baseline, setup["reports"][0]),
                              bind_ghidra_evidence(baseline, second))


# --- Real Ghidra: the manipulations above, applied to a genuine report (opt-in) -------------------

@pytest.fixture(scope="module")
def real_exact(tmp_path_factory):
    if not HEADLESS or not CC:
        pytest.skip("real Ghidra test needs AEGIS_GHIDRA_HEADLESS and a C compiler")
    work = tmp_path_factory.mktemp("real-exact")
    source = work / "fixture.c"
    source.write_text("__attribute__((noinline)) int aegis_exact(int a) { return a * 13 - 2; }\n"
                      "int main(int argc, char **argv) { (void)argv; return aegis_exact(argc); }\n")
    binary = work / "fixture"
    subprocess.run([CC, "-O1", "-fno-inline", "-o", str(binary), str(source)], check=True, timeout=120)
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    tool = planned_ghidra_tool(Path(HEADLESS), function="aegis_exact").model_dump(mode="json")
    baseline, _ = manifests_for(sha, digest("unused protected artifact"), tool)
    report = analyze(binary, work / "out", Path(HEADLESS), function="aegis_exact", expected_sha256=sha)
    return baseline, report.read_bytes()


@pytest.mark.parametrize("name", sorted(MANIPULATIONS))
def test_real_ghidra_report_manipulations_are_rejected(real_exact, name):
    assert_manipulation_rejected(*real_exact, name)
