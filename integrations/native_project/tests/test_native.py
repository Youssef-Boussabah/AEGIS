import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from runner import Failure, Runner, digest
from workflow import REPO, adapter_job, build, load_manifest, resolve_tools, verify_report

OWNED = REPO / "integrations/native_project/examples/owned"


def owned_plan(tmp_path, *, backend="llvm-shield-mirage", optimization="2"):
    project = tmp_path / "owned source"
    shutil.copytree(OWNED, project)
    value = json.loads((project / "project.json").read_text())
    value.update(backend=backend, optimization=optimization)
    (project / "project.json").write_text(json.dumps(value))
    return load_manifest(project / "project.json"), project


@pytest.mark.parametrize("backend", ["llvm-shield", "llvm-shield-mirage"])
@pytest.mark.parametrize("optimization", ["2", "3"])
def test_multifile_native_equivalence_retention_and_integrity(tmp_path, plugin, backend, optimization):
    plan, project = owned_plan(tmp_path, backend=backend, optimization=optimization)
    before = {p.name: digest(p) for p in project.iterdir() if p.is_file()}
    output = tmp_path / "build [space];report=private"
    report = build(plan, output, plugin=plugin, execute=True)
    assert report["status"] == "succeeded", report.get("error")
    assert report["coverage"]["requested_units"] == report["coverage"]["transformed_units"] == 2
    assert report["coverage"]["unprotected_units"] == 2
    assert report["coverage"]["adapter_reported_transformed_functions"] == 3
    assert report["coverage"]["adapter_reported_transformed_sites"] == 5
    assert report["coverage"]["entire_application_protection_claimed"] is False
    assert report["execution"]["status"] == "equivalent_for_cases"
    assert len(report["execution"]["cases"]) == 11
    assert all(c["equal"] for c in report["execution"]["cases"])
    native = report["linked_native_observations"]
    assert {f["name"] for f in native["shield_functions"]} == {"mix_pair", "fold_word", "step_byte"}
    assert any(f["observation"] == "machine_bytes_differ" for f in native["shield_functions"])
    if backend == "llvm-shield-mirage":
        assert len(native["mirage_symbols"]) == 6
        assert all(d["present_only_in_protected"] for d in native["mirage_symbols"])
        options = [u["effective_adapter_options"] for u in report["units"] if u["protect"]]
        assert len({o["mirage-seed"] for o in options}) == 2
    else:
        assert native["mirage_symbols"] == []
    assert before == {p.name: digest(p) for p in project.iterdir() if p.is_file()}
    verified = verify_report(output / "report.json")
    assert verified["status"] == "verified" and verified["signed"] is False
    assert verified["artifact_count"] == len(report["artifacts"])
    target = output / "protected.elf"
    target.write_bytes(target.read_bytes() + b"tamper")
    with pytest.raises(Failure) as info:
        verify_report(output / "report.json")
    assert info.value.code == "ARTIFACT_INTEGRITY_ERROR"


def test_cmake_compile_database_build(tmp_path, plugin):
    plan, project = owned_plan(tmp_path)
    cmake_build = tmp_path / "cmake build"
    runner_root = tmp_path / "configure"
    runner_root.mkdir()
    runner = Runner(runner_root)
    runner.run(["cmake", "-S", project, "-B", cmake_build, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                "-DCMAKE_C_COMPILER=/usr/bin/clang", "-DCMAKE_CXX_COMPILER=/usr/bin/clang++"], tmp_path)
    manifest = json.loads((project / "project.json").read_text())
    manifest["compile_database"] = str(cmake_build / "compile_commands.json")
    for unit in manifest["units"]:
        unit.pop("arguments")
    (project / "project.json").write_text(json.dumps(manifest))
    plan = load_manifest(project / "project.json")
    assert plan["compile_database_entries"] == 4
    report = build(plan, tmp_path / "cdb output", plugin=plugin, execute=True)
    assert report["status"] == "succeeded", report.get("error")
    assert all(case["equal"] for case in report["execution"]["cases"])
    assert report["coverage"]["transformed_units"] == 2


def test_native_execution_requires_opt_in(tmp_path, plugin):
    plan, _ = owned_plan(tmp_path)
    output = tmp_path / "without execution"
    report = build(plan, output, plugin=plugin)
    assert report["status"] == "succeeded"
    assert report["execution"] == {"status": "not_run", "reason": "--execute was not specified"}
    assert not any(c["stage"].startswith("execute-") for c in report["commands"])


def test_partial_failure_never_links_or_counts_failed_units_as_protected(tmp_path, plugin):
    plan, _ = owned_plan(tmp_path)
    plan["units"][1]["arguments"].append("-flto")
    output = tmp_path / "partial"
    report = build(plan, output, plugin=plugin, execute=True)
    assert report["status"] == "failed" and report["error"]["code"] == "BUILD_FAILED"
    assert report["units"][1]["error"]["code"] == "INCOMPATIBLE_UNIT"
    assert report["coverage"]["transformed_units"] == 1
    assert report["coverage"]["failed_units"] == 1
    assert "objects" not in report["units"][1]
    assert not list(output.glob("*.elf"))
    assert report["execution"]["status"] == "not_run"
    assert verify_report(output / "report.json")["build_status"] == "failed"


def test_zero_transformations_is_a_real_failure(tmp_path, plugin):
    plan, _ = owned_plan(tmp_path, backend="llvm-shield")
    plan["units"] = [plan["units"][1]]
    plan["units"][0]["selection"] = {"mode": "annotated"}
    plan["link"] = None
    report = build(plan, tmp_path / "no transforms", plugin=plugin)
    assert report["status"] == "failed"
    error = report["units"][0]["error"]
    assert error["code"] == "ADAPTER_FAILED"
    assert error["details"]["adapter_error"]["code"] == "NO_TRANSFORMATIONS_APPLIED"
    assert report["coverage"]["transformed_units"] == 0
    assert "objects" not in report["units"][0]


def test_integer_signature_selection_to_objects_only(tmp_path, plugin):
    plan, _ = owned_plan(tmp_path, backend="llvm-shield")
    plan["units"] = [plan["units"][1]]
    plan["units"][0]["selection"] = {"mode": "integer-signatures"}
    plan["link"] = None
    output = tmp_path / "objects only"
    report = build(plan, output, plugin=plugin)
    assert report["status"] == "succeeded"
    assert report["units"][0]["selection_observations"]["marked_by_integration"] == ["fold_word", "mix_pair"]
    assert report["coverage"]["adapter_reported_transformed_functions"] == 2
    assert (output / "unit-000/protected.o").is_file()
    assert not list(output.glob("*.elf"))
    assert report["execution"] == {"status": "not_run", "reason": "object-only manifest"}


def test_unsafe_generated_artifact_cannot_be_reported_as_verified(tmp_path, plugin):
    plan, project = owned_plan(tmp_path, backend="llvm-shield")
    (project / "main.cpp").write_text('#include <unistd.h>\nint main() {return symlink("absent", "unsafe-link");}\n')
    plan["link"]["runs"] = [{"args": []}]
    output = tmp_path / "unsafe artifact"
    report = build(plan, output, plugin=plugin, execute=True)
    assert report["status"] == "failed" and report["error"]["code"] == "UNSAFE_PATH"
    assert report["artifact_inventory_complete"] is False
    assert (output / "report.json").is_file()
    with pytest.raises(Failure) as info:
        verify_report(output / "report.json")
    assert info.value.code == "INCOMPLETE_INVENTORY"


@pytest.mark.parametrize("fault", ["syntax", "missing", "oversized", "symbol"])
def test_unit_error_reports(tmp_path, plugin, fault):
    plan, project = owned_plan(tmp_path, backend="llvm-shield")
    plan["units"] = [plan["units"][1]]
    plan["link"] = None
    kwargs = {}
    if fault == "syntax":
        (project / "kernels.cpp").write_text("not valid c++\n")
        code = "TOOL_FAILED"
    elif fault == "missing":
        (project / "kernels.cpp").unlink()
        code = "UNIT_IO_ERROR"
    elif fault == "oversized":
        kwargs["input_limit"] = 16
        code = "INPUT_TOO_LARGE"
    else:
        plan["units"][0]["selection"] = {"mode": "symbols", "symbols": ["missing_function"]}
        code = "INCOMPATIBLE_SELECTION"
    report = build(plan, tmp_path / "bad unit", plugin=plugin, **kwargs)
    assert report["status"] == "failed"
    assert report["units"][0]["error"]["code"] == code
    assert report["coverage"]["failed_units"] == 1


def test_adapter_output_limit_uses_real_production_error(tmp_path, plugin):
    runner = Runner(tmp_path)
    tools, _ = resolve_tools({}, runner)
    ir = tmp_path / "selected.ll"
    ir.write_text('define i32 @sum(i32 %a, i32 %b) "aegis.protect" {\n %x = add i32 %a, %b\n ret i32 %x\n}\n')
    with pytest.raises(Failure) as info:
        adapter_job(runner, tools, plugin, ir, "llvm-shield", {"seed": "42"}, 65536, 100)
    assert info.value.code == "ADAPTER_FAILED"
    assert info.value.details["adapter_error"]["code"] == "OUTPUT_TOO_LARGE"


def test_missing_plugin_and_tool_fail_with_records(tmp_path, plugin):
    plan, _ = owned_plan(tmp_path)
    for label, kwargs, expected in (
        ("plugin", {"plugin": tmp_path / "missing.so"}, "PLUGIN_UNAVAILABLE"),
        ("tool", {"plugin": plugin, "tool_paths": {"opt": str(tmp_path / "missing-opt")}}, "TOOL_UNAVAILABLE"),
    ):
        report = build(plan, tmp_path / label, **kwargs)
        assert report["status"] == "failed" and report["error"]["code"] == expected
        assert verify_report(tmp_path / label / "report.json")["build_status"] == "failed"


def test_observed_execution_mismatch_is_not_equivalence(tmp_path, plugin):
    plan, project = owned_plan(tmp_path, backend="llvm-shield")
    # Printing argv[0] intentionally distinguishes the three differently named
    # binaries. This is an owned program; protection output is never fabricated.
    (project / "main.cpp").write_text('#include <cstdio>\nint main(int, char** argv) {std::puts(argv[0]);}\n')
    plan["link"]["runs"] = [{"args": []}]
    report = build(plan, tmp_path / "mismatch", plugin=plugin, execute=True)
    assert report["status"] == "failed" and report["error"]["code"] == "EXECUTION_MISMATCH"
    assert report["execution"]["status"] == "failed"
    assert report["execution"]["cases"][0]["equal"] is False


def test_cli_build_plan_and_verify(tmp_path, plugin):
    _, project = owned_plan(tmp_path)
    script = REPO / "integrations/native_project/native_project.py"
    plan = subprocess.run([sys.executable, script, "plan", project / "project.json"],
                          capture_output=True, timeout=30)
    assert plan.returncode == 0 and len(json.loads(plan.stdout)["units"]) == 4
    output = tmp_path / "cli"
    built = subprocess.run([sys.executable, script, "build", project / "project.json", "--output", output,
                            "--plugin", plugin, "--execute"], capture_output=True, timeout=60)
    assert built.returncode == 0, built.stderr + built.stdout
    assert json.loads(built.stdout)["execution"] == "equivalent_for_cases"
    verified = subprocess.run([sys.executable, script, "verify", output / "report.json"],
                             capture_output=True, timeout=30)
    assert verified.returncode == 0 and json.loads(verified.stdout)["status"] == "verified"
    again = subprocess.run([sys.executable, script, "build", project / "project.json", "--output", output,
                            "--plugin", plugin], capture_output=True, timeout=30)
    assert again.returncode == 1 and json.loads(again.stderr)["status"] == "failed"
