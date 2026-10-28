"""Offline worker-contract tests. These intentionally mock Ghidra's CLI.

A separate on-host smoke test must exercise the actual Java exporter; these
unit tests cannot prove that Ghidra compiled or ran the Java script.
See test_ghidra_real.py for the opt-in real-Ghidra test.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from aegis_lab import ghidra as ghidra_module
from aegis_lab.ghidra import AnalysisReport, WorkerError, analyze, main

EXPORTER = Path(ghidra_module.__file__).resolve().parents[2] / "scripts" / "AegisExportFunctions.java"


@pytest.fixture
def binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.elf"
    path.write_bytes(b"\x7fELF\x00AEGIS-owned-test")
    return path


def fake_ghidra(tmp_path: Path, mode: str = "ok", version: str = "12.1.4") -> Path:
    """Create a fake launcher inside a minimal Ghidra installation layout."""
    root = tmp_path / "ghidra"
    (root / "support").mkdir(parents=True, exist_ok=True)
    (root / "Ghidra").mkdir(exist_ok=True)
    (root / "Ghidra" / "application.properties").write_text(
        f"application.name=Ghidra\napplication.version={version}\n"
        "application.release.name=PUBLIC\napplication.revision.ghidra=fake-revision\n"
    )
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    path = root / "support" / "fake-headless"
    body = r'''#!/usr/bin/env python3
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
args = sys.argv[1:]
assert '-import' in args
assert '-scriptPath' in args
assert '-postScript' in args
assert '-deleteProject' in args
j = args.index('-postScript')
assert args[j+1] == 'AegisExportFunctions.java'
output = Path(args[j+2])
selector = args[j+3]
imported = Path(args[args.index('-import')+1])
state = Path(__STATE__)
mode = __MODE__
executable_sha256 = hashlib.sha256(imported.read_bytes()).hexdigest()  # as Ghidra records it at import
(state / 'argv.json').write_text(json.dumps(args))
(state / 'env.json').write_text(json.dumps(dict(os.environ)))
(state / 'cwd').write_text(os.getcwd())
if mode in ('timeout', 'straggler', 'straggler-timeout'):
    child = subprocess.Popen(['sleep', '60'])
    (state / 'child.pid').write_text(str(child.pid))
if mode == 'crash':
    print('fake analyzer failed')
    sys.exit(7)
if mode in ('timeout', 'straggler-timeout'):
    time.sleep(10)
if mode == 'missing':
    sys.exit(0)
if mode == 'badjson':
    output.write_text('{oops')
    sys.exit(0)
if mode == 'huge-export':
    output.write_text(' ' * (5 * 1024 * 1024))
    sys.exit(0)
def fn(name='add', code='int add(int a, int b) { return a + b; }', ok=True, entry='00101120', error='',
       status=None, message=''):
    status = status or ('completed_with_warnings' if message else 'completed') if ok else (status or 'failed')
    return {'name': name, 'qualified_name': name, 'entry_point': entry, 'is_thunk': False,
            'signature': 'int ' + name + '(int a, int b)',
            'decompiler_signature': 'int ' + name + '(int a, int b)' if ok else '',
            'decompile_success': ok, 'decompile_status': status, 'decompiled_c': code if ok else '',
            'decompiled_c_truncated': False, 'decompiler_message': message,
            'decompiler_message_truncated': False, 'error': error}
functions = [fn()]
program_name = imported.name
version = '12.1.4'
timed_out = False
if mode == 'no-functions':
    functions = []
if mode == 'malformed':
    functions[0]['decompile_success'] = 'false'
if mode == 'changed':
    os.chmod(imported, 0o600)
    imported.write_bytes(b'changed')
if mode == 'analysis-timeout':
    timed_out = True
if mode == 'timeout-log':
    print('ERROR REPORT: Analysis timed out at 1 seconds. Processing not completed for file')
if mode == 'script-error':
    print('ERROR REPORT SCRIPT ERROR:  (HeadlessAnalyzer) java.lang.IllegalStateException: boom')
if mode == 'ambiguous':
    functions = [fn(entry='00101120'), fn(entry='00102000')]
if mode == 'decompile-failed':
    functions = [fn(ok=False, error='decompiler timed out after 30s', status='timed_out')]
if mode == 'inconsistent-failure':
    functions = [fn(ok=False, error='')]
if mode == 'partial':
    functions = [fn(), fn(name='broken', ok=False, entry='00102000', error='pcode error')]
if mode == 'all-failed':
    functions = [fn(ok=False, error='e1'), fn(name='other', ok=False, entry='00102000', error='e2')]
if mode == 'wrong-name':
    functions = [fn(name='main')]
if mode == 'two-functions':
    functions = [fn(), fn(name='main', entry='00102000')]
if mode == 'long-code':
    functions = [fn(code='x' * 101)]
if mode == 'wrong-program':
    program_name = 'libc.so.6'
if mode == 'version-skew':
    version = '12.0'
if mode == 'huge-log':
    sys.stdout.write('L' * (300 * 1024) + '\n')
if mode == 'paths':
    print('scratch=' + os.getcwd() + '/project ghidra=' + __ROOT__)
out = {'schema_version':'aegis.lab.ghidra.v1', 'ghidra_version': version,
       'ghidra_release_name': 'PUBLIC', 'ghidra_build_date': '2026-Sep-21 1613 UTC',
       'java_version': '21.0.12', 'analysis_timed_out': timed_out,
       'program_name': program_name, 'executable_sha256': executable_sha256,
       'executable_format':'ELF', 'language_id':'x86:LE:64:default',
       'functions':functions, 'matching_function_count':len(functions),
       'functions_limited':False}
# Optional per-test hook (state/hook.py) may mutate `out`, set `raw` (bytes to write
# verbatim) or replace the output file itself before the fake exits.
raw = None
hook = state / 'hook.py'
if hook.exists():
    exec(hook.read_text())
if raw is not None:
    output.write_bytes(raw)
elif not output.exists() and not output.is_symlink():
    output.write_text(json.dumps(out))
print('fake analyzer warning')
'''.replace("__MODE__", repr(mode)).replace("__STATE__", repr(str(state))).replace("__ROOT__", repr(str(root)))
    path.write_text(body)
    path.chmod(0o755)
    return path


def run(binary: Path, tmp_path: Path, mode: str = "ok", **kwargs) -> Path:
    return analyze(binary, tmp_path / "output", fake_ghidra(tmp_path, mode), **kwargs)


def hooked_ghidra(tmp_path: Path, hook: str, mode: str = "ok") -> Path:
    """Fake launcher whose export is changed by ``hook`` (Python run inside the fake)."""
    launcher = fake_ghidra(tmp_path, mode)
    (tmp_path / "state" / "hook.py").write_text(hook)
    return launcher


def _dead(pid: int, wait: float = 3.0) -> bool:
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            if not Path("/proc").is_dir():
                os.kill(pid, 0)
                time.sleep(0.05)
                continue
            status = Path(f"/proc/{pid}/stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            return True
        if status.rsplit(")", 1)[1].split()[0] in ("Z", "X"):
            return True
        time.sleep(0.05)
    return False


def test_success_writes_verified_structured_evidence(binary: Path, tmp_path: Path) -> None:
    result = run(binary, tmp_path, expected_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), function="add")
    report = AnalysisReport.model_validate_json(result.read_bytes())
    assert report.binary.sha256 == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert report.analysis.executable_format == "ELF"
    assert report.analysis.functions[0].decompiled_c.startswith("int add(")
    assert report.export.selected_function == "add"
    assert "fake analyzer warning" in report.warnings_and_logs
    assert result.stat().st_mode & 0o777 == 0o600
    assert report.limitations


def test_does_not_overwrite_report(binary: Path, tmp_path: Path) -> None:
    run(binary, tmp_path)
    with pytest.raises(WorkerError, match="already exists"):
        run(binary, tmp_path)


def test_reject_mismatch_before_running(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="SHA-256"):
        run(binary, tmp_path, expected_sha256="0" * 64)
    assert not (tmp_path / "output").exists()


def test_reject_symlink_binary(binary: Path, tmp_path: Path) -> None:
    alias = tmp_path / "linked.elf"
    alias.symlink_to(binary)
    with pytest.raises(WorkerError, match="symlink"):
        run(alias, tmp_path)


def test_reject_symlink_output_directory(binary: Path, tmp_path: Path) -> None:
    destination = tmp_path / "target"
    destination.mkdir()
    (tmp_path / "output").symlink_to(destination)
    with pytest.raises(WorkerError, match="symlink"):
        run(binary, tmp_path)


def test_reject_empty_input(tmp_path: Path) -> None:
    binary = tmp_path / "empty"
    binary.touch()
    with pytest.raises(WorkerError, match="zero"):
        run(binary, tmp_path)


def test_ghidra_crash_never_creates_report(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="exited 7"):
        run(binary, tmp_path, "crash")
    assert not (tmp_path / "output" / "ghidra-analysis.json").exists()


def test_missing_export_never_creates_report(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="without exporting"):
        run(binary, tmp_path, "missing")


def test_invalid_json_fails_closed(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="invalid Ghidra structured output"):
        run(binary, tmp_path, "badjson")


def test_invalid_types_fails_closed(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="invalid Ghidra structured output"):
        run(binary, tmp_path, "malformed")


def test_no_functions_is_error(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="no matching"):
        run(binary, tmp_path, "no-functions")


def test_mutated_binary_is_error(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="changed during analysis"):
        run(binary, tmp_path, "changed")
    assert not (tmp_path / "output" / "ghidra-analysis.json").exists()


def test_timeout_fails_closed(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="exceeded 1s"):
        run(binary, tmp_path, "timeout", wall_timeout_seconds=1)


def test_bounded_options(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="invalid function count"):
        run(binary, tmp_path, max_functions=0)
    with pytest.raises(WorkerError, match="invalid wall timeout"):
        run(binary, tmp_path, wall_timeout_seconds=0)


def test_failed_cli_exit(binary: Path, tmp_path: Path, capsys) -> None:
    headless = fake_ghidra(tmp_path, "badjson")
    rc = main(["--binary", str(binary), "--output-dir", str(tmp_path / "out"), "--headless", str(headless)])
    assert rc == 1
    assert "failed" in capsys.readouterr().err


def test_positive_cli_exit(binary: Path, tmp_path: Path, capsys) -> None:
    headless = fake_ghidra(tmp_path)
    rc = main(["--binary", str(binary), "--output-dir", str(tmp_path / "out"), "--headless", str(headless)])
    assert rc == 0
    assert (tmp_path / "out" / "ghidra-analysis.json").exists()


# --- Hardening: incomplete analysis and exporter/request mismatches -------------


def test_analysis_timeout_flag_fails_closed(binary: Path, tmp_path: Path) -> None:
    # Ghidra 12.1.x still runs post-scripts after -analysisTimeoutPerFile fires.
    with pytest.raises(WorkerError, match="auto-analysis timed out"):
        run(binary, tmp_path, "analysis-timeout")
    assert not (tmp_path / "output" / "ghidra-analysis.json").exists()


def test_analysis_timeout_log_marker_fails_closed(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="auto-analysis timed out"):
        run(binary, tmp_path, "timeout-log")


def test_script_error_marker_fails_closed_even_with_output(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="post-script error"):
        run(binary, tmp_path, "script-error")


def test_ambiguous_selector_fails_closed(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="ambiguous selector 'add': 2 functions"):
        run(binary, tmp_path, "ambiguous", function="add")


def test_selected_function_decompile_failure_fails_closed(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="decompilation of 'add' failed: decompiler timed out"):
        run(binary, tmp_path, "decompile-failed", function="add")


def test_wildcard_partial_failure_is_reported(binary: Path, tmp_path: Path) -> None:
    report = AnalysisReport.model_validate_json(run(binary, tmp_path, "partial").read_bytes())
    assert (report.decompiled_ok_count, report.decompile_failed_count) == (1, 1)
    assert report.analysis.functions[1].error == "pcode error"
    assert any("Decompilation failed" in item for item in report.limitations)


def test_wildcard_all_failed_fails_closed(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="no exported function decompiled successfully"):
        run(binary, tmp_path, "all-failed")


def test_failure_without_error_text_is_invalid(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="invalid Ghidra structured output"):
        run(binary, tmp_path, "inconsistent-failure")


def test_exporter_must_honor_selector(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="non-matching function") as exc:
        run(binary, tmp_path, "wrong-name", function="add")
    # The exporter-controlled name is identified by position, never echoed.
    assert "main" not in str(exc.value)
    assert exc.value.violations == (("analysis.functions.0.name", "not_selected"),)
    assert exc.value.category == "analysis_rejected"


def test_exporter_must_honor_function_limit(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="more functions than requested"):
        run(binary, tmp_path, "two-functions", max_functions=1)


def test_exporter_must_honor_source_limit(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="length limit"):
        run(binary, tmp_path, "long-code", max_c_chars=100)


def test_exported_program_must_be_the_input(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="not the analyzed input"):
        run(binary, tmp_path, "wrong-program")


def test_oversized_export_fails_closed(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="bounded export limit"):
        run(binary, tmp_path, "huge-export")


# --- Tool identity and version pinning -----------------------------------------


def test_report_identifies_tool_exporter_and_parameters(binary: Path, tmp_path: Path) -> None:
    report = AnalysisReport.model_validate_json(run(binary, tmp_path, function="add").read_bytes())
    launcher = tmp_path / "ghidra" / "support" / "fake-headless"
    props = tmp_path / "ghidra" / "Ghidra" / "application.properties"
    assert report.export.ghidra_version == "12.1.4"
    assert report.export.ghidra_release_name == "PUBLIC"
    assert report.export.ghidra_revision == "fake-revision"
    assert report.export.java_version == "21.0.12"
    assert report.export.exporter_name == "AegisExportFunctions.java"
    assert report.export.exporter_script_sha256 == hashlib.sha256(EXPORTER.read_bytes()).hexdigest()
    assert report.export.ghidra_launcher_sha256 == hashlib.sha256(launcher.read_bytes()).hexdigest()
    assert report.export.ghidra_application_properties_sha256 == hashlib.sha256(props.read_bytes()).hexdigest()
    assert report.export.wall_timeout_seconds == 300
    assert (report.decompiled_ok_count, report.decompile_failed_count) == (1, 0)


def test_runtime_version_must_match_installation(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="reported version 12.0, installation declares 12.1.4"):
        run(binary, tmp_path, "version-skew")


def test_expected_ghidra_version_checked_before_running(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="installation is 12.1.4, expected 11.0"):
        run(binary, tmp_path, expected_ghidra_version="11.0")
    assert not (tmp_path / "state" / "argv.json").exists()


def test_unvalidated_ghidra_version_is_a_stated_limitation(binary: Path, tmp_path: Path) -> None:
    headless = fake_ghidra(tmp_path, "version-skew", version="12.0")
    report = AnalysisReport.model_validate_json(analyze(binary, tmp_path / "out", headless).read_bytes())
    assert any("validated with Ghidra 12.1.4 only; this run used 12.0" in item for item in report.limitations)


def test_launcher_outside_ghidra_installation_rejected(binary: Path, tmp_path: Path) -> None:
    headless = fake_ghidra(tmp_path)
    (tmp_path / "ghidra" / "Ghidra" / "application.properties").unlink()
    with pytest.raises(WorkerError, match="not inside a Ghidra installation"):
        analyze(binary, tmp_path / "out", headless)


# --- Argument, path, environment and cleanup safety ----------------------------


@pytest.mark.parametrize("selector", ["-import", "--help", "add\nmain", "a\x00b"])
def test_selector_cannot_inject_options_or_control_characters(binary: Path, tmp_path: Path, selector: str) -> None:
    with pytest.raises(WorkerError, match="must not start with '-' or contain control characters"):
        run(binary, tmp_path, function=selector)


@pytest.mark.parametrize("digest", ["A" * 64, "0" * 63, "not-a-digest"])
def test_expected_sha256_format_is_checked(binary: Path, tmp_path: Path, digest: str) -> None:
    with pytest.raises(WorkerError, match="64 lowercase hexadecimal"):
        run(binary, tmp_path, expected_sha256=digest)


def test_ghidra_reads_private_copy_and_scratch_is_removed(binary: Path, tmp_path: Path) -> None:
    run(binary, tmp_path, function="add")
    argv = json.loads((tmp_path / "state" / "argv.json").read_text())
    imported = Path(argv[argv.index("-import") + 1])
    script_dir = Path(argv[argv.index("-scriptPath") + 1])
    scratch = Path((tmp_path / "state" / "cwd").read_text())
    assert imported != binary and imported.name == binary.name
    assert imported.is_relative_to(scratch) and script_dir.is_relative_to(scratch)
    assert not scratch.exists()


def test_scratch_is_removed_after_failure(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError):
        run(binary, tmp_path, "crash")
    assert not Path((tmp_path / "state" / "cwd").read_text()).exists()


def test_environment_is_minimal_and_contained(binary: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NEBIUS_API_KEY", "must-not-leak")
    monkeypatch.setenv("GHIDRA_HEADLESS_JAVA_OPTIONS", "-Dattacker=1")
    run(binary, tmp_path)
    env = json.loads((tmp_path / "state" / "env.json").read_text())
    scratch = (tmp_path / "state" / "cwd").read_text()
    assert "NEBIUS_API_KEY" not in env
    assert "must-not-leak" not in json.dumps(env)
    for key in ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
        assert env[key].startswith(scratch)
    assert env["GHIDRA_HEADLESS_JAVA_OPTIONS"] == f"-Djava.io.tmpdir={scratch}/jtmp -XX:-UsePerfData"


def test_timeout_kills_whole_process_group(binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="exceeded 1s"):
        run(binary, tmp_path, "straggler-timeout", wall_timeout_seconds=1)
    assert _dead(int((tmp_path / "state" / "child.pid").read_text()))


def test_stragglers_killed_after_normal_exit(binary: Path, tmp_path: Path) -> None:
    started = time.monotonic()
    run(binary, tmp_path, "straggler")
    assert time.monotonic() - started < 30
    assert _dead(int((tmp_path / "state" / "child.pid").read_text()))


def test_log_is_bounded_and_flagged(binary: Path, tmp_path: Path) -> None:
    report = AnalysisReport.model_validate_json(run(binary, tmp_path, "huge-log").read_bytes())
    assert report.log_truncated is True
    assert report.log_bytes_total > ghidra_module.MAX_LOG_BYTES
    assert len(report.warnings_and_logs.encode()) <= ghidra_module.MAX_LOG_BYTES
    assert "fake analyzer warning" in report.warnings_and_logs


def test_report_redacts_local_paths(binary: Path, tmp_path: Path) -> None:
    result = run(binary, tmp_path, "paths")
    scratch = (tmp_path / "state" / "cwd").read_text()
    text = result.read_text()
    report = AnalysisReport.model_validate_json(text)
    assert scratch not in text
    assert str(tmp_path / "ghidra") not in text
    assert "scratch=<scratch>/project" in report.warnings_and_logs
    assert "ghidra=<ghidra>" in report.warnings_and_logs


def test_no_partial_files_left_in_output(binary: Path, tmp_path: Path) -> None:
    run(binary, tmp_path)
    assert sorted(p.name for p in (tmp_path / "output").iterdir()) == ["ghidra-analysis.json"]


def test_cli_passes_timeouts_and_version_pin(binary: Path, tmp_path: Path) -> None:
    headless = fake_ghidra(tmp_path)
    rc = main(["--binary", str(binary), "--output-dir", str(tmp_path / "out"), "--headless", str(headless),
               "--decompile-timeout", "7", "--analysis-timeout", "9", "--expected-ghidra-version", "12.1.4"])
    assert rc == 0
    argv = json.loads((tmp_path / "state" / "argv.json").read_text())
    j = argv.index("-postScript")
    assert argv[j + 6] == "7"
    assert argv[argv.index("-analysisTimeoutPerFile") + 1] == "9"


# --- Audit hardening: shared report invariants (worker side) -----------------------------------

SECRET = "AEGIS-SYNTHETIC-SECRET-7f3a9c"


def run_hook(binary: Path, tmp_path: Path, hook: str, mode: str = "ok", **kwargs) -> Path:
    return analyze(binary, tmp_path / "output", hooked_ghidra(tmp_path, hook, mode), **kwargs)


def reject(binary: Path, tmp_path: Path, hook: str, **kwargs) -> WorkerError:
    with pytest.raises(WorkerError) as exc:
        run_hook(binary, tmp_path, hook, **kwargs)
    assert not (tmp_path / "output" / "ghidra-analysis.json").exists()
    return exc.value


@pytest.mark.parametrize(("hook", "kwargs", "violation"), [
    ("out['executable_sha256'] = 'f' * 64", {}, ("analysis.executable_sha256", "not_analyzed_input")),
    ("out['functions'] = [fn(), fn(name='sub')]; out['matching_function_count'] = 2", {},
     ("analysis.functions.1.entry_point", "duplicate")),
    ("out['matching_function_count'] = 3; out['functions_limited'] = True\nout['functions'] = [fn()]",
     {"max_functions": 2}, ("analysis.functions", "count_inconsistent")),
    ("out['functions'][0].update(decompiled_c='x' * 50, decompiled_c_truncated=True)",
     {"max_c_chars": 100}, ("analysis.functions.0.decompiled_c_truncated", "truncation_inconsistent")),
    # 99 + one astral character = 101 UTF-16 units: over the Java limit although len() == 100.
    ("out['functions'][0]['decompiled_c'] = 'x' * 99 + '\\U0001F600'",
     {"max_c_chars": 100}, ("analysis.functions.0.decompiled_c", "exceeds_max_c_chars")),
])
def test_worker_rejects_invariant_violations(binary, tmp_path, hook, kwargs, violation):
    error = reject(binary, tmp_path, hook, **kwargs)
    assert error.category == "analysis_rejected"
    assert violation in error.violations


def test_worker_accepts_exact_truncation_with_astral_characters(binary, tmp_path):
    hook = "out['functions'][0].update(decompiled_c='x' * 98 + '\\U0001F600', decompiled_c_truncated=True)"
    report = AnalysisReport.model_validate_json(run_hook(binary, tmp_path, hook, max_c_chars=100).read_bytes())
    assert report.analysis.functions[0].decompiled_c_truncated is True
    assert any("truncated at max_c_chars" in item for item in report.limitations)


def test_exact_selector_with_duplicate_entry_points_is_ambiguous(binary, tmp_path):
    error = reject(binary, tmp_path, "out['functions'] = [fn(), fn()]; out['matching_function_count'] = 2",
                   function="add")
    assert ("analysis.matching_function_count", "ambiguous_selector") in error.violations
    assert ("analysis.functions.1.entry_point", "duplicate") in error.violations


def test_published_report_is_accepted_by_the_binder_parser(binary, tmp_path):
    from aegis_lab.ghidra import parse_analysis_report

    data = run(binary, tmp_path, function="add").read_bytes()
    assert parse_analysis_report(data).analysis.executable_sha256 == hashlib.sha256(binary.read_bytes()).hexdigest()


def test_report_model_itself_enforces_invariants(binary, tmp_path):
    from pydantic import ValidationError

    from aegis_lab.ghidra import REPORT_INVARIANT_ERROR, ReportInvariantError, parse_analysis_report

    document = json.loads(run(binary, tmp_path).read_bytes())
    document["analysis"]["analysis_timed_out"] = True
    data = json.dumps(document).encode()
    with pytest.raises(ValidationError) as exc:
        AnalysisReport.model_validate_json(data)  # even a direct parse cannot skip the invariants
    assert exc.value.errors()[0]["type"] == REPORT_INVARIANT_ERROR
    with pytest.raises(ReportInvariantError) as invariant:
        parse_analysis_report(data)
    assert invariant.value.violations == (("analysis.analysis_timed_out", "analysis_incomplete"),)


# --- Strict raw JSON (duplicate keys and other unsupported representations) ---------------------

@pytest.mark.parametrize(("hook", "category"), [
    ("out['analysis_timed_out'] = True\n"
     "raw = json.dumps(out).replace('\"analysis_timed_out\": true', "
     "'\"analysis_timed_out\": true, \"analysis_timed_out\": false').encode()", "duplicate_key"),
    ("raw = json.dumps(out).replace('\"matching_function_count\": 1', '\"matching_function_count\": NaN').encode()",
     "non_finite_number"),
    ("raw = json.dumps(out).replace('\"matching_function_count\": 1', '\"matching_function_count\": 1e999').encode()",
     "non_finite_number"),
    ("raw = json.dumps(out).encode().replace(b'ELF', b'\\xff\\xfeLF')", "invalid_utf8"),
    ("raw = b''", "empty"),
    ("raw = json.dumps(out).encode()[:-1]", "malformed_json"),
    ("os.mkfifo(output)", "not_regular_file"),
    ("os.symlink(str(imported), str(output))", "symlink_rejected"),
])
def test_raw_export_must_be_strict_json_in_a_regular_file(binary, tmp_path, hook, category):
    started = time.monotonic()
    error = reject(binary, tmp_path, hook)
    assert time.monotonic() - started < 30  # a FIFO is rejected, never waited on
    assert error.category == "invalid_ghidra_output"
    assert str(error) == f"invalid Ghidra structured output: {category}"


def test_duplicate_timeout_key_never_publishes(binary, tmp_path):
    # Codex's reproduction: contradictory duplicates must not resolve to "last value wins".
    hook = ("raw = json.dumps(out).replace('\"analysis_timed_out\": false', "
            "'\"analysis_timed_out\": true, \"analysis_timed_out\": false').encode()")
    reject(binary, tmp_path, hook)
    assert not (tmp_path / "output").exists() or not any((tmp_path / "output").iterdir())


# --- Decompiler outcomes: warnings, failures, truncation -----------------------------------------

def test_success_with_warnings_is_kept_and_reported(binary, tmp_path):
    hook = ("out['functions'] = [fn(message='Unable to resolve jump table'), fn(name='sub', entry='00102000')]; "
            "out['matching_function_count'] = 2")
    report = AnalysisReport.model_validate_json(run_hook(binary, tmp_path, hook).read_bytes())
    warned, clean = report.analysis.functions
    assert (warned.decompile_status, warned.decompile_success) == ("completed_with_warnings", True)
    assert warned.decompiler_message == "Unable to resolve jump table" and warned.error == ""
    assert (clean.decompile_status, clean.decompiler_message) == ("completed", "")
    assert report.decompiled_ok_count == 2
    assert any("decompiler reported warnings" in item for item in report.limitations)


def test_exact_selector_with_warnings_is_not_a_failure(binary, tmp_path):
    hook = "out['functions'] = [fn(message='w' * 2000)]; out['functions'][0]['decompiler_message_truncated'] = True"
    report = AnalysisReport.model_validate_json(run_hook(binary, tmp_path, hook, function="add").read_bytes())
    assert report.analysis.functions[0].decompile_status == "completed_with_warnings"
    assert any("decompiler message was truncated" in item for item in report.limitations)


@pytest.mark.parametrize(("status", "text"), [
    ("timed_out", "decompiler timed out"),
    ("cancelled", "decompilation cancelled"),
    ("failed_to_start", "decompiler failed to start"),
    ("failed", "decompiler error"),
])
def test_selected_failure_is_classified_without_echoing_ghidra_text(binary, tmp_path, status, text):
    hook = f"out['functions'] = [fn(ok=False, status={status!r}, error={SECRET!r} + '\\x1b[2J')]"
    error = reject(binary, tmp_path, hook, function="add")
    assert str(error) == f"decompilation of 'add' failed: {text} (analysis.functions.0.decompile_status)"
    assert SECRET not in str(error)


@pytest.mark.parametrize("change", [
    {"decompile_status": "failed"},                                # success flag with a failure status
    {"decompile_status": "completed", "decompiler_message": "w"},  # message on a clean success
    {"decompile_status": "completed_with_warnings"},               # warning status without a message
    {"error": "leftover"},                                         # success with an error
    {"decompiler_message_truncated": True},                        # truncation flag without a message
    {"decompile_status": "completed_with_warnings", "decompiler_message": "w" * 2001},  # unbounded
])
def test_function_outcome_must_be_self_consistent(binary, tmp_path, change):
    error = reject(binary, tmp_path, f"out['functions'][0].update({change!r})")
    assert error.category == "invalid_ghidra_output"
    assert "functions.0" in str(error)


def test_failed_function_cannot_claim_success_status(binary, tmp_path):
    error = reject(binary, tmp_path, "out['functions'] = [fn(), fn(name='b', entry='2', ok=False, error='e', "
                                     "status='completed')]; out['matching_function_count'] = 2")
    assert error.category == "invalid_ghidra_output"


# --- Safe file loading -------------------------------------------------------------------------

def _finishes(target, seconds: float = 20.0):
    """Run ``target`` in a thread; fail (instead of hanging the suite) if it blocks."""
    import threading

    outcome: dict = {}

    def body():
        try:
            outcome["value"] = target()
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            outcome["error"] = exc

    thread = threading.Thread(target=body, daemon=True)
    thread.start()
    thread.join(seconds)
    return not thread.is_alive(), outcome


def _unblock(fifo: Path) -> None:
    try:
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
    except OSError:
        pass


def _skip_precheck(monkeypatch) -> None:
    # Simulates a file swapped for a FIFO after the lstat() pre-check passed.
    monkeypatch.setattr(ghidra_module, "_verify_regular_file", lambda path, role, **kw: Path(path).absolute())


def test_fifo_substituted_input_is_rejected_without_blocking(tmp_path, monkeypatch):
    fifo = tmp_path / "sample.elf"
    os.mkfifo(fifo)
    _skip_precheck(monkeypatch)
    done, outcome = _finishes(lambda: analyze(fifo, tmp_path / "output", fake_ghidra(tmp_path)))
    _unblock(fifo)
    assert done, "input staging blocked on a FIFO"
    assert isinstance(outcome["error"], WorkerError)
    assert outcome["error"].category == "invalid_input"
    assert not (tmp_path / "state" / "argv.json").exists()  # Ghidra never started


def test_fifo_substituted_exporter_is_rejected_without_blocking(binary, tmp_path, monkeypatch):
    fifo = tmp_path / "scripts" / "AegisExportFunctions.java"
    fifo.parent.mkdir()
    os.mkfifo(fifo)
    _skip_precheck(monkeypatch)
    done, outcome = _finishes(lambda: analyze(binary, tmp_path / "output", fake_ghidra(tmp_path), script_path=fifo))
    _unblock(fifo)
    assert done and isinstance(outcome["error"], WorkerError)
    assert outcome["error"].category == "invalid_installation"


def test_fifo_launcher_is_not_hashed_by_blocking_read(binary, tmp_path, monkeypatch):
    launcher = fake_ghidra(tmp_path)
    launcher.unlink()
    os.mkfifo(launcher, 0o755)
    _skip_precheck(monkeypatch)
    done, outcome = _finishes(lambda: analyze(binary, tmp_path / "output", launcher))
    _unblock(launcher)
    assert done and isinstance(outcome["error"], WorkerError)
    assert outcome["error"].category == "invalid_installation"


def test_fifo_application_properties_is_rejected_without_blocking(binary, tmp_path):
    launcher = fake_ghidra(tmp_path)
    properties = tmp_path / "ghidra" / "Ghidra" / "application.properties"
    properties.unlink()
    os.mkfifo(properties)
    done, outcome = _finishes(lambda: ghidra_module._read_application_properties(launcher))
    _unblock(properties)
    assert done and isinstance(outcome["error"], WorkerError)
    assert "not inside a Ghidra installation" in str(outcome["error"])


def test_symlinked_application_properties_is_rejected(binary, tmp_path):
    launcher = fake_ghidra(tmp_path)
    properties = tmp_path / "ghidra" / "Ghidra" / "application.properties"
    real = tmp_path / "elsewhere.properties"
    real.write_bytes(properties.read_bytes())
    properties.unlink()
    properties.symlink_to(real)
    with pytest.raises(WorkerError, match="not inside a Ghidra installation"):
        analyze(binary, tmp_path / "output", launcher)


def test_oversized_application_properties_is_rejected_before_reading(binary, tmp_path, monkeypatch):
    launcher = fake_ghidra(tmp_path)
    properties = tmp_path / "ghidra" / "Ghidra" / "application.properties"
    with properties.open("r+b") as handle:
        handle.truncate(1 << 30)  # sparse 1 GiB
    import aegis_lab.safe_io as safe_io

    reads: list[int] = []
    real_read = safe_io.os.read
    monkeypatch.setattr(safe_io.os, "read", lambda fd, n: reads.append(n) or real_read(fd, n))
    with pytest.raises(WorkerError, match="exceeds size limit"):
        ghidra_module._read_application_properties(launcher)
    assert reads == []


@pytest.mark.parametrize("version", ["", "12.1.4 \x1b[2J", f"12.1.4;{SECRET}!", "-12", "1" * 65])
def test_application_version_must_have_a_safe_format(binary, tmp_path, version):
    launcher = fake_ghidra(tmp_path, version="12.1.4")
    properties = tmp_path / "ghidra" / "Ghidra" / "application.properties"
    properties.write_text(f"application.version={version}\n")
    with pytest.raises(WorkerError, match="no valid application.version") as exc:
        analyze(binary, tmp_path / "output", launcher)
    assert SECRET not in str(exc.value)


def test_unreadable_input_is_a_worker_error(binary, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root bypasses file permissions")
    binary.chmod(0)
    with pytest.raises(WorkerError) as exc:
        run(binary, tmp_path)
    assert exc.value.category == "invalid_input"
    assert str(exc.value) == "input binary could not be read (permission_denied)"


def test_output_directory_replaced_during_analysis_is_not_followed(binary, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    output = tmp_path / "output"
    hook = (f"os.rename({str(output)!r}, {str(output) + '.moved'!r}); "
            f"os.symlink({str(elsewhere)!r}, {str(output)!r})")
    with pytest.raises(WorkerError, match="output directory was replaced") as exc:
        run_hook(binary, tmp_path, hook)
    assert exc.value.category == "output_failed"
    assert list(elsewhere.iterdir()) == []
    assert list((tmp_path / "output.moved").iterdir()) == []


def test_output_directory_removed_during_analysis_fails_closed(binary, tmp_path):
    with pytest.raises(WorkerError, match="output directory was removed"):
        run_hook(binary, tmp_path, f"import shutil; shutil.rmtree({str(tmp_path / 'output')!r})")
    assert not (tmp_path / "output").exists()


# --- CLI diagnostics never echo rejected or tool-controlled values -------------------------------

def _cli(capsys, argv) -> tuple[int, str]:
    try:
        rc = main(argv)
    except SystemExit as exc:  # argparse
        rc = exc.code
    captured = capsys.readouterr()
    return rc, captured.out + captured.err


def _assert_clean(text: str, *extra: str) -> None:
    for forbidden in (SECRET, "\x1b", "input_value", "pydantic", "Traceback", *extra):
        assert forbidden not in text


def test_cli_does_not_echo_rejected_json_values(binary, tmp_path, capsys):
    headless = hooked_ghidra(tmp_path, f"out['functions'][0]['decompile_success'] = {SECRET!r} + '\\x1b[2J'")
    rc, text = _cli(capsys, ["--binary", str(binary), "--output-dir", str(tmp_path / "o"), "--headless", str(headless)])
    assert rc == 1
    assert "[invalid_ghidra_output]" in text and "functions.0.decompile_success: invalid_type" in text
    _assert_clean(text)


def test_cli_does_not_echo_unknown_field_names(binary, tmp_path, capsys):
    headless = hooked_ghidra(tmp_path, f"out[{SECRET!r}] = 1")
    rc, text = _cli(capsys, ["--binary", str(binary), "--output-dir", str(tmp_path / "o"), "--headless", str(headless)])
    assert rc == 1 and "<unknown>: unknown_field" in text
    _assert_clean(text)


def test_cli_does_not_print_ghidra_log_or_error_strings(binary, tmp_path, capsys):
    headless = hooked_ghidra(tmp_path, f"print({SECRET!r} + ' ' + str(Path.home())); sys.exit(7)")
    rc, text = _cli(capsys, ["--binary", str(binary), "--output-dir", str(tmp_path / "o"), "--headless", str(headless)])
    assert rc == 1 and "Ghidra exited 7" in text
    _assert_clean(text, str(Path.home()), str(tmp_path))
    # The redacted tail stays available to programmatic callers.
    with pytest.raises(WorkerError) as exc:
        analyze(binary, tmp_path / "o2", headless)
    assert SECRET in exc.value.log_tail and str(Path.home()) not in exc.value.log_tail


def test_cli_does_not_echo_paths_or_os_messages(tmp_path, capsys):
    secret_dir = tmp_path / SECRET
    secret_dir.mkdir()
    headless = fake_ghidra(tmp_path)
    rc, text = _cli(capsys, ["--binary", str(secret_dir / "missing.elf"), "--output-dir", str(secret_dir / "o"),
                             "--headless", str(headless)])
    assert rc == 1 and "[invalid_input]" in text
    _assert_clean(text, "No such file")


@pytest.mark.parametrize("argv", [
    ["--max-functions", SECRET],
    ["--wall-timeout", f"{SECRET}\x1b[2J"],
    [f"--{SECRET}"],
    [SECRET],
])
def test_cli_argument_errors_do_not_echo_values(binary, tmp_path, capsys, argv):
    base = ["--binary", str(binary), "--output-dir", str(tmp_path / "o"), "--headless", str(fake_ghidra(tmp_path))]
    rc, text = _cli(capsys, base + argv)
    assert rc == 2
    _assert_clean(text)


def test_cli_argument_error_names_the_option(binary, tmp_path, capsys):
    rc, text = _cli(capsys, ["--binary", str(binary), "--output-dir", "o", "--headless", "h", "--max-functions", "x"])
    assert rc == 2 and "invalid value for --max-functions" in text


def test_cli_unexpected_exception_is_not_rendered(binary, tmp_path, capsys, monkeypatch):
    def explode(*args, **kwargs):
        raise OSError(f"{SECRET} {tmp_path}")

    monkeypatch.setattr(ghidra_module, "analyze", explode)
    rc, text = _cli(capsys, ["--binary", str(binary), "--output-dir", "o", "--headless", "h"])
    assert rc == 3 and "[internal_error]: OSError" in text
    _assert_clean(text, str(tmp_path))


def test_cli_rejects_malformed_expected_version_without_echo(binary, tmp_path, capsys):
    rc, text = _cli(capsys, ["--binary", str(binary), "--output-dir", str(tmp_path / "o"),
                             "--headless", str(fake_ghidra(tmp_path)), "--expected-ghidra-version", f"x\x1b{SECRET}"])
    assert rc == 1 and "expected Ghidra version has an invalid format" in text
    _assert_clean(text)


def test_terminal_text_escapes_and_bounds():
    from aegis_lab.diagnostics import terminal_text

    assert terminal_text("a\x1b[2Jb‮c\n") == "a\\u001b[2Jb\\u202ec\\u000a"
    assert terminal_text("x" * 600).endswith("...<truncated>") and len(terminal_text("x" * 600)) == 514
