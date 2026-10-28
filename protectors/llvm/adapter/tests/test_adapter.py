import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from aegis_core.adapter import AdapterResult
from aegis_core.models import EvidenceSource, JobStatus
from aegis_cli.main import main as cli


def run(core, pending):
    job = core.run(pending.job_id)
    report = core.get_report(job.job_id)
    assert report.status == job.status
    return job, report


def failure(core, pending, code):
    job, report = run(core, pending)
    assert job.status == JobStatus.FAILED
    assert job.error.code == "ADAPTER_FAILED"
    assert job.error.details["adapter_error"]["code"] == code
    assert report.error == job.error
    assert not job.output_artifacts
    return job


def test_trusted_fixture_end_to_end(make_job):
    core, pending = make_job(options={"seed": "18446744073709551615", "max-sites": 3})
    job, report = run(core, pending)
    assert job.status == JobStatus.SUCCEEDED, job.error
    assert {artifact.name for artifact in job.output_artifacts} == {"protected.ll", "shield-report.json"}
    for artifact in job.output_artifacts:
        raw = core.store.artifact_path(artifact).read_bytes()
        assert raw and artifact.size_bytes == len(raw)
        assert artifact.sha256 == hashlib.sha256(raw).hexdigest()
        assert any(ev.source == EvidenceSource.ORCHESTRATOR and ev.artifact_sha256 == artifact.sha256
                   for ev in report.evidence)
    shield = json.loads((core.store.outputs_dir(job.job_id) / "shield-report.json").read_bytes())
    assert type(shield["schema_version"]) is int and report.schema_version == "1"
    assert shield["config"]["seed"] == "18446744073709551615"
    assert shield["transformed_sites"] > 0
    assert shield["module"] == "shield-input.ll"
    transformed = (core.store.outputs_dir(job.job_id) / "protected.ll").read_bytes()
    assert b"!aegis.shield.generated" in transformed
    assert transformed != core.store.artifact_path(job.input_artifact).read_bytes()
    claims = [ev for ev in report.evidence if ev.source == EvidenceSource.ADAPTER]
    assert len(claims) == 1
    assert claims[0].data["transformed_sites"] == shield["transformed_sites"]
    assert "no established security property" in claims[0].summary
    assert not report.attack_evaluations


@pytest.mark.parametrize("options", [{"enabled": False}, {"max-sites": 0}])
def test_noop_options(make_job, options):
    core, job = make_job(options=options)
    failure(core, job, "NO_TRANSFORMATIONS_APPLIED")
    assert not list(core.store.outputs_dir(job.job_id).iterdir())


@pytest.mark.parametrize("data", [b"", b"; empty module\n",
    b"define i32 @sum(i32 %x, i32 %y) { %r = add i32 %x, %y\n ret i32 %r }\n",
    b'define i32 @sum(i32 %x, i32 %y) "aegis.protect" { %r = add nsw i32 %x, %y\n ret i32 %r }\n'])
def test_unselected_and_ineligible_inputs(make_job, data):
    core, job = make_job(data=data)
    failure(core, job, "EMPTY_ARTIFACT" if not data else "NO_TRANSFORMATIONS_APPLIED")


@pytest.mark.parametrize("options", [
    {"seed": 2**64 - 1}, {"seed": True}, {"seed": 42.0}, {"seed": "18446744073709551616"},
    {"seed": "-1"}, {"seed": "1;report=evil"}, {"seed": "１"}, {"seed": ""},
    {"seed": "0" * 21}, {"max-sites": True}, {"max-sites": -1}, {"max-sites": 1_000_001},
    {"max-sites": "3"}, {"max-sites": 3.0}, {"enabled": "true"}, {"enabled": 1},
    {"config": "injected.json"}, {"report": "../inputs/fixture.ll"}, {"plugin": "evil.so"},
])
def test_invalid_options(make_job, options):
    core, job = make_job(options=options)
    failure(core, job, "INVALID_OPTIONS")


@pytest.mark.parametrize("data,code", [(b"\x7fELF\x00native", "UNSUPPORTED_FORMAT"),
    (b"BC\xc0\xdebitcode", "UNSUPPORTED_FORMAT"), (b"MZbinary", "UNSUPPORTED_FORMAT"),
    (b"not LLVM IR", "LLVM_FAILED")])
def test_invalid_input_formats(make_job, data, code):
    core, job = make_job(data=data)
    failure(core, job, code)


def test_relative_paths_metacharacters_and_environment(make_job, tmp_path, wrapper, command, monkeypatch):
    marker = tmp_path / "leaked"
    monkeypatch.setenv("AEGIS_TEST_SECRET", "must not leak")
    spy = wrapper("assert 'AEGIS_TEST_SECRET' not in os.environ\n"
                  "assert set(os.environ) <= {'PATH','LANG','LC_ALL','HOME','TMPDIR'}\n"
                  "assert pathlib.Path('shield-input.ll').is_file()\n"
                  "assert pathlib.Path('shield-config.json').is_file()\n"
                  "assert all('store;' not in arg for arg in sys.argv[1:])\n"
                  "os.execv(real_opt, [real_opt, *sys.argv[1:]])")
    cmd = [*command]
    cmd[cmd.index("--opt") + 1] = spy
    core, pending = make_job(root=tmp_path / "store;with,<angle>(parentheses) $() space", cmd=cmd,
                             name="a;$(touch leaked).ll")
    job, _ = run(core, pending)
    assert job.status == JobStatus.SUCCEEDED, job.error
    assert not marker.exists()


@pytest.mark.parametrize("field,value,code", [
    ("--opt", "/no/such/opt", "TOOL_UNAVAILABLE"),
    ("--opt", "relative/opt", "INVALID_CONFIGURATION"),
    ("--plugin", "/no/such/plugin.so", "PLUGIN_UNAVAILABLE"),
    ("--plugin", "relative/plugin.so", "PLUGIN_UNAVAILABLE"),
])
def test_missing_and_relative_tools(make_job, command, field, value, code):
    command[command.index(field) + 1] = value
    core, job = make_job(cmd=command)
    failure(core, job, code)


def test_unloadable_plugin(make_job, command, tmp_path):
    plugin = tmp_path / "invalid.so"
    plugin.write_text("not a plugin")
    command[command.index("--plugin") + 1] = str(plugin)
    core, job = make_job(cmd=command)
    failure(core, job, "LLVM_FAILED")


def test_wrong_llvm_version(make_job, command, tmp_path):
    tool = tmp_path / "old-opt"
    tool.write_text(f'#!{sys.executable}\nprint("LLVM version 21.1.0")\n')
    tool.chmod(0o755)
    command[command.index("--opt") + 1] = str(tool)
    core, job = make_job(cmd=command)
    failure(core, job, "UNSUPPORTED_LLVM")


@pytest.mark.parametrize("extra,code", [
    (("--max-output-bytes", "16"), "OUTPUT_TOO_LARGE"),
    (("--max-report-bytes", "16"), "OUTPUT_TOO_LARGE"),
    (("--max-input-bytes", "16"), "INPUT_TOO_LARGE"),
])
def test_byte_limits(make_job, extra, code):
    core, job = make_job(extra=extra)
    failure(core, job, code)


@pytest.mark.parametrize("body", [
    "pathlib.Path('protected.ll').write_bytes(b'x' * 100000)",
    "sys.stdout.write('x' * 100000); sys.stdout.flush()",
    "sys.stderr.write('x' * 100000); sys.stderr.flush()",
])
def test_live_output_limits(make_job, command, wrapper, body):
    command[command.index("--opt") + 1] = wrapper(body + "\ntime.sleep(30)")
    core, job = make_job(cmd=command, extra=("--max-output-bytes", "128"))
    failure(core, job, "OUTPUT_TOO_LARGE")


def test_timeout_kills_llvm_process_group(make_job, command, wrapper, tmp_path):
    pidfile = tmp_path / "child.pid"
    command[command.index("--opt") + 1] = wrapper(
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"pathlib.Path({str(pidfile)!r}).write_text(str(child.pid))\n"
        "time.sleep(60)")
    core, pending = make_job(cmd=command, timeout=1)
    job, report = run(core, pending)
    assert job.status == JobStatus.FAILED and job.error.code == "ADAPTER_TIMEOUT"
    assert report.error == job.error
    assert pidfile.is_file()
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        proc_stat = Path(f"/proc/{pid}/stat")
        if not proc_stat.exists() or proc_stat.read_text().split()[2] == "Z":
            break
        time.sleep(0.02)
    else:
        os.kill(pid, signal.SIGKILL)
        pytest.fail("LLVM descendant survived the core timeout")


@pytest.mark.parametrize("mutation,code", [
    ("path.write_text('{broken')", "INVALID_SHIELD_REPORT"),
    ("path.write_text(path.read_text()[:-1] + ',\"backend\":\"aegis-shield-llvm\"}')", "INVALID_SHIELD_REPORT"),
    ("report['schema_version'] = '1'", "INVALID_SHIELD_REPORT"),
    ("report['schema_version'] = True", "INVALID_SHIELD_REPORT"),
    ("report['backend'] = 'other'", "INVALID_SHIELD_REPORT"),
    ("report['config']['seed'] = '1'", "INVALID_SHIELD_REPORT"),
    ("report['llvm_version'] = '22.0.0'", "INVALID_SHIELD_REPORT"),
    ("report['module'] = '/wrong/input'", "INVALID_SHIELD_REPORT"),
    ("report['transformed_sites'] += 1", "INVALID_SHIELD_REPORT"),
    ("report['transformed_sites'] = True", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['extra'] = 1", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['reason'] = 'invented'", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['reason'] = 'disabled'", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['status'] = 'skipped'", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['annotated'] = False", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['transformed_sites'][0]['bit_width'] = 1", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['transformed_sites'][0]['add_index'] = -1", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['transformed_sites'][0]['variant'] = 'invented'", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['transformed_sites'] *= 2; report['transformed_sites'] += 1", "INVALID_SHIELD_REPORT"),
    ("report['functions'].append(report['functions'][0]); report['transformed_sites'] += 1", "INVALID_SHIELD_REPORT"),
    ("report['functions'][0]['skipped_adds'] = {'budget': 0}", "INVALID_SHIELD_REPORT"),
    ("report['functions'] = {}", "INVALID_SHIELD_REPORT"),
    ("path.unlink()", "INVALID_ARTIFACT"),
    ("path.write_text('')", "EMPTY_ARTIFACT"),
    ("path.unlink(); path.symlink_to('shield-config.json')", "UNSAFE_PATH"),
    ("path.unlink(); os.link('shield-config.json', path)", "UNSAFE_PATH"),
    ("pathlib.Path('protected.ll').write_text('')", "EMPTY_ARTIFACT"),
    ("pathlib.Path('protected.ll').write_text('invalid IR')", "LLVM_FAILED"),
    ("pathlib.Path('protected.ll').write_bytes(pathlib.Path('shield-input.ll').read_bytes())", "INVALID_ARTIFACT"),
    ("pathlib.Path('protected.ll').unlink()", "INVALID_ARTIFACT"),
    ("pathlib.Path('protected.ll').unlink(); pathlib.Path('protected.ll').symlink_to('shield-input.ll')", "UNSAFE_PATH"),
])
def test_corrupted_real_artifacts(make_job, command, wrapper, mutation, code):
    # Delegate protection to real opt before deliberately damaging its result.
    body = ("result = subprocess.run([real_opt, *sys.argv[1:]])\n"
            "if result.returncode: sys.exit(result.returncode)\n"
            "if '-load-pass-plugin' not in sys.argv: sys.exit(0)\n"
            "path = pathlib.Path('shield-report.json')\n"
            "report = json.loads(path.read_text())\n"
            f"{mutation}\n")
    if mutation.startswith("report["):
        body += "path.write_text(json.dumps(report))\n"
    command[command.index("--opt") + 1] = wrapper(body)
    core, job = make_job(cmd=command)
    failure(core, job, code)


@pytest.mark.parametrize("update,code", [
    ({"protocol": "wrong"}, "INVALID_REQUEST"), ({"extra": 1}, "INVALID_REQUEST"),
    ({"task": "attack_lab"}, "UNSUPPORTED_TASK"), ({"authorization": {}}, "UNSUPPORTED_TASK"),
    ({"job_id": "../escape"}, "INVALID_REQUEST"), ({"input_sha256": "a" * 64}, "ARTIFACT_INTEGRITY_ERROR"),
    ({"input_path": "../inputs/fixture.ll"}, "UNSAFE_PATH"),
    ({"output_dir": "../outputs"}, "UNSAFE_PATH"), ({"options": []}, "INVALID_OPTIONS"),
    ({"input_path": None}, "INVALID_REQUEST"),
])
def test_wire_validation(direct, update, code):
    invoke, _, _ = direct
    result = AdapterResult.model_validate(invoke(update))
    assert result.status == "failed" and result.error.code == code


@pytest.mark.parametrize("raw", ['{"protocol": 1, "protocol": 2}', '{', '[]', 'null', 'NaN'])
def test_malformed_request(direct, raw):
    invoke, _, _ = direct
    result = AdapterResult.model_validate(invoke(raw=raw))
    assert result.status == "failed" and result.error.code == "INVALID_REQUEST"


@pytest.mark.parametrize("target", ["inputs/fixture.ll", "outputs", "outputs/protected.ll"])
def test_symlinks_and_existing_output_rejected(direct, tmp_path, target):
    invoke, job, _ = direct
    path = job / target
    if path.is_file():
        real = tmp_path / "real.ll"
        real.write_bytes(path.read_bytes())
        path.unlink()
    elif path.is_dir():
        real = tmp_path / "real-output"
        real.mkdir()
        path.rmdir()
    else:
        real = tmp_path / "unrelated"
        real.write_text("do not overwrite")
    path.symlink_to(real)
    result = invoke()
    assert result["status"] == "failed" and result["error"]["code"] == "UNSAFE_PATH"
    if real.is_file() and target.endswith("protected.ll"):
        assert real.read_text() == "do not overwrite"


def test_cli_registration_and_large_seed(tmp_path, command, trusted_ir, capsys):
    config = tmp_path / "aegis.toml"
    config.write_text('[storage]\nroot = "store"\n[adapters.llvm-shield]\ncommand = '
                      + json.dumps(command) + '\ntasks = ["protect"]\ntimeout_seconds = 30\n')
    source = tmp_path / "fixture.ll"
    source.write_bytes(trusted_ir)
    code = cli(["protect", "--config", str(config), "--json", str(source),
                "--backend", "llvm-shield", "--option", 'seed="18446744073709551615"'])
    job = json.loads(capsys.readouterr().out)
    assert code == 0 and job["status"] == "succeeded"
    assert job["policy"]["options"]["seed"] == "18446744073709551615"
    assert cli(["report", "--config", str(config), "--json", job["job_id"]]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "succeeded"
