"""Real Shield + Mirage backend through Core. No fake protection, no native execution."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import pytest

from aegis_core.adapter import AdapterResult
from aegis_core.config import config_from_mapping
from aegis_core.models import EvidenceSource, JobStatus, ProtectionPolicy
from aegis_core.orchestrator import Orchestrator

ADAPTER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ADAPTER.parents[1] / "mirage" / "src"))
from aegis_mirage.transform import MirageConfig, decoy_source  # noqa: E402

BACKEND = "llvm-shield-mirage"
OUTPUTS = {"protected.ll", "shield-stage.ll", "shield-report.json", "mirage-report.json"}


@pytest.fixture(scope="session")
def link(request):
    path = request.config.getoption("--shield-llvm-link")
    if not path or not Path(path).is_file():
        pytest.fail("Supply --shield-llvm-link (LLVM 22 llvm-link)")
    return str(Path(path).absolute())


@pytest.fixture
def combined(tools, link):
    return [sys.executable, str(ADAPTER / "aegis_shield_mirage_adapter.py"), "--opt", tools[1],
            "--plugin", tools[0], "--clang", tools[2], "--llvm-link", link]


@pytest.fixture
def submit(tmp_path, combined, trusted_ir):
    def make(*, data=None, options=None, cmd=None, extra=(), timeout=60, backend=BACKEND):
        config = config_from_mapping({"storage": {"root": str(tmp_path / "store")}, "adapters": {
            backend: {"command": [*(cmd or combined), *extra], "timeout_seconds": timeout}}},
            base_dir=tmp_path)
        core = Orchestrator(config)
        pending = core.submit(ProtectionPolicy(backend=backend, options=options or {"seed": "42"}),
                              data=trusted_ir if data is None else data, name="fixture.ll")
        job = core.run(pending.job_id)
        report = core.get_report(job.job_id)
        assert report.status == job.status
        return core, job, report
    return make


def outputs(core, job):
    return {a.name: core.store.artifact_path(a).read_bytes() for a in job.output_artifacts}


def failed(result, code):
    core, job, report = result
    assert job.status == JobStatus.FAILED, job
    assert job.error.code == "ADAPTER_FAILED"
    assert job.error.details["adapter_error"]["code"] == code, job.error
    assert not job.output_artifacts and report.error == job.error
    return job


def test_verified_chain_end_to_end(submit, trusted_ir):
    core, job, report = submit()
    assert job.status == JobStatus.SUCCEEDED, job.error
    files = outputs(core, job)
    assert set(files) == OUTPUTS
    hashes = {a.name: a.sha256 for a in job.output_artifacts}
    for name, raw in files.items():  # Core hashed every artifact itself
        assert hashes[name] == hashlib.sha256(raw).hexdigest()
        assert any(ev.source == EvidenceSource.ORCHESTRATOR and ev.artifact_sha256 == hashes[name]
                   for ev in report.evidence)
    mirage = json.loads(files["mirage-report.json"])
    shield = json.loads(files["shield-report.json"])
    # The chain is checkable from orchestrator hashes alone.
    assert mirage["input_sha256"] == hashes["shield-stage.ll"]
    assert mirage["output_sha256"] == hashes["protected.ll"]
    assert shield["transformed_sites"] > 0 and shield["module"] == "shield-input.ll"
    assert mirage["inserted_count"] == 3 and mirage["security_property"] == "not_established"
    assert mirage["configuration"] == {"seed": 42, "enabled": True, "count": 3}
    assert {t["version"] for t in mirage["toolchain"].values()} == {shield["llvm_version"]}
    final = files["protected.ll"].decode()
    assert b"!aegis.shield.generated" in files["shield-stage.ll"] and "!aegis.shield.generated" in final
    _, names = decoy_source(MirageConfig(seed=42))
    assert list(names) == mirage["inserted_functions"]
    for name in names:
        assert f"@{name}(" in final and name not in files["shield-stage.ll"].decode()
        assert not any("call " in line and "@" + name in line for line in final.splitlines())
    assert core.store.artifact_path(job.input_artifact).read_bytes() == trusted_ir
    claims = [ev for ev in report.evidence if ev.source == EvidenceSource.ADAPTER]
    assert len(claims) == 2 and all("no established security property" in c.summary for c in claims)
    chain = claims[1].data["chain"]
    assert chain == {"shield_stage_sha256": hashes["shield-stage.ll"],
                     "mirage_input_sha256": hashes["shield-stage.ll"],
                     "final_output_sha256": hashes["protected.ll"]}
    assert not any(name in json.dumps(claims[1].data) for name in names)  # names stay in the artifact
    assert not report.attack_evaluations


def test_shield_stage_matches_standalone_and_runs_are_deterministic(submit, make_job):
    core, job, _ = submit(options={"seed": "7", "max-sites": 2})
    again_core, again, _ = submit(options={"seed": "7", "max-sites": 2})
    first, second = outputs(core, job), outputs(again_core, again)
    assert first == second
    alone_core, alone = make_job(options={"seed": "7", "max-sites": 2})
    alone = alone_core.run(alone.job_id)
    assert alone.status == JobStatus.SUCCEEDED
    standalone = outputs(alone_core, alone)
    assert first["shield-stage.ll"] == standalone["protected.ll"]
    assert first["shield-report.json"] == standalone["shield-report.json"]
    other_core, other, _ = submit(options={"seed": "7", "max-sites": 2, "mirage-seed": "8"})
    changed = outputs(other_core, other)
    assert changed["shield-stage.ll"] == first["shield-stage.ll"]
    assert changed["protected.ll"] != first["protected.ll"]


def test_disabled_mirage_control_is_exact(submit):
    core, job, report = submit(options={"seed": "42", "mirage-enabled": False})
    assert job.status == JobStatus.SUCCEEDED, job.error
    files = outputs(core, job)
    assert files["protected.ll"] == files["shield-stage.ll"]
    assert json.loads(files["mirage-report.json"])["inserted_count"] == 0
    claim = [ev for ev in report.evidence if ev.source == EvidenceSource.ADAPTER][1]
    assert claim.data["enabled"] is False and claim.summary.startswith("Mirage disabled (control)")


@pytest.mark.parametrize("options", [{"seed": "42", "enabled": False}, {"seed": "42", "max-sites": 0},
                                     {"seed": "42", "enabled": False, "mirage-enabled": True}])
def test_shield_noop_fails_even_with_mirage(submit, options):
    failed(submit(options=options), "NO_TRANSFORMATIONS_APPLIED")


def test_large_shield_seed_needs_explicit_mirage_seed(submit):
    failed(submit(options={"seed": "18446744073709551615"}), "INVALID_OPTIONS")
    core, job, _ = submit(options={"seed": "18446744073709551615", "mirage-seed": "9223372036854775807"})
    assert job.status == JobStatus.SUCCEEDED, job.error
    assert json.loads(outputs(core, job)["mirage-report.json"])["configuration"]["seed"] == 2**63 - 1


@pytest.mark.parametrize("options", [
    {"mirage-seed": 42}, {"mirage-seed": "-1"}, {"mirage-seed": "9223372036854775808"},
    {"mirage-seed": "1;x"}, {"mirage-seed": ""}, {"mirage-seed": "0" * 20},
    {"mirage-count": 0}, {"mirage-count": 33}, {"mirage-count": True}, {"mirage-count": "3"},
    {"mirage-count": 3.0}, {"mirage-enabled": "true"}, {"mirage-enabled": 1},
    {"mirage-output": "x"}, {"clang": "/tmp/evil"}, {"seed": 42}, {"max-sites": -1},
])
def test_invalid_options(submit, options):
    failed(submit(options={"seed": "1", **options}), "INVALID_OPTIONS")


def test_standalone_shield_rejects_mirage_options(make_job):
    core, job = make_job(options={"mirage-count": 3})
    job = core.run(job.job_id)
    assert job.error.details["adapter_error"]["code"] == "INVALID_OPTIONS"


@pytest.mark.parametrize("flag,value,code", [
    ("--clang", "clang", "INVALID_CONFIGURATION"), ("--clang", "/no/such/clang", "TOOL_UNAVAILABLE"),
    ("--llvm-link", "llvm-link", "INVALID_CONFIGURATION"),
    ("--llvm-link", "/no/such/llvm-link", "TOOL_UNAVAILABLE"),
    ("--plugin", "/no/such/plugin.so", "PLUGIN_UNAVAILABLE"),
])
def test_missing_tools(submit, combined, flag, value, code):
    combined[combined.index(flag) + 1] = value
    failed(submit(cmd=combined), code)


def tool_wrapper(tmp_path, real, body, name):
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\nimport os, pathlib, subprocess, sys, time\n"
                    f"real = {real!r}\n{body}\n")
    path.chmod(0o755)
    return str(path)


def test_toolchain_version_mismatch(submit, combined, tmp_path, tools):
    combined[combined.index("--clang") + 1] = tool_wrapper(
        tmp_path, tools[2], "print('clang version 21.1.0')", "old-clang")
    job = failed(submit(cmd=combined), "MIRAGE_FAILED")
    assert "matching_llvm22_required" in job.error.details["adapter_error"]["message"]


def test_decoy_symbol_collision(submit, trusted_ir):
    _, names = decoy_source(MirageConfig(seed=42))
    data = trusted_ir + f"\ndefine i32 @{names[0]}(i32 %x) {{\n  ret i32 %x\n}}\n".encode()
    job = failed(submit(data=data), "MIRAGE_FAILED")
    assert "decoy_symbol_collision" in job.error.details["adapter_error"]["message"]


def test_target_triple_mismatch(submit, trusted_ir):
    text = trusted_ir.decode()
    start = text.index('target triple = "')
    end = text.index('"', start + len('target triple = "'))
    data = (text[:start] + 'target triple = "aarch64-unknown-linux-gnu' + text[end:]).encode()
    _, job, _ = submit(data=data)
    assert job.status == JobStatus.FAILED
    assert job.error.details["adapter_error"]["code"] == "MIRAGE_FAILED"
    assert "target_triple_mismatch" in job.error.details["adapter_error"]["message"]


def test_vendor_only_triple_difference_succeeds_with_module_triple(submit, trusted_ir):
    """rustc emits x86_64-unknown-linux-gnu where Clang defaults to x86_64-pc-linux-gnu."""
    text = trusted_ir.decode()
    start = text.index('target triple = "') + len('target triple = "')
    default = text[start:text.index('"', start)]
    parts = default.split("-")
    if len(parts) != 4:
        pytest.skip(f"host default triple {default!r} has no vendor field")
    triple = "-".join([parts[0], "unknown" if parts[1] != "unknown" else "pc", *parts[2:]])
    core, job, _ = submit(data=text.replace(f'target triple = "{default}"', f'target triple = "{triple}"').encode())
    assert job.status == JobStatus.SUCCEEDED, job.error
    outputs = {a.name: a for a in job.output_artifacts}
    final = core.store.artifact_path(outputs["protected.ll"]).read_text()
    assert f'target triple = "{triple}"' in final and default not in final
    report = json.loads(core.store.artifact_path(outputs["mirage-report.json"]).read_text())
    assert report["input_sha256"] == outputs["shield-stage.ll"].sha256
    assert report["output_sha256"] == outputs["protected.ll"].sha256
    assert report["inserted_count"] == 3


@pytest.mark.parametrize("body,code", [
    # llvm-link "succeeds" without adding decoys: Mirage must notice.
    ("import shutil\nshutil.copy('input.ll', sys.argv[sys.argv.index('-o') + 1])", "MIRAGE_FAILED"),
    # llvm-link emits an invalid module: the verifier must reject it.
    ("pathlib.Path(sys.argv[sys.argv.index('-o') + 1]).write_text('broken')", "LLVM_FAILED"),
    ("sys.exit(3)", "LLVM_FAILED"),
    ("pathlib.Path(sys.argv[sys.argv.index('-o') + 1]).write_bytes(b'x' * 200000)", "OUTPUT_TOO_LARGE"),
])
def test_corrupted_mirage_stage(submit, combined, tmp_path, link, body, code):
    wrapper = tool_wrapper(tmp_path, link, "if '--version' in sys.argv:\n"
                           "    os.execv(real, [real, *sys.argv[1:]])\n" + body, "link-wrapper")
    combined[combined.index("--llvm-link") + 1] = wrapper
    failed(submit(cmd=combined, extra=("--max-output-bytes", "100000")), code)


def test_final_module_byte_limit(submit):
    # Shield's 2.6 kB output fits; the decoy-extended module does not.
    failed(submit(extra=("--max-output-bytes", "3000")), "OUTPUT_TOO_LARGE")


def test_mirage_tools_get_minimal_environment(submit, combined, tmp_path, tools, monkeypatch):
    monkeypatch.setenv("AEGIS_TEST_SECRET", "must not leak")
    spy = tool_wrapper(tmp_path, tools[2], "assert 'AEGIS_TEST_SECRET' not in os.environ\n"
                       "assert set(os.environ) <= {'PATH','LANG','LC_ALL','HOME','TMPDIR'}\n"
                       "os.execv(real, [real, *sys.argv[1:]])", "spy-clang")
    combined[combined.index("--clang") + 1] = spy
    _, job, _ = submit(cmd=combined)
    assert job.status == JobStatus.SUCCEEDED, job.error


def test_timeout_kills_mirage_stage_tools(submit, combined, tmp_path, tools):
    pidfile = tmp_path / "child.pid"
    hang = tool_wrapper(tmp_path, tools[2], "if '--version' in sys.argv:\n"
                        "    os.execv(real, [real, *sys.argv[1:]])\n"
                        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                        f"pathlib.Path({str(pidfile)!r}).write_text(str(child.pid))\n"
                        "time.sleep(60)", "hang-clang")
    combined[combined.index("--clang") + 1] = hang
    _, job, _ = submit(cmd=combined, timeout=5)
    assert job.status == JobStatus.FAILED and job.error.code == "ADAPTER_TIMEOUT"
    assert pidfile.is_file(), "the Mirage stage was never reached"
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        stat = Path(f"/proc/{pid}/stat")
        if not stat.exists() or stat.read_text().split()[2] == "Z":
            break
        time.sleep(0.02)
    else:
        os.kill(pid, signal.SIGKILL)
        pytest.fail("Mirage-stage descendant survived the Core timeout")


def test_adapter_without_mirage_checkout_fails_closed(submit, combined, tmp_path):
    copy = tmp_path / "deploy" / "llvm" / "adapter"
    copy.mkdir(parents=True)
    for name in ("aegis_llvm_adapter.py", "aegis_shield_mirage_adapter.py", "report.py"):
        shutil.copy(ADAPTER / name, copy / name)
    combined[1] = str(copy / "aegis_shield_mirage_adapter.py")
    failed(submit(cmd=combined), "TOOL_UNAVAILABLE")


@pytest.mark.parametrize("update,code", [({"task": "attack_lab"}, "UNSUPPORTED_TASK"),
                                         ({"authorization": {}}, "UNSUPPORTED_TASK"),
                                         ({"input_sha256": "a" * 64}, "ARTIFACT_INTEGRITY_ERROR"),
                                         ({"output_dir": "../outputs"}, "UNSAFE_PATH")])
def test_wire_validation(direct, combined, update, code):
    _, job, request = direct
    path = job / "adapter/request.json"
    path.write_text(json.dumps({**request, "backend": BACKEND, **update}))
    proc = subprocess.run([*combined, "--aegis-request", str(path)], cwd=job / "work",
                          capture_output=True, timeout=60)
    assert proc.returncode == 0, proc.stderr.decode()
    result = AdapterResult.model_validate(json.loads(proc.stdout))
    assert result.status == "failed" and result.error.code == code
    assert not list((job / "outputs").iterdir())
