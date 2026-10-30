"""AEGIS Evaluate (live NVIDIA binding) checks: no network, no real credential, no native candidate run."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("live_evaluate", ROOT / "scripts/live_evaluate.py")
live_evaluate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live_evaluate)

FAKE_SECRET = "fake-test-credential-not-a-real-key"


def test_credential_file_must_be_private_regular_and_outside_the_repository(tmp_path):
    good = tmp_path / "key"
    good.write_text(FAKE_SECRET + "\n")
    good.chmod(0o600)
    assert live_evaluate.read_credential(good) == FAKE_SECRET
    good.chmod(0o640)
    with pytest.raises(live_evaluate.EvaluateError, match="private_regular_file"):
        live_evaluate.read_credential(good)
    good.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(good)
    with pytest.raises(live_evaluate.EvaluateError, match="private_regular_file"):
        live_evaluate.read_credential(link)
    blank = tmp_path / "blank"
    blank.write_text("two words\n")
    blank.chmod(0o600)
    with pytest.raises(live_evaluate.EvaluateError, match="malformed"):
        live_evaluate.read_credential(blank)


def test_credential_file_inside_repository_is_refused(tmp_path):
    inside = ROOT / "scripts/tests" / f".tmp-credential-{os.getpid()}"
    inside.write_text(FAKE_SECRET)
    try:
        inside.chmod(0o600)
        with pytest.raises(live_evaluate.EvaluateError, match="inside_repository"):
            live_evaluate.read_credential(inside)
    finally:
        inside.unlink()


def test_approval_refuses_non_interactive_use(tmp_path):
    result = subprocess.run([str(ROOT / ".venv/bin/python"), str(ROOT / "scripts/live_evaluate.py"), "approve",
                             "--workdir", str(tmp_path), "--target", "protected"],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert result.returncode == 2
    assert "approval_requires_interactive_operator_terminal" in result.stderr
    assert not list(tmp_path.rglob("approval-*.json"))


def fake_workdir(tmp_path, approvals=1):
    work = tmp_path / "eval"
    (work / "protected").mkdir(parents=True)
    for i in range(approvals):
        (work / "protected" / f"approval-2026103{i}T000000Z.json").write_text(json.dumps({"max_spend_microusd": 10_000_000, "context_tokens": 1_048_576,
            "input_microusd_per_million": 60_000, "output_microusd_per_million": 240_000, "max_requests": 1}))
    target = {"manifest": str(work / "m.json"), "ghidra_report": str(work / "g.json"), "artifact": str(work / "a"),
              "artifact_sha256": "0" * 64}
    (work / "binding.json").write_text(json.dumps({"job_id": "f" * 32, "model": live_evaluate.MODEL,
                                                   "targets": {"protected": target}}))
    return work


def run_args(work, **kw):
    return SimpleNamespace(**{"workdir": work, "target": "protected", "approval": None, "credential_file": None,
                              "use_environment_credential": True, "max_output_tokens": 8192, "budget_ledger": None,
                              "project_budget_microusd": 20_000_000, **kw})


@pytest.mark.parametrize("approvals", [0, 2])
def test_run_needs_exactly_one_saved_approval(tmp_path, monkeypatch, approvals):
    monkeypatch.setenv("NEBIUS_API_KEY", FAKE_SECRET)
    monkeypatch.setattr(live_evaluate.subprocess, "run", lambda *a, **k: pytest.fail("no subprocess expected"))
    with pytest.raises(live_evaluate.EvaluateError, match="exactly_one_saved_approval"):
        live_evaluate.run_live(run_args(fake_workdir(tmp_path, approvals)))


def test_run_refuses_missing_environment_credential(tmp_path, monkeypatch):
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.setattr(live_evaluate.subprocess, "run", lambda *a, **k: pytest.fail("no subprocess expected"))
    with pytest.raises(live_evaluate.EvaluateError, match="credential_environment_variable_missing"):
        live_evaluate.run_live(run_args(fake_workdir(tmp_path)))


@pytest.mark.parametrize("disable_thinking", [False, True])
def test_secret_reaches_only_the_live_runner_and_never_records(tmp_path, monkeypatch, capsys, disable_thinking):
    monkeypatch.setenv("NEBIUS_API_KEY", FAKE_SECRET)
    work = fake_workdir(tmp_path)
    calls = []

    def fake_run(argv, capture_output=False, text=False, env=None, **kw):
        calls.append((argv, env))
        if "preflight" in argv:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"approval_validated": True,
                "candidate_execution_authorized": False, "proposed_model": live_evaluate.MODEL}), stderr="")
        if "run" in argv:
            return SimpleNamespace(returncode=1, stdout='{"generation_status": "invalid_output"}', stderr="live_trial_failed: x")
        pytest.fail(f"unexpected subprocess {argv}")

    monkeypatch.setattr(live_evaluate.subprocess, "run", fake_run)
    assert live_evaluate.run_live(run_args(work, disable_thinking=disable_thinking)) == 1
    assert all(("--disable-thinking" in argv) is disable_thinking for argv, _ in calls)
    preflight_env, live_env = calls[0][1], calls[1][1]
    assert "NEBIUS_API_KEY" not in preflight_env
    assert live_env["NEBIUS_API_KEY"] == FAKE_SECRET
    assert not any(FAKE_SECRET in str(a) for argv, _ in calls for a in argv)
    printed = capsys.readouterr()
    records = b"".join(p.read_bytes() for p in work.rglob("*") if p.is_file())
    assert FAKE_SECRET not in printed.out + printed.err and FAKE_SECRET.encode() not in records
    ledger = [json.loads(line) for line in (tmp_path / "nvidia-budget-ledger.jsonl").read_text().splitlines()]
    assert [e["event"] for e in ledger] == ["reserved", "finished"] and ledger[0]["ceiling_microusd"] == 10_000_000
    # A started request stays committed at the Lab's worst-case reservation, not the cap.
    assert ledger[0]["lab_reservation_microusd"] == 64_881
    assert live_evaluate.ledger_committed(tmp_path / "nvidia-budget-ledger.jsonl") == 64_881


def test_project_budget_is_enforced_before_any_paid_call(tmp_path, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", FAKE_SECRET)
    work = fake_workdir(tmp_path)
    ledger = tmp_path / "nvidia-budget-ledger.jsonl"
    for _ in range(3):  # $10.50 already committed
        live_evaluate.ledger_append(ledger, {"event": "historical", "lab_reservation_microusd": 3_500_000})

    def fake_run(argv, **kw):
        assert "run" not in argv[3:5], "the paid runner must not start"
        return SimpleNamespace(returncode=0, stdout=json.dumps({"approval_validated": True,
            "candidate_execution_authorized": False, "proposed_model": live_evaluate.MODEL}), stderr="")

    monkeypatch.setattr(live_evaluate.subprocess, "run", fake_run)
    with pytest.raises(live_evaluate.EvaluateError, match="project_budget_would_be_exceeded"):
        live_evaluate.run_live(run_args(work))  # 10.50 + 10.00 ceiling > 20.00
    assert live_evaluate.ledger_committed(ledger) == 10_500_000  # nothing new reserved


def test_run_refuses_an_unapproved_preflight(tmp_path, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", FAKE_SECRET)

    def fake_run(argv, **kw):
        assert "run" not in argv[3:5], "the paid runner must not start"
        return SimpleNamespace(returncode=0, stdout=json.dumps({"approval_validated": False,
            "candidate_execution_authorized": False, "proposed_model": live_evaluate.MODEL}), stderr="")

    monkeypatch.setattr(live_evaluate.subprocess, "run", fake_run)
    with pytest.raises(live_evaluate.EvaluateError, match="preflight_not_approved"):
        live_evaluate.run_live(run_args(fake_workdir(tmp_path)))


def test_inference_only_run_never_compiles_or_executes_a_returned_candidate(tmp_path, monkeypatch):
    """An inference approval cannot implicitly authorize the separate score command."""
    import hashlib

    monkeypatch.setenv("NEBIUS_API_KEY", FAKE_SECRET)
    work = fake_workdir(tmp_path)
    candidate = b"uint32_t opaque(uint32_t a,uint32_t b,uint32_t c,uint32_t d){return a;}"
    digest = hashlib.sha256(candidate).hexdigest()

    def fake_run(argv, **kwargs):
        assert "score" not in argv, "inference-only approval must never launch candidate scoring"
        if "preflight" in argv:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"approval_validated": True,
                "candidate_execution_authorized": False, "proposed_model": live_evaluate.MODEL}), stderr="")
        if "run" in argv:
            output = Path(argv[argv.index("--output-dir") + 1])
            (output / "private-evidence").mkdir(parents=True)
            (output / "private-evidence" / digest).write_bytes(candidate)
            (output / "experiment.json").write_text(json.dumps({
                "generation_status": "generated_but_behaviorally_unscored", "candidate_sha256": digest}))
            return SimpleNamespace(returncode=0, stdout="{}", stderr="")
        assert "reconstruction" in argv  # Archive projection is allowed; candidate execution is not.
        return SimpleNamespace(returncode=1, stdout="", stderr="synthetic_export_not_available")

    monkeypatch.setattr(live_evaluate.subprocess, "run", fake_run)
    assert live_evaluate.run_live(run_args(work)) == 0
    result = json.loads(next(work.glob("live-*-binding.json")).read_text())
    assert result["candidate_sha256"] == digest
    assert result["candidate_scoring"] == {
        "status": "not_run", "reason": "inference_approval_does_not_authorize_candidate_execution"}
    assert "sandbox_score" not in result


# Owned ImageLab kernel transliterated to C by the AEGIS team (not model output): a known-correct control.
CORRECT = r"""
static uint32_t clampbias(uint32_t v, uint32_t bias) { if (v < bias) return 0; v -= bias; return v > 255u ? 255u : v; }
static uint32_t chan(uint32_t c, uint32_t y, uint32_t sat, uint32_t con, uint32_t bri) {
  uint32_t s = clampbias((c * sat + 256u * y + 1020u * 256u - y * sat + 128u) >> 8, 1020u);
  uint32_t k = clampbias((s * con + 256u * 128u + 512u * 256u - 128u * con + 128u) >> 8, 512u);
  return clampbias(k + bri, 255u);
}
uint32_t opaque(uint32_t px, uint32_t sat, uint32_t con, uint32_t bri) {
  sat = sat < 1024u ? sat : 1024u; con = con < 1024u ? con : 1024u; bri = bri < 510u ? bri : 510u;
  uint32_t r = px & 255u, g = (px >> 8) & 255u, b = (px >> 16) & 255u;
  uint32_t y = (77u * r + 150u * g + 29u * b + 128u) >> 8;
  return chan(r, y, sat, con, bri) | (chan(g, y, sat, con, bri) << 8) | (chan(b, y, sat, con, bri) << 16) | (px & 0xFF000000u);
}
"""


def score(tmp_path, source):
    path = tmp_path / "candidate.c"
    path.write_text(source)
    result = subprocess.run([str(ROOT / ".venv/bin/python"), str(ROOT / "scripts/live_evaluate.py"), "score", str(path)],
                            capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


needs_tools = pytest.mark.skipif(not (shutil.which("clang") and shutil.which("node") and shutil.which("wasm-ld")),
                                 reason="clang, wasm-ld and node are required for the wasm sandbox")


@needs_tools
def test_sandbox_score_accepts_a_correct_control_and_rejects_wrong_or_escaping_code(tmp_path):
    good = score(tmp_path, CORRECT)
    assert good["status"] == "behaviorally_verified_on_hidden_cases" and good["fail"] == 0 and good["pass"] == good["cases"]
    assert good["imports"] == 0 and good["native_execution_of_candidate"] is False
    wrong = score(tmp_path, "uint32_t opaque(uint32_t a, uint32_t b, uint32_t c, uint32_t d) { return a; }")
    assert wrong["status"] == "behaviorally_incorrect" and wrong["fail"] > 0
    for escaping in ('#include <stdio.h>\nuint32_t opaque(uint32_t a, uint32_t b, uint32_t c, uint32_t d) { puts("x"); return a; }',
                     "int system(const char *);\nuint32_t opaque(uint32_t a, uint32_t b, uint32_t c, uint32_t d) { return system(\"id\"); }"):
        assert score(tmp_path, escaping)["status"] == "candidate_build_failed"
