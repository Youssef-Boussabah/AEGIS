from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_cli.main import (
    EXIT_AUTHORIZATION,
    EXIT_CONFIG,
    EXIT_CONFLICT,
    EXIT_FAILED,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_UNSUPPORTED,
    EXIT_USAGE,
    main,
)
from aegis_core.config import load_config
from aegis_core.models import ProtectionPolicy
from aegis_core.orchestrator import Orchestrator
from aegis_core.testing import write_test_config


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG", raising=False)
    (tmp_path / "sample.bin").write_bytes(b"\x7fELF cli test payload")
    return tmp_path


@pytest.fixture
def configured(workspace: Path) -> Path:
    write_test_config(workspace)
    return workspace


def _json(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


# ------------------------------------------------------------------- init


def test_init_creates_config_and_store(workspace, capsys):
    assert main(["init"]) == EXIT_OK
    assert (workspace / "aegis.toml").is_file()
    assert (workspace / ".aegis" / "jobs").is_dir()
    assert "no protection backends are registered" in capsys.readouterr().out


def test_init_refuses_to_overwrite(workspace, capsys):
    assert main(["init"]) == EXIT_OK
    capsys.readouterr()
    assert main(["init", "--json"]) == EXIT_CONFIG
    assert _json(capsys)["error"]["code"] == "CONFIG_EXISTS"
    assert main(["init", "--force"]) == EXIT_OK


def test_commands_without_config_fail_explicitly(workspace, capsys):
    assert main(["inspect"]) == EXIT_CONFIG
    assert "CONFIG_NOT_FOUND" in capsys.readouterr().err


def test_fresh_init_has_no_backends_so_protect_is_unsupported(workspace, capsys):
    main(["init"])
    capsys.readouterr()
    assert main(["protect", "sample.bin", "--backend", "llvm"]) == EXIT_UNSUPPORTED
    err = capsys.readouterr().err
    assert "UNSUPPORTED_BACKEND" in err
    assert not list((workspace / ".aegis" / "jobs").iterdir())


# ---------------------------------------------------------------- inspect


def test_inspect_health(configured, capsys):
    assert main(["inspect", "--json"]) == EXIT_OK
    body = _json(capsys)
    assert body["status"] == "ok"
    assert body["backends"][0]["name"] == "fake"
    assert body["attack_lab_enabled"] is False


def test_inspect_health_degraded(configured, capsys):
    with open(configured / "aegis.toml", "a") as handle:
        handle.write('\n[adapters.ghost]\ncommand = ["/nonexistent/adapter"]\n')
    assert main(["inspect"]) == EXIT_FAILED
    assert "UNAVAILABLE" in capsys.readouterr().out


def test_inspect_unknown_job(configured, capsys):
    assert main(["inspect", "f" * 32, "--json"]) == EXIT_NOT_FOUND
    assert _json(capsys)["error"]["code"] == "JOB_NOT_FOUND"


# ---------------------------------------------------------------- protect


def test_protect_success_then_inspect_and_report(configured, capsys):
    assert main(["protect", "sample.bin", "--backend", "fake", "--json"]) == EXIT_OK
    job = _json(capsys)
    assert job["status"] == "succeeded"
    assert len(job["output_artifacts"]) == 1

    assert main(["inspect", job["job_id"]]) == EXIT_OK
    assert "succeeded" in capsys.readouterr().out

    assert main(["report", job["job_id"]]) == EXIT_OK
    text = capsys.readouterr().out
    assert "status:    succeeded" in text and "limitations:" in text

    out = configured / "report.json"
    assert main(["report", job["job_id"], "--output", str(out)]) == EXIT_OK
    assert json.loads(out.read_text())["job_id"] == job["job_id"]


def test_protect_failure_exits_nonzero(configured, capsys):
    code = main(["protect", "sample.bin", "--backend", "fake", "--option", "mode=crash", "--json"])
    assert code == EXIT_FAILED
    job = _json(capsys)
    assert job["status"] == "failed"
    assert job["error"]["code"] == "ADAPTER_FAILED"
    assert main(["report", job["job_id"], "--json"]) == EXIT_FAILED
    assert _json(capsys)["error"]["code"] == "ADAPTER_FAILED"


def test_protect_missing_input(configured, capsys):
    assert main(["protect", "nope.bin", "--backend", "fake"]) == EXIT_NOT_FOUND
    assert "INPUT_NOT_FOUND" in capsys.readouterr().err


def test_protect_bad_option_syntax(configured, capsys):
    assert main(["protect", "sample.bin", "--backend", "fake", "--option", "novalue"]) == EXIT_USAGE
    assert "INVALID_REQUEST" in capsys.readouterr().err


def test_attack_lab_requires_authorization(configured, capsys):
    code = main(["protect", "sample.bin", "--backend", "fake", "--task", "attack-lab"])
    assert code == EXIT_AUTHORIZATION
    assert "AUTHORIZATION_REQUIRED" in capsys.readouterr().err


def test_attack_lab_partial_authorization_is_rejected(workspace, capsys):
    write_test_config(workspace, attack_lab_enabled=True)
    code = main(
        ["protect", "sample.bin", "--backend", "fake", "--task", "attack-lab",
         "--authorized-by", "lead"]
    )
    assert code == EXIT_AUTHORIZATION


def test_authorized_attack_lab(workspace, capsys):
    write_test_config(workspace, attack_lab_enabled=True)
    code = main(
        ["protect", "sample.bin", "--backend", "fake", "--task", "attack-lab",
         "--option", "mode=attack", "--authorized-by", "lead",
         "--authorization-ref", "ENG-42", "--authorization-scope", "sample.bin", "--json"]
    )
    assert code == EXIT_OK
    job_id = _json(capsys)["job_id"]
    assert main(["report", job_id, "--json"]) == EXIT_OK
    assert _json(capsys)["attack_evaluations"][0]["outcome"] == "resisted"


# ----------------------------------------------------------------- report


def test_report_not_ready(configured, capsys):
    orch = Orchestrator(load_config(configured / "aegis.toml"))
    job = orch.submit(ProtectionPolicy(backend="fake"), data=b"x", name="p.bin")
    assert main(["report", job.job_id, "--json"]) == EXIT_CONFLICT
    assert _json(capsys)["error"]["code"] == "REPORT_NOT_READY"


def test_report_unknown_job(configured, capsys):
    assert main(["report", "0" * 32]) == EXIT_NOT_FOUND


def test_explicit_config_path(tmp_path, capsys):
    config_dir = tmp_path / "elsewhere"
    config_dir.mkdir()
    path = write_test_config(config_dir)
    assert main(["inspect", "--config", str(path), "--json"]) == EXIT_OK
    assert _json(capsys)["config_path"] == str(path)


def test_module_entry_point_runs():
    result = subprocess.run(
        [sys.executable, "-m", "aegis_cli", "--version"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0
    assert result.stdout.startswith("aegis ")
