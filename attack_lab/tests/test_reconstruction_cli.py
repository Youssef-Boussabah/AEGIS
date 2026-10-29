"""CLI tests for ``python -m aegis_lab.reconstruction`` (offline only).

They confirm the dry run withholds the prompt by default, offline runs publish a
valid record exclusively and return outcome-specific exit codes, and the live
path is always refused before credentials are read or any request is made. No
real token or network is used.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from test_reconstruction import NEBIUS_ENDPOINT, approval_for, build_fixture

from aegis_lab import fake_provider as fake_provider_module
from aegis_lab.fake_provider import FakeProvider
from aegis_lab.manifest import TrialManifest
from aegis_lab.provider import NebiusProvider, ProviderError
from aegis_lab.reconstruction import (
    EXIT_AUTHORIZATION_BLOCKED,
    EXIT_COMPLETED,
    EXIT_INTERRUPTED,
    EXIT_INVALID,
    EXIT_NOT_COMPLETED,
    EXIT_PUBLICATION_FAILED,
    load_reconstruction_record,
    main,
    planned_attack_digests,
    prepare_reconstruction,
)


def write_inputs(tmp_path, manifest, report):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json())
    report_path = tmp_path / "report.json"
    report_path.write_bytes(report)
    return manifest_path, report_path


@pytest.fixture
def paths(tmp_path):
    manifest, report = build_fixture(tmp_path)
    manifest_path, report_path = write_inputs(tmp_path, manifest, report)
    return {"tmp": tmp_path, "manifest": manifest, "report": report, "manifest_path": manifest_path,
            "report_path": report_path}


def run_offline(paths, *extra):
    return main(["run-offline", str(paths["manifest_path"]), str(paths["report_path"]), *extra])


# --- prepare / plan -----------------------------------------------------------------------------

def test_prepare_prints_metadata_without_prompt(paths, capsys):
    rc = main(["prepare", str(paths["manifest_path"]), str(paths["report_path"])])
    out = capsys.readouterr()
    assert rc == EXIT_COMPLETED
    document = json.loads(out.out)
    assert document["stage"] == "prepared_request"
    assert "secret_add(int a, int b) {" not in out.out + out.err
    assert document["disclosure_review"]["rendered_prompt_sha256"]


def test_prepare_show_prompt_reveals_evidence_on_stderr(paths, capsys):
    rc = main(["prepare", str(paths["manifest_path"]), str(paths["report_path"]), "--show-prompt"])
    out = capsys.readouterr()
    assert rc == EXIT_COMPLETED
    assert "int r = a + b" in out.err  # evidence text appears only on stderr, only on request
    assert "int r = a + b" not in out.out


def test_plan_prints_the_digests_a_manifest_must_declare(capsys):
    rc = main(["plan", "--max-model-tokens", "4000"])
    assert rc == EXIT_COMPLETED
    assert json.loads(capsys.readouterr().out)["attack"] == planned_attack_digests(max_model_tokens=4000)


def test_prepare_with_unverifiable_phase1_digests_fails_closed(tmp_path, capsys):
    manifest, report = build_fixture(tmp_path, **{"attack.sampling_configuration_sha256": "2" * 64})
    manifest_path, report_path = write_inputs(tmp_path, manifest, report)
    rc = main(["prepare", str(manifest_path), str(report_path)])
    assert rc == EXIT_INVALID
    assert "configuration: sampling_configuration_mismatch" in capsys.readouterr().err


def test_bad_manifest_reports_safe_code(paths, capsys):
    bad = paths["tmp"] / "bad.json"
    bad.write_text("{not json")
    rc = main(["prepare", str(bad), str(paths["report_path"])])
    assert rc == EXIT_INVALID
    assert "manifest:" in capsys.readouterr().err


def test_function_not_in_report_reports_input_code(paths, capsys):
    data = paths["manifest"].model_dump(mode="json")
    data["target"]["function"] = "nonexistent"
    mangled = paths["tmp"] / "m2.json"
    mangled.write_text(TrialManifest.model_validate(data).model_dump_json())
    rc = main(["prepare", str(mangled), str(paths["report_path"])])
    assert rc == EXIT_INVALID
    assert "input: function_not_found" in capsys.readouterr().err


def test_invalid_language_reports_policy_code(paths, capsys):
    rc = main(["prepare", str(paths["manifest_path"]), str(paths["report_path"]), "--language", "c; rm -rf"])
    assert rc == EXIT_INVALID
    err = capsys.readouterr().err
    assert "disclosure: language_not_allowed" in err and "rm -rf" not in err


# --- run-offline: outcomes and exit codes (Finding 7) -------------------------------------------

def test_run_offline_publishes_valid_record(paths, capsys):
    out_path = paths["tmp"] / "record.json"
    rc = run_offline(paths, "--output", str(out_path))
    assert rc == EXIT_COMPLETED
    record = load_reconstruction_record(out_path)
    assert record.outcome.status == "completed"
    assert record.provider.external_disclosure is False
    assert capsys.readouterr().out.strip() == record.sha256()
    assert os.stat(out_path).st_mode & 0o077 == 0  # private
    assert [p.name for p in paths["tmp"].iterdir() if p.name.endswith(".partial")] == []


def test_run_offline_with_candidate_file(paths, capsys):
    candidate = paths["tmp"] / "candidate.c"
    candidate.write_text("int secret_add(int a,int b){return a+b;}")
    rc = run_offline(paths, "--candidate", str(candidate))
    assert rc == EXIT_COMPLETED
    record = json.loads(capsys.readouterr().out)
    assert "secret_add" in record["candidate"]["source"]


def test_regression_invalid_reply_exits_nonzero_and_keeps_record(paths, capsys):
    """Audit reproduction: a failed run used to exit 0."""
    reply = paths["tmp"] / "reply.txt"
    reply.write_text("```c\nint f(){return 0;}\n```")
    out_path = paths["tmp"] / "record.json"
    rc = run_offline(paths, "--reply", str(reply), "--output", str(out_path))
    assert rc == EXIT_NOT_COMPLETED
    record = load_reconstruction_record(out_path)
    assert record.outcome.status == "invalid_candidate" and record.candidate is None
    assert "invalid_candidate" in capsys.readouterr().err


def test_regression_provider_error_exits_nonzero_and_prints_record(paths, capsys, monkeypatch):
    """Audit reproduction: a malformed_response error record was printed with exit 0."""

    class ErrorFake(FakeProvider):
        def __init__(self, **kwargs):
            super().__init__(errors=[ProviderError("malformed_response", submission="completed", status=200)],
                             **kwargs)

    monkeypatch.setattr(fake_provider_module, "FakeProvider", ErrorFake)
    rc = run_offline(paths)
    out = capsys.readouterr()
    assert rc == EXIT_NOT_COMPLETED
    assert json.loads(out.out)["outcome"]["status"] == "provider_error"


def test_interrupted_run_publishes_partial_record(paths, capsys, monkeypatch):
    def interrupt(_request, _timeout):
        raise KeyboardInterrupt

    class InterruptFake(FakeProvider):
        def __init__(self, **kwargs):
            super().__init__(on_call=interrupt, **kwargs)

    monkeypatch.setattr(fake_provider_module, "FakeProvider", InterruptFake)
    out_path = paths["tmp"] / "record.json"
    rc = run_offline(paths, "--output", str(out_path))
    assert rc == EXIT_INTERRUPTED
    assert load_reconstruction_record(out_path).outcome.status == "interrupted"


def test_offline_run_against_nebius_manifest_fails_closed(tmp_path, capsys):
    manifest, report = build_fixture(tmp_path, provider="Nebius")
    manifest_path, report_path = write_inputs(tmp_path, manifest, report)
    rc = main(["run-offline", str(manifest_path), str(report_path)])
    assert rc == EXIT_INVALID
    out = capsys.readouterr()
    assert "configuration: provider_mismatch" in out.err and out.out == ""


def test_record_output_escapes_terminal_control_characters(paths, capsys):
    candidate = paths["tmp"] / "candidate.c"
    candidate.write_text("int f(void){return 0;} /* \x1b[2J ‮ */")
    rc = run_offline(paths, "--candidate", str(candidate))
    out = capsys.readouterr().out
    assert rc == EXIT_COMPLETED
    assert "\x1b" not in out and "‮" not in out


# --- run-offline: safe publication (Finding 6) --------------------------------------------------

def test_regression_output_symlink_is_not_followed(paths, capsys):
    """Audit reproduction: --output followed a symlink and destroyed the target."""
    target = paths["tmp"] / "outside-intended-output.json"
    target.write_text("PREEXISTING AUDIT RECORD")
    link = paths["tmp"] / "record-link.json"
    link.symlink_to(target)
    rc = run_offline(paths, "--output", str(link))
    assert rc == EXIT_PUBLICATION_FAILED
    assert target.read_text() == "PREEXISTING AUDIT RECORD"
    assert link.is_symlink()
    assert "output: already_exists" in capsys.readouterr().err


def test_dangling_output_symlink_is_not_followed(paths):
    link = paths["tmp"] / "dangling.json"
    link.symlink_to(paths["tmp"] / "would-be-created.json")
    assert run_offline(paths, "--output", str(link)) == EXIT_PUBLICATION_FAILED
    assert not (paths["tmp"] / "would-be-created.json").exists()


def test_existing_record_is_never_overwritten(paths):
    out_path = paths["tmp"] / "record.json"
    assert run_offline(paths, "--output", str(out_path)) == EXIT_COMPLETED
    first = out_path.read_bytes()
    assert run_offline(paths, "--output", str(out_path)) == EXIT_PUBLICATION_FAILED
    assert out_path.read_bytes() == first


@pytest.mark.parametrize("victim", ["manifest_path", "report_path"])
def test_inputs_are_never_overwritten(paths, victim):
    before = paths[victim].read_bytes()
    assert run_offline(paths, "--output", str(paths[victim])) == EXIT_PUBLICATION_FAILED
    assert paths[victim].read_bytes() == before


def test_fifo_output_is_refused_without_blocking(paths):
    fifo = paths["tmp"] / "record.fifo"
    os.mkfifo(fifo)
    assert run_offline(paths, "--output", str(fifo)) == EXIT_PUBLICATION_FAILED


def test_missing_or_symlinked_output_directory_is_refused(paths, capsys):
    assert run_offline(paths, "--output", str(paths["tmp"] / "missing" / "r.json")) == EXIT_PUBLICATION_FAILED
    assert "output: parent_not_found" in capsys.readouterr().err
    real = paths["tmp"] / "real"
    real.mkdir()
    (paths["tmp"] / "linkdir").symlink_to(real)
    assert run_offline(paths, "--output", str(paths["tmp"] / "linkdir" / "r.json")) == EXIT_PUBLICATION_FAILED
    assert "output: parent_symlink_rejected" in capsys.readouterr().err
    assert list(real.iterdir()) == []


# --- run-live: always blocked (Findings 1 and 2) ------------------------------------------------

@pytest.fixture
def live(tmp_path, monkeypatch):
    manifest, report = build_fixture(tmp_path, provider="Nebius")
    manifest_path, report_path = write_inputs(tmp_path, manifest, report)
    prepared = prepare_reconstruction(manifest, report)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("credentials must not be read while live inference is disabled")

    monkeypatch.setattr(NebiusProvider, "from_environment", classmethod(forbidden))
    monkeypatch.setattr(NebiusProvider, "_connect", forbidden)
    monkeypatch.setenv("NEBIUS_API_KEY", "SENTINEL-NOT-A-KEY")

    def invoke(approval, *extra):
        approval_path = tmp_path / f"approval-{len(list(tmp_path.glob('approval-*')))}.json"
        approval_path.write_text(approval.model_dump_json() if hasattr(approval, "model_dump_json") else approval)
        return main(["run-live", str(manifest_path), str(report_path), "--approval", str(approval_path), *extra])

    return prepared, invoke


def test_run_live_without_opt_in_fails_closed(live, capsys):
    prepared, invoke = live
    assert invoke(approval_for(prepared)) == EXIT_AUTHORIZATION_BLOCKED
    assert "authorization: live_opt_in_required" in capsys.readouterr().err


def test_run_live_with_valid_approval_is_still_blocked(live, capsys):
    prepared, invoke = live
    rc = invoke(approval_for(prepared), "--i-accept-external-disclosure")
    err = capsys.readouterr().err
    assert rc == EXIT_AUTHORIZATION_BLOCKED
    assert "authorization: live_inference_disabled" in err
    assert "blocked_by: core_execution_authorization_unavailable" in err
    assert "blocked_by: token_bound_unverified" in err
    assert "SENTINEL" not in err


def test_regression_run_live_rejects_other_port_or_path(live, capsys):
    """Audit reproduction: a host-only approval accepted another port and API path."""
    prepared, invoke = live
    for endpoint in ("https://api.tokenfactory.nebius.com:8443/v1", "https://api.tokenfactory.nebius.com/other-api"):
        rc = invoke(approval_for(prepared), "--i-accept-external-disclosure", "--endpoint", endpoint)
        assert rc == EXIT_AUTHORIZATION_BLOCKED
        assert "authorization: endpoint_not_approved" in capsys.readouterr().err


def test_run_live_endpoint_credentials_are_never_printed(live, capsys):
    prepared, invoke = live
    rc = invoke(approval_for(prepared), "--i-accept-external-disclosure",
                "--endpoint", "https://user:URL-SECRET@api.tokenfactory.nebius.com/v1")
    out = capsys.readouterr()
    assert rc == EXIT_INVALID
    assert "endpoint: endpoint_userinfo_forbidden" in out.err
    assert "URL-SECRET" not in out.err + out.out


def test_regression_run_live_rejects_expired_approval(live, capsys):
    """Audit reproduction: approvals had no expiry."""
    prepared, invoke = live
    past = datetime.now(UTC) - timedelta(days=2)
    expired = approval_for(prepared, created_at=past, valid_from=past, expires_at=past + timedelta(hours=1))
    assert invoke(expired, "--i-accept-external-disclosure") == EXIT_AUTHORIZATION_BLOCKED
    assert "authorization: approval_expired" in capsys.readouterr().err


def test_run_live_rejects_malformed_approval_without_echo(live, capsys):
    _, invoke = live
    rc = invoke('{"reference": "X", "reference": "SECRET-DUP"}', "--i-accept-external-disclosure")
    out = capsys.readouterr()
    assert rc == EXIT_INVALID
    assert "approval: duplicate_key" in out.err and "SECRET-DUP" not in out.err


def test_run_live_rejects_naive_timestamps(live, capsys):
    prepared, invoke = live
    document = json.loads(approval_for(prepared).model_dump_json())
    document["expires_at"] = "2099-01-01T00:00:00"
    assert invoke(json.dumps(document), "--i-accept-external-disclosure") == EXIT_INVALID
    assert "approval: expires_at" in capsys.readouterr().err


def test_run_live_provider_mismatch_fails_before_approval(live, capsys):
    prepared, invoke = live
    rc = invoke(approval_for(prepared), "--i-accept-external-disclosure", "--provider-name", "Other")
    assert rc == EXIT_INVALID
    assert "configuration: provider_mismatch" in capsys.readouterr().err


def test_approval_endpoint_must_be_canonical(live):
    prepared, _ = live
    with pytest.raises(ValueError):
        approval_for(prepared, endpoint="https://api.tokenfactory.nebius.com/v1")
    assert approval_for(prepared).endpoint == NEBIUS_ENDPOINT


def test_regression2_oversized_response_exits_nonzero_with_record(paths, capsys, monkeypatch):
    """Second audit: an oversized offline response escaped without any record."""
    oversized = b" " * (8 * 1024 * 1024) + b"{}"

    class OversizedFake(FakeProvider):
        def __init__(self, **kwargs):
            super().__init__(raw_body=oversized, **kwargs)

    monkeypatch.setattr(fake_provider_module, "FakeProvider", OversizedFake)
    out_path = paths["tmp"] / "record.json"
    rc = run_offline(paths, "--output", str(out_path))
    assert rc == EXIT_NOT_COMPLETED
    record = load_reconstruction_record(out_path)
    assert record.outcome.error_category == "oversized_response" and record.candidate is None
    assert out_path.stat().st_size < 64 * 1024  # the oversized body is not retained


def test_final_none_return_exits_nonzero_with_record(paths, capsys, monkeypatch):
    """Final audit: a provider returning None left no record."""

    class NoneFake(FakeProvider):
        def complete(self, request, *, timeout):
            super().complete(request, timeout=timeout)
            return None

    monkeypatch.setattr(fake_provider_module, "FakeProvider", NoneFake)
    out_path = paths["tmp"] / "record.json"
    rc = run_offline(paths, "--output", str(out_path))
    assert rc == EXIT_NOT_COMPLETED
    record = load_reconstruction_record(out_path)
    assert record.outcome.stop_reason == "provider_contract_violation"
    assert "internal_error" not in capsys.readouterr().err


@pytest.mark.parametrize("content", ["\ud800", "x\x00y"])
def test_close_invalid_returned_text_exits_one_with_record(paths, capsys, monkeypatch, content):
    from aegis_lab.provider import InferenceResponse, parse_completion

    class TextFake(FakeProvider):
        def complete(self, request, *, timeout):
            valid = parse_completion(self._body(request))
            fields = {name: getattr(valid, name) for name in InferenceResponse.model_fields}
            return InferenceResponse.model_construct(**{**fields, "content": content})

    monkeypatch.setattr(fake_provider_module, "FakeProvider", TextFake)
    out_path = paths["tmp"] / "record.json"
    assert run_offline(paths, "--output", str(out_path)) == EXIT_NOT_COMPLETED
    assert load_reconstruction_record(out_path).outcome.stop_reason == "provider_contract_violation"
    err = capsys.readouterr().err
    assert "internal_error" not in err and "\\ud800" not in err
