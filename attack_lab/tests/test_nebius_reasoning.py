"""Synthetic Nebius response-shape regressions: no network, secrets or code execution.

The fixture preserves field names/types and aggregate usage from the supplied
response. All content, reasoning, source, identifiers and timestamps are synthetic.
No test reads the operator's archive or writes into it.
"""
import hashlib
import json
from pathlib import Path

import pytest
from test_live_inference import CONFIG, ExternalFake, trial
from test_provider import FakeConnection, req
from test_reconstruction import approval_for

from aegis_lab.bounded_provider import BoundedNebiusProvider
from aegis_lab.canonical import canonical_json_bytes
from aegis_lab.completion_review import main, review_completion, write_review
from aegis_lab.disclosure import InferenceApproval
from aegis_lab.experiment import run_experiment, verify_experiment
from aegis_lab.manifest import TrialManifest
from aegis_lab.provider import (
    LEGACY_COMPLETION_PARSER as V1, NEBIUS_REASONING_COMPLETION_PARSER as V2,
    NebiusProvider, ProviderError, parse_completion,
)
from aegis_lab.reconstruction import parse_candidate_envelope, planned_attack_digests, prepare_reconstruction

FIXTURE = Path(__file__).parent / "fixtures" / "nebius-reasoning-sanitized.json"


def document():
    return json.loads(FIXTURE.read_bytes())


def wire(message_update=None):
    data = document()
    data["choices"][0]["message"].update(message_update or {})
    return json.dumps(data, ensure_ascii=True).encode()


def tree_digest(root):
    return {p.relative_to(root): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


def test_sanitized_actual_shape_legacy_rejects_current_accepts():
    legacy, current = parse_completion(wire()), parse_completion(wire(), parser=V2)
    assert legacy.unsupported_fields is True and current.unsupported_fields is False
    assert legacy.content == current.content and current.finish_reason == "stop"
    assert current.usage.total_tokens == 9825
    assert current.usage.prompt_tokens == 1786 and current.usage.completion_tokens == 8039
    assert current.refusal is current.tool_calls is False
    source, error = parse_candidate_envelope(current.content, language="c", interface="int fixture_add(int a, int b)")
    assert error is None and source
    # Parsing does not retain either opaque reasoning field in the typed response.
    assert "Synthetic placeholder" not in current.model_dump_json()
    assert current.model_dump(exclude={"unsupported_fields"}) == legacy.model_dump(exclude={"unsupported_fields"})


@pytest.mark.parametrize("field", ["reasoning", "reasoning_content"])
@pytest.mark.parametrize("value", [None, "", "Synthetic UTF-8 metadata \u00e9\nnext line"])
def test_recognized_reasoning_metadata_is_only_null_or_valid_text(field, value):
    assert not parse_completion(wire({field: value}), parser=V2).unsupported_fields


@pytest.mark.parametrize("field", ["reasoning", "reasoning_content"])
@pytest.mark.parametrize("value", [0, True, 1.5, [], {}, "bad\x00text", "\ud800"])
def test_recognized_reasoning_wrong_types_and_invalid_text_are_rejected(field, value):
    with pytest.raises(ProviderError, match="malformed_response"):
        parse_completion(wire({field: value}), parser=V2)
    # Historical v1 semantics must stay intact, even for metadata v2 refuses.
    assert parse_completion(wire({field: value}), parser=V1).unsupported_fields


@pytest.mark.parametrize("extra", [
    {"unexpected": None}, {"unexpected": "synthetic"}, {"reasoning_details": []},
    {"reasoning_content_extra": "synthetic"}, {"audio": {}}, {"annotations": []},
])
def test_unknown_and_other_nonnull_extensions_remain_unsupported(extra):
    assert parse_completion(wire(extra), parser=V2).unsupported_fields


@pytest.mark.parametrize("raw", [b"", b"not JSON", b'{"choices":', b'{"choices":[],"choices":[]}', b'{"x":NaN}'])
def test_malformed_http_json_fails_with_safe_diagnostic(raw):
    with pytest.raises(ProviderError, match="malformed_response") as info:
        parse_completion(raw, parser=V2)
    assert "choices" not in str(info.value) and "not JSON" not in str(info.value)


def test_unknown_parser_version_is_refused():
    with pytest.raises(ValueError, match="unknown_completion_parser"):
        parse_completion(wire(), parser="unknown")


def test_nebius_http_transport_selects_v2_without_network(monkeypatch):
    monkeypatch.setattr(NebiusProvider, "_connect", lambda _: FakeConnection(status=200, body=wire()))
    provider = NebiusProvider("SYNTHETIC_TEST_ONLY", allow_live=True)
    assert provider.completion_parser == V2
    assert not provider.complete(req(), timeout=2).unsupported_fields


def test_bounded_nebius_parent_selects_same_v2_parser(monkeypatch):
    monkeypatch.setattr(BoundedNebiusProvider, "_worker", lambda *a, **kw: {"response": wire()})
    provider = BoundedNebiusProvider("SYNTHETIC_TEST_ONLY", allow_live=True)
    assert not provider.complete(req(store=False), timeout=2).unsupported_fields


def archive(trial, tmp_path, *, parser=V1, message_update=None, unversioned=False):
    prepared, artifact, approval = trial
    data = prepared.manifest.model_dump(mode="json")
    data["attack"].update(planned_attack_digests(max_model_tokens=prepared.max_model_tokens,
        max_output_tokens=8192, blinded=prepared.blinded))
    prepared = prepare_reconstruction(TrialManifest.model_validate(data), prepared.report_bytes, max_output_tokens=8192)
    # This approval authorizes only the local synthetic fixture and is never sent.
    approval = InferenceApproval.model_validate({**approval.model_dump(), "manifest_sha256": prepared.manifest_sha256,
        "disclosure": approval_for(prepared, model_id=prepared.request.model)})
    response = document()
    response["model"] = prepared.request.model
    envelope = json.loads(response["choices"][0]["message"]["content"])
    envelope["interface"] = prepared.expected_interface
    response["choices"][0]["message"]["content"] = json.dumps(envelope)
    response["choices"][0]["message"].update(message_update or {})
    raw = json.dumps(response).encode()

    class ShapeFake(ExternalFake):
        completion_parser = parser

        def _body(self, request):
            return raw

        def complete(self, request, *, timeout):
            super().complete(request, timeout=timeout)  # capture exact request/response bytes
            return parse_completion(raw, parser=self.completion_parser)

    root = tmp_path / "synthetic-experiment"
    run_experiment(prepared, artifact, root, configuration=CONFIG,
        provider_factory=lambda sink: ShapeFake(sink, prepared), inference_approval=approval,
        approval_state_dir=tmp_path / "synthetic-approval-state", allow_live=True)
    if unversioned:
        path = root / "experiment.json"
        record = json.loads(path.read_bytes())
        del record["completion_parser"]
        path.write_bytes(canonical_json_bytes(record))
    return root


def test_unversioned_historical_record_keeps_v1_and_invalid_output(trial, tmp_path):
    root = archive(trial, tmp_path, unversioned=True)
    before = tree_digest(root)
    result = verify_experiment(root)
    assert result.completion_parser == V1 and result.generation_status == "invalid_output"
    assert tree_digest(root) == before


def test_new_record_binds_v2_and_verifies_accepted_candidate_text(trial, tmp_path):
    root = archive(trial, tmp_path, parser=V2)
    result = verify_experiment(root)
    assert result.completion_parser == V2 and result.generation_status == "generated_but_behaviorally_unscored"
    assert result.candidate_sha256 is not None and result.execution_performed is False


def test_relabeling_old_archive_parser_is_not_a_valid_migration(trial, tmp_path):
    root = archive(trial, tmp_path, unversioned=True)
    path = root / "experiment.json"
    data = json.loads(path.read_bytes())
    data["completion_parser"] = V2
    path.write_bytes(canonical_json_bytes(data))
    with pytest.raises(ValueError, match="response_provenance_mismatch"):
        verify_experiment(root)


def test_post_hoc_report_binds_history_and_never_rewrites_it(trial, tmp_path, capsys):
    root = archive(trial, tmp_path, unversioned=True,
        message_update={"reasoning": "PRIVATE_REASONING_SENTINEL", "reasoning_content": "PRIVATE_REASONING_SENTINEL"})
    before = tree_digest(root)
    output = tmp_path / "post-hoc.json"
    assert main([str(root), "--output", str(output)]) == 0
    emitted = capsys.readouterr().out
    result = json.loads(output.read_bytes())
    assert "PRIVATE_REASONING_SENTINEL" not in emitted and "fixture_add" not in emitted
    assert result["analysis_kind"] == "post_hoc_parser_compatibility_review"
    assert result["historical_generation_status"] == "invalid_output"
    assert result["historical_experiment_sha256"] == before[Path("experiment.json")]
    assert result["post_hoc_status"] == "candidate_text_revalidated_but_behaviorally_unscored"
    assert result["candidate_envelope_valid"] and result["candidate_sha256"]
    assert result["execution_performed"] is False and result["behavioral_scoring"] == "unscored"
    assert result["reasoning_fields_validated"] == ["reasoning", "reasoning_content"]
    assert output.stat().st_mode & 0o077 == 0
    assert tree_digest(root) == before and verify_experiment(root).generation_status == "invalid_output"
    assert main([str(root), "--output", str(output)]) == 2  # exclusive new-file publication
    assert "PRIVATE_REASONING_SENTINEL" not in capsys.readouterr().err


@pytest.mark.parametrize("extra", [{"unexpected": "must reject"}, {"content": "{malformed candidate JSON}"},
    {"tool_calls": [{"synthetic": True}]}])
def test_post_hoc_review_does_not_mask_other_response_problems(trial, tmp_path, extra):
    root = archive(trial, tmp_path, unversioned=True, message_update=extra)
    result = review_completion(root)
    assert result.post_hoc_status == "rejected" and result.candidate_sha256 is None
    assert verify_experiment(root).generation_status == "invalid_output"


def test_post_hoc_tool_does_not_reclassify_an_original_provider_refusal(trial, tmp_path):
    root = archive(trial, tmp_path, unversioned=True, message_update={"refusal": "synthetic refusal"})
    assert verify_experiment(root).generation_status == "provider_refusal"
    with pytest.raises(ValueError, match="legacy_nebius_invalid_output_record_required"):
        review_completion(root)


def test_post_hoc_tool_refuses_output_inside_original_archive(trial, tmp_path):
    root = archive(trial, tmp_path, unversioned=True)
    before = tree_digest(root)
    with pytest.raises(ValueError, match="original_archive_is_read_only"):
        write_review(root, root / "post-hoc.json")
    assert tree_digest(root) == before


def test_post_hoc_tool_requires_verifiable_history(trial, tmp_path):
    root = archive(trial, tmp_path, unversioned=True)
    record = verify_experiment(root)
    (root / "private-evidence" / record.steps[0].response_sha256).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="private_blob_digest_mismatch"):
        review_completion(root)
