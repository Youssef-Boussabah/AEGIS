"""Public export regression tests; all inference is deterministic and offline.

The external stub uses only owned synthetic artifacts and never opens a socket.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_live_inference import CONFIG, ExternalFake, run as run_live, trial, triple
from test_experiment import fx, prep

from aegis_lab.canonical import canonical_json_bytes
from aegis_lab.experiment import run_experiment, verify_experiment
from aegis_lab.fake_provider import FakeProvider
from aegis_lab.live_trial import run_trial, prepare_plan, verify_trial
from aegis_lab.private_evidence import PrivateEvidence
from aegis_lab.public_summary import (
    ComparisonEvidence, ReconstructionEvidence, export_comparison, export_experiment,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures" / "public-summary"


def edit_record(directory, edit):
    path = directory / "experiment.json"
    document = json.loads(path.read_bytes())
    edit(document)
    path.write_bytes(canonical_json_bytes(document))


def test_offline_export_is_labeled_and_contains_no_code_or_paths(fx, tmp_path):
    directory = tmp_path / "experiment"
    run_experiment(prep(fx), fx["binaries"]["baseline"], directory)
    evidence = export_experiment(directory)
    assert evidence.summary.evidence_label == "offline_scripted"
    assert evidence.summary.cost_microusd == 0
    assert evidence.summary.usage_status == "complete"
    assert evidence.summary.execution_performed is False
    encoded = evidence.model_dump_json(by_alias=True)
    assert str(tmp_path) not in encoded and "target_function" not in encoded
    assert "fake-fp" not in encoded and "messages" not in encoded
    assert evidence.source_sha256 == hashlib.sha256((directory / "experiment.json").read_bytes()).hexdigest()


@pytest.mark.parametrize("usage,expected", [(None, "unknown"), ({"prompt_tokens": "invalid"}, "unknown")])
def test_external_unknown_usage_is_null_never_zero(trial, tmp_path, usage, expected):
    run_live(trial, tmp_path, usage=usage)
    summary = export_experiment(tmp_path / "run").summary
    assert summary.provider == "Nebius" and summary.evidence_label == "external_provider_record"
    assert summary.usage_status == expected
    assert summary.reported_tokens is summary.prompt_tokens is summary.completion_tokens is None
    assert summary.known_reported_tokens == 0 and summary.charged_tokens > 0
    assert summary.cost_microusd is summary.estimated_reported_cost_microusd is None
    assert summary.reserved_spend_microusd > 0


def test_external_export_separates_usage_and_reservations(trial, tmp_path):
    run_live(trial, tmp_path, system_fingerprint="PRIVATE_RAW_FINGERPRINT")
    evidence = export_experiment(tmp_path / "run")
    summary = evidence.summary
    assert summary.reported_tokens == 160 and summary.prompt_tokens == 128 and summary.completion_tokens == 32
    assert summary.charged_tokens > summary.reported_tokens
    assert summary.cost_microusd is None and summary.estimated_reported_cost_microusd > 0
    assert summary.reported_model == summary.requested_model
    assert "PRIVATE_RAW_FINGERPRINT" not in evidence.model_dump_json()


@pytest.mark.parametrize("body", [b"not-json", b'{"choices": []}'])
def test_completed_but_malformed_response_is_verifiable_failure(trial, tmp_path, body):
    run_live(trial, tmp_path, raw_body=body)
    summary = export_experiment(tmp_path / "run").summary
    assert summary.generation_status == "provider_malformed_response"
    assert summary.candidate_sha256 is None and summary.cost_microusd is None


def test_partial_usage_does_not_present_known_subset_as_total(fx, tmp_path):
    class Partial(FakeProvider):
        def _body(self, request):
            if len(self.requests) == 1:
                self._content = '{"action":"inspect_target"}'
            else:
                self._content = '{"action":"revise_candidate","source":"int fixture(void){return 0;}"}'
                self._usage = None
            return super()._body(request)
    directory = tmp_path / "experiment"
    run_experiment(prep(fx), fx["binaries"]["baseline"], directory,
                   configuration=CONFIG.model_copy(update={"max_steps": 2}),
                   provider_factory=lambda sink: Partial(evidence_sink=sink))
    summary = export_experiment(directory).summary
    assert summary.usage_status == "partial" and summary.known_reported_tokens == 160
    assert summary.reported_tokens is summary.prompt_tokens is summary.completion_tokens is None


@pytest.mark.parametrize("field,value", [("operator_approved", 1), ("operator_approved", 1.0),
    ("provider_retention_reviewed", 1), ("request_store", 0)])
def test_approval_requires_actual_review_booleans(trial, field, value):
    from aegis_lab.disclosure import InferenceApproval

    data = trial[2].model_dump(mode="json")
    data[field] = value
    with pytest.raises(ValidationError, match="strict_boolean_required"):
        InferenceApproval.model_validate(data)


@pytest.mark.parametrize("price", [-1, "NaN", "Infinity", "-Infinity", True, None])
def test_catalogue_invalid_prices_fail_closed(price):
    from test_live_inference import catalogue, MODEL, CONTEXT
    from aegis_lab.bounded_provider import verify_model_evidence
    from aegis_lab.provider import ProviderError

    with pytest.raises(ProviderError, match="invalid_request"):
        verify_model_evidence(canonical_json_bytes({"object": "list", "data": [{"id": MODEL}]}),
            canonical_json_bytes(catalogue(input_price_per_million_tokens=price)), MODEL,
            context_tokens=CONTEXT, input_price=100_000, output_price=300_000)


def test_preflight_only_checks_credential_name_presence(trial, monkeypatch):
    from aegis_lab.live import preflight

    class PresenceOnly(dict):
        def get(self, key, default=None):
            if key == "NEBIUS_API_KEY":
                pytest.fail("credential value inspected")
            return super().get(key, default)
        def __getitem__(self, key):
            if key == "NEBIUS_API_KEY":
                pytest.fail("credential value inspected")
            return super().__getitem__(key)
    monkeypatch.setattr("aegis_lab.live.os.environ", PresenceOnly(NEBIUS_API_KEY=object()))
    summary = preflight(trial[0], trial[1], CONFIG)
    assert summary["credentials_configured"] and summary["network_requests"] == 0


def test_untrusted_model_echo_and_limitations_do_not_escape(trial, tmp_path):
    run_live(trial, tmp_path, reported_model="/private/DO_NOT_EXPORT")
    edit_record(tmp_path / "run", lambda d: d.update(limitations=["SECRET_RAW_DIAGNOSTIC"]))
    evidence = export_experiment(tmp_path / "run")
    assert evidence.summary.reported_model is None and evidence.summary.reported_model_status == "mismatch"
    assert "DO_NOT_EXPORT" not in evidence.model_dump_json() and "SECRET_RAW" not in evidence.model_dump_json()


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(generation_status="generated_but_behaviorally_unscored"),
    lambda d: d["steps"][0].update(outcome="generated_but_behaviorally_unscored"),
    lambda d: (d["steps"][0].update(charged_tokens=1), d.update(charged_tokens=1)),
    lambda d: d.update(estimated_reported_cost_microusd=0),
    lambda d: d["provider"].update(provider="OtherProvider"),
])
def test_rewritten_failure_and_ledgers_are_rejected(trial, tmp_path, mutation):
    run_live(trial, tmp_path, message_extra={"refusal": "declined"})
    edit_record(tmp_path / "run", mutation)
    with pytest.raises((ValueError, ValidationError)):
        export_experiment(tmp_path / "run")


def test_catalogue_contents_are_reverified_even_with_new_valid_blob_hash(trial, tmp_path):
    run_live(trial, tmp_path)
    directory = tmp_path / "run"
    store = PrivateEvidence(directory / "private-evidence", create=False)
    digest = store.put(canonical_json_bytes({"object": "list", "data": []}))
    edit_record(directory, lambda d: d.update(account_models_sha256=digest))
    with pytest.raises(Exception, match="model_not_found"):
        verify_experiment(directory)


def test_different_historical_candidate_cannot_replace_selected_revision(fx, tmp_path):
    from test_experiment import factory

    directory = tmp_path / "experiment"
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], directory, provider_factory=factory(
        '{"action":"revise_candidate","source":"int first(void){return 1;}"}',
        '{"action":"revise_candidate","source":"int second(void){return 2;}"}', '{"action":"finish"}'))
    edit_record(directory, lambda d: d.update(candidate_sha256=record.steps[0].candidate_sha256))
    with pytest.raises(ValueError, match="selected_candidate_mismatch"):
        verify_experiment(directory)


def test_live_timestamp_outside_approval_is_rejected(trial, tmp_path):
    run_live(trial, tmp_path)
    after = trial[2].disclosure.expires_at.isoformat()
    edit_record(tmp_path / "run", lambda d: d.update(started_at=after, finished_at=after))
    with pytest.raises(ValueError, match="experiment_outside_approval_window"):
        export_experiment(tmp_path / "run")


@pytest.fixture
def comparison(triple, tmp_path):
    prepared, _, _ = prepare_plan(triple)
    directory = tmp_path / "comparison"
    run_trial(triple, directory, provider_factory=lambda sink: ExternalFake(sink, prepared["baseline"]))
    return directory


def test_comparison_reverifies_records_without_reading_original_plan_paths(comparison, monkeypatch):
    import aegis_lab.live_trial as module

    monkeypatch.setattr(module, "prepare_plan", lambda _: pytest.fail("original plan paths read"))
    result, records = verify_trial(comparison)
    assert len(records) == 3 and result["reported_identity_comparable"]
    evidence = export_comparison(comparison)
    assert len(evidence.summary.experiments) == 3
    assert evidence.summary.protection_effect == "not_established"
    assert str(comparison) not in evidence.model_dump_json()


@pytest.mark.parametrize("field,value", [
    ("protection_effect", "resisted"), ("execution_performed", True),
    ("reported_identity_comparable", False), ("order_seed", 42),
])
def test_edited_comparison_claims_fail_closed(comparison, field, value):
    path = comparison / "live-trial.json"
    document = json.loads(path.read_bytes())
    document[field] = value
    path.write_bytes(canonical_json_bytes(document))
    with pytest.raises(ValueError):
        export_comparison(comparison)


def test_export_rejects_record_replacement_between_hash_and_verification(trial, tmp_path, monkeypatch):
    import aegis_lab.public_summary as module

    run_live(trial, tmp_path)
    original = module.read_regular_file
    def replaced(path, limit):
        data = original(path, limit)
        edit_record(tmp_path / "run", lambda d: d.update(limitations=["changed record"]))
        return data
    monkeypatch.setattr(module, "read_regular_file", replaced)
    with pytest.raises(ValueError, match="experiment_record_digest_mismatch"):
        export_experiment(tmp_path / "run")


def test_comparison_source_replacement_is_rejected(comparison, monkeypatch):
    import aegis_lab.public_summary as module

    original = module.read_regular_file
    def replaced(path, limit):
        data = original(path, limit)
        path.write_bytes(data + b"\n")
        return data
    monkeypatch.setattr(module, "read_regular_file", replaced)
    with pytest.raises(ValueError, match="trial_source_digest_mismatch"):
        export_comparison(comparison)


def test_comparison_identity_requires_one_complete_identity():
    from aegis_lab.live_trial import identity_comparable

    row = {"reported_models": ["a", "b"], "reported_fingerprints": ["fp1", "fp2"], "reported_identity_complete": True}
    assert not identity_comparable({k: row for k in ("baseline", "shield", "mirage")})
    row = {"reported_models": ["a"], "reported_fingerprints": ["fp1"], "reported_identity_complete": False}
    assert not identity_comparable({k: row for k in ("baseline", "shield", "mirage")})


def test_cli_uses_private_exclusive_output_and_sanitizes_failures(trial, tmp_path, monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("evidence_exporter", ROOT / "scripts" / "export-product-evidence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run_live(trial, tmp_path)
    output = tmp_path / "summary.json"
    monkeypatch.setattr("sys.argv", ["export", "reconstruction", str(tmp_path / "run"), "--output", str(output)])
    assert module.main() == 0
    original = output.read_bytes()
    assert output.stat().st_mode & 0o077 == 0
    assert hashlib.sha256(original).hexdigest() in capsys.readouterr().out
    assert module.main() == 1 and output.read_bytes() == original
    assert str(tmp_path) not in capsys.readouterr().err


@pytest.mark.parametrize("name,model", [
    ("offline-scripted.json", ReconstructionEvidence),
    ("synthetic-nebius.json", ReconstructionEvidence),
    ("synthetic-comparison.json", ComparisonEvidence),
])
def test_frontend_fixtures_are_schema_valid_and_explicitly_non_live(name, model):
    evidence = model.model_validate_json((FIXTURES / name).read_bytes())
    assert evidence.summary.evidence_label in ("offline_scripted", "synthetic_fixture")
    schema = json.loads((FIXTURES / "schema.json").read_bytes())
    assert schema[evidence.kind] == model.model_json_schema()


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(prompt="DO_NOT_EXPORT"),
    lambda d: d["summary"].update(candidate_code="DO_NOT_EXPORT"),
    lambda d: d["summary"].update(execution_performed=True),
    lambda d: d["summary"].update(execution_performed=0),
    lambda d: d["summary"].update(attack_effectiveness="resisted"),
    lambda d: d["summary"].update(reported_tokens=0),
    lambda d: d["summary"].update(cost_microusd=0),
    lambda d: d["summary"].update(steps=True),
    lambda d: d["summary"].update(known_reported_tokens=2**53),
])
def test_public_schema_rejects_extra_private_fields_and_false_claims(mutation):
    document = json.loads((FIXTURES / "synthetic-nebius.json").read_bytes())
    mutation(document)
    with pytest.raises(ValidationError):
        ReconstructionEvidence.model_validate(document)
