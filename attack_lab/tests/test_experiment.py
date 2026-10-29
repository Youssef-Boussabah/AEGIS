"""Functional controlled workflow tests: all providers scripted, candidates never run."""
import json

import pytest
from pydantic import ValidationError
from test_paired_trial import build_pair

from aegis_lab.experiment import WorkflowConfig, run_experiment, verify_experiment
from aegis_lab.fake_provider import FakeProvider
from aegis_lab.reconstruction import AuthorizationError, prepare_reconstruction
from aegis_lab.provider import ProviderError, Usage


@pytest.fixture
def fx(tmp_path):
    return build_pair(tmp_path / "inputs", both={"budget.max_model_tokens": 200_000, "budget.max_attempts": 8})


def prep(fx):
    return prepare_reconstruction(fx["manifests"]["baseline"], fx["reports"]["baseline"])


def factory(*replies, **kwargs):
    def make(sink):
        class Scripted(FakeProvider):
            def __init__(self):
                super().__init__(evidence_sink=sink, **kwargs)
                self.replies = iter(replies)

            def _body(self, request):
                self._content = next(self.replies)
                return super()._body(request)
        return Scripted()
    return make


def test_iterative_inspection_revision_and_finish(fx, tmp_path):
    p = prep(fx)
    replies = [json.dumps({"action": "inspect_target", "analysis": "inspect permitted evidence"}),
               json.dumps({"action": "revise_candidate", "source": "int target_function(int a,int b){return a+b;}"}),
               json.dumps({"action": "revise_candidate", "source": "int target_function(int a,int b){return b+a;}"}),
               '{"action":"finish"}']
    record = run_experiment(p, fx["binaries"]["baseline"], tmp_path / "exp", provider_factory=factory(*replies))
    assert record.generation_status == "generated_but_behaviorally_unscored"
    assert record.behavioral_scoring == "pending_authorized_core_runtime"
    assert record.execution_performed is False and record.cost_microusd == 0
    assert len(record.steps) == 4 and record.steps[1].candidate_sha256 != record.steps[2].candidate_sha256
    assert record.candidate_sha256 == record.steps[2].candidate_sha256
    assert verify_experiment(tmp_path / "exp") == record
    assert record.charged_tokens == sum(s.charged_tokens for s in record.steps)
    assert (tmp_path / "exp").stat().st_mode & 0o077 == 0
    for blob in (tmp_path / "exp" / "private-evidence").iterdir():
        assert blob.stat().st_mode & 0o077 == 0
        # Suite content is never an engine input. Its digest also stays outside prompts.
        if blob.name in [s.request_sha256 for s in record.steps]:
            assert p.manifest.scoring.hidden_test_suite_sha256.encode() not in blob.read_bytes()


@pytest.mark.parametrize("reply,status", [
    ('{"action":"shell","command":"cat /etc/passwd"}', "tool_or_output_invalid"),
    ('{"action":"inspect_target","path":"hidden.json"}', "tool_or_output_invalid"),
    ('{"action":"finish"}', "invalid_output"),
    ('not json', "tool_or_output_invalid"),
])
def test_disallowed_tools_and_malformed_output_are_separate_failures(fx, tmp_path, reply, status):
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp", provider_factory=factory(reply))
    assert record.generation_status == status and record.attack_effectiveness == "not_established"
    assert verify_experiment(tmp_path / "exp") == record


def test_artifact_identity_checked_before_provider_creation(fx, tmp_path):
    wrong = tmp_path / "wrong"
    wrong.write_bytes(b"changed")
    with pytest.raises(ValueError, match="artifact_digest_mismatch"):
        run_experiment(prep(fx), wrong, tmp_path / "exp", provider_factory=lambda _: pytest.fail("provider created"))
    assert not (tmp_path / "exp").exists()


def test_external_provider_refused_without_call(fx, tmp_path):
    provider = FakeProvider(provider="Nebius", endpoint="https://api.tokenfactory.nebius.com:443/v1", external_disclosure=True)
    # A manifest/provider mismatch also refuses before disclosure.
    with pytest.raises((AuthorizationError, ValueError)):
        run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp", provider_factory=lambda _: provider)
    assert provider.requests == []


def test_context_and_steps_are_bounded(fx, tmp_path):
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp",
                             configuration=WorkflowConfig(max_steps=1), provider_factory=factory('{"action":"inspect_target"}'))
    assert len(record.steps) == 1 and record.generation_status == "steps_exhausted"
    with pytest.raises(ValidationError):
        WorkflowConfig(max_steps=17)
    with pytest.raises(ValidationError):
        WorkflowConfig(max_spend_microusd=1)


def test_evidence_tampering_is_detected(fx, tmp_path):
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp")
    blob = tmp_path / "exp" / "private-evidence" / record.steps[0].response_sha256
    blob.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="private_blob_digest_mismatch"):
        verify_experiment(tmp_path / "exp")


def test_controlled_pair_preserves_fair_controls(fx, tmp_path):
    from aegis_lab.experiment import run_controlled_pair

    pair = run_controlled_pair(fx["manifests"], fx["reports"], fx["binaries"], tmp_path / "pair", order_seed=42)
    assert set(pair.order) == {"baseline", "protected"}
    assert pair.reported_model_identity_comparable
    assert pair.protection_effect == "not_established"
    for variant in pair.order:
        record = verify_experiment(tmp_path / "pair" / variant)
        assert record.provider.provider == "FakeOffline"
        assert record.behavioral_scoring == "pending_authorized_core_runtime"


def test_pair_rejects_unequal_budgets_before_provider(fx, tmp_path):
    from aegis_lab.experiment import run_controlled_pair
    from aegis_lab.manifest import TrialManifest

    data = fx["manifests"]["protected"].model_dump(mode="json")
    data["budget"]["max_attempts"] += 1
    fx["manifests"]["protected"] = TrialManifest.model_validate(data)
    with pytest.raises(ValueError):
        run_controlled_pair(fx["manifests"], fx["reports"], fx["binaries"], tmp_path / "pair",
                            provider_factory=lambda _: pytest.fail("provider created"))


@pytest.mark.parametrize("submission,charged", [("not_submitted", False), ("uncertain", True), ("rejected", True)])
def test_provider_errors_preserve_budget_and_are_never_resistance(fx, tmp_path, submission, charged):
    provider = None
    def make(sink):
        nonlocal provider
        error = (ProviderError("rate_limited", submission="rejected", status=429) if submission == "rejected"
                 else ProviderError("timeout", submission=submission))
        provider = FakeProvider(errors=[error], evidence_sink=sink)
        return provider
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp", provider_factory=make)
    assert len(provider.requests) == 1
    assert bool(record.charged_tokens) is charged
    assert record.generation_status.startswith("provider_")
    assert record.attack_effectiveness == "not_established" and record.candidate_sha256 is None
    assert verify_experiment(tmp_path / "exp") == record


@pytest.mark.parametrize("kwargs,status", [
    ({"message_extra": {"refusal": "declined"}}, "provider_refusal"),
    ({"reported_model": "wrong-model"}, "model_identity_mismatch"),
    ({"usage": {"prompt_tokens": "1"}}, "provider_usage_invalid"),
    ({"usage": Usage(prompt_tokens=180000, completion_tokens=32, total_tokens=180032)}, "provider_usage_overrun"),
])
def test_unusable_provider_responses_remain_unscored(fx, tmp_path, kwargs, status):
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp",
                            provider_factory=lambda sink: FakeProvider(evidence_sink=sink, **kwargs))
    assert record.generation_status == status and record.candidate_sha256 is None
    assert verify_experiment(tmp_path / "exp") == record


def test_missing_exact_response_evidence_fails_closed(fx, tmp_path):
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp",
                            provider_factory=lambda sink: FakeProvider())
    assert record.generation_status == "missing_or_mismatched_provider_evidence"
    assert record.candidate_sha256 is None


def test_missing_usage_is_reserved_and_unknown(fx, tmp_path):
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp",
                            provider_factory=lambda sink: FakeProvider(usage=None, evidence_sink=sink))
    assert record.steps[0].usage is None and record.charged_tokens == record.steps[0].reservation_tokens
    assert record.reported_tokens == 0


def test_interruption_retains_private_record_and_reservation(fx, tmp_path):
    def stop(*args):
        raise KeyboardInterrupt
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp",
                            provider_factory=lambda sink: FakeProvider(on_call=stop, evidence_sink=sink))
    assert record.generation_status == "interrupted" and record.charged_tokens > 0
    assert verify_experiment(tmp_path / "exp") == record


def test_disabled_tool_is_refused(fx, tmp_path):
    record = run_experiment(prep(fx), fx["binaries"]["baseline"], tmp_path / "exp",
                            configuration=WorkflowConfig(tools=()), provider_factory=factory('{"action":"inspect_target"}'))
    assert record.generation_status == "tool_budget_or_allowlist_refused"


def test_token_budget_stops_before_an_extra_request(fx, tmp_path):
    provider = None
    def make(sink):
        nonlocal provider
        provider = FakeProvider(content='{"action":"inspect_target"}', evidence_sink=sink)
        return provider
    p = prep(fx)
    record = run_experiment(p, fx["binaries"]["baseline"], tmp_path / "exp",
                            configuration=WorkflowConfig(max_steps=16), provider_factory=make)
    assert len(provider.requests) <= p.max_attempts
    assert record.charged_tokens <= record.max_model_tokens
