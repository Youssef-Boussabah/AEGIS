"""Inference approval and real supervision tested without external requests or candidates."""
from datetime import UTC, datetime, timedelta
import base64
import io
import json
import os
from pathlib import Path
import sys
import time

import pytest
from pydantic import ValidationError
from test_paired_trial import build_pair
from test_reconstruction import approval_for

from aegis_lab.bounded_provider import BoundedNebiusProvider, supervise
from aegis_lab.canonical import canonical_json_bytes
from aegis_lab.disclosure import AuthorizationError, InferenceApproval
from aegis_lab.experiment import WorkflowConfig, live_workflow_sha256, run_experiment, verify_experiment
from aegis_lab.fake_provider import FakeProvider
from aegis_lab.inference import check_inference_approval, load_approval
from aegis_lab.live import main, preflight
from aegis_lab.provider import InferenceRequest, Message, ProviderError
from aegis_lab.reconstruction import prepare_reconstruction, run_live_reconstruction

MODEL = "nvidia/owned-test-model"
CONTEXT = 100_000
CONFIG = WorkflowConfig(max_steps=1)


@pytest.fixture
def trial(tmp_path):
    fx = build_pair(tmp_path / "inputs", both={"attack.provider": "Nebius", "attack.model_id": MODEL,
                   "budget.max_model_tokens": 200_000, "budget.max_attempts": 4})
    p = prepare_reconstruction(fx["manifests"]["baseline"], fx["reports"]["baseline"])
    now = datetime.now(UTC)
    disclosure = approval_for(p, model_id=MODEL, created_at=now, valid_from=now, expires_at=now + timedelta(hours=1))
    approval = InferenceApproval(operator_approved=True, disclosure=disclosure,
        manifest_sha256=p.manifest_sha256, workflow_sha256=live_workflow_sha256(CONFIG),
        max_requests=1, max_total_tokens=p.max_model_tokens, max_spend_microusd=1_000_000,
        context_tokens=CONTEXT, input_microusd_per_million=100_000, output_microusd_per_million=300_000,
        request_timeout_seconds=2, request_deadline=now + timedelta(minutes=30),
        private_archive_delete_after=now + timedelta(days=1), provider_retention_policy="Operator reviewed test terms",
        provider_retention_reviewed=True)
    return p, fx["binaries"]["baseline"], approval


class ExternalFake(FakeProvider):
    """Explicit deterministic external stub; never networked or used as real evidence."""
    hard_deadline = True

    def __init__(self, sink, p, **kwargs):
        content = json.dumps({"schema": "aegis.lab.candidate.v1", "language": "c",
                              "interface": p.expected_interface, "source": "int target_function(void){return 0;}"})
        super().__init__(provider="Nebius", endpoint="https://api.tokenfactory.nebius.com:443/v1",
                         external_disclosure=True, content=content, evidence_sink=sink, **kwargs)

    def verify_model(self, model, **kwargs):
        self._evidence_sink("account_models", canonical_json_bytes({"object": "list", "data": [{"id": MODEL}]}))
        self._evidence_sink("public_catalogue", canonical_json_bytes(catalogue()))


def catalogue(**overrides):
    flavor = {"model_id": MODEL, "max_model_len": CONTEXT, "external_provider": False,
              "input_price_per_million_tokens": 0.1, "output_price_per_million_tokens": 0.3, **overrides}
    return [{"vendor": "nvidia", "status": "active", "license": {"url": "https://example.org/license"},
             "flavors": [flavor]}]


def run(trial, tmp_path, **kwargs):
    p, artifact, approval = trial
    return run_live_reconstruction(p, artifact, tmp_path / "run", inference_approval=approval,
        approval_state_dir=tmp_path / "state", allow_live=True, configuration=CONFIG,
        provider_factory=lambda sink: ExternalFake(sink, p, **kwargs))


def test_approved_request_and_private_provenance(trial, tmp_path):
    record = run(trial, tmp_path)
    assert record.generation_status == "generated_but_behaviorally_unscored"
    assert record.execution_performed is False and record.attack_effectiveness == "not_established"
    assert record.cost_microusd is None and record.cost_basis == "provider_invoice_unknown"
    assert record.steps[0].reservation_tokens == CONTEXT + trial[0].request.max_output_tokens
    assert record.steps[0].submission == "completed"
    assert record.estimated_reported_cost_microusd > 0
    assert verify_experiment(tmp_path / "run") == record
    for path in (tmp_path / "run").rglob("*"):
        assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(AuthorizationError, match="inference_approval_already_used"):
        run_live_reconstruction(trial[0], trial[1], tmp_path / "second", inference_approval=trial[2],
            approval_state_dir=tmp_path / "state", allow_live=True, configuration=CONFIG,
            provider_factory=lambda sink: ExternalFake(sink, trial[0]))


@pytest.mark.parametrize("field,value,code", [
    ("manifest_sha256", "0" * 64, "inference_scope_mismatch"),
    ("workflow_sha256", "0" * 64, "inference_scope_mismatch"),
    ("max_requests", 2, "inference_budget_not_approved"),
    ("max_total_tokens", 1, "inference_budget_not_approved"),
    ("max_total_tokens", 200001, "inference_budget_not_approved"),
    ("max_spend_microusd", 1, "inference_budget_not_approved"),
    ("context_tokens", 1, "inference_budget_not_approved"),
])
def test_negative_approval_before_provider(trial, tmp_path, field, value, code):
    p, artifact, approval = trial
    bad = InferenceApproval.model_validate({**approval.model_dump(), field: value})
    with pytest.raises(AuthorizationError, match=code):
        run_experiment(p, artifact, tmp_path / "run", configuration=CONFIG, inference_approval=bad, allow_live=True,
            approval_state_dir=tmp_path / "state", provider_factory=lambda _: pytest.fail("provider created"))
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("field,value", [("operator_approved", False), ("provider_retention_reviewed", False),
                                         ("request_store", True), ("purpose", "execute")])
def test_draft_or_execution_approval_is_invalid(trial, field, value):
    with pytest.raises(ValidationError):
        InferenceApproval.model_validate({**trial[2].model_dump(), field: value})


def test_missing_opt_in_or_approval(trial, tmp_path):
    p, artifact, approval = trial
    for grant, opt_in, code in ((approval, False, "live_opt_in_required"),
                               (None, True, "inference_approval_required")):
        with pytest.raises(AuthorizationError, match=code):
            run_experiment(p, artifact, tmp_path / "run", configuration=CONFIG, inference_approval=grant,
                allow_live=opt_in, approval_state_dir=tmp_path / "state", provider_factory=lambda sink: ExternalFake(sink, p))


def test_expired_deadline_and_disclosure_fail_closed(trial):
    p, _, approval = trial
    with pytest.raises(AuthorizationError, match="request_deadline_expired"):
        check_inference_approval(p, CONFIG, approval, allow_live=True, now=approval.request_deadline)
    with pytest.raises(AuthorizationError, match="approval_expired"):
        check_inference_approval(p, CONFIG, approval, allow_live=True, now=approval.disclosure.expires_at)


@pytest.mark.parametrize("kwargs,status", [
    ({"reported_model": "nvidia/other"}, "model_identity_mismatch"),
    ({"message_extra": {"refusal": "cannot comply"}}, "provider_refusal"),
    ({"usage": None}, "generated_but_behaviorally_unscored"),
    ({"usage": {"prompt_tokens": "128"}}, "provider_usage_invalid"),
    ({"usage": {"prompt_tokens": CONTEXT + 1, "completion_tokens": 1, "total_tokens": CONTEXT + 2}}, "provider_usage_overrun"),
    ({"finish_reason": "length"}, "invalid_output"),
    ({"errors": [ProviderError("timeout", submission="uncertain")]}, "provider_timeout"),
    ({"errors": [ProviderError("rate_limited", submission="rejected", status=429)]}, "provider_rate_limited"),
])
def test_live_outcomes_never_imply_behavioral_success(trial, tmp_path, kwargs, status):
    record = run(trial, tmp_path, **kwargs)
    assert record.generation_status == status and len(record.steps) == 1
    assert record.execution_performed is False
    assert verify_experiment(tmp_path / "run") == record


def test_catalogue_failure_is_archived_without_post(trial, tmp_path):
    p, artifact, approval = trial
    class Missing(ExternalFake):
        def verify_model(self, *a, **kw):
            raise ProviderError("model_not_found", submission="not_submitted")
        def complete(self, *a, **kw):
            pytest.fail("POST made")
    record = run_experiment(p, artifact, tmp_path / "run", configuration=CONFIG, inference_approval=approval,
        allow_live=True, approval_state_dir=tmp_path / "state", provider_factory=lambda sink: Missing(sink, p))
    assert record.generation_status == "model_verification_model_not_found"
    assert not record.steps and record.charged_tokens == 0
    assert verify_experiment(tmp_path / "run") == record


def test_unbounded_transport_refused(trial, tmp_path):
    p, artifact, approval = trial
    def factory(sink):
        provider = ExternalFake(sink, p)
        provider.hard_deadline = False
        return provider
    with pytest.raises(AuthorizationError, match="bounded_transport_required"):
        run_experiment(p, artifact, tmp_path / "run", configuration=CONFIG, inference_approval=approval,
            allow_live=True, approval_state_dir=tmp_path / "state", provider_factory=factory)


def test_local_preflight_does_not_touch_transport_or_credentials(trial, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("NEBIUS_API_KEY", "PRIVATE_DUMMY_NEVER_PRINT")
    monkeypatch.setattr(BoundedNebiusProvider, "from_environment", lambda *a, **kw: pytest.fail("credential use"))
    p, artifact, approval = trial
    summary = preflight(p, artifact, CONFIG, approval)
    assert summary["credentials_configured"] and summary["network_requests"] == summary["billable_requests"] == 0
    assert "PRIVATE_DUMMY" not in json.dumps(summary)
    path = tmp_path / "approval.json"
    path.write_bytes(canonical_json_bytes(approval.model_dump(mode="json")))
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private_approval_required"):
        load_approval(path)


def test_supervisor_kills_stalled_worker_and_descendants(tmp_path):
    marker = tmp_path / "descendant-survived"
    script = tmp_path / "trusted-test-worker.py"
    script.write_text("import os,time\nif os.fork()==0:\n time.sleep(1.0)\n open(" + repr(str(marker)) + ",'w').write('bad')\nelse:\n time.sleep(60)\n")
    began = time.monotonic()
    with pytest.raises(ProviderError) as info:
        supervise([sys.executable, str(script)], b"", timeout=0.2)
    assert info.value.category == "deadline_exceeded" and info.value.submission == "uncertain"
    assert time.monotonic() - began < 1.0
    time.sleep(1.1)
    assert not marker.exists()


def test_supervisor_success_and_minimal_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "PRIVATE_DUMMY_NEVER_INHERIT")
    script = tmp_path / "worker.py"
    script.write_text("import os,sys,json\nsys.stdout.write(json.dumps({'secret':os.environ.get('NEBIUS_API_KEY'),'input':sys.stdin.read()}))")
    output = json.loads(supervise([sys.executable, str(script)], b"pipe-input", timeout=2))
    assert output == {"secret": None, "input": "pipe-input"}


@pytest.mark.parametrize("override", [{"max_model_len": CONTEXT + 1}, {"external_provider": True},
                                       {"input_price_per_million_tokens": 0.2},
                                       {"output_price_per_million_tokens": 0.4}])
def test_model_catalogue_must_match_approved_limits(monkeypatch, override):
    p = BoundedNebiusProvider("DUMMY", allow_live=True)
    monkeypatch.setattr(BoundedNebiusProvider, "_worker", lambda *a, **kw: {
        "account_models": canonical_json_bytes({"object": "list", "data": [{"id": MODEL}]}),
        "public_catalogue": canonical_json_bytes(catalogue(**override))})
    with pytest.raises(ProviderError, match="invalid_request"):
        p.verify_model(MODEL, context_tokens=CONTEXT, input_price=100_000, output_price=300_000, timeout=1)


def test_account_must_actually_list_selected_model(monkeypatch):
    p = BoundedNebiusProvider("DUMMY", allow_live=True)
    monkeypatch.setattr(BoundedNebiusProvider, "_worker", lambda *a, **kw: {
        "account_models": canonical_json_bytes({"object": "list", "data": []}),
        "public_catalogue": canonical_json_bytes(catalogue())})
    with pytest.raises(ProviderError, match="model_not_found"):
        p.verify_model(MODEL, context_tokens=CONTEXT, input_price=100_000, output_price=300_000, timeout=1)


def test_bounded_transport_worker_wire_roundtrip_without_network(monkeypatch):
    from aegis_lab import bounded_provider, provider_worker
    from aegis_lab.provider import NebiusProvider
    from test_provider import FakeConnection, completion_bytes

    captured = []
    raw = completion_bytes()
    request = InferenceRequest(model=MODEL, messages=(Message(role="user", content="owned test"),),
                               max_output_tokens=256, store=False)
    monkeypatch.setattr(NebiusProvider, "_connect", lambda _: FakeConnection(status=200, body=raw))

    def offline_supervise(argv, payload, *, timeout):
        # Exercise the exact production worker protocol and HTTP parser against a fake socket.
        stdout = io.StringIO()
        with monkeypatch.context() as patch:
            patch.setattr(provider_worker.sys, "stdin", io.TextIOWrapper(io.BytesIO(payload)))
            patch.setattr(provider_worker.sys, "stdout", stdout)
            patch.setattr(provider_worker.resource, "setrlimit", lambda *a: None)
            assert provider_worker.main() == 0
        assert b"DUMMY_SECRET" not in stdout.getvalue().encode()
        return stdout.getvalue().encode()

    monkeypatch.setattr(bounded_provider, "supervise", offline_supervise)
    provider = BoundedNebiusProvider("DUMMY_SECRET", allow_live=True,
                                    evidence_sink=lambda k, v: captured.append((k, v)))
    result = provider.complete(request, timeout=2)
    assert result.content == "code"
    assert captured == [("request", json.dumps(request.to_body(), ensure_ascii=False, allow_nan=False).encode()),
                        ("response", raw)]
    sent = FakeConnection.instances[-1].requests[0]
    assert sent["path"] == "/v1/chat/completions" and sent["headers"]["Authorization"] == "Bearer DUMMY_SECRET"
    body = json.loads(sent["body"])
    assert body["store"] is False and body["max_completion_tokens"] == 256 and body["service_tier"] == "default"


def test_trial_cli_draft_is_invalid_and_preflight_never_calls_provider(trial, tmp_path, monkeypatch, capsys):
    p, artifact, _ = trial
    manifest, report = tmp_path / "manifest.json", tmp_path / "report.json"
    manifest.write_bytes(p.manifest.canonical_bytes())
    report.write_bytes(p.report_bytes)
    monkeypatch.setattr(BoundedNebiusProvider, "from_environment", lambda *a, **kw: pytest.fail("credential use"))
    args = [str(manifest), str(report), str(artifact)]
    assert main(["preflight", *args]) == 0
    assert json.loads(capsys.readouterr().out)["network_requests"] == 0
    draft = tmp_path / "draft.json"
    assert main(["draft", *args, "--output", str(draft), "--context-tokens", str(CONTEXT),
                 "--input-microusd-per-million", "100000", "--output-microusd-per-million", "300000",
                 "--max-spend-microusd", "1000000"]) == 0
    assert draft.stat().st_mode & 0o077 == 0
    with pytest.raises(ValidationError):
        load_approval(draft)
    assert main(["run", *args, "--approval", str(draft), "--output-dir", str(tmp_path / "exp"),
                 "--approve-live-inference"]) == 2


def test_environment_variables_cannot_grant_permission(trial, tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_LIVE", "true")
    monkeypatch.setenv("NEBIUS_ALLOW_LIVE", "1")
    with pytest.raises(AuthorizationError, match="inference_approval_required"):
        run_live_reconstruction(trial[0], trial[1], tmp_path / "run", inference_approval=None,
            approval_state_dir=tmp_path / "state", allow_live=True,
            provider_factory=lambda _: pytest.fail("provider created"))


@pytest.fixture
def triple(tmp_path):
    from aegis_lab.live_trial import TrialPlan
    common = {"attack.provider": "Nebius", "attack.model_id": MODEL,
              "budget.max_model_tokens": 200_000, "budget.max_attempts": 4}
    pair = build_pair(tmp_path / "pair-inputs", both=common)
    from aegis_lab.ghidra import analyze
    from aegis_lab.manifest import TrialManifest
    binary = tmp_path / "third.elf"
    binary.write_bytes(b"\x7fELF owned third fake test artifact")
    report_path = analyze(binary, tmp_path / "third-analysis", pair["launcher"], function="secret_add")
    data = pair["manifests"]["protected"].model_dump(mode="json")
    data["trial_id"] = "3" * 32
    import hashlib
    data["target"]["final_artifact_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    third = {"manifests": {"protected": TrialManifest.model_validate(data)},
             "reports": {"protected": report_path.read_bytes()}, "binaries": {"protected": binary}}
    targets = {}
    for name, fx, variant in (("baseline", pair, "baseline"), ("shield", pair, "protected"),
                               ("mirage", third, "protected")):
        m, report = fx["manifests"][variant], fx["reports"][variant]
        p = prepare_reconstruction(m, report)
        now = datetime.now(UTC)
        grant = InferenceApproval(operator_approved=True,
            disclosure=approval_for(p, model_id=MODEL, created_at=now, valid_from=now, expires_at=now + timedelta(hours=1)),
            manifest_sha256=p.manifest_sha256, workflow_sha256=live_workflow_sha256(CONFIG),
            max_requests=1, max_total_tokens=p.max_model_tokens, max_spend_microusd=1_000_000,
            context_tokens=CONTEXT, input_microusd_per_million=100_000, output_microusd_per_million=300_000,
            request_timeout_seconds=2, request_deadline=now + timedelta(minutes=30),
            private_archive_delete_after=now + timedelta(days=1), provider_retention_policy="Reviewed test terms",
            provider_retention_reviewed=True)
        root = tmp_path / name
        root.mkdir(mode=0o700)
        for filename, data in (("manifest", m.canonical_bytes()), ("report", report),
                               ("approval", canonical_json_bytes(grant.model_dump(mode="json")))):
            path = root / (filename + ".json")
            path.write_bytes(data)
            path.chmod(0o600)
        targets[name] = {"manifest": root / "manifest.json", "report": root / "report.json",
                         "artifact": fx["binaries"][variant], "approval": root / "approval.json"}
    return TrialPlan(**targets, configuration=CONFIG)


def test_three_variant_trial_records_each_response_with_equal_budgets(triple, tmp_path):
    from aegis_lab.live_trial import prepare_plan, run_trial
    prepared, _, _ = prepare_plan(triple)
    made = []
    def factory(sink):
        p = ExternalFake(sink, prepared["baseline"])
        made.append(p)
        return p
    result = run_trial(triple, tmp_path / "trial", provider_factory=factory)
    assert set(result["order"]) == {"baseline", "shield", "mirage"}
    assert len(made) == 3 and all(len(p.requests) == 1 for p in made)
    assert result["execution_performed"] is False and result["protection_effect"] == "not_established"
    assert result["reported_identity_comparable"]
    for name in result["order"]:
        assert result["outcomes"][name]["generation_status"] == "generated_but_behaviorally_unscored"
        assert verify_experiment(tmp_path / "trial" / name).steps[0].reservation_tokens == CONTEXT + prepared[name].request.max_output_tokens


def test_three_variant_trial_rejects_unequal_approval_before_provider(triple, tmp_path):
    from aegis_lab.live_trial import run_trial
    path = triple.mirage.approval
    grant = json.loads(path.read_bytes())
    grant["max_spend_microusd"] += 1
    path.write_bytes(canonical_json_bytes(grant))
    with pytest.raises(ValueError, match="equal_inference_budgets_required"):
        run_trial(triple, tmp_path / "trial", provider_factory=lambda _: pytest.fail("provider created"))


def test_three_variant_trial_preserves_provider_failures(triple, tmp_path):
    from aegis_lab.live_trial import prepare_plan, run_trial
    prepared, _, _ = prepare_plan(triple)
    result = run_trial(triple, tmp_path / "trial", provider_factory=lambda sink: ExternalFake(sink, prepared["baseline"],
        errors=[ProviderError("timeout", submission="uncertain")]))
    assert all(o["generation_status"] == "provider_timeout" for o in result["outcomes"].values())
    assert all(o["requests"] == 1 for o in result["outcomes"].values())
    assert not result["reported_identity_comparable"]


@pytest.mark.parametrize("stage", ["dns", "headers", "trickle_body"])
def test_supervisor_bounds_blocking_http_phases_without_network(tmp_path, stage):
    marker = tmp_path / "entered-phase"
    script = tmp_path / "trusted-http-worker.py"
    script.write_text('''import socket,time
from pathlib import Path
from aegis_lab.provider import NebiusProvider
from aegis_lab.provider_worker import main
marker=Path(''' + repr(str(marker)) + ''')
stage=''' + repr(stage) + '''
if stage == 'dns':
 def stall(*a,**kw):
  marker.write_text('dns')
  time.sleep(60)
 socket.getaddrinfo=stall
else:
 class Sock:
  def settimeout(self,t): pass
 class Reply:
  status=200
  def getheader(self,k): return None
  def read(self,n):
   marker.write_text('body')
   while True: time.sleep(0.01)  # peer keeps an internal buffered read busy
 class Conn:
  sock=Sock()
  def connect(self): pass
  def request(self,*a,**kw): pass
  def getresponse(self):
   marker.write_text('headers')
   if stage == 'headers': time.sleep(60)
   return Reply()
  def close(self): pass
 NebiusProvider._connect=lambda self:Conn()
main()
''')
    request = InferenceRequest(model=MODEL, messages=(Message(role="user", content="owned fake request"),),
                               max_output_tokens=32, store=False)
    payload = json.dumps({"operation": "complete", "key": "SYNTHETIC_NOT_REAL", "timeout": 1,
                          "request": request.model_dump(mode="json")}).encode()
    began = time.monotonic()
    with pytest.raises(ProviderError, match="deadline_exceeded"):
        supervise([sys.executable, str(script)], payload, timeout=1)
    assert marker.exists(), "test did not reach the simulated blocking HTTP phase"
    assert time.monotonic() - began < 2


@pytest.mark.parametrize("field,value,code", [
    ("artifact_sha256", "0" * 64, "artifact_not_approved"),
    ("evidence_sha256", "0" * 64, "evidence_not_approved"),
    ("rendered_prompt_sha256", "0" * 64, "prompt_not_approved"),
    ("model_id", "nvidia/other", "model_not_approved"),
])
def test_inference_grant_requires_exact_disclosure(trial, tmp_path, field, value, code):
    p, artifact, grant = trial
    data = grant.model_dump()
    data["disclosure"] = {**grant.disclosure.model_dump(), field: value}
    grant = InferenceApproval.model_validate(data)
    with pytest.raises(AuthorizationError, match=code):
        run_live_reconstruction(p, artifact, tmp_path / "run", inference_approval=grant,
            approval_state_dir=tmp_path / "state", allow_live=True,
            provider_factory=lambda _: pytest.fail("provider created"))


def test_approved_iterative_live_scope_keeps_evidence_and_candidate_provenance(trial, tmp_path):
    from aegis_lab.manifest import TrialManifest
    p, artifact, grant = trial
    data = p.manifest.model_dump(mode="json")
    data["budget"]["max_model_tokens"] = 1_000_000
    p = prepare_reconstruction(TrialManifest.model_validate(data), p.report_bytes)
    config = WorkflowConfig(max_steps=3)
    grant = InferenceApproval.model_validate({**grant.model_dump(),
        "manifest_sha256": p.manifest_sha256, "workflow_sha256": live_workflow_sha256(config),
        "max_total_tokens": 1_000_000, "max_requests": 3,
        "disclosure": approval_for(p, model_id=MODEL)})
    class Iterative(ExternalFake):
        def _body(self, request):
            self._content = ('{"action":"inspect_target"}' if len(self.requests) == 1 else
                            '{"action":"revise_candidate","source":"int target_function(void){return 0;}"}'
                            if len(self.requests) == 2 else '{"action":"finish"}')
            return super()._body(request)
    record = run_live_reconstruction(p, artifact, tmp_path / "run", inference_approval=grant,
        approval_state_dir=tmp_path / "state", allow_live=True, configuration=config,
        provider_factory=lambda sink: Iterative(sink, p))
    assert record.generation_status == "generated_but_behaviorally_unscored" and len(record.steps) == 3
    assert verify_experiment(tmp_path / "run") == record


def test_existing_controlled_pair_accepts_separate_inference_approvals(triple, tmp_path):
    from aegis_lab.live_trial import prepare_plan
    from aegis_lab.experiment import run_controlled_pair
    prepared, grants, _ = prepare_plan(triple)
    p = prepared["baseline"]
    result = run_controlled_pair({"baseline": p.manifest, "protected": prepared["shield"].manifest},
        {"baseline": p.report_bytes, "protected": prepared["shield"].report_bytes},
        {"baseline": triple.baseline.artifact, "protected": triple.shield.artifact}, tmp_path / "pair",
        configuration=CONFIG, inference_approvals={"baseline": grants["baseline"], "protected": grants["shield"]},
        approval_state_dir=tmp_path / "state", allow_live=True, provider_factory=lambda sink: ExternalFake(sink, p))
    assert result.reported_model_identity_comparable
    for name in ("baseline", "protected"):
        assert verify_experiment(tmp_path / "pair" / name).execution_performed is False
