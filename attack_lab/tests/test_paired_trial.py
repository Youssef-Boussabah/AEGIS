"""Phase 3B: controlled paired reconstruction trials (offline only).

Ghidra reports come from the real Phase 2 worker code path (``aegis_lab.ghidra.analyze``)
driven by the offline fake launcher from test_ghidra.py; one launcher serves both
variants, so both reports bind to the same declared Ghidra tool. Provider replies go
through the production parser via ``FakeProvider``. No network call, real model or
token is used, and generated code is never compiled or executed. The opt-in test at
the end uses real Ghidra.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_ghidra import hooked_ghidra
from test_manifest import SECRET, digest, manifest_data

from aegis_lab import paired_trial
from aegis_lab.canonical import canonical_json_bytes
from aegis_lab.evidence import planned_ghidra_tool
from aegis_lab.fake_provider import FakeProvider
from aegis_lab.ghidra import analyze
from aegis_lab.manifest import TrialManifest
from aegis_lab.paired_trial import (
    PAIRED_RECORD_FILE,
    RECONSTRUCTION_FILES,
    ExperimentVerificationError,
    PairedTrialInputError,
    PairedTrialPublicationError,
    PairedTrialRecord,
    execution_order,
    main,
    parse_paired_trial_record,
    prepare_pair,
    run_paired_trial,
    verify_experiment,
)
from aegis_lab.provider import ProviderError, Usage
from aegis_lab.reconstruction import (
    EXIT_COMPLETED,
    EXIT_INTERNAL,
    EXIT_INTERRUPTED,
    EXIT_NOT_COMPLETED,
    EXIT_PUBLICATION_FAILED,
    ConfigurationError,
    parse_reconstruction_record,
    planned_attack_digests,
)
from aegis_lab.safe_io import LoadError, PublishError

FUNCTION = "secret_add"
INTERFACE = "opaque(int,int)->int"
ALPHA = "int secret_add(int a, int b) { int alpha_sum = a + b; return alpha_sum; }"
BRAVO = "int secret_add(int a, int b) { int bravo_mix = (a ^ 90) ^ 90; return bravo_mix + b; }"
BASELINE_BINARY = b"\x7fELF AEGIS-owned fixture variant-one"
PROTECTED_BINARY = b"\x7fELF AEGIS-owned fixture variant-two"
# The hook runs inside the fake launcher; it picks the decompiled body from the imported bytes.
HOOK = (
    "data = imported.read_bytes()\n"
    "f = out['functions'][0]\n"
    f"f['name'] = f['qualified_name'] = {FUNCTION!r}\n"
    f"f['signature'] = f['decompiler_signature'] = 'int {FUNCTION}(int a, int b)'\n"
    "bodies = __BODIES__\n"
    f"f['decompiled_c'] = next((v for k, v in bodies if k in data), {ALPHA!r})\n"
)
SEED_BASELINE_FIRST = next(s for s in range(64) if execution_order(
    s, pair_id="9" * 32, baseline_trial_id="1" * 32, protected_trial_id="2" * 32) == ("baseline", "protected"))
SEED_PROTECTED_FIRST = next(s for s in range(64) if execution_order(
    s, pair_id="9" * 32, baseline_trial_id="1" * 32, protected_trial_id="2" * 32) == ("protected", "baseline"))


def set_path(data: dict, path: str, value: object) -> None:
    *parents, last = path.split(".")
    for part in parents:
        data = data[part]
    data[last] = value


def build_pair(tmp_path: Path, *, baseline_binary=BASELINE_BINARY, protected_binary=PROTECTED_BINARY,
               bodies=((b"variant-two", BRAVO),), both=None, baseline=None, protected=None,
               selector=FUNCTION, hook=None) -> dict:
    """Two manifests and two worker reports produced by one fake Ghidra installation.

    ``selector`` is the Ghidra function selector declared in the tool and used for both
    worker runs; ``hook`` replaces the default export hook.
    """
    launcher = hooked_ghidra(tmp_path, hook if hook is not None else HOOK.replace("__BODIES__", repr(list(bodies))))
    tool = planned_ghidra_tool(launcher, function=selector).model_dump(mode="json")
    result = {"tmp": tmp_path, "launcher": launcher, "tool": tool, "manifests": {}, "reports": {}, "binaries": {}}
    for variant, content, overrides in (("baseline", baseline_binary, baseline),
                                        ("protected", protected_binary, protected)):
        binary = tmp_path / variant / "sample.elf"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(content)
        result["binaries"][variant] = binary
        result["reports"][variant] = analyze(binary, tmp_path / f"report-{variant}", launcher,
                                             function=selector).read_bytes()
        data = manifest_data(protected=variant == "protected")
        data["target"]["function"] = FUNCTION
        data["target"]["final_artifact_sha256"] = hashlib.sha256(content).hexdigest()
        data["attack"]["tools"] = [tool]
        data["attack"]["provider"] = "FakeOffline"
        data["scoring"]["expected_interface"] = INTERFACE
        merged = {**(both or {}), **(overrides or {})}
        for path, value in merged.items():
            set_path(data, path, value)
        digests = planned_attack_digests(max_model_tokens=data["budget"]["max_model_tokens"],
                                         blinded=not data["access"].get("access_to_symbols", False))
        for key, value in digests.items():
            if f"attack.{key}" not in merged:
                data["attack"][key] = value
        result["manifests"][variant] = TrialManifest.model_validate(data)
    return result


def prepared(fx: dict, **kwargs):
    m, r = fx["manifests"], fx["reports"]
    return prepare_pair(m["baseline"], m["protected"], r["baseline"], r["protected"], **kwargs)


class Factory:
    """Hands out providers in call order (= execution order) and remembers them."""

    def __init__(self, *providers):
        self.pending = list(providers)
        self.made: list[FakeProvider] = []

    def __call__(self):
        provider = self.pending.pop(0) if self.pending else FakeProvider()
        self.made.append(provider)
        return provider


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def run(fx, out=None, *, seed=SEED_BASELINE_FIRST, factory=None, **kwargs):
    return run_paired_trial(prepared(fx), out or fx["tmp"] / "experiment", order_seed=seed,
                            provider_factory=factory or Factory(), **kwargs)


def by_variant(record: PairedTrialRecord) -> dict:
    return {t.variant: t for t in record.trials}


@pytest.fixture
def fx(tmp_path):
    return build_pair(tmp_path)


def assert_nothing_ran(factory: Factory, out: Path) -> None:
    assert all(not p.requests for p in factory.made)
    assert not out.exists() and not out.is_symlink()


# --- Preparation: comparability is checked before any inference ----------------------------------

def test_valid_pair_is_prepared_with_identical_settings(fx):
    pair = prepared(fx)
    base, prot = pair.prepared["baseline"], pair.prepared["protected"]
    for name in paired_trial.SHARED_PREPARED_FIELDS:
        assert getattr(base, name) == getattr(prot, name), name
    assert base.request.model_copy(update={"messages": ()}) == prot.request.model_copy(update={"messages": ()})
    assert json.loads(base.request.messages[1].content)["task"] == json.loads(prot.request.messages[1].content)["task"]
    assert base.rendered_prompt_sha256 != prot.rendered_prompt_sha256  # only the evidence differs
    assert pair.cross_trial_value_findings == {"baseline": 0, "protected": 0}
    assert (base.trial_id, prot.trial_id) == ("1" * 32, "2" * 32)


def test_manifests_in_swapped_roles_are_rejected_not_reordered(fx):
    m, r = fx["manifests"], fx["reports"]
    with pytest.raises(PairedTrialInputError) as exc:
        prepare_pair(m["protected"], m["baseline"], r["protected"], r["baseline"])
    assert exc.value.issues == ("baseline-manifest: variant: not_baseline",
                                "protected-manifest: variant: not_protected")


def test_two_baselines_are_rejected(fx):
    m, r = fx["manifests"], fx["reports"]
    with pytest.raises(PairedTrialInputError, match="protected-manifest: variant: not_protected"):
        prepare_pair(m["baseline"], m["baseline"], r["baseline"], r["baseline"])


@pytest.mark.parametrize("path, value, field", [
    ("budget.max_wall_seconds", 120, "budget.max_wall_seconds"),
    ("access.access_to_original_source", True, "access.access_to_original_source"),
    ("attack.temperature", 0.5, "attack.temperature"),
    ("attack.model_id", "other-model", "attack.model_id"),
    ("target.build.debug_info", True, "target.build.debug_info"),
    ("pair_id", "8" * 32, "pair_id"),
])
def test_incomparable_manifests_fail_before_inference(tmp_path, path, value, field):
    fx = build_pair(tmp_path, protected={path: value})
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx)
    assert f"pair: {field}: differs" in exc.value.issues
    assert not (tmp_path / "experiment").exists()


def test_swapped_evidence_is_rejected(fx):
    m, r = fx["manifests"], fx["reports"]
    with pytest.raises(PairedTrialInputError) as exc:
        prepare_pair(m["baseline"], m["protected"], r["protected"], r["baseline"])
    assert exc.value.issues == ("baseline-evidence: binding: binary.sha256: mismatch",
                                "protected-evidence: binding: binary.sha256: mismatch")


def test_stale_evidence_after_artifact_revision_is_rejected(tmp_path):
    fx = build_pair(tmp_path, protected={"target.final_artifact_sha256": digest("rebuilt protected artifact")})
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx)
    assert exc.value.issues == ("protected-evidence: binding: binary.sha256: mismatch",)


def test_evidence_from_another_ghidra_configuration_is_rejected(fx):
    other = analyze(fx["binaries"]["protected"], fx["tmp"] / "other-config", fx["launcher"], function=FUNCTION,
                    max_c_chars=500).read_bytes()
    m = fx["manifests"]
    with pytest.raises(PairedTrialInputError, match="protected-evidence: binding: export.configuration: mismatch"):
        prepare_pair(m["baseline"], m["protected"], fx["reports"]["baseline"], other)


@pytest.mark.parametrize("report, issue", [
    (b"{oops", "baseline-evidence: report: malformed_json"),
    (b'{"schema_version": "a", "schema_version": "b"}', "baseline-evidence: report: duplicate_key"),
    (b"\xff\xfe", "baseline-evidence: report: invalid_utf8"),
    (b'{"schema_version": "aegis.lab.ghidra.v1"}', "baseline-evidence: report: binary: missing"),
])
def test_malformed_evidence_is_rejected_by_role(fx, report, issue):
    m = fx["manifests"]
    with pytest.raises(PairedTrialInputError) as exc:
        prepare_pair(m["baseline"], m["protected"], report, fx["reports"]["protected"])
    assert issue in exc.value.issues
    assert not any(i.startswith("protected") for i in exc.value.issues)


def test_reconstruction_input_failure_names_the_trial(tmp_path):
    # The protected evidence already uses the blinding placeholder: preparation must refuse it.
    collision = "int secret_add(int a, int b) { return target_function(a) + b; }"
    fx = build_pair(tmp_path, bodies=((b"variant-two", collision),))
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx)
    assert exc.value.issues == ("protected-preparation: disclosure: placeholder_collision",)


def test_unverifiable_attack_digests_fail_before_inference(tmp_path):
    fx = build_pair(tmp_path, both={"attack.prompt_sha256": digest("phase 1 placeholder")})
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx)
    assert set(exc.value.issues) == {"baseline-preparation: configuration: prompt_template_mismatch",
                                     "protected-preparation: configuration: prompt_template_mismatch"}


def _patch_protected_preparation(monkeypatch, change):
    """Defense in depth: simulate a Phase 3A preparation that diverges for one trial only."""
    import dataclasses

    original = paired_trial.prepare_reconstruction

    def diverging(manifest, report, **kwargs):
        result = original(manifest, report, **kwargs)
        return change(dataclasses, result) if manifest.variant == "protected" else result

    monkeypatch.setattr(paired_trial, "prepare_reconstruction", diverging)


def test_diverging_model_facing_task_is_rejected(fx, monkeypatch):
    def change(dataclasses, prepared):
        system, user = prepared.request.messages
        data = json.loads(user.content)
        data["task"]["platform"] = "linux-arm64"
        user = user.model_copy(update={"content": json.dumps(data)})
        return dataclasses.replace(prepared, request=prepared.request.model_copy(update={"messages": (system, user)}))

    _patch_protected_preparation(monkeypatch, change)
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx)
    assert exc.value.issues == ("pair: request.task: differs",)


def test_diverging_effective_settings_are_rejected(fx, monkeypatch):
    def change(dataclasses, prepared):
        return dataclasses.replace(prepared, max_attempts=2,
                                   request=prepared.request.model_copy(update={"temperature": 0.7}))

    _patch_protected_preparation(monkeypatch, change)
    with pytest.raises(PairedTrialInputError) as exc:
        prepared(fx)
    assert exc.value.issues == ("pair: prepared.max_attempts: differs", "pair: request.temperature: differs")


def test_non_bytes_evidence_is_rejected(fx):
    m = fx["manifests"]
    with pytest.raises(PairedTrialInputError, match="evidence: invalid_type"):
        prepare_pair(m["baseline"], m["protected"], "text", fx["reports"]["protected"])


# --- Run preconditions: nothing is inferred and no output exists when they fail ------------------

def test_live_provider_manifests_fail_before_inference(tmp_path):
    fx = build_pair(tmp_path, both={"attack.provider": "Nebius"})
    factory, out = Factory(), tmp_path / "experiment"
    with pytest.raises(PairedTrialInputError) as exc:
        run(fx, out, factory=factory)
    assert set(exc.value.issues) == {"baseline-preparation: configuration: provider_mismatch",
                                     "protected-preparation: configuration: provider_mismatch"}
    assert_nothing_ran(factory, out)


def test_unsupported_execution_mode_is_refused(fx):
    factory, out = Factory(), fx["tmp"] / "experiment"
    with pytest.raises(PairedTrialInputError, match="mode: execution_mode_not_supported"):
        run(fx, out, factory=factory, execution_mode="live")
    assert_nothing_ran(factory, out)


def test_shared_provider_instance_is_refused(fx):
    shared = FakeProvider()
    out = fx["tmp"] / "experiment"
    with pytest.raises(PairedTrialInputError, match="providers: provider_instance_shared"):
        run_paired_trial(prepared(fx), out, order_seed=1, provider_factory=lambda: shared)
    assert shared.requests == [] and not out.exists()


def test_external_provider_is_refused_before_any_call(fx):
    stubs = [FakeProvider(external_disclosure=True, provider="Nebius",
                          endpoint="https://api.tokenfactory.nebius.com:443/v1") for _ in range(2)]
    factory, out = Factory(*stubs), fx["tmp"] / "experiment"
    with pytest.raises(PairedTrialInputError) as exc:
        run(fx, out, factory=factory)
    assert {i.split(": ", 1)[1] for i in exc.value.issues} == {"live_inference_disabled"}
    assert_nothing_ran(factory, out)


@pytest.mark.parametrize("kind", ["duck_type", "subclass", "instance_override"])
def test_provider_factory_cannot_select_an_inference_implementation(fx, kind):
    calls = []

    def unexpected_inference(*args, **kwargs):
        calls.append(True)
        raise AssertionError("a factory-selected inference implementation ran")

    class MasqueradingProvider:
        identity = FakeProvider().identity
        external_disclosure = False
        complete = unexpected_inference

    class OverriddenFake(FakeProvider):
        complete = unexpected_inference

    def make_provider():
        if kind == "duck_type":
            return MasqueradingProvider()
        if kind == "subclass":
            return OverriddenFake()
        provider = FakeProvider()
        provider.complete = unexpected_inference
        return provider

    out = fx["tmp"] / "experiment"
    with pytest.raises(PairedTrialInputError, match="offline_provider_required"):
        run_paired_trial(prepared(fx), out, provider_factory=make_provider)
    assert calls == [] and not out.exists()


@pytest.mark.parametrize("seed", [-1, 2**63, True, 1.5, "7"])
def test_invalid_order_seed_is_refused(fx, seed):
    factory, out = Factory(), fx["tmp"] / "experiment"
    with pytest.raises(PairedTrialInputError, match="order-seed: out_of_range"):
        run(fx, out, factory=factory, seed=seed)
    assert_nothing_ran(factory, out)


def test_tampered_prepared_request_is_refused(fx):
    import dataclasses

    pair = prepared(fx)
    forged = dataclasses.replace(pair.prepared["protected"], prompt_token_bound=1)
    pair = dataclasses.replace(pair, prepared={**pair.prepared, "protected": forged})
    factory, out = Factory(), fx["tmp"] / "experiment"
    with pytest.raises(PairedTrialInputError, match="protected-preparation: configuration: "
                                                   "prepared_request_inconsistent"):
        run_paired_trial(pair, out, order_seed=1, provider_factory=factory)
    assert_nothing_ran(factory, out)


def test_existing_output_directory_is_never_reused(fx):
    out = fx["tmp"] / "experiment"
    out.mkdir()
    (out / "earlier.json").write_text("prior experiment")
    factory = Factory()
    with pytest.raises(PairedTrialPublicationError) as exc:
        run(fx, out, factory=factory)
    assert exc.value.category == "already_exists"
    assert all(not p.requests for p in factory.made)
    assert sorted(p.name for p in out.iterdir()) == ["earlier.json"]
    assert (out / "earlier.json").read_text() == "prior experiment"


def test_output_symlink_is_not_followed(fx):
    target = fx["tmp"] / "elsewhere"
    target.mkdir()
    out = fx["tmp"] / "experiment"
    out.symlink_to(target)
    with pytest.raises(PairedTrialPublicationError, match="already_exists"):
        run(fx, out)
    assert list(target.iterdir()) == []


def test_missing_output_parent_is_refused(fx):
    with pytest.raises(PairedTrialPublicationError, match="parent_not_found"):
        run(fx, fx["tmp"] / "missing" / "experiment")


# --- A valid pair ---------------------------------------------------------------------------------

def test_unchanged_valid_pair_completes(fx):
    out = fx["tmp"] / "experiment"
    result = run(fx, out)
    record = result.record
    assert result.exit_code == EXIT_COMPLETED and result.paired_record_published
    assert sorted(p.name for p in out.iterdir()) == sorted([PAIRED_RECORD_FILE, *RECONSTRUCTION_FILES.values()])
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for path in out.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    out_ = record.outcome
    assert (out_.run_status, out_.pair_status, out_.workflow_complete) == (
        "finished", "candidates_received_for_both_trials", True)
    assert out_.candidate_origin == "offline_fake_provider"
    assert out_.scoring == "not_performed"
    assert out_.reconstruction_success_established is False and out_.protection_effect_established is False
    assert record.record_signed is False and record.authorization.is_execution_permission is False
    assert record.authorization.core_attack_lab_gates == "not_integrated"
    assert record.provider.provider == "FakeOffline" and record.provider.external_disclosure is False
    assert record.errors == ()
    trials = by_variant(record)
    for variant, manifest in fx["manifests"].items():
        trial = trials[variant]
        assert trial.trial_id == manifest.trial_id and trial.manifest_sha256 == manifest.sha256()
        assert trial.artifact_sha256 == manifest.target.final_artifact_sha256
        assert trial.evidence.evidence_sha256 == hashlib.sha256(fx["reports"][variant]).hexdigest()
        assert trial.reconstruction.status == "completed" and trial.resources.attempts == 1
        data = (out / trial.reconstruction.file).read_bytes()
        assert hashlib.sha256(data).hexdigest() == trial.reconstruction.file_sha256
        assert parse_reconstruction_record(data) == result.reconstructions[variant]
    assert record.totals.attempts == 2 and record.totals.charged_tokens == 320
    assert record.comparability.final_artifacts_identical is False


def test_published_record_reloads_identically(fx):
    out = fx["tmp"] / "experiment"
    result = run(fx, out)
    data = (out / PAIRED_RECORD_FILE).read_bytes()
    reloaded = parse_paired_trial_record(data)
    assert reloaded == result.record and reloaded.sha256() == result.record.sha256()
    assert verify_experiment(out) == result.record


def test_record_is_ascii_and_holds_no_evidence_or_candidate_text(fx):
    out = fx["tmp"] / "experiment"
    run(fx, out, factory=Factory(FakeProvider(source="int x(void){return 0x5ec7;}")))
    text = (out / PAIRED_RECORD_FILE).read_bytes()
    text.decode("ascii")
    for needle in (b"alpha_sum", b"bravo_mix", b"0x5ec7", SECRET.encode()):
        assert needle not in text


def test_identical_artifacts_are_a_valid_no_op_pair(tmp_path):
    fx = build_pair(tmp_path, protected_binary=BASELINE_BINARY)
    result = run(fx)
    assert result.record.comparability.final_artifacts_identical is True
    assert any("cannot be attributed to protection" in note for note in result.record.limitations)
    assert result.record.outcome.protection_effect_established is False


# --- Order and identity ---------------------------------------------------------------------------

def test_execution_order_derivation_fixed_vector():
    # Independent recomputation of aegis.lab.trial-order.v1 from its documented definition.
    document = {"baseline_trial_id": "1" * 32, "pair_id": "9" * 32, "protected_trial_id": "2" * 32,
                "schema": "aegis.lab.trial-order.v1", "seed": 12345}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    assert raw == canonical_json_bytes(document)
    expected = ("baseline", "protected") if hashlib.sha256(raw).digest()[0] % 2 == 0 else ("protected", "baseline")
    assert execution_order(12345, pair_id="9" * 32, baseline_trial_id="1" * 32,
                           protected_trial_id="2" * 32) == expected


def test_execution_order_is_reproducible_and_uses_both_orders():
    ids = {"pair_id": "9" * 32, "baseline_trial_id": "1" * 32, "protected_trial_id": "2" * 32}
    orders = [execution_order(seed, **ids) for seed in range(64)]
    assert orders == [execution_order(seed, **ids) for seed in range(64)]
    assert set(orders) == {("baseline", "protected"), ("protected", "baseline")}
    with pytest.raises(ValueError):
        execution_order(-1, **ids)


@pytest.mark.parametrize("seed", [SEED_BASELINE_FIRST, SEED_PROTECTED_FIRST])
def test_trial_identities_never_depend_on_execution_order(tmp_path, seed):
    fx = build_pair(tmp_path)
    factory = Factory()
    result = run(fx, factory=factory, seed=seed)
    record = result.record
    sequence = execution_order(seed, pair_id="9" * 32, baseline_trial_id="1" * 32, protected_trial_id="2" * 32)
    assert record.order.sequence == sequence and record.order.seed_source == "operator"
    trials = by_variant(record)
    assert [t.variant for t in record.trials] == ["baseline", "protected"]
    for position, variant in enumerate(sequence, start=1):
        trial = trials[variant]
        assert trial.execution_position == position
        assert trial.trial_id == fx["manifests"][variant].trial_id
        assert result.reconstructions[variant].variant == variant
        # The provider created for this position received exactly this trial's prepared request.
        (request,) = factory.made[position - 1].requests
        assert request == prepared(fx).prepared[variant].request


def test_generated_seed_is_recorded_and_reproduces_the_order(fx):
    result = run_paired_trial(prepared(fx), fx["tmp"] / "experiment", provider_factory=Factory())
    order = result.record.order
    assert order.seed_source == "generated" and 0 <= order.seed < 2**63
    assert order.sequence == execution_order(order.seed, pair_id="9" * 32, baseline_trial_id="1" * 32,
                                             protected_trial_id="2" * 32)


# --- Independence and information isolation -------------------------------------------------------

def test_provider_contexts_are_independent(fx):
    factory = Factory()
    run(fx, factory=factory)
    first, second = factory.made
    assert first is not second
    assert len(first.requests) == 1 and len(second.requests) == 1
    assert first.requests[0] != second.requests[0]


def test_no_trial_sees_the_other_trials_private_data(fx):
    first_marker, second_marker = "int first_marker_q(void) { return 1; }", "int second_marker_z(void){return 2;}"
    factory = Factory(FakeProvider(source=first_marker), FakeProvider(source=second_marker))
    result = run(fx, factory=factory, seed=SEED_BASELINE_FIRST)
    first, second = factory.made
    base_prompt = "\n".join(m.content for m in first.requests[0].messages)
    prot_prompt = "\n".join(m.content for m in second.requests[0].messages)
    # Evidence and candidates stay inside their own trial.
    assert "alpha_sum" in base_prompt and "bravo_mix" not in base_prompt
    assert "bravo_mix" in prot_prompt and "alpha_sum" not in prot_prompt
    assert "first_marker_q" not in prot_prompt and "first_marker_q" not in base_prompt
    assert result.reconstructions["baseline"].candidate.source == first_marker
    assert result.reconstructions["protected"].candidate.source == second_marker
    # Neither prompt carries variant, protection, scoring, identity or authorization material.
    base_m, prot_m = fx["manifests"]["baseline"], fx["manifests"]["protected"]
    protection = prot_m.target.protection
    forbidden = [
        "baseline", "protected", base_m.trial_id, prot_m.trial_id, base_m.pair_id, prot_m.target.name,
        protection.backend.name, protection.backend.executable_sha256, protection.backend.configuration_sha256,
        protection.transformation_report_sha256, prot_m.scoring.hidden_test_suite_sha256,
        prot_m.scoring.scorer.name, prot_m.authorization.reference, prot_m.authorization.authorized_scope,
        prot_m.target.build.shared_recipe_sha256, FUNCTION,
    ]
    for prompt in (base_prompt, prot_prompt):
        for item in forbidden:
            assert item.casefold() not in prompt.casefold(), item


def test_cross_trial_values_in_evidence_are_recorded_as_findings(tmp_path):
    # Artifact-derived text that happens to contain the other trial's protection backend name.
    leaky = "int secret_add(int a, int b) { return a + b; } /* aegis-shield */"
    fx = build_pair(tmp_path, bodies=((b"variant-one", leaky), (b"variant-two", BRAVO)))
    result = run(fx)
    trials = by_variant(result.record)
    assert trials["baseline"].prepared.cross_trial_value_findings == 1
    assert trials["protected"].prepared.cross_trial_value_findings == 0
    assert any("privileged values of the other trial" in note for note in result.record.limitations)


def test_no_generated_candidate_is_executed(fx, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("a process or program was started")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse)
    for name in ("system", "execv", "execve", "execvp", "posix_spawn", "posix_spawnp", "fork"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, refuse)
    payload = '#include <stdlib.h>\nint target_function(void) { return system("touch /tmp/aegis-pwned"); }\n'
    out = fx["tmp"] / "experiment"
    result = run(fx, out, factory=Factory(FakeProvider(source=payload), FakeProvider(source=payload)))
    assert result.exit_code == EXIT_COMPLETED
    assert all(r.candidate.source == payload for r in result.reconstructions.values())
    for path in out.iterdir():
        assert not stat.S_IMODE(path.stat().st_mode) & 0o111
    assert sorted(p.name for p in out.iterdir()) == sorted([PAIRED_RECORD_FILE, *RECONSTRUCTION_FILES.values()])


# --- Trial failures are preserved, never converted into a completed comparison --------------------

def assert_failure_survives_reload(out: Path, record: PairedTrialRecord) -> None:
    assert verify_experiment(out) == record
    assert parse_paired_trial_record((out / PAIRED_RECORD_FILE).read_bytes()) == record


@pytest.mark.parametrize("seed, failing", [(SEED_BASELINE_FIRST, "baseline"), (SEED_BASELINE_FIRST, "protected"),
                                           (SEED_PROTECTED_FIRST, "baseline"), (SEED_PROTECTED_FIRST, "protected")])
def test_one_failed_trial_keeps_its_outcome(tmp_path, seed, failing):
    fx = build_pair(tmp_path)
    sequence = execution_order(seed, pair_id="9" * 32, baseline_trial_id="1" * 32, protected_trial_id="2" * 32)
    providers = [FakeProvider(content="not a candidate") if v == failing else FakeProvider() for v in sequence]
    out = tmp_path / "experiment"
    result = run(fx, out, seed=seed, factory=Factory(*providers))
    record, trials = result.record, by_variant(result.record)
    assert result.exit_code == EXIT_NOT_COMPLETED
    assert trials[failing].reconstruction.status == "invalid_candidate"
    assert trials[failing].reconstruction.candidate_sha256 is None
    other = "protected" if failing == "baseline" else "baseline"
    assert trials[other].reconstruction.status == "completed"
    assert (record.outcome.run_status, record.outcome.pair_status) == ("finished", "trial_failures")
    assert record.outcome.workflow_complete is True and record.outcome.trials_with_record == 2
    assert record.outcome.trials_completed == 1
    rejected = parse_reconstruction_record((out / RECONSTRUCTION_FILES[failing]).read_bytes()).rejected_output
    assert rejected.reply_text == "not a candidate"
    assert_failure_survives_reload(out, record)


def test_both_trials_failing_is_recorded(fx):
    out = fx["tmp"] / "experiment"
    errors = [FakeProvider(errors=[ProviderError("rate_limited", submission="rejected", status=429)]),
              FakeProvider(errors=[ProviderError("server_error", submission="uncertain", status=500)])]
    result = run(fx, out, factory=Factory(*errors))
    record = result.record
    assert result.exit_code == EXIT_NOT_COMPLETED
    trials = by_variant(record)
    assert trials["baseline"].reconstruction.status == "provider_error"
    assert trials["protected"].reconstruction.status == "submission_uncertain"  # never retried
    assert trials["protected"].resources.attempts == 1
    assert record.outcome.pair_status == "trial_failures" and record.outcome.trials_completed == 0
    assert record.totals.submitted_attempts == 2
    assert_failure_survives_reload(out, record)


def test_deadline_failure_in_one_trial_does_not_shift_the_other(fx):
    clock = Clock()

    def late(_request, _timeout):
        clock.t += 10_000  # past the 240 s wall budget
    out = fx["tmp"] / "experiment"
    result = run(fx, out, factory=Factory(FakeProvider(on_call=late), FakeProvider()),
                 monotonic=clock, sleep=clock.sleep)
    trials = by_variant(result.record)
    assert trials["baseline"].reconstruction.status == "deadline_exceeded"
    assert trials["protected"].reconstruction.status == "completed"  # its own deadline started afresh
    assert trials["baseline"].runner_wall_seconds >= 10_000
    assert result.record.outcome.pair_status == "trial_failures"
    assert_failure_survives_reload(out, result.record)


def test_token_budget_failure_is_recorded(fx):
    over = Usage(prompt_tokens=3000, completion_tokens=1999, total_tokens=4999)
    out = fx["tmp"] / "experiment"
    result = run(fx, out, factory=Factory(FakeProvider(), FakeProvider(usage=over)))
    trials = by_variant(result.record)
    assert trials["protected"].reconstruction.status == "budget_exceeded"
    assert trials["protected"].resources.charged_tokens == 4999
    assert trials["protected"].resources.reservation_exceeded is True
    assert result.record.totals.charged_tokens == 160 + 4999
    assert_failure_survives_reload(out, result.record)


def test_retryable_failures_are_counted_as_attempts(tmp_path):
    fx = build_pair(tmp_path, both={"budget.max_attempts": 2})
    clock = Clock()
    flaky = FakeProvider(errors=[ProviderError("connection_error", submission="not_submitted")])
    result = run(fx, factory=Factory(flaky, FakeProvider()), monotonic=clock, sleep=clock.sleep)
    trials = by_variant(result.record)
    assert trials["baseline"].resources.attempts == 2 and trials["baseline"].resources.submitted_attempts == 1
    assert trials["baseline"].reconstruction.status == "completed"
    assert trials["protected"].resources.attempts == 1  # the other trial's attempt state is its own


def test_exhausted_attempt_budget_is_a_trial_failure(fx):
    flaky = FakeProvider(errors=[ProviderError("connection_error", submission="not_submitted")])
    result = run(fx, factory=Factory(flaky, FakeProvider()))
    baseline = by_variant(result.record)["baseline"]
    assert baseline.reconstruction.status == "provider_error"
    assert baseline.reconstruction.stop_reason == "attempts_exhausted"
    assert baseline.resources.charged_tokens == 0 and result.record.outcome.pair_status == "trial_failures"


def test_interrupted_first_trial_stops_the_run_and_keeps_its_record(fx):
    def interrupt(_request, _timeout):
        raise KeyboardInterrupt
    out = fx["tmp"] / "experiment"
    factory = Factory(FakeProvider(on_call=interrupt), FakeProvider())
    result = run(fx, out, factory=factory)
    trials = by_variant(result.record)
    assert result.exit_code == EXIT_INTERRUPTED
    assert trials["baseline"].state == "interrupted"
    assert trials["baseline"].reconstruction.status == "interrupted"
    assert trials["protected"].state == "not_started" and trials["protected"].reconstruction is None
    assert factory.made[1].requests == []  # the second trial never ran
    assert result.record.outcome.run_status == "interrupted"
    assert result.record.outcome.pair_status == "incomplete"
    assert (out / RECONSTRUCTION_FILES["baseline"]).exists()
    assert not (out / RECONSTRUCTION_FILES["protected"]).exists()
    assert_failure_survives_reload(out, result.record)


def test_interrupted_second_trial_keeps_both_records(fx):
    def interrupt(_request, _timeout):
        raise KeyboardInterrupt
    out = fx["tmp"] / "experiment"
    result = run(fx, out, factory=Factory(FakeProvider(), FakeProvider(on_call=interrupt)))
    trials = by_variant(result.record)
    assert trials["baseline"].reconstruction.status == "completed"
    assert trials["protected"].state == "interrupted"
    assert result.record.outcome.trials_with_record == 2 and result.record.outcome.workflow_complete is False
    assert_failure_survives_reload(out, result.record)


@pytest.mark.parametrize("linked", [True, False])
def test_interrupt_during_record_publication(fx, monkeypatch, linked):
    original = paired_trial.publish_new_file

    def interrupted_publish(path, data, limit):
        if Path(path).name == RECONSTRUCTION_FILES["baseline"]:
            if linked:
                original(path, data, limit)
            raise KeyboardInterrupt
        original(path, data, limit)

    monkeypatch.setattr(paired_trial, "publish_new_file", interrupted_publish)
    out = fx["tmp"] / "experiment"
    factory = Factory()
    result = run(fx, out, factory=factory)
    base = by_variant(result.record)["baseline"]
    assert base.state == "interrupted" and base.reconstruction.status == "completed"
    assert base.reconstruction.publication == ("published" if linked else "failed")
    if not linked:
        assert base.error.codes == ("interrupted",)
    assert by_variant(result.record)["protected"].state == "not_started"
    assert factory.made[1].requests == []
    assert result.exit_code == EXIT_INTERRUPTED
    assert_failure_survives_reload(out, result.record)


def test_interrupt_between_trials_marks_the_next_trial(fx, monkeypatch):
    original = paired_trial._execute_trial
    calls = []

    def interrupted_second(run_state, *args, **kwargs):
        calls.append(run_state.variant)
        if len(calls) == 2:
            raise KeyboardInterrupt  # before the second trial's handlers are entered
        return original(run_state, *args, **kwargs)

    monkeypatch.setattr(paired_trial, "_execute_trial", interrupted_second)
    out = fx["tmp"] / "experiment"
    result = run(fx, out)
    trials = by_variant(result.record)
    assert trials["baseline"].state == "record_produced"
    assert trials["protected"].state == "interrupted" and trials["protected"].reconstruction is None
    assert result.record.outcome.run_status == "interrupted"
    assert_failure_survives_reload(out, result.record)


def test_refused_execution_is_recorded_and_stops_the_run(fx, monkeypatch):
    original, calls = paired_trial.run_reconstruction, []

    def refuse_second(prepared_request, provider, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise ConfigurationError(("prepared_request_inconsistent",))
        return original(prepared_request, provider, **kwargs)

    monkeypatch.setattr(paired_trial, "run_reconstruction", refuse_second)
    out = fx["tmp"] / "experiment"
    result = run(fx, out)
    trials = by_variant(result.record)
    assert trials["protected"].state == "execution_refused"
    assert trials["protected"].error.codes == ("configuration:prepared_request_inconsistent",)
    assert result.record.outcome.run_status == "execution_refused"
    assert result.record.errors[0].variant == "protected"
    assert result.exit_code == EXIT_NOT_COMPLETED
    assert_failure_survives_reload(out, result.record)


def test_internal_error_in_a_trial_preserves_the_other(fx, monkeypatch):
    original, calls = paired_trial.run_reconstruction, []

    def crash_second(prepared_request, provider, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError(f"unexpected {SECRET}")
        return original(prepared_request, provider, **kwargs)

    monkeypatch.setattr(paired_trial, "run_reconstruction", crash_second)
    out = fx["tmp"] / "experiment"
    result = run(fx, out)
    protected = by_variant(result.record)["protected"]
    assert protected.state == "internal_error" and protected.error.codes == ("internal_error:RuntimeError",)
    assert result.exit_code == EXIT_INTERNAL
    assert SECRET.encode() not in (out / PAIRED_RECORD_FILE).read_bytes()
    assert_failure_survives_reload(out, result.record)


def test_partial_publication_is_recorded_and_stops_the_run(fx, monkeypatch):
    original = paired_trial.publish_new_file

    def fail_protected(path, data, limit):
        if Path(path).name == RECONSTRUCTION_FILES["protected"]:
            raise PublishError("write_failed")
        original(path, data, limit)

    monkeypatch.setattr(paired_trial, "publish_new_file", fail_protected)
    out = fx["tmp"] / "experiment"
    result = run(fx, out, seed=SEED_PROTECTED_FIRST)
    trials = by_variant(result.record)
    assert trials["protected"].reconstruction.publication == "failed"
    assert trials["protected"].reconstruction.file is None
    assert trials["protected"].error.stage == "publication"
    assert trials["baseline"].state == "not_started"
    assert result.record.outcome.run_status == "publication_failed"
    assert result.exit_code == EXIT_PUBLICATION_FAILED
    assert sorted(p.name for p in out.iterdir()) == [PAIRED_RECORD_FILE]
    assert_failure_survives_reload(out, result.record)


def test_paired_record_publication_failure_keeps_trial_records(fx, monkeypatch):
    original = paired_trial.publish_new_file

    def fail_paired(path, data, limit):
        if Path(path).name == PAIRED_RECORD_FILE:
            raise PublishError("write_failed")
        original(path, data, limit)

    monkeypatch.setattr(paired_trial, "publish_new_file", fail_paired)
    out = fx["tmp"] / "experiment"
    result = run(fx, out)
    assert result.paired_record_published is False and result.exit_code == EXIT_PUBLICATION_FAILED
    assert result.record.outcome.pair_status == "candidates_received_for_both_trials"
    assert sorted(p.name for p in out.iterdir()) == sorted(RECONSTRUCTION_FILES.values())
    with pytest.raises(ExperimentVerificationError, match="paired-record: not_found"):
        verify_experiment(out)


def test_replaced_output_directory_is_detected(fx, monkeypatch):
    original = paired_trial.publish_new_file
    out = fx["tmp"] / "experiment"

    def swap_after_first(path, data, limit):
        original(path, data, limit)
        if Path(path).name == RECONSTRUCTION_FILES["baseline"]:
            out.rename(fx["tmp"] / "moved")
            out.mkdir()

    monkeypatch.setattr(paired_trial, "publish_new_file", swap_after_first)
    result = run(fx, out)
    protected = by_variant(result.record)["protected"]
    assert protected.reconstruction.publication_error == "directory_replaced"
    assert result.paired_record_published is False
    assert result.paired_record_publication_error == "directory_replaced"
    assert list(out.iterdir()) == []  # nothing was written into the substituted directory


# --- Record validation: malformed or contradictory records are rejected ---------------------------

@pytest.fixture
def published(fx):
    out = fx["tmp"] / "experiment"
    run(fx, out)
    return out, json.loads((out / PAIRED_RECORD_FILE).read_bytes())


def tamper(document: dict, path: str, value) -> bytes:
    target = document
    *parents, last = path.split(".")
    for part in parents:
        target = target[int(part)] if part.isdigit() else target[part]
    if last.isdigit():
        target[int(last)] = value
    else:
        target[last] = value
    return json.dumps(document).encode()


def flipped_seed(document: dict) -> int:
    current = tuple(document["order"]["sequence"])
    return next(s for s in range(64) if execution_order(
        s, pair_id=document["pair_id"], baseline_trial_id=document["trials"][0]["trial_id"],
        protected_trial_id=document["trials"][1]["trial_id"]) != current)


TAMPERING = {
    "order.sequence reversed": lambda d: tamper(d, "order.sequence", list(reversed(d["order"]["sequence"]))),
    "order.seed changed": lambda d: tamper(d, "order.seed", flipped_seed(d)),
    "trials reordered": lambda d: tamper(d, "trials", list(reversed(d["trials"]))),
    "duplicate trial ids": lambda d: tamper(d, "trials.1.trial_id", d["trials"][0]["trial_id"]),
    "execution positions swapped": lambda d: (tamper(d, "trials.0.execution_position",
                                                     d["trials"][1]["execution_position"]),
                                              tamper(d, "trials.1.execution_position",
                                                     3 - d["trials"][1]["execution_position"]))[1],
    "pair_status upgraded": lambda d: tamper(d, "outcome.pair_status", "trial_failures"),
    "run_status changed": lambda d: tamper(d, "outcome.run_status", "interrupted"),
    "candidate origin changed": lambda d: tamper(d, "outcome.candidate_origin", "model"),
    "success claimed": lambda d: tamper(d, "outcome.reconstruction_success_established", True),
    "protection effect claimed": lambda d: tamper(d, "outcome.protection_effect_established", True),
    "scored": lambda d: tamper(d, "outcome.scoring", "resisted"),
    "totals changed": lambda d: tamper(d, "totals.charged_tokens", d["totals"]["charged_tokens"] + 1),
    "candidate digest dropped": lambda d: tamper(d, "trials.0.reconstruction.candidate_sha256", None),
    "status changed without candidate": lambda d: tamper(d, "trials.0.reconstruction.status", "refused"),
    "not_started with a record": lambda d: tamper(d, "trials.1.state", "not_started"),
    "wrong file for variant": lambda d: tamper(d, "trials.0.reconstruction.file", "protected-reconstruction.json"),
    "identical artifacts claimed": lambda d: tamper(d, "comparability.final_artifacts_identical", True),
    "runtime field dropped": lambda d: (d["comparability"]["ghidra_runtime"].pop("java_version"),
                                       json.dumps(d).encode())[1],
    "authorization as permission": lambda d: tamper(d, "authorization.is_execution_permission", True),
    "live provider": lambda d: tamper(d, "provider.provider", "Nebius"),
    "external disclosure": lambda d: tamper(d, "provider.external_disclosure", True),
    "signed": lambda d: tamper(d, "record_signed", True),
    "error invented": lambda d: tamper(d, "errors", [{"variant": "baseline", "stage": "execution",
                                                       "codes": ["budget:x"]}]),
    "time reversed": lambda d: tamper(d, "finished_at", "2000-01-01T00:00:00Z"),
    "naive timestamp": lambda d: tamper(d, "started_at", "2026-01-01T00:00:00"),
    "unknown field": lambda d: tamper(d, "extra", 1),
    "schema version": lambda d: tamper(d, "schema_version", "aegis.lab.paired-trial.v0"),
    "live execution mode": lambda d: tamper(d, "execution_mode", "live"),
    "bad experiment id": lambda d: tamper(d, "experiment_id", "X" * 32),
}


@pytest.mark.parametrize("name", sorted(TAMPERING))
def test_contradictory_record_is_rejected(published, name):
    _out, document = published
    with pytest.raises(ValidationError):
        parse_paired_trial_record(TAMPERING[name](document))


def test_failure_record_without_its_error_entry_is_rejected(fx):
    errors = [FakeProvider(), FakeProvider()]
    out = fx["tmp"] / "experiment"
    original = paired_trial.publish_new_file

    def fail_second(path, data, limit):
        if Path(path).name == RECONSTRUCTION_FILES["protected"]:
            raise PublishError("write_failed")
        original(path, data, limit)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(paired_trial, "publish_new_file", fail_second)
        run(fx, out, factory=Factory(*errors))
    document = json.loads((out / PAIRED_RECORD_FILE).read_bytes())
    with pytest.raises(ValidationError):
        parse_paired_trial_record(tamper(document, "errors", []))
    with pytest.raises(ValidationError):  # a skipped trial cannot be claimed as run
        parse_paired_trial_record(tamper(json.loads((out / PAIRED_RECORD_FILE).read_bytes()),
                                         "outcome.run_status", "finished"))


@pytest.mark.parametrize("data, category", [
    (b'{"schema_version": "aegis.lab.paired-trial.v1", "schema_version": "x"}', "duplicate_key"),
    (b'{"totals": NaN}', "non_finite_number"),
    (b"\xff", "invalid_utf8"),
    (b" " * (paired_trial.MAX_PAIRED_RECORD_BYTES + 1), "too_large"),
])
def test_malformed_record_bytes_are_rejected(data, category):
    with pytest.raises(LoadError) as exc:
        parse_paired_trial_record(data)
    assert exc.value.category == category


# --- Verification of published experiments --------------------------------------------------------

def test_verify_with_inputs_revalidates_every_reference(fx):
    out = fx["tmp"] / "experiment"
    result = run(fx, out)
    m, r = fx["manifests"], fx["reports"]
    assert verify_experiment(out, baseline_manifest=m["baseline"], protected_manifest=m["protected"],
                             baseline_report=r["baseline"], protected_report=r["protected"]) == result.record


def test_verify_detects_a_rewritten_reconstruction_file(fx):
    out = fx["tmp"] / "experiment"
    run(fx, out)
    path = out / RECONSTRUCTION_FILES["baseline"]
    document = json.loads(path.read_bytes())
    path.chmod(0o600)
    path.write_bytes(json.dumps(document, indent=1).encode())  # same record, different bytes
    with pytest.raises(ExperimentVerificationError) as exc:
        verify_experiment(out)
    assert exc.value.issues == ("baseline-reconstruction: file_sha256: mismatch",)


def test_verify_detects_swapped_reconstruction_files(fx):
    out = fx["tmp"] / "experiment"
    run(fx, out)
    a, b = (out / RECONSTRUCTION_FILES[v] for v in ("baseline", "protected"))
    a.rename(out / "tmp.json")
    b.rename(a)
    (out / "tmp.json").rename(b)
    with pytest.raises(ExperimentVerificationError) as exc:
        verify_experiment(out)
    for role in ("baseline", "protected"):
        for name in ("file_sha256", "trial_id", "variant", "inputs.manifest_sha256"):
            assert f"{role}-reconstruction: {name}: mismatch" in exc.value.issues


def test_verify_detects_a_missing_reconstruction_file(fx):
    out = fx["tmp"] / "experiment"
    run(fx, out)
    (out / RECONSTRUCTION_FILES["protected"]).unlink()
    with pytest.raises(ExperimentVerificationError, match="protected-reconstruction: not_found"):
        verify_experiment(out)


def test_verify_detects_an_identity_edit_with_recomputed_digests(fx):
    """Phase 3A cannot detect a changed trial_id alone; the paired cross-reference does."""
    out = fx["tmp"] / "experiment"
    run(fx, out)
    rec_path, paired_path = out / RECONSTRUCTION_FILES["protected"], out / PAIRED_RECORD_FILE
    document = json.loads(rec_path.read_bytes())
    document["trial_id"] = "3" * 32
    forged = parse_reconstruction_record(json.dumps(document).encode())
    data = forged.to_json_bytes()
    rec_path.unlink()
    rec_path.write_bytes(data)
    paired = json.loads(paired_path.read_bytes())
    paired["trials"][1]["reconstruction"].update(file_sha256=hashlib.sha256(data).hexdigest(),
                                                  record_sha256=forged.sha256())
    paired_path.unlink()
    paired_path.write_bytes(json.dumps(paired).encode())
    with pytest.raises(ExperimentVerificationError) as exc:
        verify_experiment(out)
    assert exc.value.issues == ("protected-reconstruction: trial_id: mismatch",)


def test_verify_detects_resource_figures_that_disagree_with_the_trial_record(fx):
    out = fx["tmp"] / "experiment"
    run(fx, out)
    path = out / PAIRED_RECORD_FILE
    paired = json.loads(path.read_bytes())
    paired["trials"][0]["resources"]["reported_tokens"] -= 100  # internally consistent with the totals below
    paired["totals"]["reported_tokens"] -= 100
    parse_paired_trial_record(json.dumps(paired).encode())
    path.unlink()
    path.write_bytes(json.dumps(paired).encode())
    with pytest.raises(ExperimentVerificationError) as exc:
        verify_experiment(out)
    assert exc.value.issues == ("baseline-reconstruction: resources: mismatch",)


def test_verify_detects_inputs_that_do_not_match(fx, tmp_path):
    out = fx["tmp"] / "experiment"
    run(fx, out)
    other = build_pair(tmp_path / "other", bodies=((b"variant-two", BRAVO.replace("90", "91")),))
    m = fx["manifests"]
    with pytest.raises(ExperimentVerificationError) as exc:
        verify_experiment(out, baseline_manifest=m["baseline"], protected_manifest=m["protected"],
                          baseline_report=fx["reports"]["baseline"], protected_report=other["reports"]["protected"])
    assert any(i.startswith("inputs: protected-evidence: binding:") for i in exc.value.issues)
    with pytest.raises(ExperimentVerificationError, match="inputs: incomplete"):
        verify_experiment(out, baseline_manifest=m["baseline"])


@pytest.mark.parametrize("path, value", [
    ("trials.0.evidence.evidence_size_bytes", 1),
    ("trials.0.prepared.cross_trial_value_findings", 7),
    ("authorization.reference", "a different audit reference"),
    ("authorization.authorized_scope", "a different scope"),
    ("comparability.ghidra_runtime.java_version", "a different runtime"),
])
def test_verify_inputs_checks_repeated_metadata(fx, path, value):
    out = fx["tmp"] / "experiment"
    run(fx, out)
    record_path = out / PAIRED_RECORD_FILE
    document = json.loads(record_path.read_bytes())
    record_path.write_bytes(tamper(document, path, value))
    # These edits remain internally consistent, but contradict the supplied inputs.
    parse_paired_trial_record(record_path.read_bytes())
    m, r = fx["manifests"], fx["reports"]
    with pytest.raises(ExperimentVerificationError, match="mismatch"):
        verify_experiment(out, baseline_manifest=m["baseline"], protected_manifest=m["protected"],
                          baseline_report=r["baseline"], protected_report=r["protected"])


def test_verify_rejects_a_tampered_paired_record(published):
    out, document = published
    (out / PAIRED_RECORD_FILE).unlink()
    (out / PAIRED_RECORD_FILE).write_bytes(TAMPERING["pair_status upgraded"](document))
    with pytest.raises(ExperimentVerificationError) as exc:
        verify_experiment(out)
    assert exc.value.issues[0].startswith("paired-record: ")


# --- Command-line interface -----------------------------------------------------------------------

def write_inputs(fx) -> dict:
    paths = {}
    for variant in ("baseline", "protected"):
        manifest = fx["tmp"] / f"{variant}-manifest.json"
        manifest.write_text(fx["manifests"][variant].model_dump_json())
        evidence = fx["tmp"] / f"report-{variant}" / "ghidra-analysis.json"
        assert evidence.read_bytes() == fx["reports"][variant]
        paths[variant] = (manifest, evidence)
    return paths


def cli_args(paths: dict, out: Path, *extra: str, swap: bool = False) -> list[str]:
    b, p = (paths["protected"], paths["baseline"]) if swap else (paths["baseline"], paths["protected"])
    return ["run", "--baseline-manifest", str(b[0]), "--protected-manifest", str(p[0]),
            "--baseline-evidence", str(b[1]), "--protected-evidence", str(p[1]),
            "--output-dir", str(out), "--mode", "offline", *extra]


def verify_args(paths: dict, out: Path) -> list[str]:
    return ["verify", str(out), "--baseline-manifest", str(paths["baseline"][0]),
            "--protected-manifest", str(paths["protected"][0]), "--baseline-evidence", str(paths["baseline"][1]),
            "--protected-evidence", str(paths["protected"][1])]


def test_cli_runs_and_verifies_a_pair(fx, capsys):
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    assert main(cli_args(paths, out, "--order-seed", "7")) == EXIT_COMPLETED
    summary = json.loads(capsys.readouterr().out)
    assert summary["run_status"] == "finished"
    assert summary["pair_status"] == "candidates_received_for_both_trials"
    assert summary["order"] == {"seed": 7, "seed_source": "operator", "sequence": list(execution_order(
        7, pair_id="9" * 32, baseline_trial_id="1" * 32, protected_trial_id="2" * 32))}
    assert summary["reconstruction_success_established"] is False and summary["authorizes_execution"] is False
    assert str(fx["tmp"]) not in json.dumps(summary)
    assert main(verify_args(paths, out)) == EXIT_COMPLETED
    verified = json.loads(capsys.readouterr().out)
    assert verified["paired_record_sha256"] == summary["paired_record_sha256"]
    assert "re-prepared inputs" in verified["verification"]


def test_cli_rejects_swapped_role_arguments(fx, capsys):
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    assert main(cli_args(paths, out, swap=True)) == 2
    err = capsys.readouterr().err
    assert "baseline-manifest: variant: not_baseline" in err
    assert not out.exists()


def test_cli_refuses_an_existing_output_directory(fx, capsys):
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    out.mkdir()
    assert main(cli_args(paths, out)) == EXIT_PUBLICATION_FAILED
    assert "output-dir: already_exists" in capsys.readouterr().err
    assert list(out.iterdir()) == []


@pytest.mark.parametrize("extra", [["--mode", "live"], ["--order-seed", "x"]])
def test_cli_rejects_invalid_options_without_echo(fx, capsys, extra):
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    args = cli_args(paths, out)
    args[args.index("--mode"):args.index("--mode") + 2] = []
    with pytest.raises(SystemExit) as exc:
        main(args + extra + (["--mode", "offline"] if extra[0] != "--mode" else []))
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "live" not in err.split("error:")[-1] and not out.exists()


def test_cli_rejects_an_out_of_range_seed(fx, capsys):
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    assert main(cli_args(paths, out, "--order-seed", str(2**63))) == 2
    assert "order-seed: out_of_range" in capsys.readouterr().err


def test_cli_reports_missing_evidence_by_role(fx, capsys):
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    paths["protected"] = (paths["protected"][0], fx["tmp"] / "absent.json")
    assert main(cli_args(paths, out)) == 2
    assert "protected-evidence: not_found" in capsys.readouterr().err


def test_cli_never_echoes_rejected_values(fx, capsys):
    paths, out = write_inputs(fx), fx["tmp"] / f"experiment-{SECRET}"
    data = json.loads(paths["protected"][0].read_text())
    data["target"]["name"] = f"{SECRET}‮"
    paths["protected"][0].write_text(json.dumps(data))
    assert main(cli_args(paths, out)) == 2
    captured = capsys.readouterr()
    assert SECRET not in captured.err + captured.out
    assert "protected-manifest: target.name: aegis_forbidden_character" in captured.err


def test_cli_trial_failure_exits_one_with_records(fx, capsys, monkeypatch):
    factory = Factory(FakeProvider(content="```c\nint x;\n```"), FakeProvider())
    monkeypatch.setattr(paired_trial, "run_paired_trial",
                        functools.partial(paired_trial.run_paired_trial, provider_factory=factory))
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    assert main(cli_args(paths, out, "--order-seed", str(SEED_BASELINE_FIRST))) == EXIT_NOT_COMPLETED
    captured = capsys.readouterr()
    assert json.loads(captured.out)["trials"]["baseline"]["status"] == "invalid_candidate"
    assert "finished, trial_failures" in captured.err
    assert main(verify_args(paths, out)) == EXIT_COMPLETED


def test_cli_interrupted_run_exits_130_with_records(fx, capsys, monkeypatch):
    def interrupt(_request, _timeout):
        raise KeyboardInterrupt
    factory = Factory(FakeProvider(on_call=interrupt))
    monkeypatch.setattr(paired_trial, "run_paired_trial",
                        functools.partial(paired_trial.run_paired_trial, provider_factory=factory))
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    assert main(cli_args(paths, out)) == EXIT_INTERRUPTED
    assert json.loads(capsys.readouterr().out)["run_status"] == "interrupted"
    assert (out / PAIRED_RECORD_FILE).exists()


def test_cli_prints_a_safe_summary_when_the_record_cannot_be_published(fx, capsys, monkeypatch):
    original = paired_trial.publish_new_file

    def fail_paired(path, data, limit):
        if Path(path).name == PAIRED_RECORD_FILE:
            raise PublishError("write_failed")
        original(path, data, limit)

    monkeypatch.setattr(paired_trial, "publish_new_file", fail_paired)
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    assert main(cli_args(paths, out)) == EXIT_PUBLICATION_FAILED
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["run_status"] == "finished"
    assert summary["pair_status"] == "candidates_received_for_both_trials"
    assert "authorization" not in summary and "analysis" not in summary
    assert sorted(p.name for p in out.iterdir()) == sorted(RECONSTRUCTION_FILES.values())
    for variant, filename in RECONSTRUCTION_FILES.items():
        record = parse_reconstruction_record((out / filename).read_bytes())
        assert record.trial_id == fx["manifests"][variant].trial_id
        assert record.outcome.status == "completed"
    assert "paired record not published: write_failed" in captured.err


def test_cli_verify_reports_tampering(fx, capsys):
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    assert main(cli_args(paths, out)) == EXIT_COMPLETED
    (out / RECONSTRUCTION_FILES["protected"]).unlink()
    capsys.readouterr()
    assert main(["verify", str(out)]) == 2
    assert "protected-reconstruction: not_found" in capsys.readouterr().err


def test_cli_verify_requires_all_or_no_inputs(fx, capsys):
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    assert main(cli_args(paths, out)) == EXIT_COMPLETED
    assert main(["verify", str(out), "--baseline-manifest", str(paths["baseline"][0])]) == 2
    assert "inputs: incomplete" in capsys.readouterr().err


def test_module_is_runnable_with_python_m(fx):
    paths, out = write_inputs(fx), fx["tmp"] / "experiment"
    root = Path(__file__).resolve().parents[2]
    proc = subprocess.run([str(root / ".venv" / "bin" / "python"), "-m", "aegis_lab.paired_trial",
                           *cli_args(paths, out, "--order-seed", "3")],
                          capture_output=True, text=True, timeout=120, env={"PATH": os.environ.get("PATH", "")})
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["pair_status"] == "candidates_received_for_both_trials"


# --- Real Ghidra (opt-in) -------------------------------------------------------------------------

HEADLESS = os.environ.get("AEGIS_GHIDRA_HEADLESS")
CC = shutil.which("cc")
REAL_BASELINE_C = ("__attribute__((noinline)) int aegis_pair(int a, int b) { return (a * 7) + (b ^ 3); }\n"
                   "int main(int argc, char **argv) { (void)argv; return aegis_pair(argc, 5); }\n")
# A stand-in for a protected build: same interface, rewritten arithmetic. It is NOT a Shield
# output and says nothing about protection; it only gives the pair two distinct artifacts.
REAL_STANDIN_C = ("__attribute__((noinline)) int aegis_pair(int a, int b) {\n"
                  "  volatile int k = 7; int t = 0; for (int i = 0; i < k; i++) t += a;\n"
                  "  return t + ((b | 3) - (b & 3)); }\n"
                  "int main(int argc, char **argv) { (void)argv; return aegis_pair(argc, 5); }\n")


@pytest.mark.skipif(not HEADLESS or not CC, reason="real Ghidra test needs AEGIS_GHIDRA_HEADLESS and a C compiler")
def test_real_ghidra_paired_trial(tmp_path):
    tool = planned_ghidra_tool(Path(HEADLESS), function="aegis_pair").model_dump(mode="json")
    manifests, reports = {}, {}
    for variant, source in (("baseline", REAL_BASELINE_C), ("protected", REAL_STANDIN_C)):
        (tmp_path / f"{variant}.c").write_text(source)
        binary = tmp_path / f"{variant}.elf"
        subprocess.run([CC, "-O1", "-fno-inline", "-o", str(binary), str(tmp_path / f"{variant}.c")],
                       check=True, timeout=120)  # compiled for analysis only; never executed
        sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        reports[variant] = analyze(binary, tmp_path / f"out-{variant}", Path(HEADLESS), function="aegis_pair",
                                   expected_sha256=sha).read_bytes()
        data = manifest_data(protected=variant == "protected")
        data["target"].update(function="aegis_pair", final_artifact_sha256=sha)
        data["attack"].update(tools=[tool], provider="FakeOffline",
                              **planned_attack_digests(max_model_tokens=4000, blinded=True))
        data["scoring"]["expected_interface"] = "opaque(int,int)->int"
        manifests[variant] = TrialManifest.model_validate(data)
    pair = prepare_pair(manifests["baseline"], manifests["protected"], reports["baseline"], reports["protected"])
    assert pair.ghidra_runtime["ghidra_release_name"]
    out = tmp_path / "experiment"
    factory = Factory()
    result = run_paired_trial(pair, out, order_seed=11, provider_factory=factory)
    assert result.exit_code == EXIT_COMPLETED
    for provider in factory.made:
        prompt = provider.requests[0].messages[1].content
        assert "aegis_pair" not in prompt and "target_function" in prompt  # blinded in both trials
    assert verify_experiment(out, baseline_manifest=manifests["baseline"], protected_manifest=manifests["protected"],
                             baseline_report=reports["baseline"], protected_report=reports["protected"]) \
        == result.record
