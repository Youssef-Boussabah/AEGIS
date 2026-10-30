"""Current Core grant binding through Lab; all runtime results are non-executing scripted doubles."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json

import pytest

pytest.importorskip("aegis_core.lab_execution", reason="needs current Core candidate-execution contract")

from aegis_core.lab_authorization import compilation_bundle_sha256, grant_sha256  # noqa: E402
from aegis_core.lab_execution import open_session  # noqa: E402
from aegis_core.lab_ledger import GrantLedger  # noqa: E402
from scoring_fixtures import (  # noqa: E402
    BASELINE_SOURCE, core_config, experiment, grant, reconstruction_bytes, reference, scripted,
)

from aegis_lab.behavior_score import prepare_scoring, score_trial  # noqa: E402
from aegis_lab.c_abi import CANDIDATE_FILE, TRANSLATION_UNITS  # noqa: E402
from aegis_lab.core_execution import (  # noqa: E402
    CoreSessionWorker, OpenedSession, compilation_request, lab_bindings, reviewed_candidate_binding,
)
from aegis_lab.scoring import score_paired_experiment  # noqa: E402
from aegis_lab.scoring_policy import ExecutionRefused  # noqa: E402
from aegis_lab.scoring_worker import StageRefused  # noqa: E402


@pytest.fixture(scope="module", params=[False, True], ids=["blinded", "unblinded"])
def fx(request, tmp_path_factory):
    root = tmp_path_factory.mktemp("bundle-scoring")
    symbol = "secret_add" if request.param else "target_function"
    source = BASELINE_SOURCE.replace("target_function", symbol)
    result = experiment(root, baseline_source=source, protected_source=source,
                        both={"access.access_to_symbols": request.param})
    result["config"] = core_config(root)
    result["symbol"] = symbol
    return result


def prepared(fx, variant="baseline"):
    return prepare_scoring(fx["manifests"][variant], reconstruction_bytes=reconstruction_bytes(fx, variant),
                           evidence_bytes=fx["reports"][variant], suite_bytes=fx["suite"], policy=fx["policy"])


def bundle_files(request):
    return {request.candidate_name: request.candidate, **dict(request.support)}


def independent_digest(files, units):
    """Contract JSON encoded independently of both the Lab issuer and Core's helper."""
    document = {"files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                "translation_units": list(units)}
    return hashlib.sha256(json.dumps(document, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()


def test_reviewed_grant_binds_actual_multifile_job_and_symbol(fx):
    p = prepared(fx)
    issued = grant(fx)
    runtime = scripted(behavior=reference)
    score = score_trial(p, config=fx["config"], grant=issued, runtime=runtime)
    job, = runtime.compile_jobs
    files = {f.name: f.data for f in [job.candidate, *job.support_files]}
    permitted = issued.candidate(p.manifest.trial_id)
    assert p.interface.symbol == fx["symbol"]
    assert job.translation_units == list(TRANSLATION_UNITS)
    assert CANDIDATE_FILE not in job.translation_units
    assert set(files) == {CANDIDATE_FILE, *TRANSLATION_UNITS}
    assert permitted.compilation_bundle_sha256 == independent_digest(files, job.translation_units)
    assert b'__asm__("' + fx["symbol"].encode() + b'")' in files[TRANSLATION_UNITS[0]]
    assert score.result.outcome.status == "behavioral_match"
    assert score.result.worker.kind == "test_double"
    assert score.result.evidence.counts_as_behavioral_evidence is False


def test_bundle_binds_utf8_source_bytes_and_preserves_file_order_independence(fx):
    p = prepared(fx)
    request = compilation_request(p)
    # Hashing must preserve bytes, including CRLF and non-ASCII text; nothing is compiled.
    source = request.candidate + '/* reviewed café */\r\n'.encode()
    files = {**bundle_files(request), CANDIDATE_FILE: source}
    issued = reviewed_candidate_binding(candidate_id=p.manifest.trial_id, candidate=source,
        target_sha256=p.manifest.target.final_artifact_sha256, interface=p.interface.text, symbol=p.interface.symbol)
    assert issued.candidate_sha256 == hashlib.sha256(source).hexdigest()
    assert issued.compilation_bundle_sha256 == independent_digest(files, TRANSLATION_UNITS)
    assert issued.compilation_bundle_sha256 == compilation_bundle_sha256(dict(reversed(list(files.items()))), TRANSLATION_UNITS)
    assert issued.compilation_bundle_sha256 != compilation_bundle_sha256(files, tuple(reversed(TRANSLATION_UNITS)))


@pytest.mark.parametrize("digest,code", [(None, "grant_compilation_bundle_required"),
                                         ("0" * 64, "grant_compilation_bundle_mismatch")])
def test_invalid_bundle_grant_refused_before_preflight_or_budget(fx, digest, code):
    p = prepared(fx)
    issued = grant(fx, **{"candidates.0.compilation_bundle_sha256": digest})
    runtime = scripted(behavior=reference)
    with pytest.raises(ExecutionRefused) as caught:
        score_trial(p, config=fx["config"], grant=issued, runtime=runtime)
    assert caught.value.code == code
    assert runtime.preflights == runtime.compile_jobs == runtime.execute_jobs == []
    assert GrantLedger.for_config(fx["config"]).usage(issued.grant_id) is None


def test_bundle_for_other_symbol_is_refused_before_preflight(fx):
    p = prepared(fx)
    wrong = "other_owned_function"
    binding = reviewed_candidate_binding(candidate_id=p.manifest.trial_id, candidate=p.candidate_source.encode(),
        target_sha256=p.manifest.target.final_artifact_sha256, interface=p.interface.text, symbol=wrong)
    issued = grant(fx, **{"candidates.0.compilation_bundle_sha256": binding.compilation_bundle_sha256})
    runtime = scripted(behavior=reference)
    with pytest.raises(ExecutionRefused, match="grant_compilation_bundle_mismatch"):
        score_trial(p, config=fx["config"], grant=issued, runtime=runtime)
    assert runtime.preflights == []


def test_pair_refuses_invalid_second_bundle_before_factory_or_publication(fx, tmp_path):
    issued = grant(fx, **{"candidates.1.compilation_bundle_sha256": "0" * 64})
    output = tmp_path / "scores"
    with pytest.raises(ExecutionRefused, match="grant_compilation_bundle_mismatch"):
        score_paired_experiment(fx["experiment"], output, manifests=fx["manifests"], reports=fx["reports"],
            suite_bytes=fx["suite"], policy=fx["policy"], config=fx["config"], grant=issued,
            runtime_factory=lambda: pytest.fail("runtime factory invoked"))
    assert not output.exists()
    assert GrantLedger.for_config(fx["config"]).usage(issued.grant_id) is None


def altered(request, change):
    support = list(request.support)
    if change == "candidate":
        return replace(request, candidate=request.candidate + b"\n/* changed */\n")
    if change in ("harness", "candidate_unit"):
        index = 0 if change == "harness" else 1
        name, data = support[index]
        support[index] = (name, data + b"\n/* changed */\n")
        return replace(request, support=tuple(support))
    if change == "added_header":
        return replace(request, support=(*request.support, ("extra.h", b"#define OWNED 1\n")))
    if change == "removed_unit":
        return replace(request, support=tuple(support[:1]), translation_units=request.translation_units[:1])
    if change == "renamed_file":
        support[0] = ("different_harness.c", support[0][1])
        return replace(request, support=tuple(support), translation_units=(support[0][0], request.translation_units[1]))
    if change == "unit_selection":
        return replace(request, translation_units=request.translation_units[:1])
    if change == "unit_order":
        return replace(request, translation_units=tuple(reversed(request.translation_units)))
    raise AssertionError("unknown test change")


@pytest.mark.parametrize("change", ["candidate", "harness", "candidate_unit", "added_header", "removed_unit",
                                    "renamed_file", "unit_selection", "unit_order", "missing_digest"])
def test_current_core_refuses_changed_request_without_reserving_compile_budget(fx, change):
    p = prepared(fx)
    issued = grant(fx, **({"candidates.0.compilation_bundle_sha256": None} if change == "missing_digest" else {}))
    request = compilation_request(p)
    if change != "missing_digest":
        request = altered(request, change)
    runtime = scripted(behavior=reference)
    # Enter real Core to test its independent enforcement after a reviewed grant
    # could have been checked. No grant checker or runtime gate is patched.
    with open_session(fx["config"], issued, lab_bindings=lab_bindings(p), runtime=runtime) as session:
        worker = CoreSessionWorker(OpenedSession(injected=True, session=session), p.manifest.trial_id,
                                   p.candidate_sha256, issued, lab_bindings(p))
        before = GrantLedger.for_config(fx["config"]).usage(issued.grant_id)
        with pytest.raises(StageRefused) as caught:
            worker.compile(request)
        reason = ("candidate_digest_mismatch" if change == "candidate" else
                  "compilation_bundle_required" if change == "missing_digest" else "compilation_bundle_mismatch")
        assert caught.value.reason == reason
        after = GrantLedger.for_config(fx["config"]).usage(issued.grant_id)
        assert after == before
        assert after.wall_ms_reserved == 0 and not after.compilations
        assert worker.records == [] and runtime.compile_jobs == runtime.execute_jobs == []


def test_reordered_file_submission_keeps_approved_units_and_digest(fx):
    p = prepared(fx)
    issued = grant(fx)
    request = compilation_request(p)
    request = replace(request, support=tuple(reversed(request.support)))
    runtime = scripted(behavior=reference)
    with open_session(fx["config"], issued, lab_bindings=lab_bindings(p), runtime=runtime) as session:
        worker = CoreSessionWorker(OpenedSession(injected=True, session=session), p.manifest.trial_id,
                                   p.candidate_sha256, issued, lab_bindings(p))
        observation = worker.compile(request)
        assert observation.status == "exited"
        assert runtime.compile_jobs[0].translation_units == list(TRANSLATION_UNITS)
        assert len(worker.records) == 1 and runtime.execute_jobs == []


def test_adding_bundle_to_used_grant_id_preserves_core_ledger_refusal(fx):
    p = prepared(fx)
    legacy = grant(fx, **{"candidates.0.compilation_bundle_sha256": None})
    old_runtime = scripted(behavior=reference)
    with open_session(fx["config"], legacy, lab_bindings=lab_bindings(p), runtime=old_runtime):
        pass  # Registers the historical grant identity, without compiling or executing.
    issued = grant(fx, grant_id=legacy.grant_id)
    assert grant_sha256(issued) != grant_sha256(legacy)
    runtime = scripted(behavior=reference)
    with pytest.raises(ExecutionRefused) as caught:
        score_trial(p, config=fx["config"], grant=issued, runtime=runtime)
    assert (caught.value.code, caught.value.reasons) == ("core_refused", ("grant_ledger_conflict",))
    assert runtime.preflights == runtime.compile_jobs == runtime.execute_jobs == []
    assert GrantLedger.for_config(fx["config"]).usage(issued.grant_id).grant_sha256 == grant_sha256(legacy)


@pytest.mark.parametrize("gate", ["attack_lab", "candidate_execution"])
def test_bundle_metadata_does_not_grant_execution_authorization(fx, tmp_path, gate):
    p = prepared(fx)
    issued = grant(fx)
    config = core_config(tmp_path, **{gate: False})
    runtime = scripted(behavior=reference)
    with pytest.raises(ExecutionRefused) as caught:
        score_trial(p, config=config, grant=issued, runtime=runtime)
    reason = "attack_lab_disabled" if gate == "attack_lab" else "candidate_execution_disabled"
    assert (caught.value.code, caught.value.reasons) == ("core_refused", (reason,))
    assert runtime.preflights == runtime.compile_jobs == runtime.execute_jobs == []
