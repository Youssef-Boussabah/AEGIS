"""No inference/candidates: request serialization and approval-binding regressions."""
from dataclasses import replace

import pytest
from pydantic import ValidationError

from test_provider import req
from test_paired_trial import build_pair
from aegis_lab.manifest import TrialManifest
from aegis_lab.reconstruction import (ConfigurationError, planned_attack_digests,
    prepare_reconstruction, sampling_configuration_document, verify_prepared)


def test_default_request_and_sampling_documents_remain_unchanged():
    assert "chat_template_kwargs" not in req().to_body()
    assert sampling_configuration_document(max_output_tokens=256, top_p=None) == {
        "schema": "aegis.lab.sampling-configuration.v1", "max_output_tokens": 256,
        "top_p": None, "n": 1, "stop": [], "stream": False}


@pytest.mark.parametrize("flag", [False, True])
def test_control_is_exact_boolean_in_actual_wire_body(flag):
    body = req(enable_thinking=flag, store=False).to_body()
    assert body["chat_template_kwargs"] == {"enable_thinking": flag}
    assert body["max_tokens"] == body["max_completion_tokens"] == 256
    assert body["store"] is False


@pytest.mark.parametrize("flag", [0, 1, "false", "true", {}, []])
def test_request_refuses_coerced_controls(flag):
    with pytest.raises(ValidationError):
        req(enable_thinking=flag)


def test_controls_have_distinct_sampling_identities():
    values = [planned_attack_digests(max_model_tokens=10000, enable_thinking=flag)["sampling_configuration_sha256"]
              for flag in (None, False, True)]
    assert len(set(values)) == 3


def test_default_manifest_cannot_silently_disable_thinking(tmp_path):
    pair = build_pair(tmp_path)
    with pytest.raises(ConfigurationError, match="sampling_configuration_mismatch"):
        prepare_reconstruction(pair["manifests"]["baseline"], pair["reports"]["baseline"], enable_thinking=False)


def test_prepared_control_is_bound_and_rechecked(tmp_path):
    pair = build_pair(tmp_path)
    m = pair["manifests"]["baseline"].model_dump(mode="json")
    m["attack"].update(planned_attack_digests(max_model_tokens=m["budget"]["max_model_tokens"],
        blinded=True, enable_thinking=False))
    prepared = prepare_reconstruction(TrialManifest.model_validate(m), pair["reports"]["baseline"], enable_thinking=False)
    assert prepared.request.to_body()["chat_template_kwargs"] == {"enable_thinking": False}
    verify_prepared(prepared)
    changed = replace(prepared, request=prepared.request.model_copy(update={"enable_thinking": True}))
    with pytest.raises(ConfigurationError, match="prepared_request_inconsistent"):
        verify_prepared(changed)
