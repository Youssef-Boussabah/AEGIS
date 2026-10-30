"""Gates 1-3 and the candidate execution grant (aegis_core.lab_authorization)."""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_core.config import config_from_mapping, default_config_text, load_config
from aegis_core.errors import AegisError
from aegis_core.lab_authorization import (
    MAX_GRANT_BYTES,
    REFUSAL_REASONS,
    authorize_candidate_execution,
    check_attack_lab_gates,
    grant_sha256,
    load_grant,
    parse_grant,
    refuse,
)
from aegis_core.lab_limits import default_compile_ceiling, default_execute_ceiling
from aegis_core.models import AttackLabAuthorization, ErrorCode
from lab_fixtures import (
    LAB_NOW,
    TARGET_BASE,
    compile_limits_data,
    execute_limits_data,
    grant_data,
)


def _reason(info: pytest.ExceptionInfo[AegisError]) -> str:
    assert info.value.code is ErrorCode.AUTHORIZATION_REQUIRED
    return info.value.details["reason"]


def _auth(**kwargs) -> AttackLabAuthorization:
    return AttackLabAuthorization(authorized_by="lead", reference="ENG-1", scope="one artifact", **kwargs)


# ------------------------------------------------------------- gates 1 and 2


def test_gate_one_disabled_refuses_even_with_authorization(lab_config):
    with pytest.raises(AegisError) as info:
        check_attack_lab_gates(lab_config(attack_lab=False), _auth(), LAB_NOW)
    assert _reason(info) == "attack_lab_disabled"
    assert "[attack_lab] enabled = false" in info.value.message


def test_gate_two_missing_authorization_refuses(lab_config):
    with pytest.raises(AegisError) as info:
        check_attack_lab_gates(lab_config(), None, LAB_NOW)
    assert _reason(info) == "authorization_missing"


@pytest.mark.parametrize("delta", [timedelta(0), timedelta(seconds=-1)])
def test_gate_two_expired_authorization_refuses_at_and_after_expiry(lab_config, delta):
    auth = _auth(expires_at=LAB_NOW + delta)
    with pytest.raises(AegisError) as info:
        check_attack_lab_gates(lab_config(), auth, LAB_NOW)
    assert _reason(info) == "authorization_expired"
    assert info.value.details["expires_at"] == auth.expires_at.isoformat()


def test_both_gates_pass(lab_config):
    check_attack_lab_gates(lab_config(), _auth(expires_at=LAB_NOW + timedelta(seconds=1)), LAB_NOW)
    check_attack_lab_gates(lab_config(candidate_execution=False), _auth(), LAB_NOW)


def test_orchestrator_uses_the_shared_gate_check(make_orchestrator, input_file, attack_policy):
    orch = make_orchestrator(attack_lab_enabled=False)
    with pytest.raises(AegisError) as info:
        orch.submit(attack_policy(), source=input_file)
    assert _reason(info) == "attack_lab_disabled"
    assert orch.list_jobs() == []


def test_refuse_rejects_unregistered_reasons():
    with pytest.raises(AssertionError):
        refuse("made_up", "x")
    assert all(refuse(r, "m").details["reason"] == r for r in REFUSAL_REASONS)


# -------------------------------------------------------------------- gate 3


def test_candidate_execution_is_off_by_default_and_in_generated_config(tmp_path):
    config = config_from_mapping({}, base_dir=tmp_path)
    assert config.attack_lab.enabled is False
    assert config.attack_lab.candidate_execution.enabled is False
    assert config.attack_lab.candidate_execution.compile_ceiling == default_compile_ceiling()
    assert config.attack_lab.candidate_execution.execute_ceiling == default_execute_ceiling()
    path = tmp_path / "aegis.toml"
    path.write_text(default_config_text(), encoding="utf-8")
    generated = load_config(path)
    assert generated.attack_lab.enabled is False
    assert generated.attack_lab.candidate_execution.enabled is False


@pytest.mark.parametrize(
    "section",
    [
        {"enabled": "yes"},
        {"enabled": True, "unknown": 1},
        {"execute_ceiling": execute_limits_data(memory_bytes=1)},
        {"compile_ceiling": execute_limits_data()},  # missing binary_bytes
    ],
)
def test_invalid_candidate_execution_config_is_rejected(tmp_path, section):
    with pytest.raises(AegisError) as info:
        config_from_mapping({"attack_lab": {"candidate_execution": section}}, base_dir=tmp_path)
    assert info.value.code is ErrorCode.CONFIG_INVALID


def test_gate_three_is_independent_of_gate_one(lab_config, make_grant):
    grant = make_grant()
    with pytest.raises(AegisError) as info:
        authorize_candidate_execution(lab_config(candidate_execution=False), grant, LAB_NOW)
    assert _reason(info) == "candidate_execution_disabled"
    # Gate 3 open cannot substitute for gate 1.
    with pytest.raises(AegisError) as info:
        authorize_candidate_execution(lab_config(attack_lab=False), grant, LAB_NOW)
    assert _reason(info) == "attack_lab_disabled"


def test_embedded_authorization_expiry_is_gate_two(lab_config, make_grant):
    data = grant_data()
    data["authorization"]["expires_at"] = "2026-10-29T11:00:00Z"
    data["expires_at"] = "2026-10-29T11:00:00Z"
    grant = make_grant(**data)
    with pytest.raises(AegisError) as info:
        authorize_candidate_execution(lab_config(), grant, LAB_NOW)
    assert _reason(info) == "authorization_expired"


def test_all_gates_and_window_pass(lab_config, make_grant):
    authorize_candidate_execution(lab_config(), make_grant(), LAB_NOW)


def test_naive_now_is_rejected(lab_config, make_grant):
    with pytest.raises(ValueError):
        authorize_candidate_execution(lab_config(), make_grant(), LAB_NOW.replace(tzinfo=None))


@pytest.mark.parametrize(
    ("now", "reason"),
    [
        ("2026-10-29T09:59:59Z", "grant_not_yet_valid"),
        ("2026-10-30T10:00:00Z", "grant_expired"),
        ("2026-10-31T00:00:00Z", "grant_expired"),
    ],
)
def test_grant_window_is_enforced(lab_config, make_grant, now, reason):
    from datetime import datetime

    moment = datetime.fromisoformat(now.replace("Z", "+00:00"))
    with pytest.raises(AegisError) as info:
        authorize_candidate_execution(lab_config(), make_grant(), moment)
    assert _reason(info) == reason


def test_grant_limits_may_not_exceed_operator_ceilings(lab_config, make_grant):
    grant = make_grant(
        compile_limits=compile_limits_data(memory_bytes=2048 * 1024 * 1024, wall_ms=600_000),
        execute_limits=execute_limits_data(max_processes=17),
    )
    with pytest.raises(AegisError) as info:
        authorize_candidate_execution(lab_config(), grant, LAB_NOW)
    assert _reason(info) == "grant_exceeds_operator_ceiling"
    assert info.value.details["exceeding"] == {
        "compile": ["memory_bytes", "wall_ms"],
        "execute": ["max_processes"],
    }


# ------------------------------------------------------------- grant validity


def _invalid(**overrides) -> None:
    with pytest.raises(ValidationError):
        parse_or_validate(grant_data(**overrides))


def parse_or_validate(data: dict):
    from aegis_core.lab_authorization import CandidateExecutionGrant

    return CandidateExecutionGrant.model_validate_json(json.dumps(data))


def _with_auth(**fields) -> dict:
    auth = grant_data()["authorization"]
    auth.update(fields)
    return auth


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": "aegis.core.candidate-execution-grant.v2"},
        {"valid_from": "2026-10-30T10:00:00Z"},  # equal to expires_at
        {"expires_at": "2026-11-05T10:00:01Z"},  # window longer than 7 days
        {"valid_from": "2026-10-29T10:00:00"},  # naive datetime
        {"authorization": _with_auth(attested_at="2026-10-29T10:00:01Z")},  # attested after valid_from
        {"authorization": _with_auth(expires_at="2026-10-30T09:59:59Z")},  # grant outlives auth
        {"authorization": _with_auth(scope="   ")},
        {"permitted_targets": [TARGET_BASE, TARGET_BASE]},
        {"permitted_targets": [TARGET_BASE]},  # candidate B's target is not permitted
        {"permitted_targets": [TARGET_BASE, "2" * 64, "9" * 64]},  # unused target
        {"permitted_targets": ["A" * 64, "2" * 64]},  # uppercase hex
        {"stages": ["compile", "compile"]},
        {"stages": ["execute"], "compile_flags": [], "compile_limits": None},
        {"stages": []},
        {"stages": ["link"]},
        {"compile_flags": []},
        {"compile_limits": None},
        {"compile_flags": ["-std=c11", "-std=c11"]},
        {"execute_limits": None},
        {"max_executions_per_candidate": 0},
        {"stages": ["compile"]},  # execute limits/executions without execute
        {"stages": ["compile"], "execute_limits": None},  # executions without execute
        {"max_compilations_per_candidate": 0},
        {"max_total_wall_ms": 999},
        {"candidates": []},
        {"grant_id": "D" * 32},
        {"unexpected": True},
    ],
)
def test_grant_rejects_inconsistent_or_unbounded_records(overrides):
    _invalid(**overrides)


def test_duplicate_candidate_ids_are_rejected():
    data = grant_data()
    data["candidates"][1]["candidate_id"] = data["candidates"][0]["candidate_id"]
    with pytest.raises(ValidationError):
        parse_or_validate(data)


def test_attested_at_must_be_explicit_in_a_grant():
    data = grant_data()
    del data["authorization"]["attested_at"]
    with pytest.raises(ValidationError, match="attested_at"):
        parse_or_validate(data)


@pytest.mark.parametrize(
    "flag",
    [
        "-fplugin=/tmp/evil.so",
        "-include/etc/passwd",
        "@/etc/passwd",
        "-B/tmp",
        "-specs=/tmp/x",
        "-Wl,-rpath,/tmp",
        "-o",
        "-std=c11 ",
        "-O2;id",
        "-Werror=Format",
    ],
)
def test_only_allowlisted_compiler_flags(flag):
    _invalid(compile_flags=["-std=c11", flag])


def test_compile_only_grant_is_valid(make_grant):
    grant = make_grant(stages=["compile"], execute_limits=None, max_executions_per_candidate=0)
    assert grant.stages == ["compile"]


# ------------------------------------------------------------ strict parsing


def _bytes(data: dict | None = None) -> bytes:
    return json.dumps(data or grant_data()).encode("utf-8")


def test_parse_grant_round_trip_and_digest_is_order_independent(make_grant):
    grant = parse_grant(_bytes())
    assert grant == make_grant()
    reordered = json.dumps(dict(reversed(list(grant_data().items())))).encode()
    assert grant_sha256(parse_grant(reordered)) == grant_sha256(grant)
    assert len(grant_sha256(grant)) == 64


def test_grant_digest_changes_with_any_field(make_grant):
    base = grant_sha256(make_grant())
    assert grant_sha256(make_grant(max_executions_per_candidate=4)) != base
    data = grant_data()
    data["authorization"]["reference"] = "ENG-43"
    assert grant_sha256(make_grant(**data)) != base


@pytest.mark.parametrize(
    "raw",
    [
        b"\xef\xbb\xbf" + _bytes(),
        b"\xff\xfe{}",
        b"{not json",
        _bytes()[:-1] + b',"grant_id":"' + b"e" * 32 + b'"}',  # duplicate top-level key
        b'{"x": NaN}',
        b'{"x": Infinity}',
    ],
)
def test_parse_grant_rejects_non_strict_json(raw):
    with pytest.raises(AegisError) as info:
        parse_grant(raw)
    assert info.value.code is ErrorCode.INVALID_REQUEST


def test_parse_grant_rejects_nested_duplicate_keys():
    text = _bytes().decode()
    text = text.replace('"authorized_by": "security-lead"', '"authorized_by": "a", "authorized_by": "b"', 1)
    with pytest.raises(AegisError) as info:
        parse_grant(text.encode())
    assert info.value.message == "Candidate execution grant is not strict UTF-8 JSON."


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_total_wall_ms": "120000"},
        {"max_executions_per_candidate": True},
        {"max_total_wall_ms": 120000.0},
    ],
)
def test_parse_grant_is_strict_about_types(overrides):
    with pytest.raises(AegisError) as info:
        parse_grant(_bytes(grant_data(**overrides)))
    assert info.value.code is ErrorCode.INVALID_REQUEST
    assert info.value.details["errors"]


def test_parse_grant_errors_never_echo_values():
    secret = "sk-live-0123456789-do-not-print"
    data = grant_data()
    data["authorization"]["scope"] = secret
    data["grant_id"] = secret
    data[secret] = secret
    with pytest.raises(AegisError) as info:
        parse_grant(_bytes(data))
    assert secret not in json.dumps(info.value.details) + info.value.message


def test_parse_grant_size_limit():
    with pytest.raises(AegisError, match="exceeds"):
        parse_grant(b" " * (MAX_GRANT_BYTES + 1))


def test_load_grant_reads_regular_files(tmp_path, make_grant):
    path = tmp_path / "grant.json"
    path.write_bytes(_bytes())
    assert load_grant(path) == make_grant()


def test_load_grant_rejects_symlink_directory_fifo_missing_and_oversize(tmp_path):
    real = tmp_path / "grant.json"
    real.write_bytes(_bytes())
    link = tmp_path / "link.json"
    link.symlink_to(real)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (MAX_GRANT_BYTES + 1))
    for path in (link, tmp_path, fifo, tmp_path / "missing.json", big):
        with pytest.raises(AegisError) as info:
            load_grant(path)
        assert info.value.code is ErrorCode.INVALID_REQUEST
        assert str(tmp_path) not in info.value.message


def test_load_grant_accepts_path_strings(tmp_path: Path, make_grant):
    path = tmp_path / "grant.json"
    path.write_bytes(_bytes())
    assert load_grant(str(path)) == make_grant()


@pytest.mark.parametrize("value", ["true", "yes", "on", 1, "1"])
def test_existing_attack_lab_gate_opens_only_for_a_real_boolean(tmp_path, value):
    with pytest.raises(AegisError) as info:
        config_from_mapping({"attack_lab": {"enabled": value}}, base_dir=tmp_path)
    assert info.value.code is ErrorCode.CONFIG_INVALID
    assert config_from_mapping({"attack_lab": {"enabled": True}}, base_dir=tmp_path).attack_lab.enabled


def test_unknown_grant_keys_are_redacted_in_errors():
    data = grant_data()
    data["candidates"][0]["sk-hidden-key"] = 1
    with pytest.raises(AegisError) as info:
        parse_grant(_bytes(data))
    assert "sk-hidden-key" not in json.dumps(info.value.details)
    assert info.value.details["errors"][0]["loc"] == "candidates.0.<unknown>"


def test_legacy_grant_identity_is_preserved_for_the_persistent_ledger(make_grant):
    import hashlib

    grant = make_grant()
    legacy = grant.model_dump(mode="json")
    for candidate in legacy["candidates"]:
        candidate.pop("compilation_bundle_sha256")
    expected = hashlib.sha256(json.dumps(legacy, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=False).encode()).hexdigest()
    assert grant_sha256(grant) == expected


def test_bundle_digest_is_strict_and_changes_grant_identity(make_grant):
    data = make_grant().model_dump()
    data["candidates"][0]["compilation_bundle_sha256"] = "a" * 64
    from aegis_core.lab_authorization import CandidateExecutionGrant

    assert grant_sha256(CandidateExecutionGrant.model_validate(data)) != grant_sha256(make_grant())
    for invalid in ("ABC", "g" * 64, 123, True):
        data["candidates"][0]["compilation_bundle_sha256"] = invalid
        with pytest.raises(ValidationError):
            CandidateExecutionGrant.model_validate(data)
