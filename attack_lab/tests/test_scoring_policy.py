"""Phase 4: sandbox policy, scorer identity and candidate-execution authorization."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from scoring_fixtures import digest, gvisor_policy, policy_data, make_policy

from aegis_lab.safe_io import LoadError
from aegis_lab.scoring_policy import (
    SCORER_IMPLEMENTATION_FILES,
    ExecutionRefused,
    load_policy,
    parse_policy,
    planned_scorer_tool,
    scorer_configuration_sha256,
    scorer_implementation_sha256,
)


def test_policy_round_trip_and_fingerprint(tmp_path):
    policy = make_policy()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy.model_dump(mode="json")))
    assert load_policy(path) == policy
    assert len(policy.sha256()) == 64
    assert make_policy(**{"execute.wall_ms": 2001}).sha256() != policy.sha256()
    assert gvisor_policy().sha256() != policy.sha256()


@pytest.mark.parametrize("changes", [
    {"runtime.executable_sha256": digest("x")},
    {"runtime.platform": "systrap"},
    {"runtime.resource_controller": "systemd-user-scope-cgroup-v2"},
    {"runtime.rootless": True},
])
def test_test_double_runtime_must_be_inert(changes):
    with pytest.raises(ValidationError) as caught:
        make_policy(**changes)
    assert "aegis_runtime_inconsistent" in {e["type"] for e in caught.value.errors()}


@pytest.mark.parametrize("changes", [
    {"runtime.executable_sha256": None},
    {"runtime.platform": "none"},
    {"runtime.rootless": False},
    {"runtime.resource_controller": "none"},
])
def test_gvisor_runtime_requires_enforcement_fields(changes):
    data = gvisor_policy().model_dump(mode="json")
    for path, value in changes.items():
        data["runtime"][path.split(".")[1]] = value
    with pytest.raises(ValidationError):
        type(gvisor_policy()).model_validate(data)


@pytest.mark.parametrize("field,value", [
    ("runtime.network", "host"),
    ("runtime.sandbox_per_case", "shared"),
    ("runtime.environment", "inherit"),
    ("execute.memory_bytes", 2**20),
    ("execute.wall_ms", 0),
    ("execute.stdout_bytes", 0),
    ("execute.max_processes", True),
    ("compile.binary_bytes", 2**30),
    ("max_cases", 5000),
    ("compiler.executable", "/home/user/gcc"),
    ("compiler.executable", "gcc"),
    ("compiler.name", "tcc"),
])
def test_policy_bounds(field, value):
    with pytest.raises(ValidationError):
        make_policy(**{field: value})


@pytest.mark.parametrize("flag", ["-B/tmp", "-fplugin=/tmp/x.so", "-o", "@args", "-I/home", "-L/x", "-specs=x",
                                  "-wrapper", "-x", "-Wl,-rpath,/x", "-include/etc/passwd", "-std=gnu11", "-O9",
                                  "-Werror=A", " -O1"])
def test_compiler_flags_are_an_allowlist(flag):
    with pytest.raises(ValidationError):
        make_policy(**{"compiler.flags": ["-std=c11", flag]})


def test_compiler_flags_need_c11_and_no_duplicates():
    with pytest.raises(ValidationError):
        make_policy(**{"compiler.flags": ["-O1"]})
    with pytest.raises(ValidationError):
        make_policy(**{"compiler.flags": ["-std=c11", "-O1", "-O1"]})
    accepted = make_policy(**{"compiler.flags": ["-std=c11", "-O2", "-fwrapv", "-Werror=implicit-int"]})
    assert accepted.compile_argv(output="candidate", sources=("a.c", "b.c")) == (
        "/usr/bin/gcc", "-std=c11", "-O2", "-fwrapv", "-Werror=implicit-int", "-o", "candidate", "a.c", "b.c")


def test_policy_parsing_is_strict():
    data = json.dumps(policy_data()).encode()
    assert parse_policy(data) == make_policy()
    with pytest.raises(LoadError):
        parse_policy(b'{"schema_version": 1, "schema_version": 2}')
    with pytest.raises(LoadError):
        parse_policy(b" " * (64 * 1024 + 1))
    with pytest.raises(ValidationError):
        parse_policy(json.dumps({**policy_data(), "extra": 1}).encode())


def test_scorer_identity_binds_policy_and_implementation():
    policy = make_policy()
    tool = planned_scorer_tool(policy)
    assert tool.name == "aegis-lab-behavior-scorer" and tool.version == "aegis.lab.behavior-score.v1"
    assert tool.executable_sha256 == scorer_implementation_sha256()
    assert tool.configuration_sha256 == scorer_configuration_sha256(policy)
    assert planned_scorer_tool(make_policy(**{"execute.cpu_ms": 999})).configuration_sha256 != \
        tool.configuration_sha256
    assert {"behavior_score.py", "scoring_worker.py", "core_execution.py"} <= set(SCORER_IMPLEMENTATION_FILES)


def test_execution_refusal_codes_are_registered():
    refused = ExecutionRefused("core_refused", ("grant_expired",))
    assert refused.reasons == ("grant_expired",) and "grant_expired" in str(refused)
    with pytest.raises(AssertionError):
        ExecutionRefused("made_up")
    # The Lab keeps no execution permission of its own: there is no Lab authorization contract.
    import aegis_lab.scoring_policy as module

    assert not hasattr(module, "CandidateExecutionAuthorization")
    assert not hasattr(module, "check_execution_authorization")


def test_isolated_runtime_pins_runtime_and_rootfs_digests():
    policy = gvisor_policy()
    assert policy.runtime.rootfs_sha256 is not None and policy.runtime.executable_sha256 is not None
    with pytest.raises(ValidationError):
        make_policy(**{"runtime.rootfs_sha256": digest("rootfs")})


def test_firecracker_runtime_pins_every_guest_identity():
    from scoring_fixtures import firecracker_policy

    policy = firecracker_policy()
    assert policy.runtime.platform == "kvm" and policy.runtime.guest_agent_sha256 is not None
    for field in ("guest_kernel_sha256", "guest_agent_sha256", "containment_verification_sha256",
                  "rootfs_sha256", "executable_sha256"):
        data = policy.model_dump(mode="json")
        data["runtime"][field] = None
        with pytest.raises(ValidationError):
            type(policy).model_validate(data)
    data = policy.model_dump(mode="json")
    data["runtime"]["platform"] = "systrap"
    with pytest.raises(ValidationError):
        type(policy).model_validate(data)


def test_gvisor_runtime_has_no_guest_kernel_or_agent():
    for field in ("guest_kernel_sha256", "guest_agent_sha256"):
        data = gvisor_policy().model_dump(mode="json")
        data["runtime"][field] = digest("x")
        with pytest.raises(ValidationError):
            type(gvisor_policy()).model_validate(data)
    data = gvisor_policy().model_dump(mode="json")
    data["runtime"]["containment_verification_sha256"] = digest("report")
    assert type(gvisor_policy()).model_validate(data).runtime.containment_verification_sha256 == digest("report")


def test_test_double_runtime_pins_nothing():
    for field in ("guest_kernel_sha256", "guest_agent_sha256", "containment_verification_sha256"):
        with pytest.raises(ValidationError):
            make_policy(**{f"runtime.{field}": digest("x")})


def test_enforced_limits_model_is_strict():
    from aegis_lab.scoring_worker import EnforcedLimits, HostEnforcementObservation

    good = {"memory_max_bytes": 300 * 2**20, "memory_swap_max_bytes": 0, "pids_max": 16, "cpu_quota_us": 100_000,
            "cpu_period_us": 100_000, "vm_memory_mib": 200, "vcpu_count": 1,
            "block_bandwidth_bytes_per_s": 2**20, "block_ops_per_s": 10}
    limits = EnforcedLimits.model_validate(good)
    assert limits.covers(make_policy().execute) and not EnforcedLimits.model_validate(
        {**good, "vm_memory_mib": 16, "memory_max_bytes": 16 * 2**20}).covers(make_policy().execute)
    for bad in ({"memory_swap_max_bytes": 1}, {"memory_max_bytes": 2**20}, {"cpu_quota_us": 200_001},
                {"pids_max": 0}, {"vcpu_count": True}, {"extra": 1}):
        with pytest.raises(ValidationError):
            EnforcedLimits.model_validate({**good, **bad})
    observed = HostEnforcementObservation(enforced=limits, accounting={"host_cpu_usec": 1,
                                            "host_memory_peak_bytes": 2**40, "host_oom_kills": 1})
    assert observed.accounting.host_memory_peak_bytes > observed.enforced.memory_max_bytes
    for bad_peak in (-1, True, "1"):
        with pytest.raises(ValidationError):
            HostEnforcementObservation(enforced=limits, accounting={"host_cpu_usec": 1,
                                            "host_memory_peak_bytes": bad_peak, "host_oom_kills": 0})
