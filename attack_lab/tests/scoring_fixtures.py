"""Shared Phase 4 test fixtures. Nothing here compiles or executes candidate code.

Experiments are produced by the real Phase 3B runner (``run_paired_trial``) with the
offline ``FakeProvider``; Ghidra reports come from the offline fake launcher.

Execution goes through Core's real ``CandidateExecutionSession`` with real gates and
grants. The runtime is Core's non-executing ``ScriptedIsolationRuntime``, scripted here
by ``scripted``: candidate behavior is a trusted Python model, and every record says
``test_double``. These fixtures need an ``aegis_core`` that provides ``lab_execution``
(Role A, feat/core-lab-execution).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from test_paired_trial import SEED_BASELINE_FIRST, Factory, build_pair, prepared

from aegis_lab.fake_provider import FakeProvider
from aegis_lab.hidden_suite import SuiteReference, build_hidden_suite, serialize_suite, suite_sha256
from aegis_lab.manifest import ToolIdentity
from aegis_lab.paired_trial import RECONSTRUCTION_FILES, run_paired_trial
from aegis_lab.scoring_policy import SandboxPolicy, planned_scorer_tool, scorer_configuration_sha256

INTERFACE = "pixel(uint32_t, uint32_t, uint32_t)->uint32_t"
SYMBOL = "target_function"  # the blinded task label; the fixtures' manifests withhold symbols
MASK = 0xFFFFFFFF


def reference(a: int, b: int, c: int) -> int:
    """Trusted reference model of the hidden function (never candidate code)."""
    return ((a * 3) + (b ^ c) + 0x9E3779B9) & MASK


ARGUMENTS = [(0, 0, 0), (1, 2, 3), (MASK, MASK, MASK), (255, 128, 64), (0xDEAD, 0xBEEF, 0xF00D),
             (7, 0, MASK), (123456789, 987654321, 42), (2**31, 2**31 - 1, 1)]

BASELINE_SOURCE = ("#include <stdint.h>\nuint32_t target_function(uint32_t a, uint32_t b, uint32_t c) "
                   "{ return a * 3u + (b ^ c) + 0x9E3779B9u; }\n")
PROTECTED_SOURCE = ("#include <stdint.h>\nuint32_t target_function(uint32_t a, uint32_t b, uint32_t c) "
                    "{ return a * 3u + (b | c); }\n")

FIXED_NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def policy_data(**changes) -> dict:
    data = {
        "schema_version": "aegis.lab.sandbox-policy.v1",
        "runtime": {"name": "aegis-test-double", "version": "1", "executable_sha256": None, "rootfs_sha256": None,
                    "guest_kernel_sha256": None, "guest_agent_sha256": None,
                    "containment_verification_sha256": None, "platform": "none",
                    "rootless": False, "network": "none", "resource_controller": "none",
                    "sandbox_per_compilation": "fresh", "sandbox_per_case": "fresh", "environment": "empty",
                    "filesystem_layout": "aegis.lab.sandbox-filesystem.v1"},
        "compiler": {"name": "gcc", "version": "16.2.1", "executable": "/usr/bin/gcc",
                     "executable_sha256": digest("gcc"), "flags": ["-std=c11", "-O1", "-static"]},
        "compile": {"wall_ms": 30000, "cpu_ms": 20000, "memory_bytes": 512 * 2**20, "max_processes": 64,
                    "scratch_bytes": 64 * 2**20, "stdout_bytes": 65536, "stderr_bytes": 65536,
                    "binary_bytes": 8 * 2**20},
        "execute": {"wall_ms": 2000, "cpu_ms": 1000, "memory_bytes": 64 * 2**20, "max_processes": 1,
                    "scratch_bytes": 1 * 2**20, "stdout_bytes": 4096, "stderr_bytes": 65536},
        "max_cases": 4096,
        "max_total_wall_ms": 600000,
    }
    for path, value in changes.items():
        node = data
        *parents, last = path.split(".")
        for part in parents:
            node = node[part]
        node[last] = value
    return data


def make_policy(**changes) -> SandboxPolicy:
    return SandboxPolicy.model_validate(policy_data(**changes))


def gvisor_policy() -> SandboxPolicy:
    return make_policy(**{"runtime.name": "gvisor-runsc", "runtime.version": "release-20261001.0",
                          "runtime.executable_sha256": digest("runsc"), "runtime.rootfs_sha256": digest("rootfs"),
                          "runtime.platform": "systrap",
                          "runtime.rootless": True, "runtime.resource_controller": "systemd-user-scope-cgroup-v2"})


def firecracker_policy() -> SandboxPolicy:
    return make_policy(**{"runtime.name": "firecracker", "runtime.version": "firecracker-1.12.0",
                          "runtime.executable_sha256": digest("firecracker"), "runtime.rootfs_sha256": digest("rootfs"),
                          "runtime.guest_kernel_sha256": digest("vmlinux"),
                          "runtime.guest_agent_sha256": digest("agent"),
                          "runtime.containment_verification_sha256": digest("containment-report"),
                          "runtime.platform": "kvm", "runtime.rootless": True,
                          "runtime.resource_controller": "systemd-user-scope-cgroup-v2"})


def firecracker_attestation(policy: SandboxPolicy, **changes):
    """What Core's Firecracker backend attests, built from a Firecracker policy (tests only)."""
    r = policy.runtime
    data = {"runtime": "firecracker", "runtime_version": r.version, "runtime_sha256": r.executable_sha256,
            "platform": "kvm", "rootless": True, "network": "none", "rootfs_sha256": r.rootfs_sha256,
            "guest_kernel_sha256": r.guest_kernel_sha256, "guest_agent_sha256": r.guest_agent_sha256,
            "containment_verification_sha256": r.containment_verification_sha256,
            "limits_enforcement": "verified_by_cgroup_readback", "isolation_verified": True}
    data.update(changes)
    return attestation_for(policy, **data)


def host_enforcement_for(limits, *, guest_overhead_mib: int = 128, vmm_overhead_mib: int = 64,
                         vcpu_count: int = 1, **changes) -> dict:
    """Host enforcement as Core's Firecracker plan derives it from requested limits (tests only)."""
    import math

    vm_mib = math.ceil((limits.memory_bytes + limits.scratch_bytes) / 2**20) + guest_overhead_mib
    data = {"memory_max_bytes": (vm_mib + vmm_overhead_mib) * 2**20, "memory_swap_max_bytes": 0,
            "pids_max": 16, "cpu_quota_us": 100_000 * vcpu_count, "cpu_period_us": 100_000,
            "vm_memory_mib": vm_mib, "vcpu_count": vcpu_count, "block_bandwidth_bytes_per_s": 64 * 2**20,
            "block_ops_per_s": 2000, "host_cpu_usec": 1234, "host_memory_peak_bytes": 40 * 2**20,
            "host_oom_kills": 0}
    data.update(changes)
    return data


def suite_bytes(*, interface: str = INTERFACE, arguments=None, function=reference, suite_id: str = "5" * 32) -> bytes:
    ref = SuiteReference(method="frozen_reference_outputs", reference_implementation_sha256=digest("reference"),
                         generator=ToolIdentity(name="aegis-suite-builder", version="1",
                                                executable_sha256=digest("builder"),
                                                configuration_sha256=digest("builder-config")),
                         frozen_at=datetime(2026, 10, 1, tzinfo=UTC))
    suite = build_hidden_suite(suite_id=suite_id, interface=interface, reference=ref,
                               argument_sets=list(arguments or ARGUMENTS), reference_function=function)
    return serialize_suite(suite)


def scoring_overrides(policy: SandboxPolicy, suite: bytes, interface: str = INTERFACE) -> dict:
    return {"scoring.expected_interface": interface, "scoring.hidden_test_suite_sha256": suite_sha256(suite),
            "scoring.scorer": planned_scorer_tool(policy).model_dump(mode="json")}


def experiment(tmp_path: Path, *, baseline_source: str = BASELINE_SOURCE, protected_source: str = PROTECTED_SOURCE,
               policy: SandboxPolicy | None = None, suite: bytes | None = None, interface: str = INTERFACE,
               providers=None, **pair_kwargs) -> dict:
    """A published Phase 3B experiment whose manifests declare this suite, interface and scorer."""
    policy = policy or make_policy()
    suite = suite if suite is not None else suite_bytes(interface=interface)
    both = {**scoring_overrides(policy, suite, interface), **pair_kwargs.pop("both", {})}
    fx = build_pair(tmp_path, both=both, **pair_kwargs)
    pair = prepared(fx)
    if providers is None:
        providers = (FakeProvider(source=baseline_source), FakeProvider(source=protected_source))
    out = tmp_path / "experiment"
    run_paired_trial(pair, out, order_seed=SEED_BASELINE_FIRST, provider_factory=Factory(*providers))
    fx.update(experiment=out, policy=policy, suite=suite, interface=interface)
    return fx


def reconstruction_bytes(fx: dict, variant: str) -> bytes:
    return (fx["experiment"] / RECONSTRUCTION_FILES[variant]).read_bytes()


def candidate_digest(fx: dict, variant: str) -> str:
    from aegis_lab.reconstruction import parse_reconstruction_record

    return parse_reconstruction_record(reconstruction_bytes(fx, variant)).candidate.sha256


# --- Core configuration, grants and the scripted runtime ------------------------------------------

def core_config(tmp_path: Path, *, attack_lab: bool = True, candidate_execution: bool = True):
    from aegis_core.config import config_from_mapping

    tmp_path.mkdir(parents=True, exist_ok=True)  # the store root (and Core's grant ledger) lives here
    return config_from_mapping({"attack_lab": {"enabled": attack_lab,
                                               "candidate_execution": {"enabled": candidate_execution}}},
                               base_dir=tmp_path)


def grant(fx: dict, *, variants=("baseline", "protected"), now: datetime | None = None, policy=None, **changes):
    """A Core grant built from the same reviewed decision as the Lab inputs.

    Every call gets a fresh ``grant_id`` unless one is given: Core's ledger binds an id to the
    first grant contents that used it, so logically independent grants must not share an id.
    """
    from aegis_core.lab_authorization import CandidateExecutionGrant

    now = now or datetime.now(UTC)
    policy = policy or fx["policy"]
    manifests = fx["manifests"]
    targets = []
    for v in variants:
        target = manifests[v].target.final_artifact_sha256
        if target not in targets:
            targets.append(target)
    data = {
        "schema_version": "aegis.core.candidate-execution-grant.v1",
        "grant_id": secrets.token_hex(16),
        "authorization": {"authorized_by": "lab-reviewer", "reference": manifests["baseline"].authorization.reference,
                          "scope": "Phase 4 test-double scoring of AEGIS-owned fixtures",
                          "attested_at": (now - timedelta(hours=2)).isoformat(),
                          "expires_at": (now + timedelta(days=2)).isoformat()},
        "permitted_targets": targets,
        "candidates": [{"candidate_id": manifests[v].trial_id, "candidate_sha256": candidate_digest(fx, v),
                        "target_sha256": manifests[v].target.final_artifact_sha256} for v in variants],
        "stages": ["compile", "execute"],
        "compile_flags": list(policy.compiler.flags),
        "compile_limits": policy.compile.model_dump(),
        "execute_limits": policy.execute.model_dump(),
        "max_compilations_per_candidate": 1,
        "max_executions_per_candidate": len(ARGUMENTS),
        "max_total_wall_ms": 2 * (policy.compile.wall_ms + len(ARGUMENTS) * policy.execute.wall_ms),
        "lab_bindings": {"pair_id": manifests["baseline"].pair_id,
                         "hidden_test_suite_sha256": suite_sha256(fx["suite"]),
                         "sandbox_policy_sha256": policy.sha256(),
                         "scorer_configuration_sha256": scorer_configuration_sha256(policy)},
        "valid_from": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    for path, value in changes.items():
        node = data
        *parents, last = path.split(".")
        for part in parents:
            node = node[int(part)] if isinstance(node, list) else node[part]
        node[last] = value
    return CandidateExecutionGrant.model_validate(data)


def attestation_for(policy: SandboxPolicy, **changes):
    from aegis_core.lab_execution import RuntimeAttestation

    data = {"runtime": "test_double", "runtime_version": policy.runtime.version, "runtime_sha256": None,
            "platform": "none", "rootless": False, "network": "none", "rootfs_sha256": None,
            "compiler_name": policy.compiler.name, "compiler_version": policy.compiler.version,
            "compiler_sha256": policy.compiler.executable_sha256,
            "limits_enforcement": "not_enforced_test_double", "isolation_verified": False}
    data.update(changes)
    return RuntimeAttestation.model_validate(data)


def to_core(observation, kind: str, enforcement=None):
    """Convert a Lab observation into the Core observation a runtime returns. Anything else passes through.

    ``enforcement`` (a dict of Core ``HostEnforcement`` fields, or None) is attached as the
    runtime's ``host_enforcement`` observation.
    """
    from aegis_core.lab_execution import CompileObservation as CoreCompile
    from aegis_core.lab_execution import ExecuteObservation as CoreExecute
    from aegis_core.lab_execution import HostEnforcement

    from aegis_lab.scoring_worker import CompileObservation, ExecuteObservation

    host = None if enforcement is None else HostEnforcement.model_validate(enforcement)
    if kind == "execute" and type(observation) is ExecuteObservation:
        return CoreExecute(status=observation.status, exit_code=observation.exit_code, signal=observation.signal,
                           limit=observation.limit, stdout=observation.stdout,
                           stdout_truncated=observation.stdout_truncated, stderr=b"e" * observation.stderr_bytes,
                           duration_ms=1, host_enforcement=host)
    if kind == "compile" and type(observation) is CompileObservation:
        return CoreCompile(status=observation.status, exit_code=observation.exit_code, signal=observation.signal,
                           limit=observation.limit, stderr=observation.diagnostics,
                           stderr_truncated=observation.diagnostics_truncated, binary=observation.binary,
                           duration_ms=1, host_enforcement=host)
    return observation


def result_observation(value: int):
    """A clean exit whose stdout is exactly one result line, as the harness writes it."""
    from aegis_lab.scoring_worker import ExecuteObservation

    return ExecuteObservation(status="exited", exit_code=0, stdout=f"AEGIS-RESULT {value}\n".encode("ascii"))


SCRIPTED_BINARY = b"AEGIS scripted test double: not a compiled program\n"


def scripted(*, behavior=None, execute=None, compile=None, attestation=None, preflight_error=None,
             close_error=None, policy=None, enforcement=None):
    """Core's ScriptedIsolationRuntime driven by a trusted Python model. Never compiles or executes.

    ``execute(job)`` and ``compile(job)`` may return Lab observations (converted to Core's) or raise.
    ``enforcement(stage, job)`` returns the ``host_enforcement`` dict to attach, or None.
    """
    from aegis_core.testing.scripted_runtime import ScriptedIsolationRuntime

    from aegis_lab.scoring_worker import CompileObservation

    def host(stage, job):
        return None if enforcement is None else enforcement(stage, job)

    def run_execute(job):
        if execute is not None:
            return to_core(execute(job), "execute", host("execute", job))
        return to_core(result_observation(behavior(*(int(a) for a in job.args))), "execute", host("execute", job))

    def run_compile(job):
        if compile is None:
            return to_core(CompileObservation(status="exited", exit_code=0, binary=SCRIPTED_BINARY), "compile",
                           host("compile", job))
        result = compile(job) if callable(compile) else compile
        return to_core(result, "compile", host("compile", job))

    return ScriptedIsolationRuntime(compile=run_compile, execute=run_execute,
                                    attestation=attestation or attestation_for(policy or make_policy()),
                                    preflight_error=preflight_error, close_error=close_error)
