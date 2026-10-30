"""Shared data for the candidate-execution tests (imported by conftest and tests)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

LAB_NOW = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)
CANDIDATE_A = b"unsigned aegis_f(unsigned a) { return a + 1u; }\n"
CANDIDATE_B = b"unsigned aegis_f(unsigned a) { return a * 2u; }\n"
TARGET_BASE = "1" * 64
TARGET_PROT = "2" * 64
ID_A = "a" * 32
ID_B = "b" * 32


def bind_bundle(grant, files=None, units=None):
    """Reviewed fixture bundle for candidate A; never inferred from a stage call."""
    from aegis_core.lab_authorization import CandidateExecutionGrant, compilation_bundle_sha256

    files = files if files is not None else {
        "candidate.c": CANDIDATE_A, "aegis_harness.c": b"int main(void) { return 0; }\n"}
    units = units if units is not None else ["candidate.c", "aegis_harness.c"]
    data = grant.model_dump()
    next(c for c in data["candidates"] if c["candidate_id"] == ID_A)["compilation_bundle_sha256"] = compilation_bundle_sha256(files, units)
    return CandidateExecutionGrant.model_validate(data)


def lab_bindings_data() -> dict:
    return {
        "pair_id": "c" * 32,
        "hidden_test_suite_sha256": "3" * 64,
        "sandbox_policy_sha256": "4" * 64,
        "scorer_configuration_sha256": "5" * 64,
    }


def compile_limits_data(**overrides) -> dict:
    data = {
        "wall_ms": 30_000,
        "cpu_ms": 30_000,
        "memory_bytes": 512 * 1024 * 1024,
        "max_processes": 32,
        "scratch_bytes": 64 * 1024 * 1024,
        "stdout_bytes": 1024 * 1024,
        "stderr_bytes": 64 * 1024,
        "binary_bytes": 4 * 1024 * 1024,
    }
    data.update(overrides)
    return data


def execute_limits_data(**overrides) -> dict:
    data = {
        "wall_ms": 2_000,
        "cpu_ms": 2_000,
        "memory_bytes": 64 * 1024 * 1024,
        "max_processes": 4,
        "scratch_bytes": 4 * 1024 * 1024,
        "stdout_bytes": 4096,
        "stderr_bytes": 4096,
    }
    data.update(overrides)
    return data


def grant_data(**overrides) -> dict:
    """A valid grant as JSON-compatible data: two candidates, compile and execute."""
    data = {
        "schema_version": "aegis.core.candidate-execution-grant.v1",
        "grant_id": "d" * 32,
        "authorization": {
            "authorized_by": "security-lead",
            "reference": "ENG-42",
            "scope": "paired reconstruction trial, candidates listed in this grant only",
            "attested_at": "2026-10-29T09:00:00Z",
            "expires_at": "2026-11-05T00:00:00Z",
        },
        "permitted_targets": [TARGET_BASE, TARGET_PROT],
        "candidates": [
            {
                "candidate_id": ID_A,
                "candidate_sha256": hashlib.sha256(CANDIDATE_A).hexdigest(),
                "target_sha256": TARGET_BASE,
            },
            {
                "candidate_id": ID_B,
                "candidate_sha256": hashlib.sha256(CANDIDATE_B).hexdigest(),
                "target_sha256": TARGET_PROT,
            },
        ],
        "stages": ["compile", "execute"],
        "compile_flags": ["-std=c11", "-O2", "-static"],
        "compile_limits": compile_limits_data(),
        "execute_limits": execute_limits_data(),
        "max_compilations_per_candidate": 1,
        "max_executions_per_candidate": 3,
        "max_total_wall_ms": 120_000,
        "lab_bindings": lab_bindings_data(),
        "valid_from": "2026-10-29T10:00:00Z",
        "expires_at": "2026-10-30T10:00:00Z",
    }
    data.update(overrides)
    return data
