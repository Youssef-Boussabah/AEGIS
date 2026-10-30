from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_core.config import load_config
from aegis_core.models import AttackLabAuthorization, ProtectionPolicy, TaskKind
from aegis_core.orchestrator import Orchestrator
from aegis_core.testing import FAKE_BACKEND, write_test_config
from lab_fixtures import grant_data


@pytest.fixture
def make_orchestrator(tmp_path: Path):
    def factory(**config_kwargs) -> Orchestrator:
        return Orchestrator(load_config(write_test_config(tmp_path, **config_kwargs)))

    return factory


@pytest.fixture
def orchestrator(make_orchestrator) -> Orchestrator:
    return make_orchestrator()


@pytest.fixture
def input_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF fake binary for tests")
    return path


@pytest.fixture
def policy():
    """Build policies through pytest's directory-scoped fixture lookup."""
    def factory(mode: str = "ok", **kwargs) -> ProtectionPolicy:
        options = {"mode": mode, **kwargs.pop("options", {})}
        return ProtectionPolicy(backend=kwargs.pop("backend", FAKE_BACKEND), options=options, **kwargs)

    return factory


@pytest.fixture
def attack_policy(policy):
    def factory(mode: str = "attack", **kwargs) -> ProtectionPolicy:
        auth = kwargs.pop(
            "authorization",
            AttackLabAuthorization(
                authorized_by="security-lead", reference="ENG-42", scope="sample.bin only"
            ),
        )
        return policy(mode, task=TaskKind.ATTACK_LAB, authorization=auth, **kwargs)

    return factory


# ------------------------------------------------------- candidate execution

@pytest.fixture
def make_grant():
    from aegis_core.lab_authorization import CandidateExecutionGrant

    def factory(**overrides) -> CandidateExecutionGrant:
        return CandidateExecutionGrant.model_validate_json(json.dumps(grant_data(**overrides)))

    return factory


@pytest.fixture
def lab_config(tmp_path: Path):
    """Config with all three operator-side gates open (attack lab + candidate execution)."""

    def factory(*, attack_lab: bool = True, candidate_execution: bool = True):
        return load_config(
            write_test_config(
                tmp_path,
                attack_lab_enabled=attack_lab,
                candidate_execution_enabled=candidate_execution,
            )
        )

    return factory
