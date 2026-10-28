from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.config import load_config
from aegis_core.models import AttackLabAuthorization, ProtectionPolicy, TaskKind
from aegis_core.orchestrator import Orchestrator
from aegis_core.testing import FAKE_BACKEND, write_test_config


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


def policy(mode: str = "ok", **kwargs) -> ProtectionPolicy:
    options = {"mode": mode, **kwargs.pop("options", {})}
    return ProtectionPolicy(backend=kwargs.pop("backend", FAKE_BACKEND), options=options, **kwargs)


def attack_policy(mode: str = "attack", **kwargs) -> ProtectionPolicy:
    auth = kwargs.pop(
        "authorization",
        AttackLabAuthorization(
            authorized_by="security-lead", reference="ENG-42", scope="sample.bin only"
        ),
    )
    return policy(mode, task=TaskKind.ATTACK_LAB, authorization=auth, **kwargs)
