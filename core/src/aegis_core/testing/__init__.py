"""Test helpers. Not for production use.

The fake adapter in this package exercises the adapter protocol only; it performs
no protection and must never be registered as a real backend.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FAKE_BACKEND = "fake"


def fake_adapter_command() -> list[str]:
    return [sys.executable, "-m", "aegis_core.testing.fake_adapter"]


def write_test_config(
    directory: Path,
    *,
    attack_lab_enabled: bool = False,
    timeout_seconds: int = 30,
    tasks: tuple[str, ...] = ("protect", "attack_lab"),
    max_input_bytes: int = 1024 * 1024,
) -> Path:
    """Write an aegis.toml that registers the fake adapter as backend 'fake'."""
    command = ", ".join(json.dumps(arg) for arg in fake_adapter_command())
    task_list = ", ".join(json.dumps(t) for t in tasks)
    text = f"""\
[storage]
root = ".aegis"
max_input_bytes = {max_input_bytes}

[attack_lab]
enabled = {"true" if attack_lab_enabled else "false"}

[adapters.{FAKE_BACKEND}]
command = [{command}]
tasks = [{task_list}]
timeout_seconds = {timeout_seconds}
"""
    path = directory / "aegis.toml"
    path.write_text(text, encoding="utf-8")
    return path
