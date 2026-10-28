"""Basic health check shared by the API and CLI."""

from __future__ import annotations

import os
from typing import Literal

from . import __version__
from .adapter import resolve_executable
from .config import AegisConfig
from .models import AegisModel, TaskKind
from .storage import LocalArtifactStore


class BackendHealth(AegisModel):
    name: str
    tasks: list[TaskKind]
    available: bool


class HealthReport(AegisModel):
    status: Literal["ok", "degraded"]
    version: str
    storage_writable: bool
    storage_root: str | None = None
    attack_lab_enabled: bool
    backends: list[BackendHealth]
    problems: list[str]


def check_health(config: AegisConfig, *, include_paths: bool = True) -> HealthReport:
    store = LocalArtifactStore(config.storage.root, max_input_bytes=config.storage.max_input_bytes)
    problems: list[str] = []
    writable = store.is_writable()
    if not writable:
        problems.append("artifact store is not writable")
    backends = []
    path_env = os.environ.get("PATH", os.defpath)
    for name in config.supported_backends():
        spec = config.adapters[name]
        available = resolve_executable(spec.command[0], path_env) is not None
        if not available:
            problems.append(f"adapter executable for backend {name!r} is not available")
        backends.append(BackendHealth(name=name, tasks=spec.tasks, available=available))
    return HealthReport(
        status="ok" if not problems else "degraded",
        version=__version__,
        storage_writable=writable,
        storage_root=str(store.root) if include_paths else None,
        attack_lab_enabled=config.attack_lab.enabled,
        backends=backends,
        problems=problems,
    )
