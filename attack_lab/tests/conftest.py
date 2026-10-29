"""Offline is explicit; integration refuses missing dependencies and skips."""
import importlib
import os
import shutil
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--lab-profile", choices=("offline", "integration"), default="offline")


def pytest_configure(config):
    if config.getoption("--lab-profile") != "integration":
        return
    missing = []
    for module in ("aegis_core.lab_execution", "aegis_core.lab_ledger"):
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    headless = os.environ.get("AEGIS_GHIDRA_HEADLESS", "")
    if not headless or not Path(headless).is_file() or not os.access(headless, os.X_OK):
        missing.append("AEGIS_GHIDRA_HEADLESS executable")
    for tool in ("cc", "nm"):
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        raise pytest.UsageError("strict Lab integration prerequisites missing: " + ", ".join(missing))


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    profile = config.getoption("--lab-profile")
    terminalreporter.write_line(f"Lab profile: {profile}; skipped tests are NOT RUN")


def pytest_sessionfinish(session, exitstatus):
    if session.config.getoption("--lab-profile") == "integration" and session.testscollected:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter and reporter.stats.get("skipped"):
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
