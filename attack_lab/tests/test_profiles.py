"""The strict profile must refuse missing prerequisites before test collection."""
import os
import subprocess
import sys
from pathlib import Path


def test_strict_profile_refuses_missing_ghidra():
    env = dict(os.environ)
    env.pop("AEGIS_GHIDRA_HEADLESS", None)
    result = subprocess.run([sys.executable, "-m", "pytest", "attack_lab/tests/test_canonical.py",
                             "--lab-profile", "integration", "--collect-only", "-q"],
                            cwd=Path(__file__).resolve().parents[2], env=env, capture_output=True, timeout=30)
    assert result.returncode == 4
    assert b"strict Lab integration prerequisites missing" in result.stderr
    assert b"AEGIS_GHIDRA_HEADLESS executable" in result.stderr
