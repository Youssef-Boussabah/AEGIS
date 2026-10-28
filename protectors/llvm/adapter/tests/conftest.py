"""Real LLVM adapter integration suite; no fake protection backend."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aegis_core.config import config_from_mapping
from aegis_core.models import ProtectionPolicy
from aegis_core.orchestrator import Orchestrator


def pytest_addoption(parser):
    parser.addoption("--shield-plugin", default="/tmp/aegis-adapter-build/AegisShield.so")
    parser.addoption("--shield-opt", default=shutil.which("opt"))
    parser.addoption("--shield-clang", default=shutil.which("clang"))


@pytest.fixture(scope="session")
def tools(request):
    paths = tuple(request.config.getoption(name) for name in
                  ("--shield-plugin", "--shield-opt", "--shield-clang"))
    if any(not path or not Path(path).is_file() for path in paths):
        pytest.fail("Build Shield and supply --shield-plugin, --shield-opt and --shield-clang")
    return tuple(str(Path(path).absolute()) for path in paths)


@pytest.fixture(scope="session")
def trusted_ir(tools, tmp_path_factory):
    # Compile only the repository-owned source fixture. The adapter itself
    # accepts IR and never invokes clang or executes a native artifact.
    source = ROOT.parent / "tests/fixtures/annotated.c"
    dest = tmp_path_factory.mktemp("trusted-ir") / "annotated.ll"
    subprocess.run([tools[2], "-O1", "-S", "-emit-llvm", str(source), "-o", str(dest)],
                   check=True, capture_output=True, timeout=30)
    return dest.read_bytes()


@pytest.fixture
def command(tools):
    return [sys.executable, str(ROOT / "aegis_llvm_adapter.py"),
            "--opt", tools[1], "--plugin", tools[0]]


@pytest.fixture
def make_job(tmp_path, command, trusted_ir):
    def make(*, data=None, options=None, name="fixture.ll", extra=(), timeout=30,
             root=None, cmd=None):
        root = root or tmp_path / "store"
        config = config_from_mapping({"storage": {"root": str(root)}, "adapters": {
            "llvm-shield": {"command": [*(cmd or command), *extra], "timeout_seconds": timeout}}},
            base_dir=tmp_path)
        core = Orchestrator(config)
        job = core.submit(ProtectionPolicy(backend="llvm-shield", options=options or {}),
                          data=trusted_ir if data is None else data, name=name)
        return core, job
    return make


@pytest.fixture
def direct(tmp_path, command, trusted_ir):
    """Exercise malformed wire requests unreachable through typed core models."""
    job_id = "a" * 32
    job = tmp_path / job_id
    for name in ("work", "inputs", "outputs", "adapter"):
        (job / name).mkdir(parents=True)
    source = job / "inputs/fixture.ll"
    source.write_bytes(trusted_ir)
    request = {"protocol": "aegis.adapter.v1", "job_id": job_id, "task": "protect",
               "backend": "llvm-shield", "policy_name": "default", "input_path": str(source),
               "input_sha256": hashlib.sha256(trusted_ir).hexdigest(),
               "output_dir": str(job / "outputs"), "options": {}, "authorization": None}

    def invoke(update=None, *, raw=None):
        payload = {**request, **(update or {})}
        path = job / "adapter/request.json"
        path.write_text(raw if raw is not None else json.dumps(payload))
        proc = subprocess.run([*command, "--aegis-request", str(path)], cwd=job / "work",
                              capture_output=True, timeout=30)
        assert proc.returncode == 0, proc.stderr.decode()
        return json.loads(proc.stdout)
    return invoke, job, request


@pytest.fixture
def wrapper(tmp_path, tools):
    """Fault injection around real opt. Never synthesize a success report."""
    def make(body):
        path = tmp_path / "opt-wrapper"
        path.write_text(f"#!{sys.executable}\n"
                        "import json, os, pathlib, signal, subprocess, sys, time\n"
                        f"real_opt = {tools[1]!r}\n"
                        "if '--version' in sys.argv:\n"
                        "    os.execv(real_opt, [real_opt, *sys.argv[1:]])\n"
                        f"{body}\n")
        path.chmod(0o755)
        return str(path)
    return make
