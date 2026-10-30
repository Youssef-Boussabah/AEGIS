"""Final linked artifacts of the registered llvm-shield-mirage backend.

Runs the real combined adapter through Core, then compiles and links its IR
outputs. Only AEGIS-owned trusted sources run: the Mirage `signal.c` fixture
and ImageLab's own CLI/tests. No reconstruction candidate is compiled or run.
These checks observe output equality and symbol retention, not attack resistance.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from aegis_core.config import config_from_mapping
from aegis_core.models import JobStatus, ProtectionPolicy
from aegis_core.orchestrator import Orchestrator

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "protectors/llvm/adapter/aegis_shield_mirage_adapter.py"


def tool(name):
    found = shutil.which(name)
    assert found, f"Required native prerequisite missing: {name}"
    return str(Path(found).absolute())


def run(argv, cwd=None, timeout=120):
    return subprocess.check_output(list(map(str, argv)), cwd=cwd, stderr=subprocess.PIPE, timeout=timeout)


@pytest.fixture(scope="module")
def llvm():
    tools = {name: tool(name) for name in ("clang", "clang++", "opt", "llvm-link", "llvm-nm", "cmake", "ninja")}
    for name in ("clang", "opt", "llvm-link"):
        assert b"version 22." in run([tools[name], "--version"]), "Matching LLVM 22 required"
    return tools


def protect(store, llvm, plugin, data, options, name):
    command = [sys.executable, str(ADAPTER), "--opt", llvm["opt"], "--plugin", plugin,
               "--clang", llvm["clang"], "--llvm-link", llvm["llvm-link"]]
    core = Orchestrator(config_from_mapping({"storage": {"root": str(store)}, "adapters": {
        "llvm-shield-mirage": {"command": command, "timeout_seconds": 300}}}, base_dir=store.parent))
    job = core.submit(ProtectionPolicy(backend="llvm-shield-mirage", options=options), data=data, name=name)
    job = core.run(job.job_id)
    assert job.status == JobStatus.SUCCEEDED, job.error
    files = {a.name: core.store.artifact_path(a) for a in job.output_artifacts}
    return files, json.loads(files["mirage-report.json"].read_bytes())


def defined(llvm, executable):
    return set(run([llvm["llvm-nm"], "--defined-only", "--just-symbol-name", executable]).decode().split())


def test_owned_fixture_final_link_retention_and_controls(tmp_path, llvm, shield_plugin):
    source = ROOT / "protectors/mirage/tests/fixtures/signal.c"
    baseline = tmp_path / "input.ll"
    run([llvm["clang"], "-O1", "-S", "-emit-llvm", source, "-o", baseline])
    data = baseline.read_bytes()
    enabled, report = protect(tmp_path / "store", llvm, shield_plugin, data, {"seed": "42"}, "signal.ll")
    control, control_report = protect(tmp_path / "store", llvm, shield_plugin, data,
                                      {"seed": "42", "mirage-enabled": False}, "signal.ll")
    assert report["inserted_count"] == 3 and control_report["inserted_count"] == 0
    assert baseline.read_bytes() == data  # Core and the adapter never modify the input
    variants = {"baseline": baseline, "shield": enabled["shield-stage.ll"],
                "shield-mirage": enabled["protected.ll"], "mirage-disabled": control["protected.ll"]}
    outputs, symbols = {}, {}
    for name, ir in variants.items():
        executable = tmp_path / f"{name}.elf"
        run([llvm["clang"], "-O2", "-ffunction-sections", "-fdata-sections", ir,
             "-Wl,--gc-sections", "-o", executable])
        outputs[name] = run([executable])  # owned trusted fixture only
        symbols[name] = defined(llvm, executable)
    assert outputs["baseline"].strip() and len(set(outputs.values())) == 1
    for name in report["inserted_functions"]:
        assert name in symbols["shield-mirage"]
        assert all(name not in symbols[other] for other in ("baseline", "shield", "mirage-disabled"))
    assert (tmp_path / "shield-mirage.elf").stat().st_size > (tmp_path / "shield.elf").stat().st_size


def test_imagelab_final_link_retention_and_correctness(tmp_path, llvm, shield_plugin):
    build = tmp_path / "imagelab"
    common = ["-G", "Ninja", f"-DCMAKE_CXX_COMPILER={llvm['clang++']}", "-DCMAKE_BUILD_TYPE=Release",
              f"-DIMAGELAB_SHIELD_PLUGIN={shield_plugin}"]
    run([llvm["cmake"], "-S", ROOT / "demo/image_processor", "-B", build, *common], timeout=300)
    run([llvm["ninja"], "-C", build, "ir/kernels.input.ll"], timeout=300)
    kernels = (build / "ir/kernels.input.ll").read_bytes()
    files, report = protect(tmp_path / "store", llvm, shield_plugin, kernels,
                            {"seed": "42", "max-sites": 64}, "kernels.input.ll")
    shield = json.loads(files["shield-report.json"].read_bytes())
    assert shield["transformed_sites"] > 0 and report["inserted_count"] == 3
    external = tmp_path / "kernels.shield-mirage.ll"
    external.write_bytes(files["protected.ll"].read_bytes())
    run([llvm["cmake"], "-S", ROOT / "demo/image_processor", "-B", build, *common,
         f"-DIMAGELAB_EXTERNAL_KERNELS_IR={external}"], timeout=300)
    run([llvm["cmake"], "--build", build, "-j2"], timeout=600)
    # ImageLab's own suite: unit + reference tests for every variant, including
    # 'external' (Shield+Mirage), and the quick cross-variant output comparison.
    ctest = subprocess.run(["ctest", "--test-dir", str(build), "--output-on-failure"],
                           capture_output=True, text=True, timeout=600)
    assert ctest.returncode == 0, ctest.stdout[-4000:]
    assert "imagelab.reference.external" in ctest.stdout and "100% tests passed" in ctest.stdout
    fixture = ROOT / "demo/image_processor/tests/fixtures/gradient_17x9.pam"
    images = {}
    for variant in ("native", "shield", "external"):
        out = tmp_path / f"{variant}.pam"
        run([build / variant / "imagelab-cli", "enhance", fixture, out])
        images[variant] = out.read_bytes()
    assert images["native"] == images["shield"] == images["external"]
    retained = defined(llvm, build / "external/imagelab-cli")
    assert all(name in retained for name in report["inserted_functions"])
    assert not any(name in defined(llvm, build / "shield/imagelab-cli") for name in report["inserted_functions"])
