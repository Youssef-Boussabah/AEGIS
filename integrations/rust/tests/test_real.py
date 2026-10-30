"""Explicit real rustc -> Core -> Shield(+Mirage) -> Clang -> linker -> libtest suite."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

import protect

MODULE = Path(__file__).resolve().parents[1]


def capture_owned(root, extra_source=""):
    # Copy only our fixture, so Cargo never writes into the source tree.
    fixture = root / "component"
    shutil.copytree(MODULE / "fixtures/component", fixture)
    if extra_source:
        with (fixture / "src/lib.rs").open("a") as stream:
            stream.write(extra_source)
    capture = root / "invocation.json"
    cargo = protect.tool_path("cargo")
    # Resolve rustup explicitly while HOME still refers to the operator's home;
    # child stages run the concrete compiler without touching global toolchains.
    rustc = subprocess.run(["rustup", "which", "rustc"], check=True,
                           capture_output=True, text=True).stdout.strip()
    environment = {"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"],
                   "CARGO_TARGET_DIR": str(root / "target"), "CARGO_NET_OFFLINE": "true",
                   "RUSTC": rustc, "RUSTC_WRAPPER": str(MODULE / "capture.py"),
                   "AEGIS_RUST_CAPTURE": str(capture), "AEGIS_RUST_CRATE": "aegis_rust_component"}
    subprocess.run([cargo, "test", "--manifest-path", str(fixture / "Cargo.toml"),
                    "--release", "--lib", "--no-run", "--offline", "--locked"],
                   env=environment, check=True, timeout=60, capture_output=True)
    assert capture.is_file()
    return root, capture


@pytest.fixture(scope="module")
def owned_capture(tmp_path_factory):
    return capture_owned(tmp_path_factory.mktemp("rust-owned"))


@pytest.mark.parametrize("backend", ["llvm-shield", "llvm-shield-mirage"])
def test_owned_crate_end_to_end(owned_capture, rust_shield_plugin, backend):
    root, capture = owned_capture
    output = root / backend
    result = subprocess.run([sys.executable, str(MODULE / "protect.py"), "--invocation", str(capture),
                             "--output", str(output), "--plugin", str(rust_shield_plugin),
                             "--backend", backend, "--samples", "2"],
                            check=False, capture_output=True, text=True, timeout=120)
    record = json.loads((output / "run.json").read_text())
    assert result.returncode == 0, record.get("error")
    assert record["status"] == "succeeded" and record["tests"]["equivalent"]
    assert record["tests"]["baseline_passed"] and record["tests"]["original_matches_baseline"]
    assert record["shield"]["transformed_functions"] >= 2
    assert record["shield"]["transformed_sites"] >= 4
    shield = json.loads(Path(record["adapter_outputs"]["shield-report.json"]["path"]).read_text())
    owned_changed = [f for f in shield["functions"] if f["status"] == "transformed"
                     and "aegis_rust_component" in f["name"]]
    assert len(owned_changed) >= 2
    for runs in record["tests"]["observations"].values():
        assert all(r["counts"]["passed"] == 4 and r["counts"]["failed"] == 0 for r in runs)
    for artifact in record["adapter_outputs"].values():
        assert protect.digest(Path(artifact["path"])) == artifact["sha256"]
    assert record["artifacts"]["preopt_ir"]["sha256"] != record["adapter_outputs"]["protected.ll"]["sha256"]
    assert record["cargo_original"]["sha256"] == record["artifacts"]["original_binary"]["sha256"]
    if backend == "llvm-shield-mirage":
        report = json.loads(Path(record["adapter_outputs"]["mirage-report.json"]["path"]).read_text())
        assert report["inserted_count"] == 3
        assert report["input_sha256"] == record["adapter_outputs"]["shield-stage.ll"]["sha256"]
        assert report["output_sha256"] == record["adapter_outputs"]["protected.ll"]["sha256"]
        assert record["mirage_retention"]["retained"] == record["mirage_retention"]["expected"] == 3


def test_equal_failing_tests_remain_failed(tmp_path, rust_shield_plugin):
    root, capture = capture_owned(tmp_path, "\n#[test] fn deliberate_baseline_failure() { assert_eq!(1, 2); }\n")
    output = root / "failing-run"
    result = subprocess.run([sys.executable, str(MODULE / "protect.py"), "--invocation", str(capture),
                             "--output", str(output), "--plugin", str(rust_shield_plugin), "--samples", "1"],
                            check=False, capture_output=True, text=True, timeout=120)
    record = json.loads((output / "run.json").read_text())
    assert result.returncode == 1 and record["status"] == "failed"
    assert record["adapter_job"]["status"] == "succeeded"
    assert record["error"]["code"] == "BASELINE_TEST_FAILURE"
    assert record["tests"]["equivalent"] and not record["tests"]["baseline_passed"]
    assert record["tests"]["observations"]["protected"][0]["counts"]["failed"] == 1


def test_input_size_limit_stops_before_protection_job(owned_capture, tmp_path, rust_shield_plugin):
    _, capture = owned_capture
    output = tmp_path / "small-limit"
    result = subprocess.run([sys.executable, str(MODULE / "protect.py"), "--invocation", str(capture),
                             "--output", str(output), "--plugin", str(rust_shield_plugin),
                             "--max-input-bytes", "128", "--samples", "1"],
                            check=False, capture_output=True, text=True, timeout=120)
    record = json.loads((output / "run.json").read_text())
    assert result.returncode == 1 and record["error"]["code"] == "INPUT_TOO_LARGE"
    assert "adapter_job" not in record and "adapter_outputs" not in record
