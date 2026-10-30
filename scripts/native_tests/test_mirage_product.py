"""Real Mirage product smoke using explicit LLVM tools on PATH; missing tools fail."""
import hashlib
from pathlib import Path
import shutil
import subprocess

from aegis_mirage.transform import MirageConfig, transform

ROOT = Path(__file__).resolve().parents[2]


def tool(name):
    found = shutil.which(name)
    assert found, f"Required native smoke prerequisite missing: {name}"
    return found


def run(argv):
    return subprocess.check_output(list(map(str, argv)), stderr=subprocess.PIPE, timeout=30)


def test_owned_fixture_mirage_retention_and_disabled_control(tmp_path):
    clang, opt, link, nm = [tool(n) for n in ("clang", "opt", "llvm-link", "llvm-nm")]
    for executable in (clang, opt, link, nm):
        assert b"22." in run([executable, "--version"]), "Matching LLVM 22 required"
    original = tmp_path / "input.ll"
    run([clang, "-O1", "-S", "-emit-llvm", ROOT / "protectors/mirage/tests/fixtures/signal.c", "-o", original])
    enabled = transform(original, tmp_path / "enabled", MirageConfig(seed=42), clang=clang, opt=opt, llvm_link=link)
    disabled = transform(original, tmp_path / "disabled", MirageConfig(seed=42, enabled=False), clang=clang, opt=opt, llvm_link=link)
    assert enabled["inserted_count"] == 3 and disabled["inserted_count"] == 0
    assert (tmp_path / "disabled/module.ll").read_bytes() == original.read_bytes()
    outputs = []
    for variant in ("enabled", "disabled"):
        executable = tmp_path / variant / "fixture"
        run([clang, "-O2", "-ffunction-sections", "-fdata-sections", tmp_path / variant / "module.ll", "-Wl,--gc-sections", "-o", executable])
        outputs.append(run([executable]))
        names = run([nm, "--defined-only", executable]).decode()
        assert all((name in names) == (variant == "enabled") for name in enabled["inserted_functions"])
    assert outputs[0] == outputs[1] and outputs[0].strip()
    assert enabled["security_property"] == "not_established"
    assert hashlib.sha256((tmp_path / "enabled/fixture").read_bytes()).digest() != hashlib.sha256((tmp_path / "disabled/fixture").read_bytes()).digest()
