"""Only checked-in trusted fixture code runs; no reconstruction candidate executes."""
import json
from pathlib import Path

import pytest

from aegis_mirage.transform import MirageConfig, MirageError, decoy_source, digest, restore, run, transform

FIXTURE = Path(__file__).parent / "fixtures" / "signal.c"


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("mirage")
    run(["/usr/bin/clang", "-O1", "-S", "-emit-llvm", str(FIXTURE), "-o", "input.ll"], root)
    config = MirageConfig(seed=42)
    report = transform(root / "input.ll", root / "enabled", config)
    disabled = transform(root / "input.ll", root / "disabled", MirageConfig(seed=42, enabled=False))
    outputs = {}
    for variant in ("enabled", "disabled"):
        run(["/usr/bin/opt", "-passes=default<O2>,verify", "-S", str(root / variant / "module.ll"),
             "-o", f"{variant}.ll"], root)
        run(["/usr/bin/clang", "-O2", "-ffunction-sections", "-fdata-sections", f"{variant}.ll",
             "-Wl,--gc-sections", "-o", variant + ".elf"], root)
        outputs[variant] = run([str(root / (variant + ".elf"))], root)
    return root, config, report, disabled, outputs


def test_correctness_and_retention_after_optimization_and_link_gc(built):
    root, _, report, disabled, outputs = built
    assert outputs["enabled"] == outputs["disabled"]
    assert outputs["enabled"].strip()  # fixture ran its million-input digest loop
    names = run(["/usr/bin/llvm-nm", "--defined-only", "enabled.elf"], root).decode()
    control = run(["/usr/bin/llvm-nm", "--defined-only", "disabled.elf"], root).decode()
    assert report["inserted_count"] == 3 and disabled["inserted_count"] == 0
    for name in report["inserted_functions"]:
        assert name in names and name not in control
    assert digest((root / "enabled.elf").read_bytes()) != digest((root / "disabled.elf").read_bytes())
    assert (root / "enabled.elf").stat().st_size > (root / "disabled.elf").stat().st_size


def test_reproducible_and_disabled_control_is_exact(built):
    root, config, report, _, _ = built
    again = transform(root / "input.ll", root / "repeat", config)
    assert report == again
    assert (root / "enabled" / "module.ll").read_bytes() == (root / "repeat" / "module.ll").read_bytes()
    assert (root / "disabled" / "module.ll").read_bytes() == (root / "input.ll").read_bytes()
    changed = transform(root / "input.ll", root / "different", MirageConfig(seed=43))
    assert changed["output_sha256"] != report["output_sha256"]
    restore(root / "input.ll", report, root / "restored.ll")
    assert (root / "restored.ll").read_bytes() == (root / "input.ll").read_bytes()


def test_decoys_are_pure_uncalled_arithmetic(built):
    root, config, report, _, _ = built
    source, names = decoy_source(config)
    assert len(names) == 3 and b"retain" in source
    for forbidden in (b"volatile", b"system(", b"socket(", b"fopen(", b"constructor", b"main("):
        assert forbidden not in source
    ir = (root / "enabled" / "module.ll").read_text()
    for name in names:
        assert not any("call " in line and "@" + name in line for line in ir.splitlines())
    assert report["security_property"] == "not_established"


def test_failure_paths_are_explicit(built, tmp_path):
    root, config, report, _, _ = built
    with pytest.raises(MirageError, match="decoy_symbol_collision"):
        transform(root / "enabled" / "module.ll", tmp_path / "collision", config)
    with pytest.raises(FileExistsError):
        transform(root / "input.ll", root / "enabled", config)
    invalid = tmp_path / "bad.ll"
    invalid.write_text('target triple = "x86_64-pc-linux-gnu"\ndefine broken\n')
    with pytest.raises(MirageError, match="tool_failed"):
        transform(invalid, tmp_path / "bad", config)
    with pytest.raises(MirageError, match="original_digest_mismatch"):
        restore(invalid, report, tmp_path / "restore.ll")


@pytest.mark.parametrize("kwargs", [{"seed": True}, {"seed": -1}, {"seed": 2**63},
                                    {"seed": 0, "count": 0}, {"seed": 0, "count": 33},
                                    {"seed": 0, "enabled": 1}])
def test_configuration_is_strict(kwargs):
    with pytest.raises(MirageError):
        MirageConfig(**kwargs)


def test_ir_symlink_is_rejected(built, tmp_path):
    root, config, _, _, _ = built
    alias = tmp_path / "alias.ll"
    alias.symlink_to(root / "input.ll")
    with pytest.raises(OSError):
        transform(alias, tmp_path / "out", config)
