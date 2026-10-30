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


def test_supervised_runner_and_work_dir_are_used(built, tmp_path):
    """The AEGIS adapter supplies its own runner so tools stay in Core's process group."""
    root, config, report, _, _ = built
    calls = []

    def runner(argv, cwd):
        calls.append((Path(argv[0]).name, Path(cwd)))
        return run(argv, cwd)

    work = tmp_path / "work"
    work.mkdir()
    supervised = transform(root / "input.ll", tmp_path / "supervised", config, runner=runner, work_dir=work)
    assert supervised == report
    assert (tmp_path / "supervised" / "module.ll").read_bytes() == (root / "enabled" / "module.ll").read_bytes()
    assert {name for name, _ in calls} >= {"clang", "llvm-link", "opt"} and len(calls) == 7
    assert all(cwd.parent == work for _, cwd in calls) and not list(work.iterdir())

    def failing(argv, cwd):
        raise MirageError("tool_failed")

    with pytest.raises(MirageError, match="tool_failed"):
        transform(root / "input.ll", tmp_path / "never", config, runner=failing, work_dir=work)
    assert not (tmp_path / "never").exists()


def _retarget(source: Path, destination: Path, triple: str) -> Path:
    text = source.read_text()
    default = text.split('target triple = "', 1)[1].split('"', 1)[0]
    destination.write_text(text.replace(f'target triple = "{default}"', f'target triple = "{triple}"'))
    return destination


def test_vendor_only_triple_difference_builds_decoys_for_module_triple(built, tmp_path):
    """rustc emits x86_64-unknown-linux-gnu; Clang defaults to x86_64-pc-linux-gnu (same target)."""
    root, config, _, _, _ = built
    default = (root / "input.ll").read_text().split('target triple = "', 1)[1].split('"', 1)[0]
    parts = default.split("-")
    if len(parts) != 4:
        pytest.skip(f"host clang default triple {default!r} has no vendor field")
    vendor = "unknown" if parts[1] != "unknown" else "pc"
    triple = "-".join([parts[0], vendor, *parts[2:]])
    module = _retarget(root / "input.ll", tmp_path / "vendor.ll", triple)
    calls = []

    def runner(argv, cwd):
        calls.append([Path(argv[0]).name, *argv[1:]])
        return run(argv, cwd)

    report = transform(module, tmp_path / "out", config, runner=runner, work_dir=tmp_path)
    output = (tmp_path / "out" / "module.ll").read_text()
    assert f'target triple = "{triple}"' in output and default not in output
    assert report["inserted_count"] == 3
    for name in report["inserted_functions"]:
        assert f"@{name}(" in output
    assert [c for c in calls if c[0] == "clang" and f"--target={triple}" in c]
    # The decoy-only change is the same as for the default triple: drop the inserted
    # functions and the remaining input is byte-identical to what was supplied.
    assert report["input_sha256"] == digest(module.read_bytes())


@pytest.mark.parametrize("triple", ["aarch64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-linux-gnu",
                                    "x86_64-unknown-linux-musl", "x86_64-pc-windows-msvc"])
def test_other_triple_mismatches_still_fail(built, tmp_path, triple):
    root, config, _, _, _ = built
    module = _retarget(root / "input.ll", tmp_path / "other.ll", triple)
    default = (root / "input.ll").read_text().split('target triple = "', 1)[1].split('"', 1)[0]
    if triple == default:
        pytest.skip("host default triple equals the mismatch case")
    with pytest.raises(MirageError, match="target_triple_mismatch"):
        transform(module, tmp_path / "out", config)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(("module", "default", "expected"), [
    ("x86_64-unknown-linux-gnu", "x86_64-pc-linux-gnu", True),
    ("x86_64-pc-linux-gnu", "x86_64-pc-linux-gnu", False),
    ("x86_64-unknown-linux-musl", "x86_64-pc-linux-gnu", False),
    ("aarch64-unknown-linux-gnu", "x86_64-pc-linux-gnu", False),
    ("x86_64-linux-gnu", "x86_64-pc-linux-gnu", False),
    ("x86_64-unknown-linux-gnu-extra", "x86_64-pc-linux-gnu", False),
    ("x86_64-un known-linux-gnu", "x86_64-pc-linux-gnu", False),
    ("x86_64--linux-gnu", "x86_64-pc-linux-gnu", False),
])
def test_same_target_except_vendor_is_narrow(module, default, expected):
    from aegis_mirage.transform import same_target_except_vendor
    assert same_target_except_vendor(module, default) is expected


def test_oversized_input_is_reported_as_too_large_not_irregular(tmp_path):
    from aegis_mirage.transform import read
    big = tmp_path / "big.ll"
    big.write_bytes(b"x" * 11)
    with pytest.raises(MirageError, match="^input_too_large$"):
        read(big, limit=10)
    assert read(big, limit=11) == b"x" * 11
    with pytest.raises(MirageError, match="^invalid_regular_input$"):
        read(tmp_path, limit=10)  # a directory is still not a regular input
