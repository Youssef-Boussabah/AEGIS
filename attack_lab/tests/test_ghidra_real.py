"""Opt-in tests that run a real Ghidra installation and the real Java exporter.

Run with, for example:
    AEGIS_GHIDRA_HEADLESS=$HOME/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
        .venv/bin/python -m pytest attack_lab/tests/test_ghidra_real.py -v

These tests are skipped (= not run) without AEGIS_GHIDRA_HEADLESS or a C compiler.
The fixture program is compiled fresh and is AEGIS-owned test code; it is never executed.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from aegis_lab.ghidra import AnalysisReport, WorkerError, analyze

HEADLESS = os.environ.get("AEGIS_GHIDRA_HEADLESS")
CC = shutil.which("cc")
pytestmark = pytest.mark.skipif(
    not HEADLESS or not CC, reason="real Ghidra test needs AEGIS_GHIDRA_HEADLESS and a C compiler"
)

MAIN_C = """
__attribute__((noinline)) int aegis_mix(int a, int b) { return (a * 7) ^ (b - 3); }
int dup_a(int); int dup_b(int);
int main(int argc, char **argv) { (void)argv; return aegis_mix(argc, 5) + dup_a(argc) + dup_b(argc); }
"""
# Two TU-local functions with the same name: an exact-name selector is ambiguous.
DUP_A_C = "__attribute__((noinline)) static int dup(int x) { return x * 3; } int dup_a(int x) { return dup(x); }\n"
DUP_B_C = "__attribute__((noinline)) static int dup(int x) { return x * 5; } int dup_b(int x) { return dup(x); }\n"


@pytest.fixture(scope="module")
def fixture_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    work = tmp_path_factory.mktemp("ghidra-real")
    sources = []
    for name, text in (("main.c", MAIN_C), ("dup_a.c", DUP_A_C), ("dup_b.c", DUP_B_C)):
        (work / name).write_text(text)
        sources.append(str(work / name))
    output = work / "aegis_fixture"
    subprocess.run([CC, "-O1", "-fno-inline", "-o", str(output), *sources], check=True, timeout=120)
    return output


def _symbol_offset(binary: Path, name: str) -> int:
    nm = shutil.which("nm")
    if nm is None:
        pytest.skip("nm not available for the independent symbol cross-check")
    out = subprocess.run([nm, str(binary)], check=True, capture_output=True, text=True, timeout=60).stdout
    matches = [int(line.split()[0], 16) for line in out.splitlines() if line.endswith(f" {name}")]
    assert len(matches) == 1
    return matches[0]


def test_real_ghidra_decompiles_selected_function(fixture_binary: Path, tmp_path: Path) -> None:
    digest = hashlib.sha256(fixture_binary.read_bytes()).hexdigest()
    result = analyze(fixture_binary, tmp_path / "out", Path(HEADLESS), function="aegis_mix", expected_sha256=digest)
    text = result.read_text()
    report = AnalysisReport.model_validate_json(text)
    (fn,) = report.analysis.functions
    assert report.binary.sha256 == digest
    assert report.analysis.analysis_timed_out is False
    assert fn.name == "aegis_mix" and fn.decompile_success
    # The decompiled body must come from the machine code: multiply by 7, xor, subtract 3.
    assert "7" in fn.decompiled_c and "^" in fn.decompiled_c and "3" in fn.decompiled_c
    # Independent cross-check of the entry point against the ELF symbol table
    # (Ghidra's default image base for x86-64 PIE ELF is 0x100000).
    assert int(fn.entry_point, 16) - 0x100000 == _symbol_offset(fixture_binary, "aegis_mix")
    assert report.export.ghidra_version
    assert str(Path.home()) not in text


def test_real_ghidra_ambiguous_static_functions_fail_closed(fixture_binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="ambiguous selector 'dup': 2 functions"):
        analyze(fixture_binary, tmp_path / "out", Path(HEADLESS), function="dup")
    assert not (tmp_path / "out" / "ghidra-analysis.json").exists()


def test_real_ghidra_missing_function_fails_closed(fixture_binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="no matching analyzed functions"):
        analyze(fixture_binary, tmp_path / "out", Path(HEADLESS), function="no_such_function")


def _many_functions(tmp_path: Path, count: int = 3000) -> Path:
    """A larger AEGIS-owned fixture, so Ghidra auto-analysis needs more than one second."""
    body = "".join(
        f"__attribute__((noinline)) int f{i}(int a) {{ return (a ^ {i}) * {i % 97 + 3} + f{i - 1}(a - 1); }}\n"
        for i in range(1, count)
    )
    source = tmp_path / "many.c"
    source.write_text("__attribute__((noinline)) int f0(int a) { return a; }\n" + body +
                      f"int main(int argc, char **argv) {{ (void)argv; return f{count - 1}(argc); }}\n")
    output = tmp_path / "many"
    subprocess.run([CC, "-O0", "-o", str(output), str(source)], check=True, timeout=300)
    return output


def _aegis_ghidra_processes() -> list[int]:
    """Processes still running inside a worker scratch directory (Ghidra and its JVMs inherit it as cwd)."""
    prefix = os.path.join(tempfile.gettempdir(), "aegis-ghidra-")
    found = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                cwd = os.readlink(entry / "cwd")
            except OSError:
                continue
            if cwd.startswith(prefix):
                found.append(int(entry.name))
    return found


def test_real_ghidra_analysis_timeout_fails_closed(tmp_path: Path) -> None:
    binary = _many_functions(tmp_path)
    with pytest.raises(WorkerError, match="auto-analysis timed out") as exc:
        analyze(binary, tmp_path / "out", Path(HEADLESS), function="f0", analysis_timeout_seconds=1)
    assert exc.value.category in ("ghidra_failed", "analysis_rejected")
    assert not (tmp_path / "out" / "ghidra-analysis.json").exists()


def test_real_ghidra_wall_timeout_kills_the_process_group(fixture_binary: Path, tmp_path: Path) -> None:
    with pytest.raises(WorkerError, match="exceeded 2s wall time") as exc:
        analyze(fixture_binary, tmp_path / "out", Path(HEADLESS), function="aegis_mix", wall_timeout_seconds=2)
    assert exc.value.category == "ghidra_timeout"
    assert not (tmp_path / "out" / "ghidra-analysis.json").exists()
    assert _aegis_ghidra_processes() == []
