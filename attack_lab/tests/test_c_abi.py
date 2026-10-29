"""Phase 4: aegis.lab.c-abi.scalar-u32.v1 interface parsing and harness generation.

Nothing here executes code. The optional syntax checks run the host C compiler with
``-fsyntax-only`` on scorer-generated harness units and AEGIS-written stubs only (never on
a reconstruction candidate); they produce no binary.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from aegis_lab.c_abi import (
    CANDIDATE_FILE,
    CANDIDATE_UNIT_FILE,
    HARNESS_FILE,
    HARNESS_TEMPLATE_SHA256,
    MAX_ARITY,
    InterfaceError,
    ScalarInterface,
    check_symbol,
    encode_arguments,
    harness_sha256,
    harness_sources,
    parse_interface,
    parse_result_line,
)


def u32s(n: int, sep: str = ", ") -> str:
    return sep.join(["uint32_t"] * n)


@pytest.mark.parametrize("text,arity", [
    ("f()->uint32_t", 0),
    ("f(uint32_t)->uint32_t", 1),
    (f"pixel({u32s(3)})->uint32_t", 3),
    (f"pixel({u32s(3, ',')})->uint32_t", 3),
    (f"pixel({u32s(4)}) -> uint32_t", 4),
    (f"pixel({u32s(7)})->uint32_t", 7),
    (f"wide({u32s(MAX_ARITY)})->uint32_t", MAX_ARITY),
])
def test_supported_interfaces(text, arity):
    assert parse_interface(text) == ScalarInterface(text=text, arity=arity)


@pytest.mark.parametrize("label", ["imagelab_tone_map_pixel", "imagelab_color_adjust_pixel",
                                   "imagelab_enhance_pixel", "opaque", "target_function"])
@pytest.mark.parametrize("arity", [3, 4, 7])
def test_imagelab_shaped_signatures_are_generic(label, arity):
    # The ABI depends only on the types: no label is recognized or special-cased.
    interface = parse_interface(f"{label}({u32s(arity)})->uint32_t")
    assert interface.arity == arity
    other = parse_interface(f"x({u32s(arity)})->uint32_t")
    assert harness_sources(interface, "target_function") == harness_sources(other, "target_function")


@pytest.mark.parametrize("text,code", [
    ("opaque(int,int)->int", "unsupported_return_type"),
    ("f(uint32_t)->int", "unsupported_return_type"),
    ("f(uint32_t)->uint64_t", "unsupported_return_type"),
    ("f(int)->uint32_t", "unsupported_parameter_type"),
    ("f(uint32_t, int)->uint32_t", "unsupported_parameter_type"),
    ("f(uint32_t*)->uint32_t", "unsupported_parameter_type"),
    ("f(uint32_t[4])->uint32_t", "unsupported_parameter_type"),
    ("f(unsigned int)->uint32_t", "unsupported_parameter_type"),
    ("f(void)->uint32_t", "unsupported_parameter_type"),
    (f"f({u32s(MAX_ARITY + 1)})->uint32_t", "unsupported_arity"),
    ("uint32_t f(uint32_t a)", "interface_invalid"),
    ("f(uint32_t,  uint32_t)->uint32_t", "interface_invalid"),
    ("f(uint32_t, ...)->uint32_t", "interface_invalid"),
    ("f(uint32_t)\u00a0->uint32_t", "interface_invalid"),
    ("f(uint32_t)->uint32_t\n", "interface_invalid"),
    ("f(uint32_t)\t->uint32_t", "interface_invalid"),
    ("", "interface_invalid"),
    ("f(uint32_t)->uint32_t; system()", "interface_invalid"),
])
def test_rejected_interfaces(text, code):
    with pytest.raises(InterfaceError) as caught:
        parse_interface(text)
    assert caught.value.code == code
    assert caught.value.kind == ("invalid" if code == "interface_invalid" else "unsupported")


def test_non_string_and_oversized_interfaces_are_invalid():
    for value in (None, 3, b"f()->uint32_t", "f(" + "uint32_t," * 30 + "uint32_t)->uint32_t"):
        with pytest.raises(InterfaceError) as caught:
            parse_interface(value)
        assert caught.value.code in ("interface_invalid", "unsupported_arity")


@pytest.mark.parametrize("symbol,code", [
    ("main", "symbol_reserved"), ("write", "symbol_reserved"), ("dup2", "symbol_reserved"),
    ("int", "symbol_reserved"), ("_Bool", "symbol_reserved"), ("_hidden", "symbol_reserved"),
    ("__x", "symbol_reserved"), ("aegis_harness_target", "symbol_reserved"),
    ("ns::f", "symbol_not_c_identifier"), ("9f", "symbol_not_c_identifier"), ("f-g", "symbol_not_c_identifier"),
    ("x" * 64, "symbol_not_c_identifier"), ("", "symbol_not_c_identifier"), ("f\n", "symbol_not_c_identifier"),
    ("f\x00", "symbol_not_c_identifier"), ("f\u00e9", "symbol_not_c_identifier"),
])
def test_rejected_symbols(symbol, code):
    with pytest.raises(InterfaceError) as caught:
        check_symbol(symbol)
    assert caught.value.code == code


def test_accepted_symbols():
    for symbol in ("target_function", "secret_add", "f", "A1_b2", "x" * 63):
        assert check_symbol(symbol) == symbol


def test_unregistered_interface_code_is_an_assertion():
    with pytest.raises(AssertionError):
        InterfaceError("made_up")


def test_harness_is_generated_from_arity_and_symbol_only():
    sources = harness_sources(parse_interface(f"p({u32s(3)})->uint32_t"), "target_function")
    assert set(sources) == {HARNESS_FILE, CANDIDATE_UNIT_FILE}
    harness, unit = sources[HARNESS_FILE].decode(), sources[CANDIDATE_UNIT_FILE].decode()
    assert 'aegis_harness_target(uint32_t, uint32_t, uint32_t) __asm__("target_function")' in harness
    assert "aegis_harness_target(arguments[0], arguments[1], arguments[2])" in harness
    assert "if (argc != 4)" in harness
    assert "uint32_t target_function(uint32_t, uint32_t, uint32_t);" in unit
    assert f'#include "{CANDIDATE_FILE}"' in unit
    assert harness_sources(parse_interface(f"p({u32s(3)})->uint32_t"), "target_function") == sources
    assert harness_sha256(sources) != harness_sha256(harness_sources(parse_interface(f"p({u32s(4)})->uint32_t"),
                                                                     "target_function"))
    assert harness_sha256(sources) != harness_sha256(harness_sources(parse_interface(f"p({u32s(3)})->uint32_t"),
                                                                     "other_name"))


def test_nullary_harness_uses_void():
    sources = harness_sources(parse_interface("p()->uint32_t"), "f")
    assert b"aegis_harness_target(void)" in sources[HARNESS_FILE]
    assert b"uint32_t f(void);" in sources[CANDIDATE_UNIT_FILE]
    assert b"aegis_harness_target()" in sources[HARNESS_FILE]


def test_harness_refuses_reserved_symbols():
    with pytest.raises(InterfaceError):
        harness_sources(parse_interface("p()->uint32_t"), "main")


def test_harness_template_digest_is_a_fixed_vector():
    # Changes whenever the generator changes; the scorer configuration binds it.
    assert HARNESS_TEMPLATE_SHA256 == harness_sha256(harness_sources(ScalarInterface("t(uint32_t)->uint32_t", 1),
                                                                     "f"))
    assert len(HARNESS_TEMPLATE_SHA256) == 64


def test_encode_arguments_is_strict():
    assert encode_arguments((0, 1, 4294967295)) == ("0", "1", "4294967295")
    for bad in ((True,), (-1,), (2**32,), (1.0,), ("1",)):
        with pytest.raises(ValueError):
            encode_arguments(bad)


@pytest.mark.parametrize("stdout,value", [
    (b"AEGIS-RESULT 0\n", 0),
    (b"AEGIS-RESULT 42\n", 42),
    (b"AEGIS-RESULT 4294967295\n", 4294967295),
    (b"AEGIS-RESULT 4294967296\n", None),
    (b"AEGIS-RESULT 9999999999\n", None),
    (b"AEGIS-RESULT 042\n", None),
    (b"AEGIS-RESULT 42", None),
    (b"AEGIS-RESULT 42\r\n", None),
    (b"AEGIS-RESULT 42\n\n", None),
    (b"AEGIS-RESULT 42\nAEGIS-RESULT 43\n", None),
    (b"noise\nAEGIS-RESULT 42\n", None),
    (b"AEGIS-RESULT -1\n", None),
    (b"AEGIS-RESULT  42\n", None),
    (b"", None),
    ("AEGIS-RESULT 42\n", None),
])
def test_result_line_parsing(stdout, value):
    assert parse_result_line(stdout) == value


# --- Optional syntax checks of generated code (trusted inputs only, no binary is produced) ---------

CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
needs_cc = pytest.mark.skipif(CC is None, reason="no host C compiler for -fsyntax-only checks")


def syntax_check(tmp_path: Path, files: dict[str, bytes], unit: str) -> subprocess.CompletedProcess:
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    return subprocess.run([CC, "-std=c11", "-fsyntax-only", "-Werror=implicit-function-declaration", unit],
                          cwd=tmp_path, capture_output=True, timeout=60, env={"PATH": "/usr/bin:/bin"})


@needs_cc
@pytest.mark.parametrize("arity", [0, 1, 3, 4, 7, 16])
def test_generated_units_are_valid_c11(tmp_path, arity):
    interface = parse_interface(f"p({u32s(arity)})->uint32_t")
    params = ", ".join(f"uint32_t a{i}" for i in range(arity)) or "void"
    stub = f"#include <stdint.h>\nuint32_t aegis_stub_fn({params}) {{ return 7u; }}\n".replace(
        "aegis_stub_fn", "trusted_stub").encode()
    files = {**harness_sources(interface, "trusted_stub"), CANDIDATE_FILE: stub}
    for unit in (HARNESS_FILE, CANDIDATE_UNIT_FILE):
        result = syntax_check(tmp_path, files, unit)
        assert result.returncode == 0, result.stderr.decode(errors="replace")[-2000:]


@needs_cc
def test_mismatched_definition_is_a_compile_error(tmp_path):
    # A definition whose types differ from the interface is rejected at compile time.
    interface = parse_interface(f"p({u32s(2)})->uint32_t")
    stub = b"int trusted_stub(int a, int b) { return a + b; }\n"
    files = {**harness_sources(interface, "trusted_stub"), CANDIDATE_FILE: stub}
    result = syntax_check(tmp_path, files, CANDIDATE_UNIT_FILE)
    assert result.returncode != 0
