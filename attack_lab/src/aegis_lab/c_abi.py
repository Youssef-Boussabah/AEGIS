"""Generic C11 scalar-integer ABI for behavioral scoring (``aegis.lab.c-abi.scalar-u32.v1``).

Phase 4. The supported interface is a fixed-arity function of ``uint32_t``
arguments returning ``uint32_t``, written in the existing Lab interface notation
(the one ``disclosure.check_task_fields`` accepts), for example::

    pixel(uint32_t, uint32_t, uint32_t)->uint32_t

Arity 0 to 16 is supported. The interface label (``pixel``) is not a C symbol:
the C function the harness calls is the reconstruction task's
``function_label`` (``target_function`` when the run was blinded). Nothing here
depends on a particular target or function name.

The harness is generated from the arity and symbol only, so it cannot contain
hidden-test inputs or expected outputs. It is two translation units:

- ``aegis_candidate_unit.c`` declares the expected prototype and then includes
  the candidate source (``candidate.c``). A definition with other parameter or
  return types is a compile-time conflict, not undefined behavior at link time.
- ``aegis_harness.c`` parses decimal arguments, redirects the candidate's stdout
  to stderr, calls the function through an assembler label (so header names can
  never collide with the symbol), and writes exactly one line,
  ``AEGIS-RESULT <decimal>\\n``, to the saved original stdout.

Candidate code runs in the same process and can forge or suppress that line.
That is candidate behavior: the scorer classifies whatever it observes and
never trusts it beyond the strict line format.

This module only generates text and parses text. It never compiles or runs anything.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .canonical import canonical_sha256
from .disclosure import _INTERFACE_RE

ABI_VERSION = "aegis.lab.c-abi.scalar-u32.v1"
HARNESS_VERSION = "aegis.lab.c-harness.scalar-u32.v1"
OBSERVATION_PROTOCOL = "aegis.lab.c-observation.result-line.v1"
MAX_ARITY = 16
U32_MAX = 2**32 - 1
SCALAR_TYPE = "uint32_t"

HARNESS_FILE = "aegis_harness.c"
CANDIDATE_UNIT_FILE = "aegis_candidate_unit.c"
CANDIDATE_FILE = "candidate.c"
# Compiler order; candidate.c is staged and included by the candidate unit, never compiled alone.
TRANSLATION_UNITS = (HARNESS_FILE, CANDIDATE_UNIT_FILE)
BINARY_FILE = "candidate"
# Exit status the harness uses for its own argument or I/O failures. Candidate code can exit with
# the same status, so it is recorded but never trusted as a harness diagnosis.
HARNESS_FAILURE_EXIT = 125

INVALID_INTERFACE_CODES = frozenset({"interface_invalid"})
UNSUPPORTED_INTERFACE_CODES = frozenset({
    "unsupported_return_type",
    "unsupported_parameter_type",
    "unsupported_arity",
    "symbol_not_c_identifier",
    "symbol_reserved",
})
INTERFACE_ERROR_CODES = INVALID_INTERFACE_CODES | UNSUPPORTED_INTERFACE_CODES

# C11 keywords (6.4.1) cannot name a function.
_C11_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
    "volatile", "while", "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic",
    "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local",
})
# Symbols the harness itself defines or calls. A candidate defining one would replace part of
# the harness, so such an interface is refused instead of being scored ambiguously.
_HARNESS_SYMBOLS = frozenset({"main", "write", "dup", "dup2", "_start"})
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
_SPLIT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\((.*)\) ?-> ?(.+)")
_RESULT_LINE = re.compile(rb"AEGIS-RESULT (0|[1-9][0-9]{0,9})\n")


class InterfaceError(ValueError):
    """The interface or symbol is outside this ABI. ``code`` is a fixed, safe string."""

    def __init__(self, code: str) -> None:
        if code not in INTERFACE_ERROR_CODES:
            raise AssertionError(f"unregistered interface error code {code!r}")
        self.code = code
        self.kind = "invalid" if code in INVALID_INTERFACE_CODES else "unsupported"
        super().__init__(code)


@dataclass(frozen=True)
class ScalarInterface:
    text: str
    arity: int


def parse_interface(text: str) -> ScalarInterface:
    """Accept exactly ``label(uint32_t, ...)->uint32_t``; never rewrite or guess.

    Text the Lab's interface notation does not accept is ``interface_invalid``.
    Well-formed notation with another type or more than ``MAX_ARITY`` parameters is
    unsupported (``unsupported_*``), so a later ABI version could add it.
    """
    # fullmatch: a regex "$" would also accept a trailing newline. Only ASCII spaces are allowed.
    if (not isinstance(text, str) or len(text) > 200 or not text.isascii()
            or not _INTERFACE_RE.fullmatch(text)):
        raise InterfaceError("interface_invalid")
    match = _SPLIT.fullmatch(text)
    if match is None:  # pragma: no cover - _INTERFACE_RE already implies this shape
        raise InterfaceError("interface_invalid")
    _label, params, result = match.groups()
    if result != SCALAR_TYPE:
        raise InterfaceError("unsupported_return_type")
    if params == "":
        return ScalarInterface(text=text, arity=0)
    parts = params.split(",")
    for index, part in enumerate(parts):
        # The notation allows at most one space after a comma; nothing else is normalized.
        if index and part.startswith(" "):
            part = part[1:]
        if part != SCALAR_TYPE:
            raise InterfaceError("unsupported_parameter_type")
    if len(parts) > MAX_ARITY:
        raise InterfaceError("unsupported_arity")
    return ScalarInterface(text=text, arity=len(parts))


def check_symbol(symbol: str) -> str:
    """The C function name the harness will call. Reserved or non-C names are refused."""
    if not isinstance(symbol, str) or not _C_IDENTIFIER.fullmatch(symbol):
        raise InterfaceError("symbol_not_c_identifier")
    if (symbol in _C11_KEYWORDS or symbol in _HARNESS_SYMBOLS or symbol.startswith("_")
            or symbol.startswith("aegis_")):
        raise InterfaceError("symbol_reserved")
    return symbol


def _parameter_list(arity: int, *, named: bool) -> str:
    if arity == 0:
        return "void"
    return ", ".join(f"uint32_t a{i}" if named else "uint32_t" for i in range(arity))


def harness_sources(interface: ScalarInterface, symbol: str) -> dict[str, bytes]:
    """The two generated translation units. Deterministic in (arity, symbol) only."""
    check_symbol(symbol)
    arity = interface.arity
    prototype_params = _parameter_list(arity, named=False)
    call_args = ", ".join(f"arguments[{i}]" for i in range(arity))
    unit = (
        f"/* {HARNESS_VERSION}: candidate unit generated by the AEGIS scorer. */\n"
        "#include <stdint.h>\n"
        f"uint32_t {symbol}({prototype_params});\n"
        f'#include "{CANDIDATE_FILE}"\n'
    )
    harness = (
        f"/* {HARNESS_VERSION}: harness generated by the AEGIS scorer. It contains no test data. */\n"
        "#include <stdint.h>\n"
        "#include <unistd.h>\n"
        "\n"
        f'uint32_t aegis_harness_target({prototype_params}) __asm__("{symbol}");\n'
        "\n"
        "static int aegis_harness_parse(const char *text, uint32_t *out) {\n"
        "    uint64_t value = 0;\n"
        "    if (text[0] == '\\0' || (text[0] == '0' && text[1] != '\\0')) return 0;\n"
        "    for (; *text; ++text) {\n"
        "        if (*text < '0' || *text > '9') return 0;\n"
        "        value = value * 10u + (uint64_t)(*text - '0');\n"
        "        if (value > UINT32_MAX) return 0;\n"
        "    }\n"
        "    *out = (uint32_t)value;\n"
        "    return 1;\n"
        "}\n"
        "\n"
        "int main(int argc, char **argv) {\n"
        f"    uint32_t arguments[{max(arity, 1)}] = {{0}};\n"
        "    char line[32] = \"AEGIS-RESULT \";\n"
        "    char digits[10];\n"
        "    int length = 13, count = 0, result_fd;\n"
        "    uint32_t result;\n"
        f"    if (argc != {arity + 1}) return {HARNESS_FAILURE_EXIT};\n"
        f"    for (int i = 0; i < {arity}; ++i)\n"
        f"        if (!aegis_harness_parse(argv[i + 1], &arguments[i])) return {HARNESS_FAILURE_EXIT};\n"
        "    result_fd = dup(1);\n"
        f"    if (result_fd < 0 || dup2(2, 1) < 0) return {HARNESS_FAILURE_EXIT};\n"
        f"    result = aegis_harness_target({call_args});\n"
        "    do { digits[count++] = (char)('0' + result % 10u); result /= 10u; } while (result);\n"
        "    while (count) line[length++] = digits[--count];\n"
        "    line[length++] = '\\n';\n"
        f"    if (write(result_fd, line, (size_t)length) != length) return {HARNESS_FAILURE_EXIT};\n"
        "    return 0;\n"
        "}\n"
    )
    return {HARNESS_FILE: harness.encode("ascii"), CANDIDATE_UNIT_FILE: unit.encode("ascii")}


def compilation_sources(candidate: bytes, interface: ScalarInterface, symbol: str) -> dict[str, bytes]:
    """Exact staged files for operator review and compilation; contains no hidden test data."""
    return {CANDIDATE_FILE: candidate, **harness_sources(interface, symbol)}


def harness_sha256(sources: dict[str, bytes]) -> str:
    """Digest of the generated units (canonical JSON of name -> SHA-256 of bytes)."""
    return canonical_sha256({name: hashlib.sha256(data).hexdigest() for name, data in sorted(sources.items())})


# The template, rendered for a fixed representative interface, identifies the harness code in
# the scorer configuration. Any change to the generator changes this digest.
HARNESS_TEMPLATE_SHA256 = harness_sha256(harness_sources(ScalarInterface("t(uint32_t)->uint32_t", 1), "f"))


def encode_arguments(arguments: tuple[int, ...]) -> tuple[str, ...]:
    """Canonical decimal argv strings. Values are validated, never coerced."""
    out = []
    for value in arguments:
        if type(value) is not int or not 0 <= value <= U32_MAX:
            raise ValueError("argument outside uint32_t")
        out.append(str(value))
    return tuple(out)


def parse_result_line(stdout: bytes) -> int | None:
    """The observed return value, or ``None`` unless stdout is exactly one canonical result line."""
    if not isinstance(stdout, bytes):
        return None
    match = _RESULT_LINE.fullmatch(stdout)
    if match is None:
        return None
    value = int(match.group(1))
    return value if value <= U32_MAX else None
