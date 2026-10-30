"""Conservative selection in clang's canonical textual IR; LLVM verifies edits.

This is intentionally not a general LLVM parser. Unknown signatures are never
marked automatically. Explicit symbols must resolve to eligible definitions.
"""
from __future__ import annotations

import hashlib
import re
import struct

from runner import Failure

INT = re.compile(r"i[1-9][0-9]*")
NAME = re.compile(r'@(?P<name>"(?:[^"\\]|\\[0-9A-Fa-f]{2})*"|[-a-zA-Z$._0-9]+)\(')


def decode_name(value):
    if value.startswith('"'):
        raw = re.sub(r"\\([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), value[1:-1])
        return raw
    return value


def definitions(text):
    groups = {m[1]: m[2] for m in re.finditer(r"^attributes #(\d+) = \{(.*)\}$", text, re.M)}
    result = []
    for index, line in enumerate(text.splitlines()):
        if not line.startswith("define "):
            continue
        match = NAME.search(line)
        if not match or not line.endswith("{"):
            raise Failure("UNSUPPORTED_IR", "Expected a canonical single-line clang function header.")
        start = match.end() - 1
        depth, end = 1, start + 1
        while end < len(line) and depth:
            depth += (line[end] == "(") - (line[end] == ")")
            end += 1
        if depth:
            raise Failure("UNSUPPORTED_IR", "Unbalanced IR function signature.")
        head, params, post = line[:match.start()], line[start + 1:end - 1], line[end:]
        # Scalar integer return must be the last token before the symbol.
        ret = head.split()[-1]
        args = [part.strip().split()[0] for part in params.split(",")] if params.strip() else []
        attrs = post + " " + " ".join(groups.get(g, "") for g in re.findall(r"#(\d+)", post))
        eligible = bool(INT.fullmatch(ret) and all(INT.fullmatch(arg) for arg in args)
                        and "optnone" not in attrs)
        result.append({"name": decode_name(match["name"]), "line": index, "end": end,
                       "integer_signature": eligible})
    return result


def select(text, selection):
    funcs = definitions(text)
    if selection["mode"] == "annotated":
        # Source annotations remain unchanged; the actual Shield report counts them.
        return text, {"definitions": len(funcs), "integer_signature_candidates": sum(
            f["integer_signature"] for f in funcs), "marked_by_integration": []}
    requested = set(selection.get("symbols", []))
    eligible = {f["name"] for f in funcs if f["integer_signature"]}
    if selection["mode"] == "symbols" and not requested <= eligible:
        raise Failure("INCOMPATIBLE_SELECTION", "Selected symbols are absent or have unsupported signatures.",
                      symbols=sorted(requested - eligible))
    chosen = eligible if selection["mode"] == "integer-signatures" else requested
    lines = text.splitlines(keepends=True)
    for func in funcs:
        if func["name"] in chosen:
            line = lines[func["line"]]
            # Function attributes occur after unnamed_addr and before attribute groups.
            tail = line[func["end"]:]
            match = re.match(r"\s*(?:(?:local_)?unnamed_addr\s*)?", tail)
            offset = func["end"] + match.end()
            lines[func["line"]] = line[:offset] + ' "aegis.protect" ' + line[offset:]
    return "".join(lines), {"definitions": len(funcs), "integer_signature_candidates": len(eligible),
                            "marked_by_integration": sorted(chosen)}


def elf_functions(path):
    """Read exact STT_FUNC bytes from native little-endian ELF64 symtab.

    No inference about attack resistance or instruction semantics is made.
    Missing/stripped symbols are absent, never classified as retained.
    """
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 64:
        raise Failure("UNSUPPORTED_FORMAT", "Native retention inspection requires little-endian ELF64.")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 62:
        raise Failure("UNSUPPORTED_FORMAT", "Native retention inspection requires x86-64.")
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count = struct.unpack_from("<HH", data, 58)
    if size != 64 or not count or offset + size * count > len(data):
        raise Failure("INVALID_ARTIFACT", "Invalid or extended ELF section table.")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size) for i in range(count)]
    result = {}
    try:
        for section in sections:
            if section[1] != 2:  # SHT_SYMTAB, including local symbols
                continue
            strings_section = sections[section[6]]
            strings = data[strings_section[4]:strings_section[4] + strings_section[5]]
            if section[9] != 24 or section[4] + section[5] > len(data):
                raise ValueError("Invalid symbol table")
            for pos in range(section[4], section[4] + section[5], 24):
                name, info, _, index, value, length = struct.unpack_from("<IBBHQQ", data, pos)
                if info & 15 != 2 or not length or not 0 < index < len(sections):
                    continue
                sec = sections[index]
                begin = sec[4] + value - sec[3]
                if begin < sec[4] or begin + length > min(sec[4] + sec[5], len(data)):
                    raise ValueError("Function outside its section")
                end = strings.index(b"\0", name)
                symbol = strings[name:end].decode("utf-8")
                if symbol in result:
                    # Ambiguous local symbols cannot support an exact comparison.
                    result[symbol] = None
                else:
                    result[symbol] = data[begin:begin + length]
    except (IndexError, ValueError, struct.error, UnicodeError) as exc:
        raise Failure("INVALID_ARTIFACT", "Invalid ELF symbols or sections.") from exc
    return result


def compare_functions(baseline, protected, transformed, decoys=()):
    before, after = elf_functions(baseline), elf_functions(protected)
    records = []
    for name in transformed:
        a, b = before.get(name), after.get(name)
        status = "symbol_unavailable" if a is None or b is None else (
            "machine_bytes_differ" if a != b else "identical_machine_bytes")
        records.append({"name": name, "observation": status,
                        "baseline_size": len(a) if a is not None else None,
                        "protected_size": len(b) if b is not None else None,
                        "baseline_sha256": hashlib.sha256(a).hexdigest() if a is not None else None,
                        "protected_sha256": hashlib.sha256(b).hexdigest() if b is not None else None})
    return {"shield_functions": records, "mirage_symbols": [
        {"name": name, "present_only_in_protected": name not in before and after.get(name) is not None}
        for name in decoys], "interpretation": "Byte differences and retained symbols are static observations; "
        "they do not establish semantic transformation retention or attack resistance."}
