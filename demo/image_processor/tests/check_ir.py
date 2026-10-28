#!/usr/bin/env python3
"""Check ImageLab kernels IR against protect.allowlist and the LLVM Shield.

    check_ir.py annotations --ir kernels.input.ll --allowlist protect.allowlist
    check_ir.py shield --baseline kernels.input.ll --transformed kernels.shield.ll
                       --report kernels.shield.report.json --allowlist protect.allowlist

`annotations` checks that the functions selected by "aegis.protect" (via
llvm.global.annotations or the string function attribute, as the Shield reads
them) are exactly the allowlist, and that each one meets the Shield's
selection requirements: a definition, scalar-integer return and arguments,
not variadic, no optnone, and at least one add without nuw/nsw flags.

`shield` checks a Shield run: the report covers every allowlisted function
as transformed and nothing else as annotated, the transformed IR defines the
same functions, and only allowlisted bodies changed. These are structural
checks. A changed IR body is NOT evidence of protection; the Shield has no
established security property (protectors/llvm/README.md).

Textual IR parsing here targets what Clang/opt 22 print for this project; it
is not a general LLVM IR parser.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ANNOTATION = "aegis.protect"
INT_TYPE = re.compile(r"^i\d+$")


def read_allowlist(path: Path) -> list[str]:
    names = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.append(line)
    if len(names) != len(set(names)):
        raise SystemExit(f"{path}: duplicate entries")
    return names


def decode_ir_string(body: str) -> str:
    out = bytearray()
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 3 <= len(body):
            out.append(int(body[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(ord(body[i]))
            i += 1
    return out.rstrip(b"\x00").decode("utf-8", "replace")


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not inside (), [], {} or quotes."""
    parts, depth, current, quoted = [], 0, [], False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        if not quoted:
            if ch in "([{<":
                depth += 1
            elif ch in ")]}>":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append("".join(current).strip())
                current = []
                continue
        current.append(ch)
    if "".join(current).strip():
        parts.append("".join(current).strip())
    return parts


class Module:
    def __init__(self, text: str) -> None:
        self.text = text
        self.strings = {m.group(1): decode_ir_string(m.group(2)) for m in re.finditer(
            r'^(@[\w.$]+) = [^\n]*?constant \[\d+ x i8\] c"((?:[^"\\]|\\[0-9A-Fa-f]{2})*)"',
            text, re.M)}
        self.attribute_groups = {m.group(1): m.group(2) for m in re.finditer(
            r"^attributes (#\d+) = \{ (.*) \}$", text, re.M)}
        self.functions: dict[str, dict] = {}
        for m in re.finditer(r"^define ([^@\n]*)@([\w.$]+|\"[^\"]+\")\((.*)\)(.*)\{$", text, re.M):
            name = m.group(2).strip('"')
            end = text.index("\n}\n", m.end())
            self.functions[name] = {
                "prefix": m.group(1),
                "params": m.group(3),
                "suffix": m.group(4),
                "body": text[m.end():end],
            }

    def annotated(self) -> set[str]:
        selected = set()
        m = re.search(r"^@llvm\.global\.annotations = .*?\[(\{.*\})\], section", self.text, re.M)
        if m:
            for entry in re.finditer(r"\{ ptr @([\w.$]+), ptr (@[\w.$]+),", m.group(1)):
                if self.strings.get(entry.group(2)) == ANNOTATION:
                    selected.add(entry.group(1))
        for name, fn in self.functions.items():
            for group in re.findall(r"#\d+", fn["suffix"]):
                # Attribute presence selects, whatever its value.
                if re.search(rf'"{re.escape(ANNOTATION)}"(=|\s|$)',
                             self.attribute_groups.get(group, "")):
                    selected.add(name)
        return selected

    def signature_problems(self, name: str) -> list[str]:
        fn = self.functions.get(name)
        if fn is None:
            return ["not defined in this module"]
        problems = []
        ret = fn["prefix"].split()[-1] if fn["prefix"].split() else ""
        if not INT_TYPE.match(ret):
            problems.append(f"return type {ret!r} is not a scalar integer")
        params = split_top_level(fn["params"])
        for p in params:
            if p == "...":
                problems.append("variadic")
            elif not INT_TYPE.match(p.split()[0]):
                problems.append(f"parameter {p!r} is not a scalar integer")
        for group in re.findall(r"#\d+", fn["suffix"]):
            if re.search(r"\boptnone\b", self.attribute_groups.get(group, "")):
                problems.append("has optnone")
        return problems

    def unflagged_adds(self, name: str) -> int:
        body = self.functions[name]["body"]
        return len(re.findall(r"= add (?!nuw|nsw)i\d+ ", body))


def check_annotations(args: argparse.Namespace) -> int:
    allow = read_allowlist(args.allowlist)
    module = Module(args.ir.read_text())
    annotated = module.annotated()
    failures = []
    if annotated != set(allow):
        failures.append(f"annotated set {sorted(annotated)} != allowlist {sorted(allow)}")
    for name in allow:
        for problem in module.signature_problems(name):
            failures.append(f"{name}: {problem}")
        if name in module.functions:
            adds = module.unflagged_adds(name)
            print(f"{name}: {adds} add(s) without nuw/nsw")
            if adds == 0:
                failures.append(f"{name}: no add without nuw/nsw; the Shield would change nothing")
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{len(allow)} allowlisted function(s); {len(failures)} failure(s)")
    return 1 if failures else 0


def check_shield(args: argparse.Namespace) -> int:
    allow = set(read_allowlist(args.allowlist))
    baseline = Module(args.baseline.read_text())
    transformed = Module(args.transformed.read_text())
    report = json.loads(args.report.read_text())
    failures = []

    if report.get("backend") != "aegis-shield-llvm" or report.get("schema_version") != 1:
        failures.append("report is not an aegis-shield-llvm v1 report")
    rows = {row["name"]: row for row in report.get("functions", [])}
    total = 0
    for name, row in rows.items():
        sites = len(row.get("transformed_sites", []))
        total += sites
        if name in allow:
            if not row.get("annotated") or row.get("status") != "transformed" or sites == 0:
                failures.append(f"{name}: annotated={row.get('annotated')} "
                                f"status={row.get('status')} reason={row.get('reason')}")
            else:
                skipped = row.get("skipped_adds", {})
                print(f"{name}: {sites} site(s) transformed, skipped {skipped}")
        elif row.get("annotated") or sites:
            failures.append(f"{name}: not allowlisted but annotated or transformed")
    for name in allow - rows.keys():
        failures.append(f"{name}: missing from the report")
    if report.get("transformed_sites") != total:
        failures.append("module transformed_sites != sum of function sites")

    if set(baseline.functions) != set(transformed.functions):
        failures.append(f"defined functions differ: {sorted(baseline.functions)} vs "
                        f"{sorted(transformed.functions)}")
    for name in baseline.functions.keys() & transformed.functions.keys():
        same = baseline.functions[name]["body"] == transformed.functions[name]["body"]
        if name in allow and same:
            failures.append(f"{name}: body unchanged")
        if name not in allow and not same:
            failures.append(f"{name}: not allowlisted but body changed")
    if transformed.annotated() != allow:
        failures.append("annotations changed in the transformed IR")

    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{total} site(s) transformed in total; {len(failures)} failure(s). "
          "Structural check only: no security property is implied.")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("annotations")
    a.add_argument("--ir", type=Path, required=True)
    a.add_argument("--allowlist", type=Path, required=True)
    s = sub.add_parser("shield")
    s.add_argument("--baseline", type=Path, required=True)
    s.add_argument("--transformed", type=Path, required=True)
    s.add_argument("--report", type=Path, required=True)
    s.add_argument("--allowlist", type=Path, required=True)
    args = parser.parse_args()
    return check_annotations(args) if args.command == "annotations" else check_shield(args)


if __name__ == "__main__":
    sys.exit(main())
