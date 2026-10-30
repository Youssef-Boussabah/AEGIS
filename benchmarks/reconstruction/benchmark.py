#!/usr/bin/env python3
"""Optional, offline evaluation of owned targets. No candidate execution entry point."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import statistics
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = "aegis.reconstruction.comparison.v1"
VARIANTS = ("baseline", "shield", "shield_mirage")
TARGETS = ["recon_gate", "recon_mix"]
MAX_FILE = 128 * 1024 * 1024
MAX_JSON = 8 * 1024 * 1024
PINNED = {
    "target.c": "55c17fee8d936a0f5123b31f0e737d73bd6b5aedb1b034ec414dec49bb3459d9",
    "runner.c": "eb84f47adeede48b92ef8c83949784e50aabf55a1158bdbee0849fa87b6f521b",
    "oracle.json": "2b333ba0e867b91684d73d19cae732c4443aa6499616a88a75bcf92c3aa0b6b4",
}


class Invalid(ValueError):
    """Fixed diagnostic code; rejected evidence values are never printed."""


def require(condition, code):
    if not condition:
        raise Invalid(code)


def exact(value, keys, code="invalid_fields"):
    require(type(value) is dict and set(value) == set(keys.split()), code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def identity(value):
    return digest(canonical(value))


def sha(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid_digest")
    return value


def integer(value, low=0, high=2**53 - 1):
    require(type(value) is int and low <= value <= high, "invalid_integer")
    return value


def text(value, limit=256):
    require(type(value) is str and 0 < len(value) <= limit
            and all(32 <= ord(c) < 127 for c in value), "invalid_text")
    return value


def names(value):
    require(type(value) is list and 0 < len(value) <= 64, "invalid_targets")
    require(all(type(s) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s) for s in value),
            "invalid_targets")
    require(value == sorted(set(value)), "noncanonical_targets")
    return value


def timestamp(value):
    require(type(value) is str and value.endswith("Z"), "invalid_timestamp")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise Invalid("invalid_timestamp") from None
    return result


def utcnow():
    return datetime.now(timezone.utc)


def stamp(value=None):
    return (value or utcnow()).isoformat().replace("+00:00", "Z")


def read_file(path, limit=MAX_FILE):
    """Regular files only; no final symlink or unbounded read."""
    import stat
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            st = os.fstat(stream.fileno())
            require(stat.S_ISREG(st.st_mode) and st.st_size <= limit, "invalid_file")
            data = stream.read(limit + 1)
            require(len(data) <= limit and len(data) == st.st_size, "file_changed_or_oversized")
            return data
    except OSError:
        raise Invalid("unreadable_regular_file") from None


def parse_json(data):
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, "duplicate_json_key")
            obj[key] = value
        return obj
    def finite(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite_json")
        return number
    try:
        require(len(data) <= MAX_JSON, "oversized_json")
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_float=finite,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid("nonfinite_json")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, Invalid):
            raise
        raise Invalid("invalid_json") from None


def load(path):
    return parse_json(read_file(path, MAX_JSON))


def write_json(path, value):
    # Refuse replacement, so a completed run remains immutable to this command.
    with Path(path).open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


def contained(root, relative):
    require(type(relative) is str and relative and not Path(relative).is_absolute(), "invalid_path")
    rel = Path(relative)
    require(".." not in rel.parts, "path_escape")
    root = Path(root).resolve()
    current = root
    for part in rel.parts:
        current = current / part
        require(not current.is_symlink(), "symlink_path")
    require(current.resolve().is_relative_to(root), "path_escape")
    return current


def reference(root, path):
    relative = str(Path(path).relative_to(root))
    data = read_file(contained(root, relative))
    return {"path": relative, "sha256": digest(data), "size_bytes": len(data)}


def checked(root, ref, limit=MAX_FILE):
    exact(ref, "path sha256 size_bytes")
    sha(ref["sha256"])
    integer(ref["size_bytes"], 0, limit)
    data = read_file(contained(root, ref["path"]), limit)
    require(len(data) == ref["size_bytes"] and digest(data) == ref["sha256"], "file_binding_mismatch")
    return data


def validate_controls(c):
    exact(c, "capabilities analysis_tools prompt_template_sha256 system_prompt_sha256 workflow_sha256 "
          "request_parameters_sha256 model_identity max_attempts max_input_tokens max_output_tokens "
          "max_total_tokens max_spend_microusd "
          "time_budget_seconds random_seed context_policy oracle_access source_access")
    require(type(c["capabilities"]) is list and c["capabilities"] == sorted(set(c["capabilities"]))
            and set(c["capabilities"]) <= {"static_disassembly", "ghidra_decompilation", "rea_reasoning"},
            "unsupported_capability")
    for key in ("prompt_template_sha256", "system_prompt_sha256", "workflow_sha256", "request_parameters_sha256"):
        sha(c[key])
    require(type(c["analysis_tools"]) is dict and len(c["analysis_tools"]) <= 16, "invalid_analysis_tools")
    for name, tool in c["analysis_tools"].items():
        text(name, 64)
        exact(tool, "version executable_sha256 configuration_sha256")
        text(tool["version"], 128)
        sha(tool["executable_sha256"])
        sha(tool["configuration_sha256"])
    text(c["model_identity"])
    for key in ("max_attempts", "max_input_tokens", "max_output_tokens", "max_total_tokens", "time_budget_seconds"):
        integer(c[key], 1, 10**9)
    integer(c["max_spend_microusd"], 0, 20000000)
    if c["random_seed"] is not None:
        integer(c["random_seed"], 0, 2**32 - 1)
    require(c["context_policy"] == "selected_functions_only" and c["oracle_access"] == "none"
            and c["source_access"] == "none", "unsupported_attacker_access")


def validate_oracle(o, targets):
    exact(o, "schema interface cases")
    require(o["schema"] == "aegis.reconstruction.oracle.v1" and type(o["interface"]) is str and
            re.fullmatch(r"u32\((?:u32(?:,u32)*)?\)", o["interface"]), "unsupported_oracle")
    args = o["interface"][4:-1]
    arity = 0 if not args else len(args.split(","))
    require(arity <= 16, "unsupported_oracle")
    require(type(o["cases"]) is list and 0 < len(o["cases"]) <= 10000, "missing_oracle_cases")
    seen, inputs, functions = set(), {}, set()
    for case in o["cases"]:
        exact(case, "id function arguments expected")
        text(case["id"], 64)
        require(case["id"] not in seen and case["function"] in targets, "oracle_case_identity")
        require(type(case["arguments"]) is list and len(case["arguments"]) == arity, "oracle_arguments")
        for arg in case["arguments"]:
            integer(arg, 0, 2**32 - 1)
        integer(case["expected"], 0, 2**32 - 1)
        key = (case["function"], *case["arguments"])
        require(key not in inputs or inputs[key] == case["expected"], "contradictory_oracle")
        seen.add(case["id"])
        inputs[key] = case["expected"]
        functions.add(case["function"])
    require(functions == set(targets), "oracle_target_coverage")


def shield_report_checked(raw, config, version, targets):
    r = parse_json(raw)
    exact(r, "schema_version backend llvm_version module config transformed_sites functions")
    require(type(r["schema_version"]) is int and r["schema_version"] == 1 and
            r["backend"] == "aegis-shield-llvm" and r["llvm_version"] == version, "shield_report_mismatch")
    text(r["module"], 4096)
    exact(r["config"], "seed max_sites_per_function enabled")
    require(type(r["config"]["enabled"]) is bool and r["config"] == {"enabled": True,
            "seed": str(config["seed"]), "max_sites_per_function": config["max_sites"]}, "shield_report_mismatch")
    integer(r["config"]["max_sites_per_function"], 1, 1000000)
    integer(r["transformed_sites"], 1, 1000000)
    require(type(r["functions"]) is list and len(r["functions"]) <= 100000, "invalid_shield_functions")
    total, found = 0, set()
    for f in r["functions"]:
        exact(f, "name annotated status reason transformed_sites skipped_adds")
        text(f["name"], 4096)
        require(f["name"] not in found and type(f["annotated"]) is bool, "invalid_shield_function")
        found.add(f["name"])
        require(type(f["transformed_sites"]) is list and len(f["transformed_sites"]) <= config["max_sites"],
                "invalid_shield_sites")
        changed = bool(f["transformed_sites"])
        require(f["status"] in ("transformed", "skipped") and (f["status"] == "transformed") == changed and
            f["reason"] in {"not-annotated", "disabled", "declaration", "unsupported-signature", "optnone",
                            "no-eligible-sites", "expanded"} and (f["reason"] == "expanded") == changed and
            (not changed or f["annotated"]), "contradictory_shield_claim")
        ordinals = []
        for site in f["transformed_sites"]:
            exact(site, "add_index bit_width variant")
            ordinals.append(integer(site["add_index"], 0, 1000000))
            integer(site["bit_width"], 2, 128)
            require(site["variant"] in ("xor-carry", "or-carry"), "invalid_shield_site")
        require(ordinals == sorted(set(ordinals)), "invalid_shield_sites")
        require(type(f["skipped_adds"]) is dict and set(f["skipped_adds"]) <=
                {"already-generated", "unsupported-type", "overflow-flags", "undef-or-poison", "budget"},
                "invalid_shield_skips")
        for count in f["skipped_adds"].values():
            integer(count, 1, 1000000)
        total += len(ordinals)
    require(total == r["transformed_sites"] and set(targets) <= found, "shield_report_totals_or_targets_mismatch")
    return r


def mirage_report_checked(raw, config, ir_sha, tools):
    r = parse_json(raw)
    exact(r, "schema_version mechanism configuration input_sha256 output_sha256 decoy_source_sha256 "
          "inserted_functions inserted_count toolchain runtime_side_effects final_artifact_retention security_property")
    require(r["schema_version"] == "aegis.mirage.report.v1" and
            r["mechanism"] == "retained_unreachable_arithmetic_functions" and
            r["runtime_side_effects"] == "no_callers_or_initializers_inserted" and
            r["final_artifact_retention"] == "requires_independent_check" and
            r["security_property"] == "not_established", "unsupported_mirage_claim")
    exact(r["configuration"], "seed enabled count")
    require(type(r["configuration"]["enabled"]) is bool and r["configuration"] ==
            {"seed": config["seed"], "enabled": True, "count": config["count"]}, "mirage_report_mismatch")
    integer(r["configuration"]["seed"], 0, 2**64 - 1)
    integer(r["configuration"]["count"], 1, 64)
    integer(r["inserted_count"], 1, 64)
    for key in ("input_sha256", "output_sha256", "decoy_source_sha256"):
        sha(r[key])
    names(sorted(r["inserted_functions"]))
    require(r["output_sha256"] == ir_sha and len(set(r["inserted_functions"])) ==
            r["inserted_count"] == config["count"], "mirage_report_mismatch")
    exact(r["toolchain"], "clang opt llvm_link")
    for key, name in (("clang", "clang"), ("opt", "opt"), ("llvm_link", "llvm-link")):
        exact(r["toolchain"][key], "version sha256")
        require(name in tools and r["toolchain"][key] == tools[name], "mirage_toolchain_mismatch")
    return r


def validate_manifest(m, root, now=None):
    exact(m, "schema comparison_id created_at valid_until targets sources oracle build_conditions "
          "attacker_controls artifacts")
    require(m["schema"] == SCHEMA, "unsupported_comparison")
    text(m["comparison_id"], 80)
    start, end, now = timestamp(m["created_at"]), timestamp(m["valid_until"]), now or utcnow()
    require(start <= now <= end and timedelta(0) < end - start <= timedelta(days=7), "stale_comparison")
    targets = names(m["targets"])
    require(type(m["sources"]) is list and m["sources"], "missing_sources")
    for source in m["sources"]:
        checked(root, source)
    oracle = parse_json(checked(root, m["oracle"], MAX_JSON))
    validate_oracle(oracle, targets)
    build = m["build_conditions"]
    exact(build, "tools target_triple frontend_flags final_flags environment source_identity")
    require(type(build["tools"]) is dict and build["tools"], "missing_toolchain")
    for name, tool in build["tools"].items():
        text(name, 40)
        exact(tool, "sha256 version")
        sha(tool["sha256"])
        text(tool["version"], 2000)
    text(build["target_triple"])
    for flags in (build["frontend_flags"], build["final_flags"]):
        require(type(flags) is list and flags, "missing_flags")
        for flag in flags:
            text(flag, 256)
    require(build["environment"] == "minimal-v1", "unsupported_build_environment")
    require(build["source_identity"] == identity(m["sources"]), "source_identity_mismatch")
    validate_controls(m["attacker_controls"])
    require(type(m["artifacts"]) is list and 2 <= len(m["artifacts"]) <= 32, "missing_artifacts")
    ids, shield_configs = set(), []
    for a in m["artifacts"]:
        exact(a, "id variant file ir targets build_conditions_sha256 protection shield_report mirage_report")
        text(a["id"], 80)
        require(a["id"] not in ids and a["variant"] in VARIANTS, "artifact_identity")
        ids.add(a["id"])
        require(a["targets"] == targets, "different_target_functions")
        require(a["build_conditions_sha256"] == identity(build), "noncomparable_build")
        checked(root, a["file"])
        checked(root, a["ir"])
        exact(a["protection"], "shield mirage")
        s, d = a["protection"]["shield"], a["protection"]["mirage"]
        if a["variant"] == "baseline":
            require(s is None and d is None and a["shield_report"] is None and a["mirage_report"] is None,
                    "baseline_protection_conflict")
        else:
            exact(s, "seed max_sites")
            integer(s["seed"], 0, 2**64 - 1)
            integer(s["max_sites"], 1, 1000000)
            shield_configs.append(s)
            shield_report_checked(checked(root, a["shield_report"], MAX_JSON), s, build["tools"]["clang"]["version"], targets)
        if a["variant"] == "shield_mirage":
            exact(d, "seed count")
            integer(d["seed"], 0, 2**64 - 1)
            integer(d["count"], 1, 64)
            mirage_report_checked(checked(root, a["mirage_report"], MAX_JSON), d, a["ir"]["sha256"], build["tools"])
        else:
            require(d is None and a["mirage_report"] is None, "unexpected_mirage")
    require(sum(a["variant"] == "baseline" for a in m["artifacts"]) == 1, "one_baseline_required")
    require(shield_configs and all(c == shield_configs[0] for c in shield_configs), "noncomparable_protection")
    # The combined pipeline must consume exactly the Shield stage compared here.
    shield_irs = {a["ir"]["sha256"] for a in m["artifacts"] if a["variant"] == "shield"}
    for a in m["artifacts"]:
        if a["variant"] == "shield_mirage":
            r = parse_json(checked(root, a["mirage_report"], MAX_JSON))
            require(r["input_sha256"] in shield_irs, "different_shield_stage")
    return oracle


def elf_measure(data, targets, decoys=()):
    """Read final ELF64 little-endian bytes and defined function symbols; no tools run."""
    def unpack(fmt, offset):
        require(type(offset) is int and 0 <= offset <= len(data) - struct.calcsize(fmt), "malformed_elf")
        return struct.unpack_from(fmt, data, offset)
    header = unpack("<16sHHIQQQIHHHHHH", 0)
    require(header[0][:7] == b"\x7fELF\x02\x01\x01" and header[1] in (2, 3), "unsupported_binary")
    require(header[11] == 64 and 0 < header[12] <= 4096 and header[13] < header[12], "unsupported_elf_sections")
    sections = [unpack("<IIQQQQIIQQ", header[6] + 64 * i) for i in range(header[12])]

    def section_bytes(s):
        require(s[1] != 8 and s[4] <= len(data) and s[5] <= len(data) - s[4], "malformed_elf")
        return data[s[4]:s[4] + s[5]]

    def cstring(blob, offset):
        require(0 <= offset < len(blob), "malformed_elf_string")
        end = blob.find(b"\0", offset, offset + 4096)
        require(end != -1, "malformed_elf_string")
        return blob[offset:end].decode("utf-8", "replace")

    section_names = section_bytes(sections[header[13]])
    symbols, dynamic, text_size = {}, set(), 0
    definitions, locations, ambiguous, symbol_count = set(), {}, set(), 0
    for s in sections:
        if cstring(section_names, s[0]) == ".text":
            text_size += len(section_bytes(s))
        if s[1] not in (2, 11):
            continue
        require(s[9] == 24 and s[5] % 24 == 0 and s[6] < len(sections), "malformed_elf_symbols")
        symbol_count += s[5] // 24
        require(symbol_count <= 100000, "elf_symbol_limit")
        strings, entries = section_bytes(sections[s[6]]), section_bytes(s)
        for offset in range(0, len(entries), 24):
            name_i, info, other, section_i, value, size = struct.unpack_from("<IBBHQQ", entries, offset)
            if info & 15 != 2 or not 0 < section_i < len(sections):
                continue
            name = cstring(strings, name_i)
            if s[1] == 11 and info >> 4 in (1, 2) and other & 3 in (0, 3):
                dynamic.add(name)
            target_section = sections[section_i]
            if not target_section[2] & 4 or size == 0:
                continue
            content = section_bytes(target_section)
            relative = value - target_section[3]
            require(0 <= relative <= len(content) and size <= len(content) - relative, "malformed_elf_symbol_range")
            location = (section_i, value, size)
            definitions.add((name, location))
            if name in locations and locations[name] != location:
                ambiguous.add(name)
            locations[name] = location
            symbols[name] = {"bytes": size, "code_sha256": (digest(content[relative:relative + size])
                             if name in targets or name in decoys else None),
                             "binding": {0: "local", 1: "global", 2: "weak"}.get(info >> 4, "other"),
                             "visibility": {0: "default", 1: "internal", 2: "hidden", 3: "protected"}[other & 3]}
    for name in ambiguous:
        symbols.pop(name, None)
    return {"executable_bytes": len(data), "text_bytes": text_size,
            "targets": {name: ({**symbols[name], "dynamic_export": name in dynamic} if name in symbols else None)
                        for name in targets},
            "defined_function_symbols": len(definitions), "dynamic_function_exports": len(dynamic),
            "mirage_retention": {"expected": len(decoys), "observed": sum(n in symbols for n in decoys)}}


def measure_static(m, root):
    result = {}
    for a in m["artifacts"]:
        decoys = [] if a["mirage_report"] is None else parse_json(checked(root, a["mirage_report"], MAX_JSON))["inserted_functions"]
        measured = elf_measure(checked(root, a["file"]), m["targets"], decoys)
        measured["artifact_sha256"] = a["file"]["sha256"]
        measured["shield_ir_sites_reported"] = (0 if a["shield_report"] is None else
            parse_json(checked(root, a["shield_report"], MAX_JSON))["transformed_sites"])
        measured["shield_selected_ir_sites_reported"] = (0 if a["shield_report"] is None else
            sum(len(f["transformed_sites"]) for f in parse_json(checked(root, a["shield_report"], MAX_JSON))["functions"]
                if f["name"] in m["targets"]))
        result[a["id"]] = measured
    baseline = next(result[a["id"]] for a in m["artifacts"] if a["variant"] == "baseline")
    for measured in result.values():
        own, base = measured["targets"], baseline["targets"]
        measured["target_code_comparison"] = ("unavailable" if any(own[n] is None or base[n] is None for n in own)
            else "identical" if all(own[n]["code_sha256"] == base[n]["code_sha256"] for n in own)
            else "different_not_attributed")
    return result


def run(argv, cwd, *, input_data=b"", timeout=120, env_extra=None, log=None):
    """Only called for operator-trusted tools and freshly built owned targets."""
    argv = [str(a) for a in argv]
    if log is not None:
        log.append(argv)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(cwd), "TMPDIR": str(cwd)}
    env.update(env_extra or {})
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, tempfile.TemporaryFile() as inp:
        inp.write(input_data)
        inp.seek(0)
        started = time.perf_counter_ns()
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=inp, stdout=out, stderr=err,
                                shell=False, start_new_session=True)
        try:
            # pidfd completion avoids Popen.wait(timeout)'s polling quantization in timings.
            require(hasattr(os, "pidfd_open"), "linux_pidfd_required")
            pidfd = os.pidfd_open(proc.pid)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(pidfd, selectors.EVENT_READ)
                    require(bool(selector.select(timeout)), "process_timeout")
                proc.wait()
            finally:
                os.close(pidfd)
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        elapsed = (time.perf_counter_ns() - started) / 1e9
        require(proc.returncode == 0, "trusted_process_failed")
        out.seek(0)
        output = out.read(1024 * 1024 + 1)
        require(len(output) <= 1024 * 1024 and err.seek(0, 2) <= 1024 * 1024, "process_output_limit")
        return output, elapsed


def reference_value(function, a, b):
    v = (a + b) & 0xffffffff
    if function == "recon_mix":
        v ^= v >> 13
        v = (v * 129) & 0xffffffff
        return ((v ^ (v >> 17)) + 0x9e3779b9) & 0xffffffff
    require(function == "recon_gate", "unsupported_trusted_function")
    return (((v ^ 0xa5a5a5a5) + 17) if v % 8 == 3 else (v // 8 + (b ^ 0x13579bdf))) & 0xffffffff


def execute_owned(root, a, argv, *, input_data=b"", log=None):
    # This helper is private to demo construction; verify/import never call it.
    checked(root, a["file"])
    output, elapsed = run([contained(root, a["file"]["path"]), *argv], root,
                          input_data=input_data, timeout=30, log=log)
    checked(root, a["file"])
    return output, elapsed


def demo(output_dir, plugin, *, samples=9, iterations=2000000, targets=None):
    integer(samples, 3, 101)
    integer(iterations, 1, 100000000)
    targets = TARGETS if targets is None else names(targets)
    require(set(targets) <= set(TARGETS), "unsupported_owned_target")
    output_dir = Path(output_dir).absolute()
    require(not output_dir.resolve().is_relative_to(ROOT), "build_output_must_be_outside_source_tree")
    require(not output_dir.exists(), "output_directory_exists")
    output_dir.mkdir(mode=0o700, parents=True)
    root, commands = output_dir, []
    (root / "inputs").mkdir(mode=0o700)
    for name, expected in PINNED.items():
        data = read_file(HERE / "fixtures" / name)
        require(digest(data) == expected, "trusted_fixture_pin_mismatch")
        (root / "inputs" / name).write_bytes(data)
    oracle_path = root / "inputs/oracle.json"
    if targets != TARGETS:
        selected = load(oracle_path)
        selected["cases"] = [c for c in selected["cases"] if c["function"] in targets]
        oracle_path = root / "inputs/selected-oracle.json"
        write_json(oracle_path, selected)
    # Snapshot the plugin; no write or build in another owner's active directories.
    plugin_data = read_file(Path(plugin).absolute())
    (root / "Shield.so").write_bytes(plugin_data)
    tools = {}
    for name in ("clang", "opt", "llvm-link"):
        import shutil
        path = shutil.which(name, path="/usr/bin:/bin")
        require(path is not None, "missing_llvm_tool")
        data = read_file(Path(path).resolve())
        version, _ = run([path, "--version"], root, log=commands)
        found = re.search(rb"(?:clang|LLVM) version (22\.\d+\.\d+)", version)
        require(found is not None, "llvm22_required")
        tools[name] = {"sha256": digest(data), "version": found[1].decode()}
    require(len({t["version"] for t in tools.values()}) == 1, "toolchain_version_mismatch")
    tools["shield-plugin"] = {"sha256": digest(plugin_data), "version": "operator-trusted-build"}
    mirage_files = sorted((ROOT / "protectors/mirage/src/aegis_mirage").glob("*.py"))
    mirage_identity = identity({p.name: digest(read_file(p)) for p in mirage_files})
    tools["mirage-source"] = {"sha256": mirage_identity, "version": "local-source-snapshot-identity"}
    # Copy the trusted transformer so concurrent source edits cannot alter this run.
    package = root / "transformer" / "aegis_mirage"
    package.mkdir(parents=True, mode=0o700)
    for p in mirage_files:
        (package / p.name).write_bytes(read_file(p))
    require(identity({p.name: digest(read_file(package / p.name)) for p in mirage_files}) == mirage_identity,
            "transformer_changed")
    tools["python"] = {"sha256": digest(read_file(Path(sys.executable).resolve())), "version": sys.version.split()[0]}
    sources = [reference(root, root / "inputs" / n) for n in ("target.c", "runner.c")]
    triple, _ = run(["/usr/bin/clang", "-dumpmachine"], root, log=commands)
    frontend = ["-std=c11", "-O1", "-S", "-emit-llvm"]
    final = ["-O2", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections", "-Wl,--build-id=none"]
    build = {"tools": tools, "target_triple": triple.decode().strip(), "frontend_flags": frontend,
             "final_flags": final, "environment": "minimal-v1", "source_identity": identity(sources)}
    require(build["target_triple"].startswith("x86_64-"), "demo_requires_x86_64")
    baseline = root / "baseline.ll"
    run(["/usr/bin/clang", *frontend, root / "inputs/target.c", "-o", baseline], root, log=commands)
    shield, shield_report = root / "shield.ll", root / "shield-report.json"
    run(["/usr/bin/opt", "-load-pass-plugin", root / "Shield.so",
         f"-passes=aegis-shield<seed=42;max-sites=16;report={shield_report}>,verify",
         "-S", baseline, "-o", shield], root, log=commands)
    run([sys.executable, "-B", "-m", "aegis_mirage", shield, "--output-dir", root / "mirage",
         "--seed", "42", "--count", "3"], root,
        env_extra={"PYTHONPATH": str(root / "transformer")}, log=commands)
    controls = {"capabilities": ["ghidra_decompilation", "rea_reasoning", "static_disassembly"],
        "analysis_tools": {},
        "prompt_template_sha256": digest(b"Reconstruct these functions as uint32 C.\n{{CONTEXT}}\n"),
        "system_prompt_sha256": digest(b"Use only the provided decompilation. Do not execute code."),
        "workflow_sha256": digest(b"single-attempt-selected-functions-v1"),
        "request_parameters_sha256": digest(b"not-scheduled-no-inference"),
        "model_identity": "not_scheduled", "max_attempts": 1, "max_input_tokens": 8192,
        "max_output_tokens": 4096, "max_total_tokens": 16384, "max_spend_microusd": 100000,
        "time_budget_seconds": 300, "random_seed": 42,
        "context_policy": "selected_functions_only", "oracle_access": "none", "source_access": "none"}
    artifacts = []
    for variant, ir in zip(VARIANTS, (baseline, shield, root / "mirage/module.ll")):
        exe = root / (variant + ".elf")
        run(["/usr/bin/clang", *final, ir, root / "inputs/runner.c", "-o", exe], root, log=commands)
        artifacts.append({"id": variant, "variant": variant, "file": reference(root, exe),
            "ir": reference(root, ir), "targets": targets, "build_conditions_sha256": identity(build),
            "protection": {"shield": None if variant == "baseline" else {"seed": 42, "max_sites": 16},
                           "mirage": {"seed": 42, "count": 3} if variant == "shield_mirage" else None},
            "shield_report": None if variant == "baseline" else reference(root, shield_report),
            "mirage_report": reference(root, root / "mirage/report.json") if variant == "shield_mirage" else None})
    start = utcnow()
    manifest = {"schema": SCHEMA, "comparison_id": "owned-u32-seed42", "created_at": stamp(start),
        "valid_until": stamp(start + timedelta(days=7)), "targets": targets, "sources": sources,
        "oracle": reference(root, oracle_path), "build_conditions": build,
        "attacker_controls": controls, "artifacts": artifacts}
    oracle = validate_manifest(manifest, root)
    for case in oracle["cases"]:
        require(reference_value(case["function"], *case["arguments"]) == case["expected"], "frozen_oracle_disagrees")
    measurements = measure_static(manifest, root)
    inputs = "".join(f"{0 if c['function'] == 'recon_mix' else 1} {c['arguments'][0]} {c['arguments'][1]}\n"
                     for c in oracle["cases"]).encode()
    expected = "".join(str(c["expected"]) + "\n" for c in oracle["cases"]).encode()
    bench_expected = 0x12345678
    for i in range(iterations):
        bench_expected = reference_value("recon_mix", bench_expected, i)
        bench_expected = reference_value("recon_gate", bench_expected, i ^ 0xfedcba98)
    for a in artifacts:
        output, _ = execute_owned(root, a, ["--cases"], input_data=inputs, log=commands)
        require(output == expected, "owned_oracle_mismatch")
        measurements[a["id"]]["correctness"] = {"status": "passed", "cases": len(oracle["cases"]),
            "oracle_sha256": manifest["oracle"]["sha256"], "observed_output_sha256": digest(output)}
        measurements[a["id"]]["process_wall_seconds"] = []
        output, _ = execute_owned(root, a, ["--bench", str(iterations)], log=commands)
        require(output == f"{bench_expected}\n".encode(), "owned_benchmark_oracle_mismatch")
    orders = []
    for index in range(samples):
        order = artifacts[index % 3:] + artifacts[:index % 3]
        if index % 2:
            order = list(reversed(order))
        orders.append([a["id"] for a in order])
        for a in order:
            output, elapsed = execute_owned(root, a, ["--bench", str(iterations)], log=commands)
            require(output == f"{bench_expected}\n".encode(), "owned_benchmark_oracle_mismatch")
            measurements[a["id"]]["process_wall_seconds"].append(elapsed)
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), "unknown")
    import platform
    result = {"schema": "aegis.reconstruction.measurements.v1", "comparison_sha256": identity(manifest),
        "manifest": manifest, "measured_at": stamp(), "cpu": cpu, "platform": platform.platform(),
        "python": sys.version.split()[0], "samples": samples, "warmups": 1, "iterations": iterations,
        "sample_order": orders, "commands": commands, "measurements": measurements,
        "candidate_execution": "unavailable_no_validated_isolation", "evidence": [],
        "limitations": [f"Single owned fixture, {len(targets)} selected uint32 functions, {len(oracle['cases'])} public cases; finite regression evidence only.",
            "Unpinned shared host; process wall timings include startup, scheduling and frequency noise.",
            "Symbol and machine-byte observations are structural, not reverse-engineering resistance.",
            "Shield site counts are plugin claims; final target bytes are independently read from the ELF.",
            "The owned measurement run performed no Ghidra, REA, model request or candidate compilation/execution.",
            "Build metadata and evidence files are unsigned; hashes check consistency, not origin."]}
    # Recheck both binary identities and tool identities after all measurements.
    validate_manifest(manifest, root)
    for name in ("clang", "opt", "llvm-link"):
        require(digest(read_file(Path("/usr/bin", name).resolve())) == tools[name]["sha256"], "tool_changed")
    write_json(root / "comparison.json", manifest)
    write_json(root / "measurements.json", result)
    (root / "RESULTS.md").write_text(render(result), encoding="utf-8")
    return result


def render(r):
    exact(r, "schema comparison_sha256 manifest measured_at cpu platform python samples warmups iterations "
          "sample_order commands measurements candidate_execution evidence limitations")
    require(r.get("schema") == "aegis.reconstruction.measurements.v1", "unsupported_measurements")
    m = r["manifest"]
    require(identity(m) == r["comparison_sha256"], "measurement_binding_mismatch")
    require(r["candidate_execution"] == "unavailable_no_validated_isolation", "unsupported_execution_claim")
    integer(r["samples"], 3, 101)
    require(type(r["evidence"]) is list, "invalid_import_results")
    allowed = {"structural_observation", "candidate_text_unscored", "generation_observation",
               "behavioral_suite_match", "behavioral_suite_mismatch", "attack_failed", "inconclusive"}
    evidence_keys = set()
    for e in r["evidence"]:
        require(e.get("classification") in allowed and e.get("comparison_sha256") == identity(m),
                "unsupported_evidence_claim")
        a = next((a for a in m["artifacts"] if a["id"] == e.get("artifact_id")), None)
        require(a is not None and e.get("artifact_sha256") == a["file"]["sha256"], "evidence_artifact_mismatch")
        require(e.get("security_property", "not_established") == "not_established", "unsupported_security_claim")
        key = (e["artifact_id"], sha(e.get("source_sha256")))
        require(key not in evidence_keys, "duplicate_evidence")
        evidence_keys.add(key)
    lines = ["# Reconstruction benchmark results", "", "Generated from actual final binaries and owned oracle runs.",
        "No reverse-engineering resistance or general security property is established.", "",
        f"Measured at: {r['measured_at']}. CPU: {r['cpu']}. Platform: {r['platform']}.",
        f"LLVM: {m['build_conditions']['tools']['clang']['version']}; Python: {r['python']}; seed: 42.",
        f"Timing: {r['samples']} samples per variant, {r['warmups']} warmup, {r['iterations']:,} iterations/sample; "
        "both target functions per iteration. Process wall time, shared host, no CPU pinning.", "",
        "| Variant | ELF bytes | .text bytes | Target symbols / dynamic exports | Target bytes vs baseline | Mirage retained | Oracle cases | Wall median [min, max] ms | Behavioral evidence |",
        "| --- | ---: | ---: | --- | --- | --- | --- | --- | --- |"]
    for a in m["artifacts"]:
        v = r["measurements"][a["id"]]
        times = v["process_wall_seconds"]
        require(len(times) == r["samples"] and all(type(t) in (float, int) and 0 < t < 30 for t in times),
                "invalid_timing_samples")
        visible = sum(x is not None for x in v["targets"].values())
        dynamic = sum(x is not None and x["dynamic_export"] for x in v["targets"].values())
        retained = v["mirage_retention"]
        evidence = [e for e in r["evidence"] if e["artifact_id"] == a["id"]]
        behavioral = [e["classification"] for e in evidence if e["kind"] == "behavioral_receipt"]
        status = ", ".join(behavioral) if behavioral else "absent; scoring unavailable"
        lines.append(f"| {a['variant']} | {v['executable_bytes']} | {v['text_bytes']} | {visible}/{len(m['targets'])} / {dynamic} | "
            f"{v['target_code_comparison']} | {retained['observed']}/{retained['expected']} | "
            f"{v['correctness']['status']} {v['correctness']['cases']} | "
            f"{statistics.median(times)*1000:.3f} [{min(times)*1000:.3f}, {max(times)*1000:.3f}] | {status} |")
    lines += ["", "Exact final artifact SHA-256:", ""]
    for a in m["artifacts"]:
        lines.append(f"- `{a['variant']}`: `{a['file']['sha256']}`")
    lines += ["", "Imported analysis and reconstruction evidence:", ""]
    if not r["evidence"]:
        lines.append("Absent. No attack was scored. Behavioral scoring is unavailable without validated isolation.")
    else:
        lines += ["| Artifact | Evidence kind | Classification | Provider-reported tokens | Estimated micro-USD |",
                  "| --- | --- | --- | ---: | ---: |"]
        for e in r["evidence"]:
            tokens = e.get("reported_total_tokens")
            cost = e.get("estimated_reported_cost_microusd")
            lines.append(f"| {e['artifact_id']} | {e['kind']} | {e['classification']} | "
                         f"{tokens if tokens is not None else 'unknown/not applicable'} | "
                         f"{cost if cost is not None else 'unknown/not applicable'} |")
        lines += ["", "Provider usage is reported, estimates are not invoices, and unsigned archives do not attest provider origin. "
                  "Candidate text and parser acceptance are separate from behavioral reconstruction."]
    lines += ["", f"Comparison identity (canonical JSON SHA-256): `{r['comparison_sha256']}`.",
        f"Frozen oracle SHA-256: `{m['oracle']['sha256']}`.", "",
        "Shield IR sites reported (module / selected targets): " + ", ".join(
            f"{a['variant']}={r['measurements'][a['id']]['shield_ir_sites_reported']}/"
            f"{r['measurements'][a['id']]['shield_selected_ir_sites_reported']}"
                                                 for a in m["artifacts"]) + ".",
        "Function byte comparisons measure structural differences. They do not attribute a particular retained "
        "Shield transformation, and they do not establish attack resistance. Mirage retention counts show "
        "defined executable function bodies in the final ELF, not whether an analyst was misled.", "",
        "Limitations:", ""] + ["- " + s for s in r["limitations"]]
    lines += ["", "Reproduce using the commands in [README.md](README.md). `measured-results.json` retains all raw timing "
        "samples, commands, compiler/tool hashes, source hashes, build flags and the comparison manifest. "
        "Full binary/IR/report archives stay outside the repository.", ""]
    return "\n".join(lines)


def report_archive(measurement_path, records=(), trusted_receipts=(), now=None):
    """Re-read actual artifacts before adding independently checked evidence to a report."""
    from evidence import verify_record
    r = load(measurement_path)
    m, root = r["manifest"], Path(measurement_path).parent
    oracle = validate_manifest(m, root, now)
    actual = measure_static(m, root)
    for a in m["artifacts"]:
        recorded = r["measurements"][a["id"]]
        require(all(recorded.get(k) == value for k, value in actual[a["id"]].items()), "stale_static_measurements")
        correct = recorded["correctness"]
        exact(correct, "status cases oracle_sha256 observed_output_sha256")
        expected = "".join(str(c["expected"]) + "\n" for c in oracle["cases"]).encode()
        require(correct == {"status": "passed", "cases": len(oracle["cases"]), "oracle_sha256": m["oracle"]["sha256"],
                            "observed_output_sha256": digest(expected)}, "invalid_correctness_record")
    require(timestamp(m["created_at"]) <= timestamp(r["measured_at"]) <= min(timestamp(m["valid_until"]), now or utcnow()),
            "stale_measurements")
    r["evidence"] = [verify_record(load(p), Path(p).parent, m, root,
                                   trusted_receipts=trusted_receipts, now=now) for p in records]
    render(r)  # Check duplicate evidence and unsupported classifications before returning.
    return r


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("demo", help="build/run only the pinned, owned fixtures")
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--plugin", type=Path, required=True, help="operator-trusted LLVM 22 Shield plugin")
    p.add_argument("--samples", type=int, default=9)
    p.add_argument("--iterations", type=int, default=2000000)
    p.add_argument("--target", action="append", choices=TARGETS, help="selected functions; default both owned targets")
    p = sub.add_parser("verify", help="read and hash only; never execute artifacts")
    p.add_argument("comparison", type=Path)
    p.add_argument("--as-of", help="explicit retrospective validation time, UTC ending Z")
    p = sub.add_parser("render", help="render a recorded measurement snapshot; not a new verification")
    p.add_argument("measurements", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("report", help="recheck an actual archive and import evidence before rendering")
    p.add_argument("measurements", type=Path)
    p.add_argument("--evidence", type=Path, action="append", default=[])
    p.add_argument("--trust-receipt", action="append", default=[])
    p.add_argument("--as-of", help="explicit retrospective UTC time")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--json-output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            r = demo(args.output_dir, args.plugin, samples=args.samples, iterations=args.iterations,
                     targets=sorted(set(args.target)) if args.target else None)
            print("measured " + r["comparison_sha256"])
        elif args.command == "verify":
            m = load(args.comparison)
            validate_manifest(m, args.comparison.parent, timestamp(args.as_of) if args.as_of else None)
            measure_static(m, args.comparison.parent)
            print("bindings_checked " + identity(m) + (" retrospective" if args.as_of else " current"))
        elif args.command == "render":
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(render(load(args.measurements)))
        else:
            r = report_archive(args.measurements, args.evidence, args.trust_receipt,
                               timestamp(args.as_of) if args.as_of else None)
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(render(r))
            if args.json_output:
                write_json(args.json_output, r)
    except (Invalid, OSError, KeyError, TypeError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Invalid) else "invalid_input_or_environment", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
