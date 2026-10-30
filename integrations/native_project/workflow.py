"""Optional native build consumer of the unchanged aegis.adapter.v1 protocol."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import sys
import time
import uuid

from ir import compare_functions, select
from runner import Failure, Runner, digest, read_json, regular, write_json

REPO = Path(__file__).resolve().parents[2]
SCHEMA = "aegis.native-project.v1"
DEFAULT_LIMIT = 64 * 1024**2


def fields(value, allowed, required=()):
    if type(value) is not dict or value.keys() - set(allowed) or set(required) - value.keys():
        raise Failure("INVALID_MANIFEST", "Missing or unknown manifest fields.")


def strings(value, *, nonempty=False):
    if (type(value) is not list or len(value) > 4096 or (nonempty and not value)
            or any(type(s) is not str or not s or "\x00" in s or len(s) > 8192 for s in value)):
        raise Failure("INVALID_MANIFEST", "Expected a bounded array of nonempty strings.")
    return value


def canonical(base, value):
    if type(value) is not str or not value or "\x00" in value:
        raise Failure("INVALID_MANIFEST", "Expected a nonempty path string.")
    path = Path(value)
    path = path if path.is_absolute() else base / path
    # Normalize '..' but refuse symbolic links in any remaining component.
    path = Path(os.path.abspath(path))
    if path.resolve() != path:
        raise Failure("UNSAFE_PATH", "Symlinked input and output paths are unsupported.")
    return path


def normalize_flags(arguments, cwd, source=None):
    """Translate a deliberately limited clang compile invocation, never a shell.

    Only optimization/output/dependency bookkeeping flags are replaced. Every
    other unsupported option is an explicit error rather than silently dropped.
    """
    arguments = strings(arguments)
    result, removed = [], []
    i = 0
    while i < len(arguments):
        arg = arguments[i]
        if arg == "-Ofast":
            raise Failure("INCOMPATIBLE_UNIT", "-Ofast changes language semantics; supply explicit supported flags.")
        if arg in ("-o", "-MF", "-MT", "-MQ"):
            if i + 1 >= len(arguments):
                raise Failure("INCOMPATIBLE_UNIT", "Missing compiler option value.")
            removed.extend(arguments[i:i + 2])
            i += 2
            continue
        if arg in ("-c", "-MD", "-MMD", "-MP") or re.fullmatch(r"-O(?:[0-3sgz])?", arg):
            removed.append(arg)
        elif arg in ("-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros", "-D", "-U"):
            if i + 1 >= len(arguments):
                raise Failure("INCOMPATIBLE_UNIT", "Missing compiler option value.")
            value = arguments[i + 1]
            if value.startswith("-") or value.startswith("@"):
                raise Failure("INCOMPATIBLE_UNIT", "Unsafe compiler option value.")
            result.extend([arg, value])
            i += 1
        elif (re.fullmatch(r"-(?:D|U|I).+", arg)
              or re.fullmatch(r"-std=(?:c|gnu)(?:\+\+)?[0-9a-z]+", arg)
              or re.fullmatch(r"-W(?:all|extra|pedantic|error(?:=[-a-z0-9]+)?|no-[-a-z0-9]+|[-a-z0-9]+)", arg)
              or re.fullmatch(r"-g(?:[0-3]|line-tables-only)?", arg)
              or arg in {"-pthread", "-pedantic", "-pipe", "-fPIC", "-fpic", "-fPIE", "-fpie",
                         "-fno-exceptions", "-fexceptions", "-fno-rtti", "-frtti", "-fwrapv",
                         "-fno-strict-aliasing", "-fstrict-aliasing", "-fno-omit-frame-pointer",
                         "-fomit-frame-pointer", "-ffunction-sections", "-fdata-sections",
                         "-fno-builtin", "-fno-common", "-fcommon", "-funsigned-char", "-fsigned-char",
                         "-fvisibility=hidden", "-fvisibility=default", "-fvisibility-inlines-hidden"}):
            result.append(arg)
        elif source is not None and not arg.startswith("-") and canonical(cwd, arg) == source:
            removed.append(arg)
        else:
            raise Failure("INCOMPATIBLE_UNIT", "Compiler option is outside the supported clang subset.",
                          option=arg)
        i += 1
    return result, removed


def load_manifest(path):
    path = canonical(Path.cwd(), str(path))
    manifest = read_json(path)
    fields(manifest, {"schema_version", "project_root", "compile_database", "units", "backend",
                      "options", "optimization", "link"}, {"schema_version", "project_root", "units"})
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise Failure("INVALID_MANIFEST", "schema_version must be integer 1.")
    root = canonical(path.parent, manifest["project_root"])
    if not root.is_dir():
        raise Failure("INVALID_MANIFEST", "Project root is not a directory.")
    backend = manifest.get("backend", "llvm-shield")
    if backend not in ("llvm-shield", "llvm-shield-mirage"):
        raise Failure("UNSUPPORTED_BACKEND", "Only the two production LLVM protection adapters are supported.")
    options = manifest.get("options", {"seed": "42"})
    fields(options, {"seed", "max-sites", "enabled"} | (
        {"mirage-seed", "mirage-count", "mirage-enabled"} if backend == "llvm-shield-mirage" else set()))
    # Full option typing/ranges belong to the unchanged production adapters.
    if len(json.dumps(options)) > 16384:
        raise Failure("INVALID_MANIFEST", "Options exceed the local bound.")
    optimization = manifest.get("optimization", "2")
    if type(optimization) is not str or optimization not in ("0", "1", "2", "3", "s", "z"):
        raise Failure("INVALID_MANIFEST", "optimization must be a string: 0, 1, 2, 3, s or z.")
    db = None
    if "compile_database" in manifest:
        db_path = canonical(path.parent, manifest["compile_database"])
        db = read_json(db_path, 16 * 1024**2)
        if type(db) is not list or len(db) > 100000 or any(type(e) is not dict for e in db):
            raise Failure("INVALID_MANIFEST", "Invalid compile database.")
    raw_units = manifest["units"]
    if type(raw_units) is not list or not 1 <= len(raw_units) <= 128:
        raise Failure("INVALID_MANIFEST", "Declare between 1 and 128 translation units.")
    units, seen = [], set()
    for raw in raw_units:
        fields(raw, {"source", "arguments", "selection", "protect"}, {"source"})
        source = canonical(root, raw["source"])
        if not source.is_relative_to(root) or source in seen:
            raise Failure("UNSAFE_PATH", "Sources must be unique and contained in the project root.")
        seen.add(source)
        if source.suffix not in (".c", ".cc", ".cpp", ".cxx", ".C"):
            raise Failure("INCOMPATIBLE_UNIT", "Only C/C++ translation units are supported.")
        protect = raw.get("protect", True)
        if type(protect) is not bool:
            raise Failure("INVALID_MANIFEST", "protect must be a boolean.")
        selection = raw.get("selection", {"mode": "annotated"})
        fields(selection, {"mode", "symbols"}, {"mode"})
        if selection["mode"] not in ("annotated", "integer-signatures", "symbols"):
            raise Failure("INVALID_MANIFEST", "Unknown function selection mode.")
        if selection["mode"] == "symbols":
            names = strings(selection.get("symbols"), nonempty=True)
            if len(set(names)) != len(names):
                raise Failure("INVALID_MANIFEST", "Selected symbols must be unique.")
        elif "symbols" in selection:
            raise Failure("INVALID_MANIFEST", "symbols requires symbols selection mode.")
        cwd, args = root, raw.get("arguments", [])
        if db is not None:
            if "arguments" in raw:
                raise Failure("INVALID_MANIFEST", "Unit arguments cannot override a compile database entry.")
            matches = []
            for entry in db:
                directory = canonical(path.parent, entry.get("directory"))
                if canonical(directory, entry.get("file")) == source:
                    matches.append((entry, directory))
            if len(matches) != 1:
                raise Failure("INCOMPATIBLE_UNIT", "Source must have exactly one compile database entry.",
                              source=str(source), matching_entries=len(matches))
            entry, cwd = matches[0]
            args = entry.get("arguments")
            if args is None:
                if type(entry.get("command")) is not str:
                    raise Failure("INVALID_MANIFEST", "Compile entry needs arguments or command.")
                args = shlex.split(entry["command"], posix=True)
            strings(args, nonempty=True)
            if not re.fullmatch(r"clang(?:\+\+)?(?:-22)?", Path(args[0]).name):
                raise Failure("INCOMPATIBLE_UNIT", "Compile database must use a direct clang driver.")
            args = args[1:]
        # Unsupported flags become a per-unit failure in build(), allowing a full report.
        units.append({"source": str(source), "relative_source": str(source.relative_to(root)),
                      "cwd": str(cwd), "arguments": args, "protect": protect, "selection": selection})
    if not any(u["protect"] for u in units):
        raise Failure("INVALID_MANIFEST", "At least one translation unit must request protection.")
    link = manifest.get("link")
    if link is not None:
        fields(link, {"arguments", "runs"})
        for arg in strings(link.get("arguments", [])):
            if arg not in ("-Wl,--gc-sections", "-pthread", "-no-pie") and not re.fullmatch(r"-l[a-zA-Z0-9_+-]+", arg):
                raise Failure("INVALID_MANIFEST", "Unsupported link argument.", option=arg)
        runs = link.get("runs", [])
        if type(runs) is not list or len(runs) > 256:
            raise Failure("INVALID_MANIFEST", "At most 256 execution cases are supported.")
        for run in runs:
            fields(run, {"args", "expected_exit"}, {"args"})
            # Empty arguments are useful and safe for native programs.
            if (type(run["args"]) is not list or len(run["args"]) > 128 or any(
                    type(a) is not str or "\x00" in a or len(a) > 8192 for a in run["args"])):
                raise Failure("INVALID_MANIFEST", "Invalid execution argument array.")
            status = run.get("expected_exit", 0)
            if type(status) is not int or not 0 <= status <= 255:
                raise Failure("INVALID_MANIFEST", "expected_exit must be 0..255.")
    return {"manifest": str(path), "manifest_sha256": digest(path), "project_root": str(root),
            "compile_database_entries": len(db) if db is not None else None,
            "compile_database_sha256": digest(db_path) if db is not None else None,
            "backend": backend, "options": options, "optimization": optimization,
            "units": units, "link": link}


def resolve_tools(paths, runner):
    tools, versions = {}, {}
    for name in ("clang", "clang++", "opt", "llvm-link"):
        found = shutil.which(paths.get(name, name))
        if not found:
            raise Failure("TOOL_UNAVAILABLE", "Required LLVM executable is unavailable.", tool=name)
        tools[name] = str(Path(found).absolute())
        raw, _, _ = runner.run([tools[name], "--version"], runner.root, stage="version")
        match = re.search(rb"(?:LLVM|clang) version (22\.\d+\.\d+)(?:\s|$)", raw)
        if not match:
            raise Failure("UNSUPPORTED_LLVM", "Every tool must be LLVM 22.x.", tool=name)
        versions[name] = match[1].decode("ascii")
    if len(set(versions.values())) != 1:
        raise Failure("UNSUPPORTED_LLVM", "All LLVM tool versions must match exactly.")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise Failure("UNSUPPORTED_PLATFORM", "Native integration currently supports Linux x86-64.")
    return tools, versions


def adapter_job(runner, tools, plugin, ir, backend, options, input_limit, output_limit):
    """Supervise the actual production adapter in its required private job layout.

    This consumer owns hashes and group timeout. These are native build records,
    not Core jobs, provenance signatures, or EvidenceRecord objects.
    """
    job_id = uuid.uuid4().hex
    job = runner.root / "adapter-jobs" / job_id
    for name in ("inputs", "outputs", "work", "adapter"):
        (job / name).mkdir(parents=True, mode=0o700)
    source = job / "inputs" / "unit.ll"
    regular(ir, input_limit, code="INPUT_TOO_LARGE")
    shutil.copyfile(ir, source)
    source_hash = digest(source)
    request = {"protocol": "aegis.adapter.v1", "job_id": job_id, "task": "protect",
               "backend": backend, "policy_name": "native-project", "input_path": str(source),
               "input_sha256": source_hash, "output_dir": str(job / "outputs"),
               "options": options, "authorization": None}
    request_path = job / "adapter" / "request.json"
    write_json(request_path, request)
    script = REPO / "protectors/llvm/adapter" / (
        "aegis_llvm_adapter.py" if backend == "llvm-shield" else "aegis_shield_mirage_adapter.py")
    command = [sys.executable, "-E", "-s", str(script), "--opt", tools["opt"], "--plugin", str(plugin),
               "--max-input-bytes", str(input_limit), "--max-output-bytes", str(output_limit),
               "--aegis-request", str(request_path)]
    if backend == "llvm-shield-mirage":
        command.extend(["--clang", tools["clang"], "--llvm-link", tools["llvm-link"]])
    stdout, _, _ = runner.run(command, job / "work", stage="adapter")
    write_json(job / "native-request-record.json", {"job_id": job_id, "input_sha256": source_hash,
                                                   "record_owner": "native-project consumer"})
    if digest(source) != source_hash or digest(ir) != source_hash:
        raise Failure("ARTIFACT_INTEGRITY_ERROR", "Input changed during adapter invocation.")
    try:
        result = json.loads(stdout)
    except (ValueError, RecursionError) as exc:
        raise Failure("ADAPTER_INVALID_OUTPUT", "Adapter stdout is not valid JSON.") from exc
    write_json(job / "adapter-result.json", result)
    if type(result) is not dict or result.get("protocol") != "aegis.adapter.v1":
        raise Failure("ADAPTER_INVALID_OUTPUT", "Invalid production adapter response.")
    if result.get("status") == "failed":
        raise Failure("ADAPTER_FAILED", "Production adapter failed; no protected object is registered.",
                      adapter_error=result.get("error"), job_id=job_id)
    expected = {"protected.ll", "shield-report.json"}
    if backend == "llvm-shield-mirage":
        expected |= {"shield-stage.ll", "mirage-report.json"}
    if (result.get("status") != "succeeded" or result.get("error") is not None
            or result.get("attack_evaluations") != [] or type(result.get("outputs")) is not list
            or any(type(o) is not dict or set(o) != {"path"} or type(o["path"]) is not str
                   for o in result["outputs"])
            or len(result["outputs"]) != len(expected)
            or {o["path"] for o in result["outputs"]} != expected):
        raise Failure("ADAPTER_INVALID_OUTPUT", "Unexpected production adapter outputs.")
    artifacts = {}
    for name in sorted(expected):
        path = job / "outputs" / name
        regular(path, output_limit)
        artifacts[name] = {"path": str(path.relative_to(runner.root)), "sha256": digest(path),
                           "size_bytes": path.stat().st_size}
    report = read_json(job / "outputs/shield-report.json", 4 * 1024**2)
    mirage = read_json(job / "outputs/mirage-report.json", 4 * 1024**2) if "mirage-report.json" in expected else None
    if mirage is not None and (mirage["input_sha256"] != artifacts["shield-stage.ll"]["sha256"]
                               or mirage["output_sha256"] != artifacts["protected.ll"]["sha256"]):
        raise Failure("ARTIFACT_INTEGRITY_ERROR", "Mirage chain hashes do not match output bytes.")
    runner.run([tools["opt"], "-passes=verify", "-disable-output", job / "outputs/protected.ll"],
               job / "work", stage="verify-protected-ir")
    return job / "outputs/protected.ll", report, mirage, {"job_id": job_id, "artifacts": artifacts,
                                                        "adapter_claims": result.get("evidence", [])}


def unit_options(base, backend, relative_source):
    result = dict(base)
    if backend == "llvm-shield-mirage":
        # Mirage's external decoy names depend only on seed. Reusing one seed in
        # multiple TUs produces duplicate definitions at link time.
        seed = base.get("mirage-seed", base.get("seed", "0"))
        if type(seed) is not str or not re.fullmatch(r"[0-9]{1,20}", seed) or int(seed) >= 2**63:
            raise Failure("INVALID_OPTIONS", "Combined builds require a decimal Mirage base seed below 2^63.")
        material = f"aegis.native-project.mirage.v1:{int(seed)}:{relative_source}".encode()
        result["mirage-seed"] = str(int.from_bytes(hashlib.sha256(material).digest()[:8], "big") % 2**63)
    return result


def build_unit(unit, directory, runner, tools, plugin, plan, input_limit, output_limit, record):
    directory.mkdir(mode=0o700)
    source, cwd = Path(unit["source"]), Path(unit["cwd"])
    regular(source, input_limit, code="INPUT_TOO_LARGE")
    source_hash = digest(source)
    record["source_sha256"] = source_hash
    flags, removed = normalize_flags(unit["arguments"], cwd, source)
    record.update({"effective_compile_flags": flags, "replaced_compile_arguments": removed})
    compiler = tools["clang"] if source.suffix == ".c" else tools["clang++"]
    common = [compiler, *flags]
    optimization = "-O" + plan["optimization"]
    # A normal source baseline and a matched IR baseline distinguish frontend
    # pipeline effects from changes caused by the protection adapter.
    native = directory / "native.o"
    runner.run([*common, optimization, "-c", source, "-o", native], cwd,
               watched=[(native, output_limit)], stage="compile-native")
    unmarked = directory / "input.ll"
    runner.run([*common, "-O1", "-Xclang", "-disable-llvm-passes", "-S", "-emit-llvm",
                source, "-o", unmarked], cwd, watched=[(unmarked, input_limit)], stage="emit-ir")
    regular(unmarked, input_limit, code="INPUT_TOO_LARGE")
    text = unmarked.read_text(encoding="utf-8")
    if unit["protect"]:
        text, selection = select(text, unit["selection"])
    else:
        from ir import definitions
        funcs = definitions(text)
        selection = {"definitions": len(funcs), "integer_signature_candidates": sum(
            f["integer_signature"] for f in funcs), "marked_by_integration": []}
    record["selection_observations"] = selection
    marked = directory / "selected.ll"
    marked.write_text(text, encoding="utf-8")
    regular(marked, input_limit, code="INPUT_TOO_LARGE")
    runner.run([tools["opt"], "-passes=verify", "-disable-output", marked], directory, stage="verify-input-ir")
    baseline = directory / "baseline.o"
    runner.run([*common, optimization, "-Wno-unused-command-line-argument", "-c", marked, "-o", baseline],
               cwd, watched=[(baseline, output_limit)], stage="compile-baseline-ir")
    chosen, transformed, decoys = marked, [], []
    if unit["protect"]:
        options = unit_options(plan["options"], plan["backend"], unit["relative_source"])
        record["effective_adapter_options"] = options
        chosen, report, mirage, job_record = adapter_job(
            runner, tools, plugin, marked, plan["backend"], options, input_limit, output_limit)
        record["adapter"] = job_record
        transformed = [f["name"] for f in report["functions"] if f["status"] == "transformed"]
        record["adapter_reported_coverage"] = {
            "source": "adapter", "reported_functions": len(report["functions"]),
            "annotated_functions": sum(f["annotated"] for f in report["functions"]),
            "transformed_functions": transformed, "transformed_sites": report["transformed_sites"],
            "reasons": {reason: sum(f["reason"] == reason for f in report["functions"])
                        for reason in sorted({f["reason"] for f in report["functions"]})}}
        decoys = mirage["inserted_functions"] if mirage is not None else []
    protected = directory / "protected.o"
    runner.run([*common, optimization, "-Wno-unused-command-line-argument", "-c", chosen, "-o", protected],
               cwd, watched=[(protected, output_limit)], stage="compile-protected-ir")
    for artifact in (native, baseline, protected):
        regular(artifact, output_limit)
    if digest(source) != source_hash:
        raise Failure("ARTIFACT_INTEGRITY_ERROR", "Source changed during the build.")
    record["native_observations"] = compare_functions(baseline, protected, transformed, decoys)
    record["objects"] = {name: str(path.relative_to(runner.root)) for name, path in (
        ("native", native), ("baseline", baseline), ("protected", protected))}
    record["status"] = "transformed" if unit["protect"] else "unprotected"
    return transformed, decoys


def link_and_run(plan, records, runner, tools, execute, transformed, decoys, report):
    link = plan["link"]
    if link is None:
        report["execution"] = {"status": "not_run", "reason": "object-only manifest"}
        return
    binaries = {}
    for variant in ("native", "baseline", "protected"):
        binary = runner.root / f"{variant}.elf"
        objects = [runner.root / record["objects"][variant] for record in records]
        runner.run([tools["clang++"], *objects, *link.get("arguments", []), "-o", binary],
                   runner.root, watched=[(binary, report["limits"]["output_bytes"])], stage="link-" + variant)
        regular(binary, report["limits"]["output_bytes"])
        binaries[variant] = binary
    report["binaries"] = {name: str(path.relative_to(runner.root)) for name, path in binaries.items()}
    # Names duplicated across translation units cannot be attributed unambiguously.
    report["linked_native_observations"] = compare_functions(
        binaries["baseline"], binaries["protected"], sorted(set(transformed)), decoys)
    if not execute:
        report["execution"] = {"status": "not_run", "reason": "--execute was not specified"}
        return
    runs = link.get("runs", [])
    if not runs:
        raise Failure("INVALID_MANIFEST", "--execute requires explicit run cases in the manifest.")
    cases = []
    report["execution"] = {"status": "running", "cases": cases,
                           "comparison": "exact exit status, stdout bytes and stderr bytes across 3 variants"}
    for index, case in enumerate(runs):
        values, observations = [], {}
        for variant, binary in binaries.items():
            # Separate empty cwd per case/variant prevents baseline side effects
            # from becoming protected inputs. Programs still run on the host.
            cwd = runner.root / "runs" / f"{index:04d}" / variant
            cwd.mkdir(mode=0o700, parents=True)
            value = runner.run([binary, *case["args"]], cwd,
                               expected=(case.get("expected_exit", 0),), stage="execute-" + variant)
            values.append(value)
            observations[variant] = {"stdout_sha256": hashlib.sha256(value[0]).hexdigest(),
                                     "stderr_sha256": hashlib.sha256(value[1]).hexdigest(),
                                     "returncode": value[2]}
        equal = values[0] == values[1] == values[2]
        cases.append({"args": case["args"], "equal": equal, "observations": observations})
        if not equal:
            report["execution"]["status"] = "failed"
            raise Failure("EXECUTION_MISMATCH", "Native, matched baseline and protected outputs differ.", case=index)
    report["execution"]["status"] = "equivalent_for_cases"


def coverage(records, plan):
    transformed = [r for r in records if r["status"] == "transformed"]
    return {"scope": "declared translation units only; dependencies and undeclared sources excluded",
            "declared_units": len(plan["units"]), "database_entries": plan["compile_database_entries"],
            "requested_units": sum(r["protect"] for r in records), "transformed_units": len(transformed),
            "unprotected_units": sum(r["status"] == "unprotected" for r in records),
            "failed_units": sum(r["status"] == "failed" for r in records),
            "not_attempted_units": sum(r["status"] == "not_attempted" for r in records),
            "definitions_observed": sum(r.get("selection_observations", {}).get("definitions", 0) for r in records),
            "adapter_reported_transformed_functions": sum(len(r["adapter_reported_coverage"]["transformed_functions"])
                                                         for r in transformed),
            "adapter_reported_transformed_sites": sum(r["adapter_reported_coverage"]["transformed_sites"]
                                                      for r in transformed),
            "machine_byte_different_functions_in_objects": sum(
                sum(f["observation"] == "machine_bytes_differ" for f in r.get("native_observations", {}).get(
                    "shield_functions", [])) for r in transformed),
            "entire_application_protection_claimed": False}


def build(plan, output, *, plugin, tool_paths=None, execute=False, timeout=60,
          input_limit=DEFAULT_LIMIT, output_limit=128 * 1024**2):
    output = canonical(Path.cwd(), str(output))
    if output.is_relative_to(REPO) or output.is_relative_to(Path(plan["project_root"])):
        raise Failure("UNSAFE_PATH", "Generated output must be outside the repository and project source root.")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    runner = Runner(output, timeout, max(output_limit, 4 * 1024**2))
    report = {"schema": SCHEMA, "status": "running", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "plan": plan, "units": [{"source": u["relative_source"], "protect": u["protect"],
                                       "status": "not_attempted"} for u in plan["units"]],
              "commands": runner.commands,
              "limits": {"timeout_seconds_per_command": timeout, "input_bytes": input_limit,
                         "output_bytes": output_limit, "diagnostic_bytes_per_stream": runner.log_limit,
                         "hard_file_bytes_per_child": runner.file_limit},
              "limitations": ["No established security property or attack resistance.",
                              "Adapter transformation counts are adapter claims, not independent security evidence.",
                              "Execution checks only declared cases, stdout/stderr and exit codes; not general equivalence.",
                              "Trusted host tools and source only; not a sandbox or an aggregate resource quota.",
                              "Headers, libraries, tool binaries and concurrent writers are not sealed or fully inventoried.",
                              "Native build records are unsigned; they are not Core jobs or provenance attestations."]}
    try:
        tools, versions = resolve_tools(tool_paths or {}, runner)
        report["toolchain"] = {"paths": tools, "versions": versions,
                               "host": platform.platform(), "machine": platform.machine()}
        plugin = Path(plugin).absolute()
        # Operator-trusted plugin may be a symlink; snapshot its actual bytes.
        if not plugin.is_file():
            raise Failure("PLUGIN_UNAVAILABLE", "Shield plugin is unavailable.")
        report["plugin"] = {"path": str(plugin), "sha256": digest(plugin)}
        records = report["units"]
        all_transformed, all_decoys = [], []
        for index, (unit, record) in enumerate(zip(plan["units"], records)):
            record["status"] = "running"
            try:
                transformed, decoys = build_unit(unit, output / f"unit-{index:03d}", runner, tools,
                                                 plugin, plan, input_limit, output_limit, record)
                all_transformed.extend(transformed)
                all_decoys.extend(decoys)
            except Failure as exc:
                record.update({"status": "failed", "error": exc.record()})
            except (OSError, UnicodeError) as exc:
                record.update({"status": "failed", "error": {"code": "UNIT_IO_ERROR",
                               "message": "Source or generated unit artifacts are unavailable or invalid.",
                               "details": {"type": type(exc).__name__}}})
        report["coverage"] = coverage(records, plan)
        if any(r["status"] == "failed" for r in records):
            raise Failure("BUILD_FAILED", "One or more units failed; linking and execution were not performed.")
        link_and_run(plan, records, runner, tools, execute, all_transformed, all_decoys, report)
        if digest(plugin) != report["plugin"]["sha256"]:
            raise Failure("ARTIFACT_INTEGRITY_ERROR", "Plugin changed during the build.")
        report["status"] = "succeeded"
    except Failure as exc:
        report.update({"status": "failed", "error": exc.record()})
        if report.get("execution", {}).get("status") == "running":
            report["execution"]["status"] = "failed"
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        report.update({"status": "failed", "error": {"code": "BUILD_IO_ERROR",
                       "message": "Build files or reports could not be processed.", "details": {"type": type(exc).__name__}}})
    except KeyboardInterrupt:
        report.update({"status": "failed", "error": {"code": "INTERRUPTED", "message": "Build interrupted.", "details": {}}})
        for record in report["units"]:
            if record["status"] == "running":
                record.update({"status": "failed", "error": report["error"]})
    report["coverage"] = coverage(report["units"], plan)
    report.setdefault("execution", {"status": "not_run", "reason": "build failed before execution"})
    report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report["artifacts"] = []
    report["artifact_inventory_complete"] = True
    for path in sorted(output.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        try:
            # Inventory also includes bounded inputs, logs, adapter reports and
            # partial failed files; accepted objects have their own size checks.
            regular(path, max(output_limit, input_limit, runner.file_limit), empty=True)
        except (Failure, OSError) as exc:
            error = exc.record() if isinstance(exc, Failure) else {
                "code": "BUILD_IO_ERROR", "message": "Cannot inventory a build artifact.", "details": {}}
            report.update({"status": "failed", "error": error, "artifact_inventory_complete": False})
            continue
        report["artifacts"].append({"path": str(path.relative_to(output)), "sha256": digest(path),
                                    "size_bytes": path.stat().st_size})
    write_json(output / "report.json", report)
    (output / "report.sha256").write_text(digest(output / "report.json") + "\n", encoding="ascii")
    return report


def verify_report(path):
    path = canonical(Path.cwd(), str(path))
    if digest(path) != path.with_suffix(".sha256").read_text(encoding="ascii").strip():
        raise Failure("ARTIFACT_INTEGRITY_ERROR", "Report digest does not match its sidecar.")
    report = read_json(path, 32 * 1024**2)
    if report.get("schema") != SCHEMA:
        raise Failure("INVALID_MANIFEST", "Unknown native report schema.")
    if report.get("artifact_inventory_complete") is not True:
        raise Failure("INCOMPLETE_INVENTORY", "Build reported an incomplete artifact inventory.")
    root = path.parent
    seen = set()
    for artifact in report["artifacts"]:
        target = canonical(root, artifact["path"])
        if not target.is_relative_to(root) or target in seen:
            raise Failure("UNSAFE_PATH", "Artifact escapes the report directory or is duplicated.")
        seen.add(target)
        info = regular(target, 4 * 1024**3, empty=True)
        if info.st_size != artifact["size_bytes"] or digest(target) != artifact["sha256"]:
            raise Failure("ARTIFACT_INTEGRITY_ERROR", "Artifact size or digest mismatch.", artifact=artifact["path"])
    return {"status": "verified", "build_status": report["status"], "artifact_count": len(seen),
            "signed": False, "report_sha256": digest(path)}
