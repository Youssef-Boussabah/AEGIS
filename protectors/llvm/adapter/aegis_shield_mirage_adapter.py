"""LLVM Shield + Mirage bridge for aegis.adapter.v1 (POSIX, Python >= 3.11).

One verified chain: Core's hash-checked input -> Shield (validated report,
verified IR) -> Mirage decoys added to exactly that Shield output -> plugin-free
LLVM verification of the final module. Neither stage executes or compiles a
native artifact. Run through aegis_core: every LLVM child, including Mirage's,
stays in Core's process group so Core's timeout kills it.
"""

from __future__ import annotations

import hashlib
import importlib
import re
import sys
import tempfile
from pathlib import Path

import aegis_llvm_adapter as shield
from aegis_llvm_adapter import PROTOCOL, fail

# The Mirage transformer is pinned to this checkout (sibling protectors/mirage),
# never to whatever another environment may have installed.
MIRAGE_SRC = Path(__file__).resolve().parents[2] / "mirage" / "src"
MIRAGE_SEED_MAX = 2**63 - 1
MIRAGE_OPTIONS = {"mirage-seed", "mirage-count", "mirage-enabled"}
SHIELD_OPTIONS = {"seed", "max-sites", "enabled"}


def load_mirage():
    if not (MIRAGE_SRC / "aegis_mirage" / "transform.py").is_file():
        fail("TOOL_UNAVAILABLE", "The Mirage transformer is not present beside this adapter.")
    sys.path.insert(0, str(MIRAGE_SRC))
    try:
        mirage = importlib.import_module("aegis_mirage.transform")
    except ImportError:
        fail("TOOL_UNAVAILABLE", "The Mirage transformer could not be loaded.")
    if Path(mirage.__file__).resolve().parent.parent != MIRAGE_SRC:
        fail("TOOL_UNAVAILABLE", "A different Mirage installation shadows this checkout.")
    return mirage


def combined_config(options):
    """Split and validate options. The Shield half keeps llvm-shield's exact rules."""
    if type(options) is not dict or options.keys() - SHIELD_OPTIONS - MIRAGE_OPTIONS:
        fail("INVALID_OPTIONS", "Only seed, max-sites, enabled, mirage-seed, mirage-count "
                                "and mirage-enabled options are supported.")
    config = shield.shield_config({key: options[key] for key in SHIELD_OPTIONS & options.keys()})
    if "mirage-seed" in options:
        seed = options["mirage-seed"]
        if (type(seed) is not str or not re.fullmatch(r"[0-9]{1,19}", seed)
                or int(seed) > MIRAGE_SEED_MAX):
            fail("INVALID_OPTIONS", "mirage-seed must be a decimal string from 0 to 9223372036854775807.")
    elif int(config["seed"]) <= MIRAGE_SEED_MAX:
        seed = config["seed"]  # documented default: Mirage reuses the Shield seed
    else:
        fail("INVALID_OPTIONS", "seed exceeds 9223372036854775807; set mirage-seed explicitly.")
    count = options.get("mirage-count", 3)
    if type(count) is not int or not 1 <= count <= 32:
        fail("INVALID_OPTIONS", "mirage-count must be an integer from 1 to 32.")
    enabled = options.get("mirage-enabled", True)
    if type(enabled) is not bool:
        fail("INVALID_OPTIONS", "mirage-enabled must be a boolean.")
    return config, {"seed": int(seed), "count": count, "enabled": enabled}


def absolute_tool(raw, name):
    if not Path(raw).is_absolute():
        fail("INVALID_CONFIGURATION", f"The {name} path must be absolute.")
    path = Path(raw)
    if not path.is_file():
        fail("TOOL_UNAVAILABLE", f"The configured {name} executable is unavailable.")
    return str(path)


def sha256(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def run_mirage(mirage, args, shield_ir, root, settings, tools, llvm_version):
    """Mirage on the verified Shield output with Core-supervised, bounded tools."""
    file_cap = max(args.max_output_bytes, args.max_report_bytes, shield.LOG_LIMIT)

    def runner(argv, cwd):
        cwd = Path(cwd)
        watched = [(cwd / "decoys.ll", args.max_output_bytes),
                   (cwd / "module.ll", args.max_output_bytes)]
        return shield.run_tool(list(map(str, argv)), cwd, watched, file_cap)

    work, out = root / "mirage-work", root / "mirage-out"
    work.mkdir(mode=0o700)
    try:
        config = mirage.MirageConfig(settings["seed"], settings["enabled"], settings["count"])
        report = mirage.transform(shield_ir, out, config, clang=tools["clang"],
                                  llvm_link=tools["llvm_link"], opt=tools["opt"],
                                  runner=runner, work_dir=work)
    except mirage.MirageError as exc:
        # Mirage error strings are fixed identifiers, never input-derived text.
        fail("MIRAGE_FAILED", f"Mirage stage failed: {exc}.")
    module, report_path = out / "module.ll", out / "report.json"
    shield.regular(module, args.max_output_bytes)
    shield.regular(report_path, args.max_report_bytes)
    shield_digest, final_digest = sha256(shield_ir), sha256(module)
    # Chain checks: Mirage consumed exactly the verified Shield output, and the
    # report describes exactly the module we are about to publish.
    if report["input_sha256"] != shield_digest or report["output_sha256"] != final_digest:
        fail("INVALID_ARTIFACT", "Mirage report does not bind the Shield output and final module.")
    if {t["version"] for t in report["toolchain"].values()} != {llvm_version}:
        fail("UNSUPPORTED_LLVM", "Mirage tools do not match the Shield opt version.")
    if settings["enabled"]:
        if report["inserted_count"] != settings["count"] or final_digest == shield_digest:
            fail("INVALID_ARTIFACT", "Mirage did not insert the configured decoys.")
    elif report["inserted_count"] or final_digest != shield_digest:
        fail("INVALID_ARTIFACT", "Disabled Mirage control must leave the Shield output unchanged.")
    # Independent plugin-free verification of the final module.
    shield.run_tool([tools["opt"], "-passes=verify", "-disable-output", "module.ll"], out,
                    [(module, args.max_output_bytes)], file_cap)
    if sha256(module) != final_digest:
        fail("ARTIFACT_INTEGRITY_ERROR", "Final module changed during verification.")
    return report, module, report_path, shield_digest, final_digest


def mirage_evidence(report, settings, shield_digest, final_digest):
    summary = ("Mirage reports retained, uncalled arithmetic decoy functions added to the Shield output; "
               "no established security property." if settings["enabled"] else
               "Mirage disabled (control): Shield output published unchanged; no decoys inserted.")
    return {"summary": summary,
            "data": {"enabled": settings["enabled"], "configured_count": settings["count"],
                     "inserted_count": report["inserted_count"], "seed": str(settings["seed"]),
                     "report_schema": report["schema_version"],
                     "chain": {"shield_stage_sha256": shield_digest,
                               "mirage_input_sha256": report["input_sha256"],
                               "final_output_sha256": final_digest},
                     "decoy_source_sha256": report["decoy_source_sha256"],
                     "final_artifact_retention": "requires_independent_check",
                     "limitations": "Decoys are unreachable and identifiable; retention after linking "
                                    "and attack resistance are not evaluated by this job."}}


def execute(args):
    work = Path.cwd()
    request, source, output = shield.read_request(Path(args.aegis_request), work)
    config, settings = combined_config(request.get("options", {}))
    opt = shield.tool_path(args.opt)
    plugin = shield.plugin_path(args.plugin)
    tools = {"opt": opt, "clang": absolute_tool(args.clang, "clang"),
             "llvm_link": absolute_tool(args.llvm_link, "llvm-link")}
    mirage = load_mirage()
    with tempfile.TemporaryDirectory(prefix="shield-mirage-", dir=work) as temporary:
        root = Path(temporary)
        scratch = root / "shield"
        scratch.mkdir(mode=0o700)
        shield_report = shield.run_shield(args, request, source, scratch, config, opt, plugin)
        shield_ir = scratch / "protected.ll"
        report, module, report_path, shield_digest, final_digest = run_mirage(
            mirage, args, shield_ir, root, settings, tools, shield_report["llvm_version"])
        # Published names are fixed; Core hashes every one of them.
        for src, name, limit in ((module, "protected.ll", args.max_output_bytes),
                                 (shield_ir, "shield-stage.ll", args.max_output_bytes),
                                 (scratch / "shield-report.json", "shield-report.json", args.max_report_bytes),
                                 (report_path, "mirage-report.json", args.max_report_bytes)):
            shield.publish(src, output / name, limit)
        if sha256(output / "protected.ll") != final_digest or sha256(output / "shield-stage.ll") != shield_digest:
            fail("ARTIFACT_INTEGRITY_ERROR", "Published artifacts differ from the verified chain.")
        return {"protocol": PROTOCOL, "status": "succeeded",
                "outputs": [{"path": "protected.ll"}, {"path": "shield-stage.ll"},
                            {"path": "shield-report.json"}, {"path": "mirage-report.json"}],
                "evidence": [shield.shield_evidence(shield_report),
                             mirage_evidence(report, settings, shield_digest, final_digest)],
                "attack_evaluations": [], "error": None}


def main():
    parser = shield.argument_parser(__doc__)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--llvm-link", required=True)
    return shield.respond(execute, parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
