"""Bind Ghidra analysis reports to trial manifests (``aegis.lab.evidence-binding.v1``).

Three kinds of record stay separate:

1. **Declared configuration**: the ``TrialManifest``, written before a trial.
   Its digests are the author's claims.
2. **Checked evidence**: this module. It checks that a Ghidra report
   (``aegis.lab.ghidra.v1``, from ``aegis_lab.ghidra``) analyzed the manifest's
   final artifact, using the Ghidra launcher, version and configuration the manifest
   declared. Baseline and protected evidence are bound and hashed independently.
3. **Attack outcomes**: not produced here and not implemented yet.

A binding is a consistency check of an *unsigned* report file. It does not show
that the report came from the worker (report signing is not implemented), that the
artifact presently on disk has the declared hash, or anything about attack success.
It never authorizes execution; both Core attack-lab gates remain mandatory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from . import ghidra
from .canonical import CANONICALIZATION, canonical_sha256
from .diagnostics import SafeArgumentParser, model_field_names, validation_issues
from .ghidra import OBSERVED_RUNTIME_FIELDS, AnalysisReport, ExportIdentity, ReportInvariantError
from .manifest import (
    MANIFEST_ERROR_TYPES,
    ManifestPairError,
    PairValidation,
    ToolIdentity,
    TrialManifest,
    load_manifest,
    validate_pair,
)
from .safe_io import LoadError, read_regular_file

EVIDENCE_BINDING_SCHEMA = "aegis.lab.evidence-binding.v1"
GHIDRA_CONFIGURATION_SCHEMA = "aegis.lab.ghidra-configuration.v1"
# A report holds at most 4 MiB of exporter output plus a 128 KiB log tail; JSON
# re-escaping and indentation stay well below this bound.
MAX_GHIDRA_REPORT_BYTES = 8 * 1024 * 1024
GHIDRA_TOOL_KEY = "ghidra"  # compared case-insensitively with ToolIdentity.name

# Every ExportIdentity field that is fixed before the run and can change the output.
# The version and launcher digest are bound separately through ToolIdentity.version
# and ToolIdentity.executable_sha256. Release name, build date and Java version are
# reported by the running Ghidra; they are recorded as observations and compared
# across a pair instead (OBSERVED_RUNTIME_FIELDS, defined with the report invariants).
GHIDRA_CONFIGURATION_FIELDS = (
    "ghidra_application_properties_sha256",
    "ghidra_revision",
    "exporter_name",
    "exporter_script_sha256",
    "selected_function",
    "max_functions",
    "max_c_chars",
    "decompile_timeout_seconds",
    "analysis_timeout_seconds",
    "wall_timeout_seconds",
)

REPORT_FIELDS = model_field_names(AnalysisReport)
MANIFEST_FIELDS = model_field_names(TrialManifest)


class EvidenceBindingError(ValueError):
    """Evidence does not belong to the manifest, or the report is invalid.

    ``fields`` are report, manifest or pair field paths; ``reasons`` are fixed codes
    (``mismatch`` unless stated otherwise). Neither ever contains a report value.
    """

    def __init__(self, fields: tuple[str, ...], reasons: tuple[str, ...] | None = None):
        self.fields = fields
        self.reasons = reasons if reasons is not None else ("mismatch",) * len(fields)
        if len(self.reasons) != len(fields):
            raise AssertionError("one reason per field")
        super().__init__("evidence does not match its manifest: " + ", ".join(
            f"{field}: {reason}" for field, reason in zip(fields, self.reasons)))


def ghidra_configuration_sha256(export: ExportIdentity | dict[str, Any]) -> str:
    """Digest for ``ToolIdentity.configuration_sha256`` of a Ghidra tool entry."""
    values = export.model_dump(mode="json") if isinstance(export, ExportIdentity) else dict(export)
    missing = [name for name in GHIDRA_CONFIGURATION_FIELDS if name not in values]
    if missing:
        raise ValueError("missing Ghidra configuration fields: " + ", ".join(missing))
    document = {"schema": GHIDRA_CONFIGURATION_SCHEMA, **{name: values[name] for name in GHIDRA_CONFIGURATION_FIELDS}}
    return canonical_sha256(document)


def planned_ghidra_tool(
    headless: Path,
    *,
    script_path: Path | None = None,
    function: str = "*",
    max_functions: int = 64,
    max_c_chars: int = 12000,
    decompile_timeout_seconds: int = 30,
    analysis_timeout_seconds: int = 120,
    wall_timeout_seconds: int = 300,
) -> ToolIdentity:
    """Compute the ToolIdentity to declare in a manifest *before* running the worker.

    Reads the same installation files the worker hashes. Arguments must equal the
    ones later passed to ``aegis_lab.ghidra.analyze``, or the binding will fail.
    """
    headless = ghidra._verify_regular_file(Path(headless), "headless launcher", category="invalid_installation")
    properties, properties_sha256 = ghidra._read_application_properties(headless)
    exporter = Path(script_path) if script_path is not None else (
        Path(ghidra.__file__).resolve().parents[2] / "scripts" / ghidra.EXPORTER_NAME
    )
    exporter = ghidra._verify_regular_file(exporter, "Ghidra exporter", category="invalid_installation")
    configuration = {
        "ghidra_application_properties_sha256": properties_sha256,
        "ghidra_revision": properties.get("application.revision.ghidra", ""),
        "exporter_name": ghidra.EXPORTER_NAME,
        "exporter_script_sha256": ghidra.sha256_file(
            exporter, ghidra.MAX_EXPORTER_BYTES, role="Ghidra exporter", category="invalid_installation"),
        "selected_function": function,
        "max_functions": max_functions,
        "max_c_chars": max_c_chars,
        "decompile_timeout_seconds": decompile_timeout_seconds,
        "analysis_timeout_seconds": analysis_timeout_seconds,
        "wall_timeout_seconds": wall_timeout_seconds,
    }
    return ToolIdentity(
        name="Ghidra",
        version=properties["application.version"],
        executable_sha256=ghidra.sha256_file(
            headless, ghidra.MAX_LAUNCHER_BYTES, role="headless launcher", category="invalid_installation"),
        configuration_sha256=ghidra_configuration_sha256(configuration),
    )


def parse_ghidra_report(data: bytes) -> AnalysisReport:
    """Parse untrusted report bytes with the worker's own rules.

    Raises LoadError (strict JSON), pydantic.ValidationError (schema) or
    ghidra.ReportInvariantError (``ghidra.report_violations``: incomplete analysis,
    program identity, selector, limits, duplicate entry points, internal consistency).
    """
    return ghidra.parse_analysis_report(data)


@dataclass(frozen=True)
class GhidraEvidence:
    trial_id: str
    manifest_sha256: str
    artifact_sha256: str
    evidence_sha256: str
    evidence_size_bytes: int
    observed: dict[str, Any]

    def record(self) -> dict[str, Any]:
        return {
            "trial_id": self.trial_id,
            "manifest_sha256": self.manifest_sha256,
            "artifact_sha256": self.artifact_sha256,
            "evidence_kind": "ghidra_analysis",
            "evidence_schema": ghidra.SCHEMA,
            "evidence_sha256": self.evidence_sha256,
            "evidence_size_bytes": self.evidence_size_bytes,
            "observed": dict(self.observed),
        }


def _ghidra_tool(manifest: TrialManifest) -> ToolIdentity | None:
    for tool in manifest.attack.tools:
        if tool.name.casefold() == GHIDRA_TOOL_KEY:
            return tool
    return None


def bind_ghidra_evidence(manifest: TrialManifest, report_bytes: bytes) -> GhidraEvidence:
    """Check one report against one manifest. Hashes exactly the bytes that were parsed.

    Raises LoadError or pydantic.ValidationError for unparseable reports, and
    EvidenceBindingError for invalid (``ghidra.report_violations``) or mismatched ones.
    """
    try:
        report = parse_ghidra_report(report_bytes)
    except ReportInvariantError as exc:
        raise EvidenceBindingError(exc.fields, tuple(reason for _, reason in exc.violations)) from None
    tool = _ghidra_tool(manifest)
    if tool is None:
        raise EvidenceBindingError(("attack.tools",))
    mismatches: list[str] = []
    if report.binary.sha256 != manifest.target.final_artifact_sha256:
        mismatches.append("binary.sha256")
    if report.export.ghidra_version != tool.version:
        mismatches.append("export.ghidra_version")
    if report.export.ghidra_launcher_sha256 != tool.executable_sha256:
        mismatches.append("export.ghidra_launcher_sha256")
    if ghidra_configuration_sha256(report.export) != tool.configuration_sha256:
        mismatches.append("export.configuration")
    # Internal consistency (versions, counts) is part of the report invariants
    # already enforced by parse_ghidra_report.
    if mismatches:
        raise EvidenceBindingError(tuple(mismatches))
    return GhidraEvidence(
        trial_id=manifest.trial_id,
        manifest_sha256=manifest.sha256(),
        artifact_sha256=report.binary.sha256,
        evidence_sha256=hashlib.sha256(report_bytes).hexdigest(),
        evidence_size_bytes=len(report_bytes),
        observed={
            **{name: getattr(report.export, name) for name in OBSERVED_RUNTIME_FIELDS},
            "exported_function_count": len(report.analysis.functions),
            "decompiled_ok_count": report.decompiled_ok_count,
            "decompile_failed_count": report.decompile_failed_count,
            "decompiled_with_warnings_count": sum(
                1 for fn in report.analysis.functions if fn.decompile_status == "completed_with_warnings"),
            "truncated_function_count": sum(1 for fn in report.analysis.functions if fn.decompiled_c_truncated),
            "functions_limited": report.analysis.functions_limited,
            "log_truncated": report.log_truncated,
        },
    )


def bind_ghidra_pair(pair: PairValidation, baseline_report: bytes, protected_report: bytes) -> dict[str, Any]:
    """Bind each variant's report to its own manifest and compare the observed Ghidra runtime."""
    return compare_pair_evidence(
        pair, bind_ghidra_evidence(pair.baseline, baseline_report), bind_ghidra_evidence(pair.protected, protected_report)
    )


def compare_pair_evidence(pair: PairValidation, baseline: GhidraEvidence, protected: GhidraEvidence) -> dict[str, Any]:
    """Combine two bindings, which must have been made against exactly these manifests.

    Trial ids alone are not enough: a revised manifest keeps its trial id, so each
    binding's recorded manifest fingerprint and artifact digest must equal the
    current manifest's. Byte-identical baseline and protected artifacts stay valid.
    """
    stale: list[str] = []
    for role, evidence, manifest in (("baseline", baseline, pair.baseline), ("protected", protected, pair.protected)):
        if evidence.trial_id != manifest.trial_id:
            stale.append(f"{role}.trial_id")
        if evidence.manifest_sha256 != manifest.sha256():
            stale.append(f"{role}.manifest_sha256")
        if evidence.artifact_sha256 != manifest.target.final_artifact_sha256:
            stale.append(f"{role}.artifact_sha256")
    if stale:
        raise EvidenceBindingError(tuple(stale), ("stale_or_swapped",) * len(stale))
    runtime_differences = tuple(
        f"observed.{name}" for name in OBSERVED_RUNTIME_FIELDS if baseline.observed[name] != protected.observed[name]
    )
    if runtime_differences:
        raise EvidenceBindingError(runtime_differences)
    return {
        "schema_version": EVIDENCE_BINDING_SCHEMA,
        "verification": "consistency_check_of_unsigned_reports",
        "pair_id": pair.baseline.pair_id,
        "baseline": baseline.record(),
        "protected": protected.record(),
        "final_artifacts_identical": pair.final_artifacts_identical,
        "checks": [
            "manifests are a comparable pair (declared configuration only)",
            "each report's binary.sha256 equals its own manifest's final_artifact_sha256",
            "each report's Ghidra version, launcher digest and configuration digest equal the declared Ghidra tool",
            "each binding was made against the current manifest (trial id, manifest fingerprint, artifact digest)",
            "each report satisfies the aegis.lab.ghidra.v1 invariants (complete analysis, program and "
            "executable identity, exact-selector match, function and source limits, unique entry points, "
            "consistent versions and counts)",
            "both reports observed the same Ghidra release, build date and Java version",
        ],
        "fingerprints": f"manifest_sha256: sha256 over {CANONICALIZATION}; evidence_sha256: sha256 of report file bytes",
        "not_established": [
            "that the reports were produced by the AEGIS worker (they are not signed)",
            "that the artifact files presently on disk have the declared hashes",
            "that the protection was retained in the final protected artifact",
            "that any attack was run, or any outcome",
        ],
        "attacks_executed": False,
        "authorizes_execution": False,
    }


def _describe(role: str, exc: Exception, fields: frozenset[str], custom: frozenset[str] = frozenset()) -> list[str]:
    if isinstance(exc, LoadError):
        return [f"{role}: {exc.category}"]
    if isinstance(exc, ValidationError):
        return [f"{role}: {issue}" for issue in validation_issues(exc, fields, custom)]
    if isinstance(exc, ManifestPairError):
        return [f"pair: {field}: differs" for field in exc.fields]
    if isinstance(exc, ReportInvariantError):
        return [f"{role}: {field}: {reason}" for field, reason in exc.violations]
    if isinstance(exc, EvidenceBindingError):
        return [f"{role}: {field}: {reason}" for field, reason in zip(exc.fields, exc.reasons)]
    raise TypeError("unsupported failure type")


def _bind_pair_command(args: argparse.Namespace) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    manifests: list[TrialManifest | None] = []
    for role, path in (("baseline-manifest", args.baseline_manifest), ("protected-manifest", args.protected_manifest)):
        try:
            manifests.append(load_manifest(path))
        except (LoadError, ValidationError) as exc:
            manifests.append(None)
            issues.extend(_describe(role, exc, MANIFEST_FIELDS, MANIFEST_ERROR_TYPES))
    reports: list[bytes | None] = []
    for role, path in (("baseline-report", args.baseline_report), ("protected-report", args.protected_report)):
        try:
            data = read_regular_file(path, MAX_GHIDRA_REPORT_BYTES)
            parse_ghidra_report(data)
            reports.append(data)
        except (LoadError, ValidationError, ReportInvariantError) as exc:
            reports.append(None)
            issues.extend(_describe(role, exc, REPORT_FIELDS))
    if issues:
        return None, issues
    first, second = manifests
    try:
        pair = validate_pair(first, second)
    except ManifestPairError as exc:
        return None, _describe("pair", exc, MANIFEST_FIELDS)
    # Reports are matched to manifests by argument role, then verified by artifact hash.
    if pair.baseline is not first:
        return None, ["baseline-manifest: variant: not_baseline"]
    bound: list[GhidraEvidence] = []
    for role, manifest, report in (("baseline-report", pair.baseline, reports[0]),
                                   ("protected-report", pair.protected, reports[1])):
        try:
            bound.append(bind_ghidra_evidence(manifest, report))
        except EvidenceBindingError as exc:
            issues.extend(_describe(role, exc, REPORT_FIELDS))
    if issues:
        return None, issues
    try:
        return compare_pair_evidence(pair, *bound), []
    except EvidenceBindingError as exc:
        return None, _describe("pair-evidence", exc, REPORT_FIELDS)


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(
        prog="python -m aegis_lab.evidence",
        description="Bind Ghidra reports to trial manifests; never runs an attack",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    tool = sub.add_parser("ghidra-tool", help="print the Ghidra ToolIdentity to declare before a run")
    tool.add_argument("--headless", type=Path, required=True)
    tool.add_argument("--function", default="*")
    tool.add_argument("--max-functions", type=int, default=64)
    tool.add_argument("--max-c-chars", type=int, default=12000)
    tool.add_argument("--decompile-timeout", type=int, default=30)
    tool.add_argument("--analysis-timeout", type=int, default=120)
    tool.add_argument("--wall-timeout", type=int, default=300)
    bind = sub.add_parser("bind-pair", help="check both Ghidra reports against their manifests")
    for name in ("baseline_manifest", "protected_manifest", "baseline_report", "protected_report"):
        bind.add_argument(name, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "ghidra-tool":
            try:
                identity = planned_ghidra_tool(
                    args.headless, function=args.function, max_functions=args.max_functions,
                    max_c_chars=args.max_c_chars, decompile_timeout_seconds=args.decompile_timeout,
                    analysis_timeout_seconds=args.analysis_timeout, wall_timeout_seconds=args.wall_timeout,
                )
            except (ghidra.WorkerError, LoadError, OSError, ValidationError):
                print("cannot identify Ghidra installation: launcher_or_installation_invalid", file=sys.stderr)
                return 2
            print(json.dumps(identity.model_dump(mode="json"), indent=2, sort_keys=True))
            return 0
        record, issues = _bind_pair_command(args)
    except Exception as exc:  # never let an unexpected message reach the terminal
        print(f"evidence binding failed: internal_error ({type(exc).__name__})", file=sys.stderr)
        return 3
    if record is None:
        print("evidence binding failed:", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
