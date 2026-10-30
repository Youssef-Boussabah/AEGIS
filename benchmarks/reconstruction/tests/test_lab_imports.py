"""Parser compatibility with current local Lab contracts, using synthetic records only."""
from copy import deepcopy
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import benchmark as b
import evidence as e
from test_benchmark import Fixture


class GhidraImportTests(Fixture):
    def ghidra(self):
        record = self.record()
        _, configuration_digest, _, _ = e.lab_modules()
        export = {"ghidra_version": "12.1.4", "ghidra_release_name": "PUBLIC", "ghidra_build_date": "synthetic-test",
            "ghidra_revision": "synthetic", "java_version": "21.synthetic", "ghidra_launcher_sha256": b.digest(b"launcher"),
            "ghidra_application_properties_sha256": b.digest(b"properties"), "exporter_name": "AegisExportFunctions.java",
            "exporter_script_sha256": b.digest(b"exporter"), "selected_function": "*", "max_functions": 2,
            "max_c_chars": 1000, "decompile_timeout_seconds": 30, "analysis_timeout_seconds": 120,
            "wall_timeout_seconds": 300}
        functions = [{"name": n, "qualified_name": n, "entry_point": f"{4096+i*16:08x}", "is_thunk": False,
            "signature": "uint32_t " + n + "(uint32_t,uint32_t)", "decompiler_signature": "synthetic",
            "decompile_success": True, "decompile_status": "completed", "decompiled_c": "/* synthetic */ " + n,
            "decompiled_c_truncated": False, "decompiler_message": "", "decompiler_message_truncated": False,
            "error": ""} for i, n in enumerate(b.TARGETS)]
        artifact = self.manifest["artifacts"][0]["file"]
        runtime = {k: export[k] for k in ("ghidra_version", "ghidra_release_name", "ghidra_build_date", "java_version")}
        report = {"schema_version": "aegis.lab.ghidra.v1", "binary": {"name": "baseline.elf",
            "sha256": artifact["sha256"], "size_bytes": artifact["size_bytes"]}, "export": export,
            "analysis": {"schema_version": "aegis.lab.ghidra.v1", **runtime, "analysis_timed_out": False,
                "program_name": "baseline.elf", "executable_sha256": artifact["sha256"],
                "executable_format": "Executable and Linking Format (ELF)", "language_id": "x86:LE:64:default",
                "functions": functions, "matching_function_count": 2, "functions_limited": False},
            "decompiled_ok_count": 2, "decompile_failed_count": 0, "duration_seconds": 0.1,
            "warnings_and_logs": "synthetic regression only", "log_bytes_total": 0, "log_truncated": False,
            "limitations": ["synthetic regression fixture, not real Ghidra evidence"]}
        self.controls["analysis_tools"]["Ghidra"] = {"version": export["ghidra_version"],
            "executable_sha256": export["ghidra_launcher_sha256"], "configuration_sha256": configuration_digest(export)}
        record.update(kind="ghidra", controls=deepcopy(self.controls), prompt=None,
                      comparison_sha256=b.identity(self.manifest), source=self.write("ghidra.json", report))
        return record, report

    def test_valid_native_ghidra_schema_without_running_ghidra(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no Ghidra jobs")):
            record, _ = self.ghidra()
            result = self.verify(record)
            self.assertEqual(result["classification"], "structural_observation")
            self.assertEqual(len(result["functions"]), 2)

    def test_ghidra_source_binary_mismatch(self):
        record, report = self.ghidra()
        report["binary"]["sha256"] = b.digest(b"wrong")
        report["analysis"]["executable_sha256"] = report["binary"]["sha256"]
        record["source"] = self.write("ghidra.json", report)
        self.invalid(lambda: self.verify(record), "analysis_artifact_mismatch")

    def test_ghidra_tool_configuration_and_launcher(self):
        for field, value, code in [("max_c_chars", 999, "analysis_configuration_mismatch"),
                                   ("ghidra_launcher_sha256", b.digest(b"other launcher"), "analysis_tool_mismatch")]:
            record, report = self.ghidra()
            report["export"][field] = value
            record["source"] = self.write("ghidra.json", report)
            self.invalid(lambda: self.verify(record), code)

    def test_ghidra_timeout_is_not_failed_behavioral_attack(self):
        record, report = self.ghidra()
        report["analysis"]["functions"][0].update(decompile_status="timed_out", decompile_success=False,
            decompiled_c="", error="synthetic timeout")
        report.update(decompiled_ok_count=1, decompile_failed_count=1)
        record["source"] = self.write("ghidra.json", report)
        self.assertEqual(self.verify(record)["classification"], "structural_observation")

    def test_ghidra_failed_analysis_or_missing_target_is_invalid(self):
        record, report = self.ghidra()
        report["analysis"]["analysis_timed_out"] = True
        record["source"] = self.write("ghidra.json", report)
        self.invalid(lambda: self.verify(record), "invalid_ghidra_report")
        record, report = self.ghidra()
        report["analysis"]["functions"][0]["name"] = "other"
        record["source"] = self.write("ghidra.json", report)
        self.invalid(lambda: self.verify(record), "analysis_target_missing_or_ambiguous")

    def test_unknown_nested_ghidra_claim_is_rejected(self):
        record, report = self.ghidra()
        report["analysis"]["functions"][0]["security_score"] = 100
        record["source"] = self.write("ghidra.json", report)
        self.invalid(lambda: self.verify(record), "invalid_ghidra_report")


class NemotronImportTests(Fixture):
    def summary(self, fixture="synthetic-nebius.json"):
        record = self.record()
        summary = b.load(b.ROOT / "attack_lab/tests/fixtures/public-summary" / fixture)
        summary["summary"]["artifact_sha256"] = record["artifact_sha256"]
        self.controls["model_identity"] = summary["summary"]["requested_model"]
        record.update(kind="nemotron_summary", controls=deepcopy(self.controls),
                      comparison_sha256=b.identity(self.manifest), source=self.write("summary.json", summary))
        return record, summary

    def test_synthetic_nemotron_summary_remains_unscored(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no provider or candidate execution")):
            record, _ = self.summary()
            result = self.verify(record)
            self.assertEqual(result["classification"], "candidate_text_unscored")
            self.assertEqual(result["origin"], "synthetic_fixture")
            self.assertEqual(result["behavioral_scoring"], "unavailable")
            self.assertEqual(result["provider_authenticity"], "not_independently_attested")

    def test_summary_cannot_change_its_security_or_execution_claim(self):
        for key, value in [("execution_performed", True), ("attack_effectiveness", "resisted"),
                           ("behavioral_scoring", "successful"), ("security_score", 100)]:
            record, doc = self.summary()
            doc["summary"][key] = value
            record["source"] = self.write("summary.json", doc)
            self.invalid(lambda: self.verify(record), "invalid_nemotron_summary")

    def test_summary_token_usage_and_missing_limitations_rejected(self):
        record, doc = self.summary()
        doc["summary"]["reported_tokens"] += 1
        record["source"] = self.write("summary.json", doc)
        self.invalid(lambda: self.verify(record), "invalid_nemotron_summary")
        record, doc = self.summary()
        doc["summary"]["limitations"] = []
        record["source"] = self.write("summary.json", doc)
        self.invalid(lambda: self.verify(record), "invalid_nemotron_summary")

    def test_summary_artifact_and_model_mismatch(self):
        record, doc = self.summary()
        doc["summary"]["artifact_sha256"] = b.digest(b"other artifact")
        record["source"] = self.write("summary.json", doc)
        self.invalid(lambda: self.verify(record), "research_artifact_mismatch")
        record, doc = self.summary()
        self.controls["model_identity"] = "nvidia/different-model"
        record["controls"] = deepcopy(self.controls)
        record["comparison_sha256"] = b.identity(self.manifest)
        self.invalid(lambda: self.verify(record), "research_model_mismatch")

    def test_post_hoc_parser_review_preserves_historical_failure(self):
        record, _ = self.summary("synthetic-post-hoc.json")
        result = self.verify(record)
        self.assertEqual(result["generation_status"], "invalid_output")
        self.assertIsNone(result["candidate_sha256"])
        self.assertEqual(result["post_hoc_status"], "candidate_text_revalidated_but_behaviorally_unscored")

    def test_comparison_row_mirage_maps_only_by_verified_combined_artifact(self):
        record = self.record()
        doc = b.load(b.ROOT / "attack_lab/tests/fixtures/public-summary/synthetic-comparison.json")
        artifact = self.manifest["artifacts"][2]
        row = next(r for r in doc["summary"]["experiments"] if r["variant"] == "mirage")
        row["summary"]["artifact_sha256"] = artifact["file"]["sha256"]
        self.controls["model_identity"] = row["summary"]["requested_model"]
        record.update(kind="nemotron_summary", artifact_id=artifact["id"], artifact_sha256=artifact["file"]["sha256"],
            controls=deepcopy(self.controls), comparison_sha256=b.identity(self.manifest), source=self.write("summary.json", doc))
        context = b.load(self.root / "context.txt")
        context["artifact_sha256"] = artifact["file"]["sha256"]
        data = b.canonical(context)
        (self.root / "context.txt").write_bytes(data)
        template = (self.root / "template.txt").read_bytes()
        (self.root / "rendered.txt").write_bytes(template.replace(b"{{CONTEXT}}", data))
        record["prompt"]["context"] = self.ref("context.txt")
        record["prompt"]["rendered"] = self.ref("rendered.txt")
        self.assertEqual(self.verify(record)["artifact_id"], "shield_mirage")


if __name__ == "__main__":
    import unittest
    unittest.main()
