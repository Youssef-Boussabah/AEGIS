"""Opt-in local native integration. Executes only the pinned owned fixtures."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import benchmark as b


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        plugin = os.environ.get("AEGIS_RECONSTRUCTION_PLUGIN")
        if not plugin:
            raise unittest.SkipTest("native suite not run: set AEGIS_RECONSTRUCTION_PLUGIN to a trusted LLVM 22 plugin")
        cls.scratch = tempfile.TemporaryDirectory(prefix="aegis-reconstruction-native-tests-")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.root = Path(cls.scratch.name)
        cls.result = b.demo(cls.root / "first", Path(plugin), samples=3, iterations=10000)
        cls.second = b.demo(cls.root / "second", Path(plugin), samples=3, iterations=10000, targets=["recon_mix"])

    def test_all_variants_pass_predefined_oracle_and_final_decoys_survive(self):
        m = self.result["measurements"]
        for name in b.VARIANTS:
            self.assertEqual(m[name]["correctness"]["cases"], 24)
            self.assertEqual(m[name]["correctness"]["status"], "passed")
            self.assertEqual(len(m[name]["process_wall_seconds"]), 3)
        self.assertEqual(m["shield_mirage"]["mirage_retention"], {"expected": 3, "observed": 3})
        self.assertGreater(m["shield_mirage"]["text_bytes"], m["shield"]["text_bytes"])
        self.assertGreater(m["shield"]["shield_ir_sites_reported"], 0)

    def test_repeated_builds_have_identical_final_hashes(self):
        for name in b.VARIANTS:
            self.assertEqual(self.result["measurements"][name]["artifact_sha256"],
                             self.second["measurements"][name]["artifact_sha256"])

    def test_single_function_scope_selects_only_frozen_cases(self):
        self.assertEqual(self.second["manifest"]["targets"], ["recon_mix"])
        for measured in self.second["measurements"].values():
            self.assertEqual(measured["correctness"]["cases"], 12)
        self.assertEqual(self.second["measurements"]["shield"]["shield_selected_ir_sites_reported"], 2)

    def test_production_drafts_and_import_bindings_with_synthetic_ghidra_no_network(self):
        # Reports are explicitly synthetic test data, not real Ghidra evidence.
        from copy import deepcopy
        from unittest.mock import patch
        from test_lab_imports import GhidraImportTests
        import evidence
        import prepare_live
        helper = GhidraImportTests("test_ghidra_source_binary_mismatch")
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        _, report = helper.ghidra()
        from aegis_lab.manifest import ToolIdentity
        tool = ToolIdentity(name="Ghidra", **helper.controls["analysis_tools"]["Ghidra"])
        reports = {}
        for a in self.second["manifest"]["artifacts"]:
            r = deepcopy(report)
            r["binary"].update(name=Path(a["file"]["path"]).name, sha256=a["file"]["sha256"], size_bytes=a["file"]["size_bytes"])
            r["analysis"].update(program_name=r["binary"]["name"], executable_sha256=a["file"]["sha256"])
            path = self.root / (a["variant"] + "-SYNTHETIC-ghidra.json")
            b.write_json(path, r)
            reports[a["variant"]] = path
        with patch("aegis_lab.evidence.planned_ghidra_tool", return_value=tool):
            handoff = prepare_live.prepare(self.root / "second/measurements.json", self.root / "SYNTHETIC-prep",
                self.root / "not-launched-headless", reports=reports)
        self.assertEqual(handoff["network_requests"], 0)
        self.assertFalse(handoff["approvals_granted"])
        self.assertEqual(handoff["proposed_max_spend_microusd"], 300000)
        root = self.root / "SYNTHETIC-prep"
        m = b.load(root / "comparison.json")
        for label in ("baseline", "shield", "mirage"):
            draft = b.load(root / label / "approval.DRAFT.json")
            self.assertFalse(draft["operator_approved"])
            self.assertFalse(draft["provider_retention_reviewed"])
        a = m["artifacts"][0]
        record = {"schema": evidence.SCHEMA, "comparison_sha256": b.identity(m), "artifact_id": a["id"],
            "artifact_sha256": a["file"]["sha256"], "targets": m["targets"], "controls": m["attacker_controls"],
            "recorded_at": b.stamp(), "kind": "ghidra", "source": b.reference(root, root / "baseline/ghidra/ghidra-analysis.json"),
            "prompt": b.load(root / "baseline/prompt-bindings.json"), "candidate": None}
        with patch("subprocess.Popen", side_effect=AssertionError("no process during import")):
            self.assertEqual(evidence.verify_record(record, root, m, root)["classification"], "structural_observation")

    def test_report_revalidates_archive_without_executing_binaries(self):
        from unittest.mock import patch
        with patch("subprocess.Popen", side_effect=AssertionError("report must be read-only")):
            result = b.report_archive(self.root / "first/measurements.json")
            self.assertIn("absent; scoring unavailable", b.render(result))

    def test_report_rejects_stale_measurement_snapshot(self):
        path = self.root / "first/measurements.json"
        snapshot = b.load(path)
        snapshot["measurements"]["baseline"]["text_bytes"] += 1
        altered = path.parent / "altered-measurements.json"
        b.write_json(altered, snapshot)
        with self.assertRaisesRegex(b.Invalid, "stale_static_measurements"):
            b.report_archive(altered)

    def test_render_rejects_unsupported_claims(self):
        from copy import deepcopy
        r = deepcopy(self.result)
        r["evidence"] = [{"artifact_id": "baseline", "classification": "resistant",
                          "comparison_sha256": r["comparison_sha256"]}]
        with self.assertRaisesRegex(b.Invalid, "unsupported_evidence_claim"):
            b.render(r)


if __name__ == "__main__":
    unittest.main()
