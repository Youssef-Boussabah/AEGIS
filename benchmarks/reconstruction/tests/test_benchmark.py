"""Synthetic regression fixtures. None of these records are research evidence."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import benchmark as b
import evidence as e

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
TEMPLATE = b"Reconstruct only these functions:\n{{CONTEXT}}\n"
SYSTEM = b"Synthetic regression test; no inference."


def synthetic_elf(decoys=()):
    """Minimal parser fixture, never executed or presented as an actual measurement."""
    all_names = b.TARGETS + list(decoys)
    strings = b"\0" + b"".join(n.encode() + b"\0" for n in all_names)
    section_names = b"\0.shstrtab\0.strtab\0.text\0.symtab\0.dynsym\0"
    code = b"\x90\xc3" * len(all_names)
    symbols = bytes(24) + b"".join(struct.pack("<IBBHQQ", strings.index(n.encode()), 0x12, 0, 3,
        0x1000 + 2*i, 2) for i, n in enumerate(all_names))
    # Export only recon_gate in .dynsym; .symtab retains both targets and decoys.
    dynamic = bytes(24) + symbols[24:48]
    payloads = [section_names, strings, code, symbols, dynamic]
    data = bytearray(bytes(64))
    offsets = []
    for payload in payloads:
        offsets.append(len(data))
        data.extend(payload)
    while len(data) % 8:
        data.append(0)
    section_offset = len(data)
    data.extend(bytes(64))
    for index, (name, kind, flags, address, link, entry) in enumerate([
        (".shstrtab", 3, 0, 0, 0, 0), (".strtab", 3, 0, 0, 0, 0),
        (".text", 1, 6, 0x1000, 0, 0), (".symtab", 2, 0, 0, 2, 24),
        (".dynsym", 11, 0, 0, 2, 24)]):
        data.extend(struct.pack("<IIQQQQIIQQ", section_names.index(name.encode()), kind, flags, address,
                                offsets[index], len(payloads[index]), link, 1, 8, entry))
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, ident, 3, 62, 1, 0, 0, section_offset, 0,
                     64, 0, 0, 64, 6, 1)
    return bytes(data)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="aegis-reconstruction-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in b.PINNED:
            (self.root / name).write_bytes((b.HERE / "fixtures" / name).read_bytes())
        self.oracle = b.load(self.root / "oracle.json")
        self.sources = [self.ref(n) for n in ("target.c", "runner.c")]
        self.tool = {"name": "REA", "version": "synthetic-regression-only", "executable_sha256": b.digest(b"tool"),
                     "configuration_sha256": b.digest(b"configuration")}
        self.controls = {"capabilities": ["ghidra_decompilation", "rea_reasoning", "static_disassembly"],
            "analysis_tools": {"REA": {k: v for k, v in self.tool.items() if k != "name"}},
            "prompt_template_sha256": b.digest(TEMPLATE),
            "system_prompt_sha256": b.digest(SYSTEM), "workflow_sha256": b.digest(b"workflow"),
            "request_parameters_sha256": b.digest(b"synthetic-request-parameters"),
            "model_identity": "synthetic-test",
            "max_attempts": 1, "max_input_tokens": 8192, "max_output_tokens": 4096,
            "max_total_tokens": 16384, "max_spend_microusd": 100000,
            "time_budget_seconds": 300, "random_seed": 42, "context_policy": "selected_functions_only",
            "oracle_access": "none", "source_access": "none"}
        build = {"tools": {name: {"sha256": b.digest(name.encode()), "version": "22.synthetic"}
                            for name in ("clang", "opt", "llvm-link")},
            "target_triple": "x86_64-pc-linux-gnu", "frontend_flags": ["-O1"], "final_flags": ["-O2"],
            "environment": "minimal-v1", "source_identity": b.identity(self.sources)}
        for variant in b.VARIANTS:
            (self.root / (variant + ".ll")).write_text("synthetic-IR-" + variant)
            (self.root / (variant + ".elf")).write_bytes(synthetic_elf(["decoy_a", "decoy_b", "decoy_c"]
                if variant == "shield_mirage" else ()))
        self.write("shield-report.json", {"schema_version": 1, "backend": "aegis-shield-llvm",
            "llvm_version": "22.synthetic", "module": "synthetic-baseline.ll",
            "config": {"enabled": True, "seed": "42", "max_sites_per_function": 16}, "transformed_sites": 5,
            "functions": [{"name": name, "annotated": True, "status": "transformed", "reason": "expanded",
                "skipped_adds": {}, "transformed_sites": [{"add_index": i, "bit_width": 32, "variant": "xor-carry"}
                                                         for i in range(count)]}
                          for name, count in (("recon_mix", 2), ("recon_gate", 3))]})
        self.write("mirage-report.json", {"schema_version": "aegis.mirage.report.v1",
            "configuration": {"enabled": True, "seed": 42, "count": 3},
            "input_sha256": self.ref("shield.ll")["sha256"], "output_sha256": self.ref("shield_mirage.ll")["sha256"],
            "inserted_count": 3, "inserted_functions": ["decoy_a", "decoy_b", "decoy_c"],
            "mechanism": "retained_unreachable_arithmetic_functions", "decoy_source_sha256": b.digest(b"synthetic-decoys"),
            "toolchain": {key: build["tools"][name] for key, name in
                          (("clang", "clang"), ("opt", "opt"), ("llvm_link", "llvm-link"))},
            "runtime_side_effects": "no_callers_or_initializers_inserted",
            "final_artifact_retention": "requires_independent_check", "security_property": "not_established"})
        artifacts = []
        for variant in b.VARIANTS:
            artifacts.append({"id": variant, "variant": variant, "file": self.ref(variant + ".elf"),
                "ir": self.ref(variant + ".ll"), "targets": b.TARGETS, "build_conditions_sha256": b.identity(build),
                "protection": {"shield": None if variant == "baseline" else {"seed": 42, "max_sites": 16},
                               "mirage": {"seed": 42, "count": 3} if variant == "shield_mirage" else None},
                "shield_report": None if variant == "baseline" else self.ref("shield-report.json"),
                "mirage_report": self.ref("mirage-report.json") if variant == "shield_mirage" else None})
        self.manifest = {"schema": b.SCHEMA, "comparison_id": "synthetic-unit-only",
            "created_at": b.stamp(NOW - timedelta(minutes=1)), "valid_until": b.stamp(NOW + timedelta(days=1)),
            "targets": b.TARGETS, "sources": self.sources, "oracle": self.ref("oracle.json"),
            "build_conditions": build, "attacker_controls": self.controls, "artifacts": artifacts}

    def ref(self, name):
        return b.reference(self.root, self.root / name)

    def write(self, name, data):
        (self.root / name).write_text(json.dumps(data, indent=2) + "\n")
        return self.ref(name)

    def validate(self, m=None):
        return b.validate_manifest(m or self.manifest, self.root, NOW)

    def invalid(self, callback, code):
        with self.assertRaisesRegex(b.Invalid, "^" + code + "$"):
            callback()

    def prompt(self):
        context = {"artifact_sha256": self.manifest["artifacts"][0]["file"]["sha256"],
                   "functions": [{"name": n, "decompiled_c": "/* synthetic */ uint32_t " + n + "(uint32_t a, uint32_t b);"}
                                 for n in b.TARGETS]}
        data = {"template": TEMPLATE, "system": SYSTEM, "context": b.canonical(context),
                "rendered": TEMPLATE.replace(b"{{CONTEXT}}", b.canonical(context))}
        for name, value in data.items():
            (self.root / (name + ".txt")).write_bytes(value)
        return {name: self.ref(name + ".txt") for name in data}, context

    def record(self):
        prompt, context = self.prompt()
        source = {"schema": "aegis.reconstruction.rea-observation.v1",
            "artifact_sha256": self.manifest["artifacts"][0]["file"]["sha256"], "targets": b.TARGETS,
            "tool": self.tool,
            "raw": self.write("raw.json", {"notice": "SYNTHETIC regression fixture, not research evidence"}),
            "observations": [{"function": f["name"], "status": "completed", "decompiled_c": f["decompiled_c"],
                              "structural_metrics": {"decompiler_complexity": 9999}} for f in context["functions"]]}
        return {"schema": e.SCHEMA, "comparison_sha256": b.identity(self.manifest), "artifact_id": "baseline",
            "artifact_sha256": self.manifest["artifacts"][0]["file"]["sha256"], "targets": b.TARGETS,
            "controls": deepcopy(self.controls), "recorded_at": b.stamp(NOW - timedelta(seconds=1)),
            "kind": "rea", "source": self.write("rea.json", source), "prompt": prompt, "candidate": None}

    def verify(self, record, trusted=()):
        return e.verify_record(record, self.root, self.manifest, self.root, trusted_receipts=trusted, now=NOW)

    def receipt(self):
        record = self.record()
        record["kind"] = "behavioral_receipt"
        (self.root / "candidate.txt").write_bytes(b"SYNTHETIC bytes; never compiled or executed")
        record["candidate"] = self.ref("candidate.txt")
        receipt = {"schema": "aegis.reconstruction.replay-receipt.v1", "verifier_id": "synthetic-test-reviewer",
            "comparison_sha256": b.identity(self.manifest), "artifact_id": "baseline",
            "artifact_sha256": record["artifact_sha256"], "controls_sha256": b.identity(self.controls),
            "targets": b.TARGETS, "oracle_sha256": self.manifest["oracle"]["sha256"],
            "candidate_sha256": record["candidate"]["sha256"], "recorded_at": record["recorded_at"],
            "isolation": {"runtime": "firecracker", "validation_sha256": b.digest(b"synthetic-validation"),
                          "attestation_sha256": b.digest(b"synthetic-attestation")},
            "compilation": {"status": "succeeded", "compiler_sha256": self.manifest["build_conditions"]["tools"]["clang"]["sha256"],
                            "log_sha256": b.digest(b"synthetic-log")},
            "cases": [{"id": c["id"], "status": "returned", "value": c["expected"]} for c in self.oracle["cases"]]}
        record["source"] = self.write("receipt.json", receipt)
        return record, receipt


class ManifestTests(Fixture):
    def test_valid_comparison(self):
        self.assertEqual(len(self.validate()["cases"]), 24)

    def test_only_baseline_and_shield_is_valid(self):
        self.manifest["artifacts"].pop()
        self.validate()

    def test_missing_and_unknown_fields(self):
        for key in self.manifest:
            with self.subTest(key=key):
                m = deepcopy(self.manifest)
                del m[key]
                self.invalid(lambda: self.validate(m), "invalid_fields")
        self.manifest["security_score"] = 100
        self.invalid(self.validate, "invalid_fields")

    def test_mismatched_binary_and_source(self):
        for name in ("baseline.elf", "target.c", "oracle.json", "shield-report.json"):
            with self.subTest(name=name):
                p = self.root / name
                original = p.read_bytes()
                p.write_bytes(original + b" ")
                self.invalid(self.validate, "file_binding_mismatch")
                p.write_bytes(original)

    def test_different_target_functions(self):
        self.manifest["artifacts"][1]["targets"] = ["other"]
        self.invalid(self.validate, "different_target_functions")

    def test_mismatched_build_conditions(self):
        self.manifest["artifacts"][1]["build_conditions_sha256"] = b.digest(b"other flags")
        self.invalid(self.validate, "noncomparable_build")

    def test_build_source_identity(self):
        self.manifest["build_conditions"]["source_identity"] = b.digest(b"other source")
        self.invalid(self.validate, "source_identity_mismatch")

    def test_stale_future_and_overlong_window(self):
        for delta in (-2, 2):
            self.invalid(lambda: b.validate_manifest(self.manifest, self.root, NOW + timedelta(days=delta)), "stale_comparison")
        self.manifest["valid_until"] = b.stamp(NOW + timedelta(days=8))
        self.invalid(self.validate, "stale_comparison")

    def test_unsupported_capability_and_oracle_leakage(self):
        for key, value, code in [("capabilities", ["execute_on_host"], "unsupported_capability"),
                                 ("oracle_access", "full", "unsupported_attacker_access"),
                                 ("source_access", "full", "unsupported_attacker_access"),
                                 ("max_attempts", True, "invalid_integer")]:
            with self.subTest(key=key):
                m = deepcopy(self.manifest)
                m["attacker_controls"][key] = value
                self.invalid(lambda: self.validate(m), code)

    def test_no_protected_artifacts(self):
        self.manifest["artifacts"] = self.manifest["artifacts"][:1]
        self.invalid(self.validate, "missing_artifacts")

    def test_two_baselines(self):
        a = deepcopy(self.manifest["artifacts"][0])
        a["id"] = "baseline_copy"
        self.manifest["artifacts"].append(a)
        self.invalid(self.validate, "one_baseline_required")

    def test_shield_report_is_not_success_when_zero_sites(self):
        report = b.load(self.root / "shield-report.json")
        report["transformed_sites"] = 0
        ref = self.write("shield-report.json", report)
        for a in self.manifest["artifacts"][1:]:
            a["shield_report"] = ref
        self.invalid(self.validate, "invalid_integer")

    def test_different_shield_seed_rejected_even_with_matching_report(self):
        a = self.manifest["artifacts"][2]
        a["protection"]["shield"]["seed"] = 43
        report = b.load(self.root / "shield-report.json")
        report["config"]["seed"] = "43"
        a["shield_report"] = self.write("other-shield-report.json", report)
        self.invalid(self.validate, "noncomparable_protection")

    def test_combined_must_consume_the_compared_shield_ir(self):
        report = b.load(self.root / "mirage-report.json")
        report["input_sha256"] = b.digest(b"different stage")
        self.manifest["artifacts"][2]["mirage_report"] = self.write("mirage-report.json", report)
        self.invalid(self.validate, "different_shield_stage")

    def test_reports_reject_unsupported_security_claims(self):
        report = b.load(self.root / "mirage-report.json")
        report["security_property"] = "reverse_engineering_resistant"
        self.manifest["artifacts"][2]["mirage_report"] = self.write("mirage-report.json", report)
        self.invalid(self.validate, "unsupported_mirage_claim")

    def test_shield_claims_require_consistent_targets_and_sites(self):
        report = b.load(self.root / "shield-report.json")
        report["functions"][0]["status"] = "skipped"
        ref = self.write("shield-report.json", report)
        for a in self.manifest["artifacts"][1:]:
            a["shield_report"] = ref
        self.invalid(self.validate, "contradictory_shield_claim")
        report["functions"][0]["status"] = "transformed"
        report["functions"][0]["name"] = "other_target"
        ref = self.write("shield-report.json", report)
        for a in self.manifest["artifacts"][1:]:
            a["shield_report"] = ref
        self.invalid(self.validate, "shield_report_totals_or_targets_mismatch")

    def test_mirage_toolchain_mismatch(self):
        report = b.load(self.root / "mirage-report.json")
        report["toolchain"]["clang"]["sha256"] = b.digest(b"different clang")
        self.manifest["artifacts"][2]["mirage_report"] = self.write("mirage-report.json", report)
        self.invalid(self.validate, "mirage_toolchain_mismatch")

    def test_oracle_contradiction_and_missing_target_cases(self):
        oracle = deepcopy(self.oracle)
        c = deepcopy(oracle["cases"][0])
        c.update(id="different-id", expected=1)
        oracle["cases"].append(c)
        self.invalid(lambda: b.validate_oracle(oracle, b.TARGETS), "contradictory_oracle")
        oracle["cases"] = [c for c in self.oracle["cases"] if c["function"] == "recon_mix"]
        self.invalid(lambda: b.validate_oracle(oracle, b.TARGETS), "oracle_target_coverage")

    def test_all_frozen_oracles_match_independent_reference(self):
        for c in self.oracle["cases"]:
            self.assertEqual(c["expected"], b.reference_value(c["function"], *c["arguments"]))

    def test_other_scalar_arity_can_be_imported_without_execution(self):
        oracle = {"schema": "aegis.reconstruction.oracle.v1", "interface": "u32(u32,u32,u32,u32)",
            "cases": [{"id": "synthetic-only", "function": "synthetic_four_args", "arguments": [0, 1, 2, 3], "expected": 0}]}
        b.validate_oracle(oracle, ["synthetic_four_args"])
        oracle["cases"][0]["arguments"].pop()
        self.invalid(lambda: b.validate_oracle(oracle, ["synthetic_four_args"]), "oracle_arguments")


class FileAndELFTests(Fixture):
    def test_duplicate_keys_nonfinite_and_invalid_json(self):
        for data, code in [(b'{"a":1,"a":2}', "duplicate_json_key"), (b'{"a":NaN}', "nonfinite_json"),
                           (b'{"a":1e9999}', "nonfinite_json"),
                           (b'\xff', "invalid_json"), (b'{} trailing', "invalid_json")]:
            self.invalid(lambda: b.parse_json(data), code)

    def test_path_escape_and_symlink(self):
        self.invalid(lambda: b.contained(self.root, "../outside"), "path_escape")
        self.invalid(lambda: b.contained(self.root, "/etc/passwd"), "invalid_path")
        (self.root / "link").symlink_to(self.root / "target.c")
        self.invalid(lambda: b.contained(self.root, "link"), "symlink_path")
        (self.root / "dirlink").symlink_to(self.root, target_is_directory=True)
        self.invalid(lambda: b.contained(self.root, "dirlink/target.c"), "symlink_path")

    def test_fifo_does_not_block(self):
        os.mkfifo(self.root / "fifo")
        self.invalid(lambda: b.read_file(self.root / "fifo"), "invalid_file")

    def test_elf_functions_exports_and_decoy_retention(self):
        r = b.elf_measure(synthetic_elf(["decoy"]), b.TARGETS, ["decoy", "absent"])
        self.assertEqual(r["text_bytes"], 6)
        self.assertEqual(r["mirage_retention"], {"expected": 2, "observed": 1})
        self.assertTrue(r["targets"]["recon_gate"]["dynamic_export"])
        self.assertFalse(r["targets"]["recon_mix"]["dynamic_export"])
        self.assertEqual(r["targets"]["recon_mix"]["binding"], "global")

    def test_missing_symbol_is_unavailable(self):
        r = b.elf_measure(synthetic_elf(), ["missing"])
        self.assertIsNone(r["targets"]["missing"])

    def test_ambiguous_function_symbols_are_unavailable(self):
        r = b.elf_measure(synthetic_elf(["recon_mix"]), b.TARGETS, ["recon_mix"])
        self.assertIsNone(r["targets"]["recon_mix"])
        self.assertEqual(r["mirage_retention"]["observed"], 0)

    def test_elf_truncated_and_invalid_sections(self):
        good = synthetic_elf()
        for data in (b"", good[:63], good[:-1], b"MZ" + good[2:]):
            with self.subTest(length=len(data)):
                with self.assertRaises(b.Invalid):
                    b.elf_measure(data, b.TARGETS)

    def test_static_measurement_never_creates_process(self):
        with patch("subprocess.Popen", side_effect=AssertionError("execution forbidden")):
            measured = b.measure_static(self.manifest, self.root)
            self.assertEqual(measured["shield_mirage"]["mirage_retention"]["observed"], 3)

    def test_trusted_process_deadline_and_minimal_environment(self):
        # Only installed trusted tools are run, never a candidate or imported artifact.
        self.invalid(lambda: b.run(["/usr/bin/sleep", "1"], self.root, timeout=0.005), "process_timeout")
        with patch.dict(os.environ, {"AEGIS_SYNTHETIC_SECRET_MARKER": "unit-test-only"}):
            output, _ = b.run([sys.executable, "-I", "-c",
                "import os; print('AEGIS_SYNTHETIC_SECRET_MARKER' in os.environ)"], self.root)
        self.assertEqual(output, b"False\n")

    def test_demo_rejects_modified_trusted_pin_before_process_creation(self):
        with patch.dict(b.PINNED, {"target.c": "0" * 64}), patch("subprocess.Popen", side_effect=AssertionError("no execution")):
            self.invalid(lambda: b.demo(self.root / "bad-pin", self.root / "unused-plugin"), "trusted_fixture_pin_mismatch")


class EvidenceTests(Fixture):
    def test_complexity_only_stays_structural(self):
        result = self.verify(self.record())
        self.assertEqual(result["classification"], "structural_observation")
        self.assertEqual(result["behavioral_scoring"], "unavailable")
        self.assertNotIn("resistance", result)

    def test_no_prompt_required_for_static_observation(self):
        record = self.record()
        record["prompt"] = None
        self.assertEqual(self.verify(record)["prompt_binding"], "not_applicable")

    def test_missing_source_and_unknown_security_claim(self):
        record = self.record()
        (self.root / "rea.json").unlink()
        self.invalid(lambda: self.verify(record), "unreadable_regular_file")
        record = self.record()
        record["resisted"] = True
        self.invalid(lambda: self.verify(record), "invalid_fields")

    def test_mismatched_configuration_prompt_budget_and_model(self):
        for key, value in [("max_attempts", 2), ("model_identity", "other-model"),
                           ("analysis_tools", {}),
                           ("random_seed", 999)]:
            with self.subTest(key=key):
                record = self.record()
                record["controls"][key] = value
                self.invalid(lambda: self.verify(record), "noncomparable_attacker_configuration")

    def test_evidence_wrong_artifact_target_and_comparison(self):
        for key, value, code in [("artifact_sha256", b.digest(b"other"), "evidence_artifact_mismatch"),
                                 ("targets", ["other"], "evidence_target_mismatch"),
                                 ("comparison_sha256", b.digest(b"other"), "evidence_comparison_mismatch")]:
            record = self.record()
            record[key] = value
            self.invalid(lambda: self.verify(record), code)

    def test_stale_and_future_evidence(self):
        for delta in (-120, 1):
            record = self.record()
            record["recorded_at"] = b.stamp(NOW + timedelta(seconds=delta))
            self.invalid(lambda: self.verify(record), "stale_or_future_evidence")

    def test_rendered_prompt_cannot_be_changed_independently(self):
        record = self.record()
        (self.root / "rendered.txt").write_bytes(b"different instructions")
        record["prompt"]["rendered"] = self.ref("rendered.txt")
        self.invalid(lambda: self.verify(record), "rendered_prompt_mismatch")

    def test_template_and_system_must_be_identical(self):
        for field in ("template", "system"):
            record = self.record()
            (self.root / (field + ".txt")).write_bytes(b"changed")
            record["prompt"][field] = self.ref(field + ".txt")
            self.invalid(lambda: self.verify(record), "noncomparable_prompts")

    def test_prompt_cannot_include_a_different_target_or_extra_field(self):
        record = self.record()
        context = b.load(self.root / "context.txt")
        context["functions"][0]["name"] = "other"
        self.replace_context(record, context)
        self.invalid(lambda: self.verify(record), "prompt_target_mismatch")
        record = self.record()
        context = b.load(self.root / "context.txt")
        context["hidden_oracle"] = [42]
        self.replace_context(record, context)
        self.invalid(lambda: self.verify(record), "invalid_fields")

    def replace_context(self, record, context):
        data = b.canonical(context)
        (self.root / "context.txt").write_bytes(data)
        (self.root / "rendered.txt").write_bytes(TEMPLATE.replace(b"{{CONTEXT}}", data))
        record["prompt"]["context"] = self.ref("context.txt")
        record["prompt"]["rendered"] = self.ref("rendered.txt")

    def test_prompt_cannot_change_decompiled_text(self):
        record = self.record()
        context = b.load(self.root / "context.txt")
        context["functions"][0]["decompiled_c"] += " altered"
        self.replace_context(record, context)
        self.invalid(lambda: self.verify(record), "context_analysis_mismatch")

    def test_analysis_different_tool(self):
        record = self.record()
        source = b.load(self.root / "rea.json")
        source["tool"]["executable_sha256"] = b.digest(b"different tool")
        record["source"] = self.write("rea.json", source)
        self.invalid(lambda: self.verify(record), "analysis_tool_mismatch")

    def test_rea_metrics_cannot_claim_security(self):
        record = self.record()
        source = b.load(self.root / "rea.json")
        source["observations"][0]["structural_metrics"]["resistance_score"] = 100
        record["source"] = self.write("rea.json", source)
        self.invalid(lambda: self.verify(record), "unsupported_structural_metric")

    def test_behavioral_claim_requires_out_of_band_trusted_digest(self):
        record, _ = self.receipt()
        self.invalid(lambda: self.verify(record), "untrusted_independent_verification_receipt")

    def test_verified_receipt_derived_from_case_outputs(self):
        record, receipt = self.receipt()
        result = self.verify(record, [record["source"]["sha256"]])
        self.assertEqual(result["classification"], "behavioral_suite_match")
        self.assertEqual(result["case_counts"]["matched"], 24)
        self.assertEqual(result["security_property"], "not_established")
        receipt["cases"][0]["value"] ^= 1
        record["source"] = self.write("receipt.json", receipt)
        self.assertEqual(self.verify(record, [record["source"]["sha256"]])["classification"], "behavioral_suite_mismatch")

    def test_failure_infrastructure_and_absence_are_separate(self):
        for status, expected in [("timeout", "attack_failed"), ("crash", "attack_failed"),
                                 ("infrastructure_failure", "inconclusive"), ("not_run", "inconclusive")]:
            with self.subTest(status=status):
                record, receipt = self.receipt()
                receipt["cases"][0].update(status=status, value=None)
                record["source"] = self.write("receipt.json", receipt)
                self.assertEqual(self.verify(record, [record["source"]["sha256"]])["classification"], expected)

    def test_compile_rejection_and_infrastructure_failure(self):
        for status, expected in [("candidate_rejected", "attack_failed"), ("infrastructure_failure", "inconclusive")]:
            record, receipt = self.receipt()
            receipt["compilation"]["status"] = status
            receipt["cases"] = []
            record["source"] = self.write("receipt.json", receipt)
            self.assertEqual(self.verify(record, [record["source"]["sha256"]])["classification"], expected)

    def test_missing_cases_or_candidate_digest_rejected(self):
        for mutate, code in [(lambda r: r["cases"].pop(), "incomplete_replay_cases"),
                             (lambda r: r.update(candidate_sha256=b.digest(b"other")), "replay_binding_mismatch")]:
            record, receipt = self.receipt()
            mutate(receipt)
            record["source"] = self.write("receipt.json", receipt)
            self.invalid(lambda: self.verify(record, [record["source"]["sha256"]]), code)

    def test_host_and_test_double_never_count(self):
        for runtime in ("host", "none", "test_double", "aegis-test-double"):
            record, receipt = self.receipt()
            receipt["isolation"]["runtime"] = runtime
            record["source"] = self.write("receipt.json", receipt)
            self.invalid(lambda: self.verify(record, [record["source"]["sha256"]]), "unvalidated_isolation")

    def test_scoring_cannot_omit_prompt(self):
        record, _ = self.receipt()
        record["prompt"] = None
        self.invalid(lambda: self.verify(record, [record["source"]["sha256"]]), "missing_comparable_prompt")

    def test_imports_never_create_process_or_execute_candidate(self):
        record, _ = self.receipt()
        with patch("subprocess.Popen", side_effect=AssertionError("execution forbidden")):
            self.assertEqual(self.verify(record, [record["source"]["sha256"]])["classification"], "behavioral_suite_match")


if __name__ == "__main__":
    unittest.main()
