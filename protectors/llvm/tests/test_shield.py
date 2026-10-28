#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import tempfile
import unittest

from common import ROOT, load_report, run, runtime_ir, transform

PARSER = argparse.ArgumentParser()
PARSER.add_argument("--plugin", required=True)
PARSER.add_argument("--opt", required=True)
PARSER.add_argument("--clang", required=True)
ARGS, REST = PARSER.parse_known_args()


class ShieldTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-shield-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.ll"
        self.source.write_text(runtime_ir())
        self.output = self.root / "output.ll"
        self.report = self.root / "report.json"

    def apply(self, options="", source=None, output=None, tail="verify"):
        transform(ARGS.opt, ARGS.plugin, source or self.source, output or self.output,
                  options, self.report, tail)
        return load_report(self.report)

    def normalized(self, path):
        # opt records its input path in a non-semantic comment on each run.
        return "\n".join(line for line in path.read_text().splitlines()
                         if not line.startswith("; ModuleID ="))

    def test_ir_really_changes_and_report_matches(self):
        baseline = self.root / "canonical.ll"
        run(ARGS.opt, "-S", self.source, "-o", baseline)
        report = self.apply("seed=42")
        self.assertEqual(report["transformed_sites"], 18)
        self.assertNotEqual(self.normalized(baseline), self.normalized(self.output))
        self.assertIn("freeze i", self.output.read_text())
        self.assertIn("!aegis.shield.generated", self.output.read_text())
        variants = {site["variant"] for row in report["functions"] for site in row["transformed_sites"]}
        self.assertEqual(variants, {"xor-carry", "or-carry"})

    def test_determinism_and_seed_changes(self):
        first = self.apply("seed=42;max-sites=2")
        ir = self.output.read_bytes()
        self.assertEqual(first, self.apply("seed=42;max-sites=2"))
        self.assertEqual(ir, self.output.read_bytes())
        second = self.apply("seed=43;max-sites=2")
        self.assertNotEqual(first["functions"], second["functions"])
        self.assertNotEqual(ir, self.output.read_bytes())

    def test_disabled_and_zero_budget_are_noops(self):
        baseline = self.root / "canonical.ll"
        run(ARGS.opt, "-S", self.source, "-o", baseline)
        for option in ("enabled=false", "max-sites=0"):
            with self.subTest(option=option):
                report = self.apply(option)
                self.assertEqual(report["transformed_sites"], 0)
                self.assertEqual(self.normalized(baseline), self.normalized(self.output))

    def test_budget(self):
        report = self.apply("max-sites=1")
        for row in report["functions"]:
            self.assertLessEqual(len(row["transformed_sites"]), 1)
        chain = next(row for row in report["functions"] if row["name"] == "chain")
        self.assertEqual(chain["skipped_adds"]["budget"], 3)

    def test_config_and_override(self):
        config = self.root / "config.json"
        config.write_text(json.dumps({"schema_version": 1, "seed": "18446744073709551615",
                                      "enabled": False, "max_sites_per_function": 1}))
        report = self.apply(f"config={config}")
        self.assertEqual(report["transformed_sites"], 0)
        self.assertEqual(report["config"]["seed"], str(2**64 - 1))
        report = self.apply(f"enabled=true;seed=0;max-sites=2;config={config}")
        self.assertEqual(report["config"], {"enabled": True, "seed": "0", "max_sites_per_function": 2})
        self.assertGreater(report["transformed_sites"], 0)

    def test_negative_functions_and_instructions(self):
        report = self.apply(source=ROOT / "fixtures/negative.ll")
        self.assertEqual(report["transformed_sites"], 0)
        rows = {row["name"]: row for row in report["functions"]}
        self.assertEqual(rows["plain"]["reason"], "not-annotated")
        self.assertEqual(rows["flagged"]["skipped_adds"], {"overflow-flags": 3})
        self.assertEqual(rows["indeterminate"]["skipped_adds"], {"undef-or-poison": 2})
        for name in ("bit", "too_wide", "vector_inside"):
            self.assertEqual(rows[name]["skipped_adds"], {"unsupported-type": 1})
        for name in ("pointer", "varargs", "void_return", "vectors"):
            self.assertEqual(rows[name]["reason"], "unsupported-signature")
        self.assertEqual(rows["off"]["reason"], "optnone")
        self.assertEqual(rows["external"]["reason"], "declaration")
        baseline = self.root / "canonical.ll"
        run(ARGS.opt, "-S", ROOT / "fixtures/negative.ll", "-o", baseline)
        self.assertEqual(self.normalized(baseline), self.normalized(self.output))

    def test_clang_annotation_exact_match(self):
        run(ARGS.clang, "-O1", "-S", "-emit-llvm", ROOT / "fixtures/annotated.c", "-o", self.source)
        report = self.apply()
        self.assertEqual(report["transformed_sites"], 1)
        rows = {row["name"]: row for row in report["functions"]}
        self.assertTrue(rows["selected"]["annotated"])
        self.assertFalse(rows["plain"]["annotated"])
        self.assertFalse(rows["other_annotation"]["annotated"])
        run(ARGS.clang, "-O2", "-c", self.output, "-o", self.root / "annotated.o")

    def test_immediate_second_run_is_noop(self):
        self.apply()
        first = self.output.read_text()
        again = self.root / "again.ll"
        report = self.apply(source=self.output, output=again)
        self.assertEqual(report["transformed_sites"], 0)
        self.assertEqual(self.normalized(self.output), self.normalized(again))
        self.assertEqual(first, self.output.read_text())

    def test_runtime_equivalence_optimized(self):
        # Independent unsigned-C reference checks each result, then compares a
        # deterministic checksum across baseline, both seeds, and -O0/-O2/-O3.
        checksums = set()
        for level in ("-O0", "-O2", "-O3"):
            for seed in (None, 0, 42):
                with self.subTest(level=level, seed=seed):
                    module = self.source
                    if seed is not None:
                        self.apply(f"seed={seed}")
                        module = self.output
                    exe = self.root / f"run-{level}-{seed}"
                    run(ARGS.clang, level, ROOT / "fixtures/runtime.c", module, "-o", exe)
                    checksums.add(run(exe).stdout)
        self.assertEqual(len(checksums), 1)
        print(f"runtime reference checksum: {next(iter(checksums)).strip()}", flush=True)

    def test_full_llvm_optimization_pipeline(self):
        self.apply("seed=19", tail="default<O2>,verify")
        exe = self.root / "optimized"
        run(ARGS.clang, "-O2", ROOT / "fixtures/runtime.c", self.output, "-o", exe)
        self.assertEqual(run(exe).returncode, 0)

    def test_indirect_undef_uses_are_frozen(self):
        self.source.write_text('''
define i32 @choose(i1 %c, i32 %a) #0 {
  %v = select i1 %c, i32 %a, i32 undef
  %x = add i32 %v, %v
  ret i32 %x
}
attributes #0 = { "aegis.protect" }
''')
        self.assertEqual(self.apply()["transformed_sites"], 1)
        self.assertEqual(self.output.read_text().count("freeze i32"), 1)

    def test_report_optional_and_empty_module(self):
        transform(ARGS.opt, ARGS.plugin, self.source, self.output)
        self.assertFalse(self.report.exists())
        self.source.write_text("; empty\n")
        self.assertEqual(self.apply()["functions"], [])

    def test_reject_invalid_options_and_configs(self):
        invalid = ("seed=-1", "seed=+1", "seed=18446744073709551616", "seed=abc",
                   "enabled=1", "max-sites=1000001", "seed=1;seed=2", "unknown=2", "seed=", "seed=1;")
        for option in invalid:
            with self.subTest(option=option):
                result = run(ARGS.opt, "-load-pass-plugin", ARGS.plugin,
                             f"-passes=aegis-shield<{option}>", "-disable-output", self.source, ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("aegis-shield:", result.stderr)
        config = self.root / "config.json"
        for value in ([], {}, {"schema_version": 2}, {"schema_version": 1, "seed": 1},
                      {"schema_version": 1, "seed": "-1"}, {"schema_version": 1, "enabled": "true"},
                      {"schema_version": 1, "max_sites_per_function": -1},
                      {"schema_version": 1, "max_sites_per_function": 1000001},
                      {"schema_version": 1, "typo": 0}):
            with self.subTest(config=value):
                config.write_text(json.dumps(value))
                result = run(ARGS.opt, "-load-pass-plugin", ARGS.plugin,
                             f"-passes=aegis-shield<config={config}>", "-disable-output", self.source, ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("aegis-shield:", result.stderr)
        config.write_text("{invalid")
        result = run(ARGS.opt, "-load-pass-plugin", ARGS.plugin,
                     f"-passes=aegis-shield<config={config}>", "-disable-output", self.source, ok=False)
        self.assertNotEqual(result.returncode, 0)
        config.unlink()
        result = run(ARGS.opt, "-load-pass-plugin", ARGS.plugin,
                     f"-passes=aegis-shield<config={config}>", "-disable-output", self.source, ok=False)
        self.assertIn("cannot read config", result.stderr)

    def test_report_failure_and_path_escaping(self):
        self.report = self.root / 'report "quoted".json'
        report = self.apply()
        self.assertEqual(report["transformed_sites"], 18)
        result = run(ARGS.opt, "-load-pass-plugin", ARGS.plugin,
                     f"-passes=aegis-shield<report={self.root}/missing/report.json>",
                     "-disable-output", self.source, ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot create report", result.stderr)


if __name__ == "__main__":
    unittest.main(argv=[__file__, *REST], verbosity=2)
