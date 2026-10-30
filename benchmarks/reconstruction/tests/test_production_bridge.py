"""Synthetic offline tests of production request rebuilding and fail-closed preparation."""
from copy import deepcopy
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import benchmark as b
import evidence as e
import prepare_live
import test_lab_imports as lab_tests
from test_benchmark import Fixture, NOW


class ProductionPromptTests(Fixture):
    # Reuse only the synthetic report builder, not the other class's test methods.
    ghidra = lab_tests.GhidraImportTests.ghidra

    def production(self):
        record, report = self.ghidra()
        self.manifest["targets"] = ["recon_mix"]
        for a in self.manifest["artifacts"]:
            a["targets"] = self.manifest["targets"]
        oracle = deepcopy(self.oracle)
        oracle["cases"] = [c for c in oracle["cases"] if c["function"] == "recon_mix"]
        self.manifest["oracle"] = self.write("selected-oracle.json", oracle)
        from aegis_lab.manifest import TrialManifest
        from aegis_lab.reconstruction import planned_attack_digests, prepare_reconstruction
        from aegis_lab.experiment import WorkflowConfig, initial_messages, live_workflow_sha256
        from aegis_lab.provider import InferenceRequest
        config = WorkflowConfig(max_steps=1)
        tool = {"name": "Ghidra", **self.controls["analysis_tools"]["Ghidra"]}
        lm = TrialManifest.model_validate({"trial_id": "1" * 32, "pair_id": "2" * 32, "variant": "baseline",
            "target": {"name": "synthetic-unit-only", "function": "recon_mix", "source_revision": "synthetic",
                "platform": "linux-x86_64", "artifact_format": "ELF", "final_artifact_sha256": record["artifact_sha256"],
                "build": {"pipeline": "synthetic-test", "compiler": {"name": "clang", "version": "22.synthetic",
                    "executable_sha256": b.digest(b"fake-compiler"), "configuration_sha256": b.digest(b"fake-flags")},
                    "shared_recipe_sha256": b.digest(b"fake-recipe"), "symbols": "present", "debug_info": False}},
            "attack": {"workflow": "ghidra_model", "tools": [tool], "provider": "Nebius",
                "model_id": "nvidia/synthetic-fixture-model", "sampling_seed": 42, "temperature": 0.0,
                "session_isolation": "fresh_session_and_workspace",
                **planned_attack_digests(max_model_tokens=16384, max_output_tokens=4096, blinded=True)},
            "access": {"workspace_policy_sha256": b.digest(b"synthetic-bound-decompilation")},
            "budget": {"max_wall_seconds": 300, "max_model_tokens": 16384, "max_tool_calls": 8, "max_attempts": 1},
            "scoring": {"hidden_test_suite_sha256": b.digest(b"no-hidden-suite"), "scorer": {"name": "absent",
                "version": "synthetic-no-execution", "executable_sha256": b.digest(b"absent"),
                "configuration_sha256": b.digest(b"absent")}, "expected_interface": "opaque(uint32_t,uint32_t)->uint32_t"},
            "authorization": {"reference": "synthetic-test-only", "authorized_scope": "no real inference or execution"}})
        lm_ref = self.write("lab-manifest.json", lm.model_dump(mode="json"))
        prepared = prepare_reconstruction(lm, b.read_file(self.root / "ghidra.json"), max_output_tokens=4096)
        request = InferenceRequest(**{**prepared.request.model_dump(), "messages": initial_messages(prepared), "store": False}).to_body()
        self.controls.update(prompt_template_sha256=lm.attack.prompt_sha256,
            system_prompt_sha256=b.digest(request["messages"][0]["content"].encode()),
            workflow_sha256=live_workflow_sha256(config),
            request_parameters_sha256=b.identity({k: v for k, v in request.items() if k != "messages"}),
            model_identity=lm.attack.model_id)
        record.update(controls=deepcopy(self.controls), targets=self.manifest["targets"],
            comparison_sha256=b.identity(self.manifest), prompt={"format": "aegis_lab", "manifest": lm_ref,
                "report": self.ref("ghidra.json"), "request": self.write("request.json", request),
                "configuration": config.model_dump(mode="json")})
        return record, request

    def test_rebuilds_actual_production_initial_messages(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no provider or Ghidra launch")):
            record, _ = self.production()
            self.assertEqual(self.verify(record)["classification"], "structural_observation")

    def test_actual_saved_request_cannot_change_prompt_or_sampling(self):
        for mutate in [lambda r: r["messages"][0].update(content="different system instructions"),
                       lambda r: r.update(temperature=0.8), lambda r: r.update(max_tokens=8192)]:
            record, request = self.production()
            mutate(request)
            record["prompt"]["request"] = self.write("request.json", request)
            self.invalid(lambda: self.verify(record), "lab_request_mismatch")

    def test_workflow_and_target_configuration_mismatch(self):
        record, _ = self.production()
        record["prompt"]["configuration"]["max_steps"] = 2
        self.invalid(lambda: self.verify(record), "lab_request_controls_mismatch")
        record, _ = self.production()
        lm = b.load(self.root / "lab-manifest.json")
        lm["target"]["function"] = "recon_gate"
        record["prompt"]["manifest"] = self.write("lab-manifest.json", lm)
        self.invalid(lambda: self.verify(record), "lab_target_mismatch")

    def test_unverified_private_archive_fails_without_execution(self):
        record, _ = self.production()
        record["kind"] = "lab_experiment"
        record["source"] = self.write("experiment.json", {"notice": "synthetic invalid archive"})
        with patch("subprocess.Popen", side_effect=AssertionError("no candidate execution")):
            self.invalid(lambda: self.verify(record), "invalid_lab_experiment_archive")

    def test_oracle_arity_must_match_production_target_interface(self):
        record, _ = self.production()
        oracle = b.load(self.root / "selected-oracle.json")
        oracle["interface"] = "u32(u32,u32,u32,u32)"
        for c in oracle["cases"]:
            c["arguments"] += [0, 0]
        self.manifest["oracle"] = self.write("selected-oracle.json", oracle)
        record["comparison_sha256"] = b.identity(self.manifest)
        self.invalid(lambda: self.verify(record), "lab_oracle_interface_mismatch")

    def test_explicit_thinking_control_is_preserved_in_production_import(self):
        record, request = self.production()
        from aegis_lab.reconstruction import planned_attack_digests
        manifest = b.load(self.root / "lab-manifest.json")
        manifest["attack"].update(planned_attack_digests(max_model_tokens=16384,
            max_output_tokens=4096, blinded=True, enable_thinking=False))
        record["prompt"]["manifest"] = self.write("lab-manifest.json", manifest)
        request["chat_template_kwargs"] = {"enable_thinking": False}
        record["prompt"]["request"] = self.write("request.json", request)
        self.controls["request_parameters_sha256"] = b.identity({k: v for k, v in request.items() if k != "messages"})
        record["controls"] = deepcopy(self.controls)
        record["comparison_sha256"] = b.identity(self.manifest)
        self.assertEqual(self.verify(record)["classification"], "structural_observation")


class PreparationRefusalTests(Fixture):
    def prepare(self):
        with patch.object(b, "report_archive", return_value={"manifest": deepcopy(self.manifest)}):
            return prepare_live.prepare(self.root / "measurements.json", self.root / "new-prep",
                                        self.root / "unused-headless")

    def one_function(self):
        self.manifest["targets"] = ["recon_mix"]
        for a in self.manifest["artifacts"]:
            a["targets"] = ["recon_mix"]

    def test_multiple_targets_need_separate_lab_trials(self):
        self.invalid(self.prepare, "production_pipeline_requires_one_selected_function")

    def test_unowned_sources_cannot_be_disclosed(self):
        self.one_function()
        self.manifest["sources"][0]["sha256"] = b.digest(b"unknown source")
        self.invalid(self.prepare, "only_pinned_owned_sources_may_be_disclosed")

    def test_identical_final_artifacts_are_not_a_three_way_transformation(self):
        self.one_function()
        self.invalid(self.prepare, "distinct_final_artifacts_required")

    def test_analysis_is_explicit_and_does_not_read_credentials(self):
        self.one_function()
        self.manifest["artifacts"][1]["file"]["sha256"] = b.digest(b"distinct-test-binary")
        with patch("subprocess.Popen", side_effect=AssertionError("no implicit analysis or provider")):
            self.invalid(self.prepare, "supply_completed_reports_or_explicit_owned_analysis")


if __name__ == "__main__":
    import unittest
    unittest.main()
