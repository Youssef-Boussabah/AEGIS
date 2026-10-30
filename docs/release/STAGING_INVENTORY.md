# Exact staging review inventory

Snapshot UTC: **2026-10-30T15:33:56.931296+00:00**. Branch `dev/integration`; HEAD `691ce2717934c22dd30883b5dd8a586ebf78bf20`.

**202 paths**: 65 modified tracked, 137 untracked. Index empty at capture. **No staging performed.**

This is a byte-bound review snapshot, not authorization to stage, license or publish.
It includes every current new implementation, test, fixture and document, including
files added by concurrent work during the audit. Git does not establish authorship.
“New during audit” means absent from the initial 110-path status, not a claim about who wrote it.

The older CHANGED_FILES.md (108 paths) is historical. Review all rows here and
STAGING_SNAPSHOT.json file digests. STAGING_PATHS.txt is the exact literal pathspec list.
Snapshot JSON omits only its own digest to avoid circular hashing. All other listed
files, including this inventory and the pathspec list, are hashed. Any change/new path
requires regeneration and review; the frozen integration gate has passed.

LICENSE is the operator-approved standard MIT with four confirmed holders.
Final contents/publication approval remains separate. No credential, approval, raw inference archive,
private job store or dependency/build directory belongs in this inventory. Ignored
dashboard dist belongs only in the separately checked archive, not source staging.

Current gate and release results are in RELEASE_CONTENTS_READY.md.
The earlier 794-test companion run does not certify the final tree. Publication still needs approval.

| Status | Path | Kind | Reviewer | Provenance in this audit |
| --- | --- | --- | --- | --- |
| ` M` | `.github/workflows/ci.yml` | Configuration / asset / review metadata | A | Pre-existing work preserved |
| ` M` | `ARCHITECTURE.md` | Documentation | A | Final system-test authorization fix (preserves earlier work) |
| ` M` | `README.md` | Documentation | A | Final system-test authorization fix (preserves earlier work) |
| ` M` | `attack_lab/README.md` | Documentation | B | Pre-existing work preserved |
| ` M` | `attack_lab/docs/live-inference.md` | Documentation | B | Pre-existing work preserved |
| ` M` | `attack_lab/pyproject.toml` | Configuration / asset / review metadata | B | Concurrent owner work; review system-test handoff |
| ` M` | `attack_lab/src/aegis_lab/bounded_provider.py` | Implementation / source asset | B | Pre-existing work preserved |
| ` M` | `attack_lab/src/aegis_lab/disclosure.py` | Implementation / source asset | B | Pre-existing work preserved |
| ` M` | `attack_lab/src/aegis_lab/experiment.py` | Implementation / source asset | B | Pre-existing work preserved |
| ` M` | `attack_lab/src/aegis_lab/live.py` | Implementation / source asset | B | Pre-existing work preserved |
| ` M` | `attack_lab/src/aegis_lab/live_trial.py` | Implementation / source asset | B | Pre-existing work preserved |
| ` M` | `attack_lab/src/aegis_lab/provider.py` | Implementation / source asset | B | Pre-existing work preserved |
| ` M` | `attack_lab/src/aegis_lab/reconstruction.py` | Implementation / source asset | B | Concurrent owner work; review system-test handoff |
| ` M` | `core/README.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `core/pyproject.toml` | Configuration / asset / review metadata | A | Concurrent owner work; review system-test handoff |
| ` M` | `core/src/aegis_core/config.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `core/src/aegis_core/models.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `core/src/aegis_core/orchestrator.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `core/src/aegis_core/storage.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `core/src/aegis_core/testing/__init__.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `docs/PROJECT_STATUS.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `docs/release/AGENT1-CONTRACT.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `docs/release/CI-INTEGRATION.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `docs/release/DEMO-SCRIPT.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `docs/release/LICENSE-MIT-DRAFT.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `docs/release/RUNBOOK.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `docs/release/SUBMISSION.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `docs/release/VALIDATION.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `platform/api/README.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `platform/api/pyproject.toml` | Configuration / asset / review metadata | A | Pre-existing work preserved |
| ` M` | `platform/api/src/aegis_api/app.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `platform/cli/README.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `platform/cli/pyproject.toml` | Configuration / asset / review metadata | A | Pre-existing work preserved |
| ` M` | `platform/cli/src/aegis_cli/main.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `platform/dashboard/FRONTEND_HANDOFF.md` | Documentation | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/README.md` | Documentation | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/index.html` | Configuration / asset / review metadata | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/package-lock.json` | Configuration / asset / review metadata | C | Concurrent owner work; review system-test handoff |
| ` M` | `platform/dashboard/package.json` | Configuration / asset / review metadata | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/playwright.config.ts` | Implementation / source asset | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/src/App.tsx` | Implementation / source asset | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/src/contracts.ts` | Implementation / source asset | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/src/style.css` | Configuration / asset / review metadata | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/tests/browser/product.spec.ts` | Test / test asset | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/tests/contracts.test.ts` | Test / test asset | C | Pre-existing work preserved |
| ` M` | `platform/dashboard/vite.config.ts` | Implementation / source asset | C | Pre-existing work preserved |
| ` M` | `protectors/llvm/adapter/README.md` | Documentation | A | Pre-existing work preserved |
| ` M` | `protectors/llvm/adapter/aegis_llvm_adapter.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `protectors/llvm/adapter/tests/conftest.py` | Test / test asset | A | Pre-existing work preserved |
| ` M` | `protectors/mirage/README.md` | Documentation | B | Pre-existing work preserved |
| ` M` | `protectors/mirage/pyproject.toml` | Configuration / asset / review metadata | B | Concurrent owner work; review system-test handoff |
| ` M` | `protectors/mirage/src/aegis_mirage/transform.py` | Implementation / source asset | B | Pre-existing work preserved |
| ` M` | `protectors/mirage/tests/test_transform.py` | Test / test asset | B | Pre-existing work preserved |
| ` M` | `provenance/README.md` | Documentation | D | Pre-existing work preserved |
| ` M` | `provenance/pyproject.toml` | Configuration / asset / review metadata | D | Pre-existing work preserved |
| ` M` | `provenance/src/aegis_provenance/cli.py` | Implementation / source asset | D | Pre-existing work preserved |
| ` M` | `provenance/src/aegis_provenance/crypto.py` | Implementation / source asset | D | Pre-existing work preserved |
| ` M` | `provenance/tests/test_provenance_cli.py` | Test / test asset | D | Pre-existing work preserved |
| ` M` | `scripts/export-product-evidence.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `scripts/product.py` | Implementation / source asset | A | Pre-existing work preserved |
| ` M` | `scripts/tests/test_product.py` | Test / test asset | A | Pre-existing work preserved |
| ` M` | `sentinel/README.md` | Documentation | D | Pre-existing work preserved |
| ` M` | `sentinel/pyproject.toml` | Configuration / asset / review metadata | D | Concurrent owner work; review system-test handoff |
| ` M` | `sentinel/src/aegis_sentinel/evaluator.py` | Implementation / source asset | D | Pre-existing work preserved |
| ` M` | `sentinel/tests/test_sentinel_evaluator.py` | Test / test asset | D | Pre-existing work preserved |
| `??` | `LICENSE` | Approved standard MIT notice; final publication review | A | Pre-existing work preserved |
| `??` | `attack_lab/LICENSE` | Configuration / asset / review metadata | B | Concurrent owner work; review system-test handoff |
| `??` | `attack_lab/docs/agent2-validation.md` | Documentation | B | Pre-existing work preserved |
| `??` | `attack_lab/docs/nebius-reasoning-compatibility.md` | Documentation | B | Pre-existing work preserved |
| `??` | `attack_lab/docs/nvidia-research-deliverable.md` | Documentation | B | Pre-existing work preserved |
| `??` | `attack_lab/docs/operator-live-run.md` | Documentation | B | Pre-existing work preserved |
| `??` | `attack_lab/docs/public-summary.md` | Documentation | B | Pre-existing work preserved |
| `??` | `attack_lab/docs/thinking-control.md` | Documentation | B | Concurrent owner work; review system-test handoff |
| `??` | `attack_lab/src/aegis_lab/completion_review.py` | Implementation / source asset | B | Pre-existing work preserved |
| `??` | `attack_lab/src/aegis_lab/public_summary.py` | Implementation / source asset | B | Pre-existing work preserved |
| `??` | `attack_lab/src/aegis_lab/remaining_inference.py` | Implementation / source asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/fixtures/nebius-reasoning-sanitized.json` | Test / test asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/fixtures/public-summary/offline-scripted.json` | Test / test asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/fixtures/public-summary/schema.json` | Test / test asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/fixtures/public-summary/synthetic-comparison.json` | Test / test asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/fixtures/public-summary/synthetic-nebius.json` | Test / test asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/fixtures/public-summary/synthetic-post-hoc.json` | Test / test asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/test_nebius_reasoning.py` | Test / test asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/test_public_summary.py` | Test / test asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/test_research_deliverable.py` | Test / test asset | B | Pre-existing work preserved |
| `??` | `attack_lab/tests/test_thinking_control.py` | Test / test asset | B | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/.gitignore` | Configuration / asset / review metadata | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/FORMATS.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/NVIDIA_DEMO.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/README.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/RESULTS.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/SYSTEM_TEST.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/VALIDATION.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/benchmark.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/evidence.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/fixtures/oracle.json` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/fixtures/runner.c` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/fixtures/target.c` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/measured-results.json` | Configuration / asset / review metadata | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/prepare_live.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/tests/test_benchmark.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/tests/test_lab_imports.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/tests/test_native.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `benchmarks/reconstruction/tests/test_production_bridge.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `core/LICENSE` | Configuration / asset / review metadata | A | Concurrent owner work; review system-test handoff |
| `??` | `core/tests/test_core_attestation_hooks.py` | Test / test asset | A | Pre-existing work preserved |
| `??` | `docs/release/ATTACK_DEFENSE_EVIDENCE.md` | Documentation | A | Concurrent owner work; review system-test handoff |
| `??` | `docs/release/CHANGED_FILES.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/FINAL_API_CONTRACT.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/FINAL_RELEASE_REPORT.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/FINAL_SIGNED_DEMO.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/FINAL_SYSTEM_TEST.md` | Documentation | A | This release-readiness task |
| `??` | `docs/release/FULL_SYSTEM_VALIDATION.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/HACKATHON_SUBMISSION_READY.md` | Documentation | A | This release-readiness task |
| `??` | `docs/release/INSTALL.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/INTEGRATION_AUDIT.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/JUDGE_RUNTIME_INFERENCE.md` | Documentation | A | This release-readiness task |
| `??` | `docs/release/NATIVE_BACKEND_CONTRACT.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/NATIVE_INTEGRATION.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/NEBIUS_SPEND_RECONCILIATION.md` | Documentation | A | This release-readiness task |
| `??` | `docs/release/NVIDIA_NEBIUS.md` | Documentation | A | Pre-existing work preserved |
| `??` | `docs/release/RELEASE_COMMANDS.md` | Documentation | A | This release-readiness task |
| `??` | `docs/release/RELEASE_CONTENTS_READY.md` | Documentation | A | This release-readiness task |
| `??` | `docs/release/STAGING_INVENTORY.md` | Documentation | A | This release-readiness task |
| `??` | `docs/release/STAGING_PATHS.txt` | Configuration / asset / review metadata | A | This release-readiness task |
| `??` | `docs/release/STAGING_SNAPSHOT.json` | Configuration / asset / review metadata | A | This release-readiness task |
| `??` | `docs/release/THIRD_PARTY_NOTICES.md` | Documentation | A | Pre-existing work preserved |
| `??` | `experiments/adaptive_mvp/README.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/RESULTS.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/SYSTEM_TEST.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/__init__.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/controller.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/evidence.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/lab_bridge.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/policy.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/target/signal.c` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/tests/test_controller.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/tests/test_evidence.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/tests/test_lab_bridge.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/tests/test_native.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/tests/test_policy.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `experiments/adaptive_mvp/verify.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/README.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/RESULTS.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/SYSTEM_TEST.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/examples/owned/CMakeLists.txt` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/examples/owned/checksum.c` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/examples/owned/compute.h` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/examples/owned/kernels.cpp` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/examples/owned/main.cpp` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/examples/owned/policy.cpp` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/examples/owned/project.json` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/ir.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/native_project.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/runner.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/tests/conftest.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/tests/test_manifest_ir.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/tests/test_native.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/native_project/tests/test_runner.py` | Test / test asset | A + affected owner; assignment to confirm | Native system-test fixture fix |
| `??` | `integrations/native_project/workflow.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/.gitignore` | Configuration / asset / review metadata | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/README.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/RESULTS.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/SYSTEM_TEST.md` | Documentation | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/capture.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/fixtures/component/Cargo.lock` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/fixtures/component/Cargo.toml` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/fixtures/component/src/lib.rs` | Owned fixture / example (review provenance) | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/protect.py` | Implementation / source asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/pyproject.toml` | Configuration / asset / review metadata | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/tests/conftest.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/tests/test_pipeline.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `integrations/rust/tests/test_real.py` | Test / test asset | A + affected owner; assignment to confirm | Concurrent owner work; review system-test handoff |
| `??` | `platform/api/LICENSE` | Configuration / asset / review metadata | A | Concurrent owner work; review system-test handoff |
| `??` | `platform/api/tests/test_api_attestation.py` | Test / test asset | A | Pre-existing work preserved |
| `??` | `platform/cli/LICENSE` | Configuration / asset / review metadata | A | Concurrent owner work; review system-test handoff |
| `??` | `platform/cli/tests/test_cli_attestation.py` | Test / test asset | A | Pre-existing work preserved |
| `??` | `platform/dashboard/LICENSE` | Configuration / asset / review metadata | C | Concurrent owner work; review system-test handoff |
| `??` | `platform/dashboard/VALIDATION.md` | Documentation | C | Pre-existing work preserved |
| `??` | `platform/dashboard/src/ResearchView.tsx` | Implementation / source asset | C | Pre-existing work preserved |
| `??` | `platform/dashboard/src/VerificationView.tsx` | Implementation / source asset | C | Pre-existing work preserved |
| `??` | `platform/dashboard/src/WorkspaceViews.tsx` | Implementation / source asset | C | Pre-existing work preserved |
| `??` | `platform/dashboard/src/attestation.ts` | Implementation / source asset | C | Pre-existing work preserved |
| `??` | `platform/dashboard/src/research-schema.json` | Configuration / asset / review metadata | C | Pre-existing work preserved |
| `??` | `platform/dashboard/src/research.ts` | Implementation / source asset | C | Pre-existing work preserved |
| `??` | `platform/dashboard/tests/attestation-fixtures.ts` | Test / test asset | C | Pre-existing work preserved |
| `??` | `platform/dashboard/tests/browser/real-attestation.spec.ts` | Test / test asset | C | Pre-existing work preserved |
| `??` | `platform/dashboard/tests/browser/workspace.spec.ts` | Test / test asset | C | Pre-existing work preserved |
| `??` | `platform/dashboard/tests/prepare_attestation.py` | Test / test asset | C | Pre-existing work preserved |
| `??` | `protectors/llvm/adapter/aegis_shield_mirage_adapter.py` | Implementation / source asset | A | Pre-existing work preserved |
| `??` | `protectors/llvm/adapter/tests/test_shield_mirage_adapter.py` | Test / test asset | A | Pre-existing work preserved |
| `??` | `protectors/mirage/LICENSE` | Configuration / asset / review metadata | B | Concurrent owner work; review system-test handoff |
| `??` | `provenance/LICENSE` | Configuration / asset / review metadata | D | Concurrent owner work; review system-test handoff |
| `??` | `provenance/src/aegis_provenance/jobs.py` | Implementation / source asset | D | Pre-existing work preserved |
| `??` | `provenance/src/aegis_provenance/testing.py` | Implementation / source asset | D | Pre-existing work preserved |
| `??` | `provenance/tests/test_prov_jobs.py` | Test / test asset | D | Pre-existing work preserved |
| `??` | `scripts/check-research-dashboard.cjs` | Implementation / source asset | A | Pre-existing work preserved |
| `??` | `scripts/live_evaluate.py` | Implementation / source asset | A | Final system-test authorization fix (preserves earlier work) |
| `??` | `scripts/native_tests/conftest.py` | Implementation / source asset | A | Pre-existing work preserved |
| `??` | `scripts/native_tests/test_shield_mirage_native.py` | Test / test asset | A | Pre-existing work preserved |
| `??` | `scripts/tests/test_live_evaluate.py` | Test / test asset | A | Final system-test authorization fix (preserves earlier work) |
| `??` | `sentinel/LICENSE` | Configuration / asset / review metadata | D | Concurrent owner work; review system-test handoff |
