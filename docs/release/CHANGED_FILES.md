# Final commit review inventory

Every entry below is currently modified or untracked and belongs in the operator's
review of the final commit. No files were staged or committed by Agent 4. Status
`M` means modified tracked file, `??` means untracked source/documentation that
must be added explicitly after review. “Agent 4” identifies files edited in this
final release task; all other changes predated it and were preserved. The operator specifically authorized
the Provenance signing-key ancestry fix and its README/tests/architecture updates.

The built `platform/dashboard/dist` is included in the review archive and its
SHA-256 inventory; it remains Git-ignored and does not belong in the source commit.
Neither dependency directories, private evidence/approvals, signing keys, local
configs/stores, nor `/tmp` reports/screenshots belong in the commit. The root
LICENSE remains a pending-approval proposal. Any later owner edit requires this
inventory and the package to be refreshed.

| Git status | File | This final release task |
| --- | --- | --- |
| `M` | `.github/workflows/ci.yml` | Preserved workstream change |
| `M` | `ARCHITECTURE.md` | Agent 4 edited |
| `M` | `README.md` | Agent 4 edited |
| `M` | `attack_lab/README.md` | Preserved workstream change |
| `M` | `attack_lab/docs/live-inference.md` | Preserved workstream change |
| `M` | `attack_lab/src/aegis_lab/bounded_provider.py` | Preserved workstream change |
| `M` | `attack_lab/src/aegis_lab/disclosure.py` | Preserved workstream change |
| `M` | `attack_lab/src/aegis_lab/experiment.py` | Preserved workstream change |
| `M` | `attack_lab/src/aegis_lab/live.py` | Preserved workstream change |
| `M` | `attack_lab/src/aegis_lab/live_trial.py` | Preserved workstream change |
| `M` | `attack_lab/src/aegis_lab/provider.py` | Preserved workstream change |
| `M` | `core/README.md` | Preserved workstream change |
| `M` | `core/src/aegis_core/config.py` | Preserved workstream change |
| `M` | `core/src/aegis_core/models.py` | Preserved workstream change |
| `M` | `core/src/aegis_core/orchestrator.py` | Preserved workstream change |
| `M` | `core/src/aegis_core/storage.py` | Preserved workstream change |
| `M` | `core/src/aegis_core/testing/__init__.py` | Preserved workstream change |
| `M` | `docs/release/AGENT1-CONTRACT.md` | Agent 4 edited |
| `M` | `docs/release/CI-INTEGRATION.md` | Agent 4 edited |
| `M` | `docs/release/DEMO-SCRIPT.md` | Agent 4 edited |
| `M` | `docs/release/LICENSE-MIT-DRAFT.md` | Agent 4 edited |
| `M` | `docs/release/RUNBOOK.md` | Agent 4 edited |
| `M` | `docs/release/SUBMISSION.md` | Agent 4 edited |
| `M` | `docs/release/VALIDATION.md` | Agent 4 edited |
| `M` | `platform/api/README.md` | Preserved workstream change |
| `M` | `platform/api/pyproject.toml` | Preserved workstream change |
| `M` | `platform/api/src/aegis_api/app.py` | Preserved workstream change |
| `M` | `platform/cli/README.md` | Preserved workstream change |
| `M` | `platform/cli/pyproject.toml` | Preserved workstream change |
| `M` | `platform/cli/src/aegis_cli/main.py` | Preserved workstream change |
| `M` | `platform/dashboard/FRONTEND_HANDOFF.md` | Preserved workstream change |
| `M` | `platform/dashboard/README.md` | Preserved workstream change |
| `M` | `platform/dashboard/index.html` | Preserved workstream change |
| `M` | `platform/dashboard/package.json` | Preserved workstream change |
| `M` | `platform/dashboard/playwright.config.ts` | Preserved workstream change |
| `M` | `platform/dashboard/src/App.tsx` | Preserved workstream change |
| `M` | `platform/dashboard/src/contracts.ts` | Preserved workstream change |
| `M` | `platform/dashboard/src/style.css` | Preserved workstream change |
| `M` | `platform/dashboard/tests/browser/product.spec.ts` | Preserved workstream change |
| `M` | `platform/dashboard/tests/contracts.test.ts` | Preserved workstream change |
| `M` | `platform/dashboard/vite.config.ts` | Preserved workstream change |
| `M` | `protectors/llvm/adapter/README.md` | Preserved workstream change |
| `M` | `protectors/llvm/adapter/aegis_llvm_adapter.py` | Preserved workstream change |
| `M` | `protectors/llvm/adapter/tests/conftest.py` | Preserved workstream change |
| `M` | `protectors/mirage/README.md` | Preserved workstream change |
| `M` | `protectors/mirage/src/aegis_mirage/transform.py` | Preserved workstream change |
| `M` | `protectors/mirage/tests/test_transform.py` | Preserved workstream change |
| `M` | `provenance/README.md` | Agent 4 edited |
| `M` | `provenance/pyproject.toml` | Preserved workstream change |
| `M` | `provenance/src/aegis_provenance/cli.py` | Preserved workstream change |
| `M` | `provenance/src/aegis_provenance/crypto.py` | Preserved workstream change |
| `M` | `provenance/tests/test_provenance_cli.py` | Preserved workstream change |
| `M` | `scripts/export-product-evidence.py` | Preserved workstream change |
| `M` | `scripts/product.py` | Agent 4 edited |
| `M` | `scripts/tests/test_product.py` | Agent 4 edited |
| `M` | `sentinel/README.md` | Preserved workstream change |
| `M` | `sentinel/src/aegis_sentinel/evaluator.py` | Preserved workstream change |
| `M` | `sentinel/tests/test_sentinel_evaluator.py` | Preserved workstream change |
| `??` | `LICENSE` | Agent 4 edited |
| `??` | `attack_lab/docs/agent2-validation.md` | Preserved workstream change |
| `??` | `attack_lab/docs/nebius-reasoning-compatibility.md` | Preserved workstream change |
| `??` | `attack_lab/docs/nvidia-research-deliverable.md` | Preserved workstream change |
| `??` | `attack_lab/docs/operator-live-run.md` | Preserved workstream change |
| `??` | `attack_lab/docs/public-summary.md` | Preserved workstream change |
| `??` | `attack_lab/src/aegis_lab/completion_review.py` | Preserved workstream change |
| `??` | `attack_lab/src/aegis_lab/public_summary.py` | Preserved workstream change |
| `??` | `attack_lab/src/aegis_lab/remaining_inference.py` | Preserved workstream change |
| `??` | `attack_lab/tests/fixtures/nebius-reasoning-sanitized.json` | Preserved workstream change |
| `??` | `attack_lab/tests/fixtures/public-summary/offline-scripted.json` | Preserved workstream change |
| `??` | `attack_lab/tests/fixtures/public-summary/schema.json` | Preserved workstream change |
| `??` | `attack_lab/tests/fixtures/public-summary/synthetic-comparison.json` | Preserved workstream change |
| `??` | `attack_lab/tests/fixtures/public-summary/synthetic-nebius.json` | Preserved workstream change |
| `??` | `attack_lab/tests/fixtures/public-summary/synthetic-post-hoc.json` | Preserved workstream change |
| `??` | `attack_lab/tests/test_nebius_reasoning.py` | Preserved workstream change |
| `??` | `attack_lab/tests/test_public_summary.py` | Preserved workstream change |
| `??` | `attack_lab/tests/test_research_deliverable.py` | Preserved workstream change |
| `??` | `core/tests/test_core_attestation_hooks.py` | Preserved workstream change |
| `??` | `docs/release/CHANGED_FILES.md` | Agent 4 edited |
| `??` | `docs/release/FINAL_API_CONTRACT.md` | Preserved workstream change |
| `??` | `docs/release/FINAL_RELEASE_REPORT.md` | Agent 4 edited |
| `??` | `docs/release/FINAL_SIGNED_DEMO.md` | Preserved workstream change |
| `??` | `docs/release/INSTALL.md` | Agent 4 edited |
| `??` | `docs/release/INTEGRATION_AUDIT.md` | Agent 4 edited |
| `??` | `docs/release/NATIVE_BACKEND_CONTRACT.md` | Preserved workstream change |
| `??` | `docs/release/NATIVE_INTEGRATION.md` | Agent 4 edited |
| `??` | `docs/release/NVIDIA_NEBIUS.md` | Agent 4 edited |
| `??` | `docs/release/THIRD_PARTY_NOTICES.md` | Agent 4 edited |
| `??` | `platform/api/tests/test_api_attestation.py` | Preserved workstream change |
| `??` | `platform/cli/tests/test_cli_attestation.py` | Preserved workstream change |
| `??` | `platform/dashboard/VALIDATION.md` | Preserved workstream change |
| `??` | `platform/dashboard/src/ResearchView.tsx` | Preserved workstream change |
| `??` | `platform/dashboard/src/VerificationView.tsx` | Preserved workstream change |
| `??` | `platform/dashboard/src/WorkspaceViews.tsx` | Preserved workstream change |
| `??` | `platform/dashboard/src/attestation.ts` | Preserved workstream change |
| `??` | `platform/dashboard/src/research-schema.json` | Preserved workstream change |
| `??` | `platform/dashboard/src/research.ts` | Preserved workstream change |
| `??` | `platform/dashboard/tests/attestation-fixtures.ts` | Preserved workstream change |
| `??` | `platform/dashboard/tests/browser/real-attestation.spec.ts` | Preserved workstream change |
| `??` | `platform/dashboard/tests/browser/workspace.spec.ts` | Preserved workstream change |
| `??` | `platform/dashboard/tests/prepare_attestation.py` | Preserved workstream change |
| `??` | `protectors/llvm/adapter/aegis_shield_mirage_adapter.py` | Preserved workstream change |
| `??` | `protectors/llvm/adapter/tests/test_shield_mirage_adapter.py` | Preserved workstream change |
| `??` | `provenance/src/aegis_provenance/jobs.py` | Agent 4 edited |
| `??` | `provenance/src/aegis_provenance/testing.py` | Preserved workstream change |
| `??` | `provenance/tests/test_prov_jobs.py` | Agent 4 edited |
| `??` | `scripts/check-research-dashboard.cjs` | Agent 4 edited |
| `??` | `scripts/native_tests/conftest.py` | Preserved workstream change |
| `??` | `scripts/native_tests/test_shield_mirage_native.py` | Preserved workstream change |

**108 files** currently require review; **23** edited by this final release task.
