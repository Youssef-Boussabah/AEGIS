# AEGIS Workstream D Handoff

**Workstream:** D — Signature, Sentinel & Verification  
**Issue:** #12  
**Date:** 2026-10-28  

---

### 1. Implemented Behavior and Files Changed

#### Implemented Behavior
- **Offline Signed Provenance Manifest:**
  - Implemented versioned provenance manifest binding final artifact SHA-256 digest, byte size, source/build reference (repository, commit, branch, job ID), toolchain (compiler, version, platform, target triple), configuration identity (profile, backend, options digest), signer identity, and signing key identifier.
  - Implemented deterministic canonical JSON serialization following RFC 8785 principles.
  - Implemented Ed25519 cryptographic signing and envelope creation (RFC 8032) using standard `cryptography` primitives.
  - Implemented strict offline verification against explicit trusted public keys, rejecting tampered artifacts (`ARTIFACT_TAMPERED`), tampered manifest fields (`SIGNATURE_INVALID`), untrusted keys (`UNTRUSTED_KEY`), key ID mismatches (`KEY_ID_MISMATCH`), malformed envelopes (`MANIFEST_MALFORMED`), unsupported versions (`UNSUPPORTED_VERSION`), and absent trusted keys (`ABSENT_TRUSTED_KEYS`).
  - Implemented `aegis-provenance` CLI (`keygen`, `sign`, `verify`, `inspect`).

- **Sentinel Rights & Usage Policy Records:**
  - Implemented versioned machine-readable Sentinel policy records with explicit distinction between `advisory_notice` and `cooperating_enforced`.
  - Implemented policy validation rejecting ambiguous duplicate permissions for the same action, inverted time windows, and unsupported schema versions.
  - Implemented cooperating tool policy evaluator enforcing artifact SHA-256 linkage, temporal validity (`not_before` / `expires_at`), environment constraints, caller authorization, and watermark requirements.
  - Implemented `aegis-sentinel` CLI (`create`, `validate`, `inspect`, `evaluate`).

- **Watermark Research and Empirical Controls:**
  - Implemented binary watermark embedding/extraction with magic framing (`\x1bAEGIS_WM\x01` / `\x1bEND_WM\x1b`), uint16 length, and CRC32 error checking.
  - Implemented textual LLVM IR metadata node (`!aegis.watermark`) and comment embedding/extraction.
  - Evaluated empirical controls across 50 unmarked samples (0.0% False Positive Rate), 20 marked samples (100% True Positive Rate), cross-mark collision tests (0% collision rate), and transformation retention.
  - Documented empirical findings in `provenance/RESEARCH_WATERMARK.md`.

#### Files Changed and Created
- **Provenance Package (`provenance/`):**
  - `provenance/pyproject.toml`
  - `provenance/README.md`
  - `provenance/RESEARCH_WATERMARK.md`
  - `provenance/ERRORS.md`
  - `provenance/MEMORY.md`
  - `provenance/HANDOFF.md`
  - `provenance/src/aegis_provenance/__init__.py`
  - `provenance/src/aegis_provenance/models.py`
  - `provenance/src/aegis_provenance/canonical.py`
  - `provenance/src/aegis_provenance/crypto.py`
  - `provenance/src/aegis_provenance/manifest.py`
  - `provenance/src/aegis_provenance/cli.py`
  - `provenance/src/aegis_provenance/watermark/__init__.py`
  - `provenance/src/aegis_provenance/watermark/models.py`
  - `provenance/src/aegis_provenance/watermark/engine.py`
  - `provenance/src/aegis_provenance/watermark/benchmark.py`
  - `provenance/tests/test_prov_canonical.py`
  - `provenance/tests/test_prov_crypto.py`
  - `provenance/tests/test_prov_manifest.py`
  - `provenance/tests/test_provenance_cli.py`
  - `provenance/tests/test_prov_watermark.py`

- **Sentinel Package (`sentinel/`):**
  - `sentinel/pyproject.toml`
  - `sentinel/README.md`
  - `sentinel/src/aegis_sentinel/__init__.py`
  - `sentinel/src/aegis_sentinel/models.py`
  - `sentinel/src/aegis_sentinel/validator.py`
  - `sentinel/src/aegis_sentinel/evaluator.py`
  - `sentinel/src/aegis_sentinel/cli.py`
  - `sentinel/tests/test_sentinel_validator.py`
  - `sentinel/tests/test_sentinel_evaluator.py`
  - `sentinel/tests/test_sentinel_cli.py`

- **Cross-Platform Compatibility & Root Configuration:**
  - `core/src/aegis_core/adapter.py` (checked `hasattr(os, 'killpg')` before calling POSIX killpg)
  - `core/tests/test_core_orchestrator.py` (normalized Windows path separators in `argv` assertion)
  - `pyproject.toml` (added `provenance/tests` and `sentinel/tests` to root `testpaths`)

---

### 2. Branch and Commit State
- **Branch:** `feat/signature-sentinel`
- **Pushed to Remote:** `origin/feat/signature-sentinel` (commits `f7c080a..571d1cb`)
- **Base Integration Commit:** `a5efcd6a7b7b1e7695995377c6b1332a14618721`
- **Working Tree State:** Clean, up to date with remote.

---

### 3. Exact Test Commands, Results, Warnings, and Checks Not Run

#### Commands Run and Results:
- **Root Combined Pytest Suite:**
  ```powershell
  .\.venv\Scripts\python.exe -m pytest
  ```
  - **Result:** **141 passed**, 1 pre-existing warning in 14.47s.
  - **Warning:** `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead.` (pre-existing dependency warning).
- **Provenance Test Suite:**
  ```powershell
  .\.venv\Scripts\python.exe -m pytest provenance/tests -v
  ```
  - **Result:** **25 passed** in 0.81s.
- **Sentinel Test Suite:**
  ```powershell
  .\.venv\Scripts\python.exe -m pytest sentinel/tests -v
  ```
  - **Result:** **11 passed** in 0.65s.

#### Suites Not Run and Reasons:
- **LLVM Shield CTest & ImageLab CTest:**
  - **Not run** on this host because LLVM 22/Clang++, CMake, and Ninja toolchains are not installed on this Windows environment. As specified in `AGENTS.md` §4, missing prerequisite toolchains are truthfully reported as **not run**, never passed.

---

### 4. Artifact / Report Locations and Hashes Relevant to Result
- Manifest test fixture verified digest:
  - Input sample binary content: `\x7fELF\x02\x01\x01\x00data-protected-binary-content`
  - SHA-256: `785d9571344beea12111516e87a29e1f5fe3a3cfc5c760ea4c1616c61f25f209`
- Benchmark report:
  - `provenance/RESEARCH_WATERMARK.md`
- Tracking files:
  - `provenance/MEMORY.md`
  - `provenance/ERRORS.md`

---

### 5. Remaining Limitations and Failed Experiments
1. **Advisory Notice Boundary:** Publishing a Sentinel policy establishes machine-readable metadata and intentions. Non-cooperating external tools and third-party decompilers cannot be compelled to respect the policy without an active enforcement wrapper.
2. **Watermarking Limits:** Trailing binary marks and LLVM metadata survive formatting and comment removal, but do not survive aggressive stripping (`strip` or `-strip-debug`) or optimization passes that prune unreferenced metadata.
3. **No Authorship Proof:** Recovering a cryptographic signature or watermark verifies the claim of the signer/tagger at build time; it does not prove legal authorship of all underlying source code.

---

### 6. Unresolved Contract Questions and Owner Needed to Resolve Them
- **Linkage to Core Jobs (Owner: Workstream A):**
  - Signing currently operates after artifact generation (`aegis-provenance sign`). Future integration can chain signing as a post-job lifecycle hook in `aegis_core.orchestrator` once Stream A coordinates any new job metadata fields.
- **Dashboard Representation (Owner: Workstream C):**
  - Stream C should display verification status as distinct visual badges (`verified`, `tampered`, `untrusted_key`, `unverified_notice`), ensuring users never confuse an attached advisory notice with cryptographic verification.

---

### 7. Next Concrete Task to Resume Work
- Stage and commit the implemented files to `feat/signature-sentinel`:
  ```bash
  git add provenance/ sentinel/ core/src/aegis_core/adapter.py core/tests/test_core_orchestrator.py pyproject.toml
  git commit -m "feat(provenance): implement signed provenance manifests, sentinel policies, and watermark research"
  ```
- Open a Pull Request targeting `dev/integration` with the contents of `provenance/HANDOFF.md`.

