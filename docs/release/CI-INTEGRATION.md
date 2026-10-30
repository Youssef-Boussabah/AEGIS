# CI coverage and Core + Lab integration gate

Current workflow `.github/workflows/ci.yml` retains the Python and real Shield
adapter jobs and the **explicit offline** Lab profile. It adds dashboard contract
checks/build, product-script failure checks, ImageLab CTest, real browser upload /
failed-job / report-download checks, and an explicit-tool Mirage smoke. No
required native/browser suite is conditionally skipped when prerequisites fail.

The Mirage product test transforms the checked-in owned fixture through the
actual merged transformer, checks the disabled byte-identical control, compiles
both variants, compares outputs and verifies retained symbols after O2/linker GC.
The original Mirage tests hard-code `/usr/bin` tools; installing LLVM 22 on a
hosted Ubuntu runner does not guarantee those paths refer to LLVM 22. The new
smoke therefore uses the transformer's supported explicit tool arguments from
PATH. The original **11-test Mirage suite is still required locally** and passed
on the validation host; it is not claimed as run in the hosted workflow. A future
owner change can make that suite tool-configurable without altering behavior.

The offline Lab job intentionally installs only Lab, not an older same-version
Core pretending to satisfy the scoring dependency. It cannot validate Phase 4.
The merged Lab profile reports skipped cases as NOT RUN. The product branch does
not copy Core from another worktree or depend on uncommitted owner snapshots.

## Enable this job only after Core is merged

Prerequisites, owned jointly by Agent 1 and Lab:

1. Merge the matching `aegis_core.lab_execution` and `aegis_core.lab_ledger`
   contracts and their tests, with package setup from the same checkout.
2. Resolve any contract drift in Lab against that exact Core. Package version
   `0.1.0` alone is insufficient evidence of compatibility.
3. Provision a pinned Ghidra 12.1.4 distribution/JDK, cc and nm on a runner that
   permits the trusted Unix-socket fixture and Ghidra subprocesses. Record its
   distribution hash and toolchain in the integration PR.
4. Enable the strict profile below as a required check. It must fail for missing
   Core, Ghidra/compiler/nm, collection failures, errors or **any skipped test**.
   A real-Ghidra timeout test can skip on fast hosts today; resolve its portability
   with the Lab owner before requiring green. Do not relax the skip gate.

Proposed job body (documentation only; not enabled prematurely):

```yaml
core-lab-integration:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: astral-sh/setup-uv@v5
    - run: uv python install 3.12
    - run: sh scripts/setup-python.sh
    - run: uv pip install --python .venv/bin/python -c core/requirements-dev.lock -e './attack_lab[dev,scoring]'
    # Add owner-reviewed pinned Ghidra/JDK provisioning here before enabling.
    - name: Require matching execution contracts
      run: .venv/bin/python -c 'import aegis_core.lab_execution, aegis_core.lab_ledger'
    - name: Strict Core + Lab integration
      env:
        AEGIS_GHIDRA_HEADLESS: /absolute/pinned/ghidra/support/analyzeHeadless
      run: .venv/bin/python -m pytest attack_lab/tests --lab-profile integration -q
```

This uses Core’s non-executing scripted runtime in tests. It does not authorize
live inference, an actual candidate runtime, VM boot or arbitrary-artifact attacks.
Runtime containment validation is a separate owner-delivered requirement.

The changed workflow has been reviewed and equivalent local suites run. No new
GitHub Actions run is claimed: these changes have not been committed or pushed.
