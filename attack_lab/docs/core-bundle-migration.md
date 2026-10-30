# Core/Lab compilation-bundle migration

Lab consumes the current Core contract in
`/home/youss/Projects/aegis-core-lab-execution/core/docs/lab-execution-contract.md`.
No Core source, authorization requirement, grant schema or ledger implementation
is changed by this migration. Agent 1's supplemental review plugin was read as a
reference only; neither tests nor production load it.

## Grant issuers and scoring

Every Lab scoring compilation has three staged files:

- `candidate.c`: the exact UTF-8 bytes of the verified reconstruction candidate;
- `aegis_harness.c`: generated from the selected symbol and interface arity;
- `aegis_candidate_unit.c`: the prototype and inclusion of `candidate.c`.

The exact ordered units are `aegis_harness.c`, `aegis_candidate_unit.c`.
The candidate is staged and included, never compiled as a separate unit.

`c_abi.compilation_sources` defines this layout. The production grant-metadata
helper `core_execution.reviewed_candidate_binding` uses Core's
`compilation_bundle_sha256` to produce a `PermittedCandidate` entry for the
operator's reviewed grant. The actual fixture issuer now uses this helper; no
pytest hook, monkeypatched issuer or test-runtime exemption supplies missing fields.
`core_execution.compilation_request` builds the same files for scoring.

For an already verified `PreparedScoring` named `prepared`, an operator's grant
issuer can obtain the reviewed candidate entry without opening Core or executing
anything:

```python
from aegis_lab.core_execution import reviewed_candidate_binding

entry = reviewed_candidate_binding(
    candidate_id=prepared.manifest.trial_id,
    candidate=prepared.candidate_source.encode("utf-8"),
    target_sha256=prepared.manifest.target.final_artifact_sha256,
    interface=prepared.interface.text,
    symbol=prepared.interface.symbol,
)
# Insert entry.model_dump(mode="json") in the operator-reviewed grant candidates.
```

The symbol comes from the verified reconstruction record's `task.function_label`,
not a hardcoded blinded label or the interface's label. Unblinded reconstruction
uses its declared function name. Source bytes are never normalized or rewritten.
No hidden test content or expected answer enters the generated source bundle.

The canonical digest binds a map of each exact filename to its byte SHA-256 and
the exact ordered unit list. File submission order is irrelevant; source bytes,
file names, additions/removals, and unit selection/order are binding. Compiler
flags and limits remain separately checked against the same Core grant and policy.

Lab refuses a missing bundle digest (`grant_compilation_bundle_required`) or a
different one (`grant_compilation_bundle_mismatch`) before opening any session,
constructing paired scoring output, invoking a runtime factory or reserving budget.
Core independently re-checks the submitted files and units at compilation. Its
`compilation_bundle_required`, `compilation_bundle_mismatch` and
`candidate_digest_mismatch` refusals remain intact, including for scripted runtimes.

All existing gates, authorization windows, target bindings, compiler allowlists,
limits, grant-wide budget reservations and persistent ledger checks remain intact.
Adding a bundle changes a grant's canonical identity. Operators must review and
reissue a grant with a fresh id and account for prior consumption; neither Lab nor
tests delete an existing ledger to migrate it.

## Reproduction against current Core

From `/home/youss/Projects/aegis-live-nebius`:

```sh
env PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS= PYTEST_ADDOPTS= \
  PYTHONPATH=/home/youss/Projects/aegis-core-lab-execution/core/src:/home/youss/Projects/aegis-live-nebius/attack_lab/src \
  AEGIS_GHIDRA_HEADLESS=/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
  /home/youss/Projects/aegis/.venv/bin/python -m pytest attack_lab/tests --lab-profile integration -q

env PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS= PYTEST_ADDOPTS= \
  PYTHONPATH=/home/youss/Projects/aegis-core-lab-execution/core/src:/home/youss/Projects/aegis-core-lab-execution/platform/api/src:/home/youss/Projects/aegis-core-lab-execution/platform/cli/src \
  /home/youss/Projects/aegis/.venv/bin/python -m pytest \
  /home/youss/Projects/aegis-core-lab-execution/core/tests \
  /home/youss/Projects/aegis-core-lab-execution/platform/api/tests \
  /home/youss/Projects/aegis-core-lab-execution/platform/cli/tests \
  -q -o cache_dir=/tmp/aegis-bundle-core-pytest-cache
```

Disabling third-party pytest plugin autoload and clearing supplemental plugin
options makes the source migration explicit. The normal repository conftests stay
in place. Python bytecode writes are disabled and Core's test cache goes to `/tmp`;
Core's worktree is not modified. Local Unix sockets and trusted Ghidra subprocesses
need an execution environment that permits them. Do not run another AEGIS Ghidra
preparation concurrently with the full suite: an existing process-cleanup test
checks globally for such processes.

The new tests use Core's real authorization, session and persistent ledger with
its non-executing `ScriptedIsolationRuntime`. Both blinded and unblinded cases
cover reviewed multi-file builds, UTF-8/CRLF preservation, file ordering, changed
candidate/harness/unit contents, added/removed/renamed files, changed unit
selection/order, missing digests, wrong symbols, early pair refusal, gate refusal,
and grant-identity conflicts. They assert zero compilation budget reserved and
zero compile/execute calls after a mismatch. No candidate compiler or VM runs.

## Validation results and remaining blockers

Current Core revision: `b3a44dc9bf6be6cc44c6208334049153ee5ae561`.
Imports of both `aegis_core.lab_authorization` and `aegis_core.lab_execution` were
independently checked to resolve under the current Core worktree's `core/src`.
Core's Git working tree was clean before and after validation. No source snapshot,
supplemental pytest plugin, VM, candidate execution, Nebius request, package
installation or Git mutation was used.

| Check | Result | Log |
| --- | --- | --- |
| Entire strict Lab suite, current Core, plugin autoload disabled | **1,986 passed; zero failures/skips/warnings**, 158.54 s | `/tmp/aegis-bundle-lab-strict.log` |
| Focused scoring and bundle migration | **247 passed**, including **38 new bundle cases**, zero skips/warnings | `/tmp/aegis-bundle-scoring-focused.log` |
| Current Core/API/CLI, isolated run | **482 passed; zero failures/skips; one warning**, 14.69 s | `/tmp/aegis-bundle-core-api-cli-isolated.log` |
| LLVM adapter, current Core and existing LLVM 22 build | **94 passed**, zero skips/warnings | `/tmp/aegis-bundle-adapter-tests.log` |
| Existing Shield CTest build | **1/1 passed** | `/tmp/aegis-bundle-shield-ctest.log` |
| Existing ImageLab CTest build | **14/14 passed** | `/tmp/aegis-bundle-imagelab-ctest.log` |

The Core/API/CLI warning is the installed Starlette/httpx TestClient deprecation.
An earlier concurrent Core/API/CLI run had **481 passed, one failed, one warning**:
`test_job_is_never_sent_unless_cgroup_limits_read_back[kw2-resource_enforcement_failed]`
reported `cleanup_failed` instead of `resource_enforcement_failed` in its fake
launcher. The complete isolated rerun passed unchanged. The first run is retained
at `/tmp/aegis-bundle-core-api-cli.log`; it is not counted as a pass. This observed
intermittent Core fixture classification remains a potential owner follow-up;
no Core test, runtime or assertion was modified.

There are **no remaining migration blockers**. Operators still need to review
and reissue legacy grants with complete bundle bindings and fresh grant ids before
real candidate work. Real candidate compilation/execution and VM validation were
**not run**, as instructed; their separate Core authorization/runtime approvals
remain required. This migration makes no behavioral or protection-effectiveness
claim. Root/shared architecture files remain owner-controlled and unchanged;
this change consumes Core's existing contract rather than altering it.

## Changed files

- `attack_lab/README.md`
- `attack_lab/docs/phase4-isolation-proposal.md`
- `attack_lab/docs/core-bundle-migration.md`
- `attack_lab/src/aegis_lab/behavior_score.py`
- `attack_lab/src/aegis_lab/c_abi.py`
- `attack_lab/src/aegis_lab/core_execution.py`
- `attack_lab/src/aegis_lab/scoring_policy.py`
- `attack_lab/tests/scoring_fixtures.py`
- `attack_lab/tests/test_compilation_bundle.py`
