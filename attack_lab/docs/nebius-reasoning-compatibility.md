# Nebius reasoning metadata compatibility — 30 October 2026

The operator supplied one archived response from
`nvidia/Nemotron-3_5-Lightning`. Inspection and revalidation were entirely offline.
Only field names/types, statuses, hashes and reported usage were printed. No
prompt, reasoning text, generated source, credential or full response was printed
or copied into a fixture. No request, approval consumption, spending-limit change,
generated-code execution, package installation, commit or push occurred.

## Exact cause and narrow fix

The assistant message contains **`reasoning` and `reasoning_content` as strings**.
Both triggered `unsupported_fields=true`: the original parser recognizes those
names only as null placeholders. `audio` and `annotations` were null and already
accepted; they did not cause rejection. Standard `function_call`, `tool_calls`
and `refusal` were null. The response finished with `stop`; reported usage is
1786 prompt + 8039 completion = 9825 total tokens. The candidate envelope is
structurally valid. These are provider reports and text validation, not behavioral
or security results.

`provider.parse_completion` now supports two explicit parser policies:

- `aegis.lab.completion-parser.v1` retains the old interpretation exactly and
  remains the default for existing direct callers and unversioned archives.
- `aegis.lab.nebius-reasoning-text.v2` additionally accepts only `reasoning` and
  `reasoning_content` as null or valid Unicode strings without NUL/lone surrogates.
  The existing 8 MiB response bound applies to the whole body. Wrong types or
  invalid text produce `malformed_response`. Opaque reasoning is never copied
  into `InferenceResponse.content` or retained in the typed parsed response.

Both Nebius HTTP parsing and the bounded parent select v2 explicitly. Unknown
assistant fields, including unknown fields whose value is null, remain
unsupported. Non-null audio/annotations, tools, refusals, malformed HTTP JSON,
duplicate JSON keys, malformed candidate JSON and mismatched envelopes retain
their existing rejection paths. Usage accounting and spending limits are unchanged.

New private experiment records include `completion_parser`; providers without an
explicit parser declaration retain v1. An absent field on an existing record
means v1. Offline verification reparses wire evidence with that recorded policy,
so old parsed-response hashes and historical classifications remain verifiable.
Changing an old record's policy without regenerating its evidence fails the
parsed-response provenance check. It is not a supported migration.

## Historical evidence and separate post-hoc result

The original archive was not edited. All **11 regular files** were hashed before
and after the compatibility change and post-hoc analysis; their names and hashes
matched. Historical verification still succeeds with `generation_status=invalid_output`
and `candidate_sha256=null`.

- Historical experiment JSON SHA-256:
  `b62672834231442ad53ecdc1f1ec5ed4b50e27343f0400fc7f6397890415126a`
- Archived response SHA-256:
  `289e65e19005ada95e5ccd3d02ec969d5fe8c068100a0d56d9b61ccc1acd2c77`
- Independently revalidated candidate text SHA-256:
  `ff05b293ff709f2afd8cd61d7147741e764c079da838e0e40395c501561fd443`

The new `aegis_lab.completion_review` command first verifies the historical record
with its original parser. For one completed legacy Nebius response previously
classified `invalid_output`, it separately checks the v2 metadata types, request
model, usage limits, refusal/tool/unknown-field gates and the exact candidate
envelope/interface. It publishes a new allowlisted report outside the archive:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.completion_review \
  /tmp/aegis-operator-review-i2Si6nvI/baseline-8192-live-run \
  --output /tmp/CHOOSE_A_NEW_POST_HOC_REPORT.json
```

The report already produced during this task is
`/tmp/aegis-nebius-compat-post-hoc-review.json` (0600). Its distinct schema is
`aegis.lab.completion-revalidation.v1`, analysis kind is
`post_hoc_parser_compatibility_review`, historical status is `invalid_output`, and
post-hoc status is **`candidate_text_revalidated_but_behaviorally_unscored`**.
It binds both historical JSON and wire-response hashes, records the candidate
text hash and reported usage, and explicitly states `execution_performed=false`,
`behavioral_scoring=unscored` and `attack_effectiveness=not_established`.

The report contains no source, prompt, reasoning, raw body, credential, provider
fingerprint or private archive paths. It is a separate analysis, **not** an
experiment replacement or a dashboard research-summary v2 artifact. Existing
public-summary exports continue to show the original `invalid_output` result.
Do not relabel the sidecar as a historical generation result or a behavioral score.
The command refuses to write inside the original archive or overwrite an existing
output. Non-metadata failures cannot become accepted candidate text through this
review. An original provider refusal is ineligible for the metadata-rejection tool.

**A fresh inference request is unnecessary to recover or validate this candidate
envelope.** The response already exists and passed this independent offline check.
This does not retroactively alter the experiment, prove the candidate compiles or
behaves correctly, or authorize code execution. Any future prospective trial or
behavioral evaluation requires its own applicable authorization.

## Regression tests and validation

`tests/fixtures/nebius-reasoning-sanitized.json` mirrors the actual field names and
types, including null metadata placeholders and usage-detail shape. Content,
reasoning, source, ID, timestamp and detail/cache counts are explicitly synthetic.
Aggregate usage numbers reproduce the safe metadata above; the fixture is not a
live inference record. The 45 new cases cover both parser policies, recognized
types, malformed text/JSON, unknown extensions, valid candidates, both transport
layers, future recorded-policy verification, immutable unversioned history,
invalid relabeling, post-hoc acceptance/rejection and private/exclusive publication.

Commands from repository root, using existing dependencies:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m pytest \
  attack_lab/tests/test_nebius_reasoning.py attack_lab/tests/test_provider.py \
  attack_lab/tests/test_experiment.py attack_lab/tests/test_live_inference.py \
  attack_lab/tests/test_public_summary.py -q
PYTHONPATH=attack_lab/src .venv/bin/python -m pytest attack_lab/tests --lab-profile offline -q
AEGIS_GHIDRA_HEADLESS=/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
PYTHONPATH=attack_lab/src .venv/bin/python -m pytest attack_lab/tests --lab-profile integration -q
git diff --check -- attack_lab
```

| Suite | Exact result | Log |
| --- | --- | --- |
| Focused Lab/provider regression | **288 passed**, zero skips/warnings; 16.28 s | `/tmp/aegis-nebius-compat-focused-final.log` |
| Full offline Lab | **2056 passed, 23 NOT RUN**, zero failures/warnings; 70.12 s. 22 real-Ghidra cases omitted and one Unix-socket fixture blocked by sandbox. | `/tmp/aegis-nebius-compat-offline.log` |
| Full strict Lab with real Ghidra | **2079 passed**, zero failures/skips/warnings; 165.31 s. Covers all 23 cases not run in the sandboxed offline profile. | `/tmp/aegis-nebius-compat-integration.log` |

One intermediate focused run was **1 failed / 287 passed**: a new test expected a
post-hoc rejection report for a response whose original state was already
`provider_refusal`. The tool correctly refused that ineligible history. The test
now checks that refusal explicitly; production behavior was not relaxed.
Strict integration runs outside the sandbox to exercise its local Unix-socket
fixture. No test performs genuine inference or executes a generated candidate.
Native/Core/API/dashboard suites were not rerun for this Lab-only parser change.
Root architecture synchronization remains with its owner; no shared Core/API or
dashboard contract changed here.

## Minimal changed-file list for this follow-up

- `attack_lab/src/aegis_lab/provider.py`
- `attack_lab/src/aegis_lab/bounded_provider.py`
- `attack_lab/src/aegis_lab/experiment.py`
- `attack_lab/src/aegis_lab/completion_review.py`
- `attack_lab/tests/test_nebius_reasoning.py`
- `attack_lab/tests/fixtures/nebius-reasoning-sanitized.json`
- `attack_lab/README.md`
- `attack_lab/docs/nebius-reasoning-compatibility.md`

The shared checkout also contains prior task changes and other agents' changes;
those are not part of this eight-file compatibility follow-up.
