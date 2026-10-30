# Benchmark-local formats (v1)

These formats do not extend any shared AEGIS model. The executable validators
are `benchmark.py` and `evidence.py`. Every object with a fixed field set rejects
unknown fields. Numbers are strict finite JSON numbers; counts are integers,
never booleans. SHA-256 is lowercase 64-hex. Lists of target names are nonempty,
sorted, unique C identifiers. All file references are exactly:

```json
{"path":"relative/file.json","sha256":"<exact byte SHA-256>","size_bytes":123}
```

References are relative to the comparison directory, or to the evidence-sidecar
directory for evidence attachments. Absolute/escaping paths and symlinks are
rejected. Nothing follows a path supplied inside raw REA text or a public summary.
JSON inputs are bounded at 8 MiB; artifact reads at 128 MiB. Rejected contents and
provider diagnostics are never printed. The benchmark is for local trusted
operators; unsigned files and hashes are not an authentication protocol.

## `aegis.reconstruction.comparison.v1`

The actual manifest is embedded in [measured-results.json](measured-results.json).
Its fields are:

| Field | Meaning |
| --- | --- |
| `schema`, `comparison_id` | Exact schema; nonempty local comparison identifier |
| `created_at`, `valid_until` | UTC strings ending `Z`; positive window no longer than 7 days |
| `targets` | Identical selected-function set for every variant |
| `sources`, `oracle` | Source-file references; predefined oracle reference |
| `build_conditions` | `tools`, `target_triple`, `frontend_flags`, `final_flags`, `environment`, `source_identity` |
| `attacker_controls` | Complete shared settings below |
| `artifacts` | One baseline and at least one protected entry |

`build_conditions.tools` maps names to exact `{sha256, version}` identities.
`environment` is `minimal-v1`. `source_identity` hashes the canonical `sources`
list. The comparison is a build declaration; imported artifacts' source-to-binary
provenance is not independently established by a matching declaration.

Each artifact has exactly `id`, `variant`, `file`, `ir`, `targets`,
`build_conditions_sha256`, `protection`, `shield_report`, `mirage_report`.
Variants are `baseline`, `shield`, `shield_mirage`. `protection` is exactly
`{shield, mirage}`: null for absent stages, otherwise `{seed,max_sites}` or
`{seed,count}` respectively. Reports are file references or null. Zero Shield
sites, changed Shield settings, or a Mirage report whose input is not the
compared Shield IR are rejected. Reported IR changes remain producer claims.

Controls have exactly these fields:

```text
capabilities                sorted subset: ghidra_decompilation, rea_reasoning,
                            static_disassembly
analysis_tools              map tool name -> {version, executable_sha256,
                                              configuration_sha256}
prompt_template_sha256      template identity (Lab uses its own template digest)
system_prompt_sha256        exact initial system-message bytes
workflow_sha256             workflow identity, including permitted actions
request_parameters_sha256   request parameters excluding messages (sampling/model/output)
model_identity              declared model identifier; not verified model weights
max_attempts                per-variant upper bound
max_input_tokens            per-request input/context upper bound
max_output_tokens           per-request output upper bound
max_total_tokens            aggregate per-variant bound
max_spend_microusd          per-variant approved ceiling, not an invoice
time_budget_seconds         per-variant wall budget
random_seed                 exact integer or null (not forwarded)
context_policy              selected_functions_only
oracle_access               none
source_access               none
```

Use all relevant tools in `analysis_tools`; Ghidra and REA can coexist. Ghidra's
configuration digest is computed by the existing
`aegis_lab.evidence.ghidra_configuration_sha256` and covers exporter/installation
hashes, selector, truncation and timeouts. REA's configuration digest must identify
the analyst's real configuration; no native REA canonicalization is presumed.
No field grants dynamic execution, API spending or attack-lab permission.

The oracle is exactly `{schema,interface,cases}` where schema is
`aegis.reconstruction.oracle.v1` and interface is `u32(...)`, with zero to sixteen
`u32` parameters separated by commas. The owned demo uses `u32(u32,u32)`; a
four-argument ImageLab comparison can declare `u32(u32,u32,u32,u32)`. All selected
functions in one comparison share this scalar interface. Each case is
`{id,function,arguments,expected}`, with exactly that number of unsigned 32-bit
arguments and one unsigned 32-bit expected result. IDs must be unique, every selected target must
have cases, and equal inputs with contradictory expectations are rejected.

## `aegis.reconstruction.evidence.v1`

```text
schema                    aegis.reconstruction.evidence.v1
comparison_sha256         canonical comparison identity
artifact_id               explicit variant entry ID
artifact_sha256           exact final bytes, checked again on disk
targets                   identical to comparison.targets
controls                  complete identical attacker_controls object
recorded_at               operator-declared observation time, within comparison
kind                      ghidra | rea | nemotron_summary | lab_experiment |
                          behavioral_receipt
source                    exact raw report/summary/experiment/receipt reference
prompt                    null or one of the exact objects below
candidate                 null, except mandatory source reference for receipt
```

The source hash is computed from the bytes actually parsed. Every verifier
re-reads comparison artifacts and attachments. Record timestamps cannot prove
when a tool really ran; reports have no authenticated clock. A new comparison ID,
changed settings or a changed artifact invalidates prior record bindings.

Static Ghidra/REA observations may omit prompts. Reconstruction summaries,
production experiments and behavioral receipts require exact prompt bindings.

Plain prompt object: exactly `{template,system,context,rendered}`, all file refs.
The template contains exactly one `{{CONTEXT}}` and no other substitutions are
performed. `rendered` must equal the exact replacement. `context` is canonical
JSON, with exactly this shape (ordered selected functions only):

```json
{
  "artifact_sha256":"<this artifact>",
  "functions":[{"name":"recon_mix","decompiled_c":"<actual selected decompilation>"}]
}
```

Production prompt object: exactly `{format,manifest,report,request,configuration}`,
with `format="aegis_lab"`, three file refs and the actual strict Lab
`WorkflowConfig` object. The reader calls `prepare_reconstruction`,
`initial_messages`, and `InferenceRequest.to_body` to rebuild the real request,
then compares it with the saved request-review bytes. It checks target, artifact,
tools, system/template/workflow, model/sampling, output/attempt/total-token and
wall limits. It never sends this request. `lab_experiment` additionally verifies
the private experiment archive and its context/token/spend approval bindings.

## REA observation projection

No native REA output format is assumed or overwritten. This exact projection is
the `source` of a `rea` evidence sidecar. `raw` points at the immutable original
REA JSON/text under the same evidence directory:

```json
{
  "schema":"aegis.reconstruction.rea-observation.v1",
  "artifact_sha256":"<final artifact SHA-256>",
  "targets":["recon_mix"],
  "tool":{
    "name":"REA",
    "version":"<actual version or revision>",
    "executable_sha256":"<actual tool digest>",
    "configuration_sha256":"<actual configuration digest>"
  },
  "raw":{"path":"claude-rea-output.json","sha256":"<actual raw digest>","size_bytes":123},
  "observations":[{
    "function":"recon_mix",
    "status":"completed",
    "decompiled_c":"<actual observed selected-function text>",
    "structural_metrics":{"decompiler_complexity":12,"basic_blocks":3}
  }]
}
```

Allowed statuses: `completed`, `failed`, `inconclusive`. Completed requires
nonempty text; the others require empty text. Optional numeric metric keys are
`decompiler_complexity`, `basic_blocks`, `instructions`, `pcode_ops` (nonnegative
integer counts). An empty metrics object is valid. No metric is interpreted as an
attack outcome. Missing/ambiguous/different functions are invalid. A reviewer
must check this operator projection against the raw output; hash consistency
alone cannot do that semantic work.

## Independent replay receipt

`behavioral_receipt` requires a raw `aegis.reconstruction.replay-receipt.v1`
record with exactly:

```text
schema, verifier_id, comparison_sha256, artifact_id, artifact_sha256,
controls_sha256, targets, oracle_sha256, candidate_sha256, recorded_at,
isolation, compilation, cases
```

All bindings must match the sidecar/comparison, including the receipt timestamp.
`isolation` is exactly `{runtime,validation_sha256,attestation_sha256}`.
`host`, `none`, `test_double`, and `aegis-test-double` are refused. These fields
are checked declarations, not a runtime validator. A trusted independent reviewer
must attest actual containment and execution, and communicate the receipt's exact
SHA-256 separately. Supply that digest with `--trust-receipt`; do not compute an
unreviewed receipt's hash and mistake that for independence. This is an explicit
local trust anchor, not a signature or implementation of Core isolation.

`compilation` is exactly `{status,compiler_sha256,log_sha256}`. Status is
`succeeded`, `candidate_rejected`, or `infrastructure_failure`. A candidate
rejection must mean the candidate was rejected by a working compiler, not that
the compiler was absent. Non-successful compilation requires an empty `cases`.
Compiler identity must match the declared comparison tool. Actual invocation
flags and isolation validation belong in the reviewer-checked receipt evidence;
the controls/workflow digest binds their predeclared policy.

Successful compilation requires one case in exact oracle order. Each case is
exactly `{id,status,value}`. Status is `returned`, `timeout`, `crash`,
`infrastructure_failure`, or `not_run`. Returned values are uint32; others null.
The reader derives:

| Observation | Classification |
| --- | --- |
| Every case returns its frozen expected value | `behavioral_suite_match` |
| At least one returned value differs, with no infrastructure/unrun case | `behavioral_suite_mismatch` |
| Candidate rejected, or crash/timeout without any returned mismatch | `attack_failed` |
| Infrastructure failure or any unrun case | `inconclusive` |
| No receipt | absent; no behavioral score |

Mixed mismatches and crashes preserve case counts and classify as mismatch;
infrastructure/unrun cases take precedence as inconclusive. Every accepted
receipt has `security_property="not_established"` and applies only to that
candidate and finite suite. Nothing executes here. No genuine replay receipt is
claimed in the recorded results; isolation remains unavailable locally.
