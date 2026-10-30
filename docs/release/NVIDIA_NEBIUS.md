# NVIDIA and Nebius: runtime, evidence and provider feedback

> Historical analysis of the 05:37 UTC archive only. The final post-integration
> operator request succeeded with 3,529 tokens and an estimated $0.000498,
> remaining behaviorally unscored. [NVIDIA_DEMO.md](../../benchmarks/reconstruction/NVIDIA_DEMO.md)
> is the final runtime record; prospective continuation text below is not a
> current instruction to request another call. No additional request is queued.

This describes inspected implementation and one operator-supplied archive, not a
new provider request. No credits were spent by the final release task. The
canonical research record and continuation instructions are in
[Agent 2's deliverable](../../attack_lab/docs/nvidia-research-deliverable.md).

## Runtime boundary

Core runs registered local Shield/Mirage compiler adapters. These do not call
Nebius or use a GPU. Separately, Lab's approved live workflow uses Nebius Token
Factory at `https://api.tokenfactory.nebius.com/v1`, fresh model-catalogue checks,
and HTTPS `chat/completions` with an explicitly selected NVIDIA model ID. The
process-bounded transport enforces request timeouts, response-size bounds,
request/token/spend limits and a single-use approval reservation. A runtime
credential stays in the operator's private environment and is never a dashboard
setting, package asset or source file.

A live inference approval permits disclosure/inference only. It does not open
Core's dual attack-lab gates or authorize generated code execution. The local
product config leaves attack-lab execution disabled. A candidate execution
runtime is unavailable here; candidates remain uncompiled and unexecuted.

The dashboard accepts an allowlisted public projection plus a separately supplied
SHA-256. It checks that digest and strict schema/consistency rules locally. The
exporter re-verifies private archive bindings offline before projection. Neither
unsigned local hashes nor a browser import authenticate the provider or model
weights. Raw responses, reasoning, prompts, candidate source, approvals and keys
stay outside the distribution.

## What was actually observed

The archived workflow is timestamped 30 October 2026, 05:37:55–05:38:25 UTC,
with canonical endpoint `https://api.tokenfactory.nebius.com:443/v1`. These local
record timestamps are not an independently measured inference-latency result.

The public summary SHA-256 is
`16be4b7bf0bfdbbe36389aca550fa703fe7f35c5e5dc3f4161b87d87e41292b6`.
The final release engineer independently re-exported the verified archive and
post-hoc sidecar on 30 October 2026; the bytes matched Agent 2's export exactly.

| Observation | Meaning |
| --- | --- |
| Requested/reported model `nvidia/Nemotron-3_5-Lightning` | Exact reported-name match; no independent weight/GPU identity verification |
| Original `invalid_output`, parser `aegis.lab.completion-parser.v1`, null candidate hash | Historical record remains unchanged |
| Non-null `reasoning` and `reasoning_content` strings | v1 marked unsupported metadata, although candidate content was structurally valid |
| Separate parser `aegis.lab.nebius-reasoning-text.v2` review | `candidate_text_revalidated_but_behaviorally_unscored`; text envelope accepted only |
| 1,786 prompt + 8,039 completion = 9,825 tokens | Provider-reported usage; no independent metering |
| 2,037 micro-USD ($0.002037) | Archived price-cap estimate for reported usage; not an invoice |
| 64,881 micro-USD ($0.064881) | Conservative budget reservation; not billed cost |
| Actual billing / weight fingerprint | Unknown / absent |
| Three-way behavior or Mirage distraction | Not measured; only a selected function was disclosed, without decoy inventory |

The v2 parser accepts only the two recognized reasoning fields as null or valid
Unicode strings without NUL/lone surrogates. It never interprets reasoning as
candidate content. Unknown fields, wrong metadata types, tools/refusals, malformed
JSON and invalid candidate envelopes remain rejected. Recorded parser versions
preserve historical verification. Every sidecar field is recomputed; matching a
source digest alone is insufficient.

Two prospective Shield/Mirage inference continuations are prepared but unapproved.
They match the actual baseline's 8,192-token output cap. The older 2,048-token plan
cannot be reused unchanged. The baseline was observed first, so this is not a
randomized prospective three-way study. No protection/attack-resistance effect is
established, and no NVIDIA/Nebius competition-track eligibility is asserted.

## Specific feedback for Nebius and NVIDIA

These are recommendations drawn from the observed archive and local integration,
not claims about current provider documentation or service guarantees.

- Publish a versioned response schema with realistic non-null `reasoning` and
  `reasoning_content` examples, field types and nullable metadata. Our original
  strict parser rejected those two strings; preserving v1 history and adding a
  narrow v2 policy recovered the existing text without another paid request.
- Clarify completion/reasoning token accounting and expose reasoning/cache detail
  consistently. This one response reports 8,039 completion tokens under an 8,192
  cap; aggregate counters alone do not identify the useful candidate-text budget.
- Provide an immutable model revision/weight fingerprint suitable for repeated
  trials. The reported model name matched, but the archived fingerprint was absent.
- Provide request-linked billed usage/cost and machine-readable tariff/retention
  versions. Our archive supports a $0.002037 estimate and $0.064881 reservation;
  neither can be reported as actual billing.
- Offer explicit per-request input/output limits. Reserving the published 1,048,576
  context plus 8,192 output tokens conservatively charges 1,056,768 budget tokens
  for this request despite 9,825 reported tokens. That is a local fail-closed
  budget policy, not observed provider billing behavior.

No inference latency, throughput, GPU type, service reliability rate or protective
benefit can be inferred from this single supplied response. Service error,
timeout and rate-limit paths have local regression coverage; they are not a live
availability measurement.
