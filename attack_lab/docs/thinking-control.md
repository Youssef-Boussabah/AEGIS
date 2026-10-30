# Explicit Nebius thinking control

The production controlled-inference path supports an opt-in
`InferenceRequest.enable_thinking` strict boolean. `None` omits the wire field;
`False` sends exactly `chat_template_kwargs: {enable_thinking: false}`.
`planned_attack_digests(..., enable_thinking=False)` and
`prepare_reconstruction(..., enable_thinking=False)` must agree. The controlled
`aegis_lab.live` draft/preflight/run CLI exposes this as `--disable-thinking`.
The setting is part of the sampling digest and every archived request body.
Verification reconstructs it from the archived, hash-bound request; changing it
without a matching manifest or reusing an old approval is refused. No default
request, historical sampling digest or legacy response policy is changed.

Nebius's own published [migration verification](https://raw.githubusercontent.com/nebius/nebius-physical-ai/main/docs/workbench/token-factory-deprecation-verification.md)
reports that its `nvidia/Nemotron-3_5-Lightning` deployment accepted this control
and returned a complete answer with zero reasoning tokens in that observation.
The [NVIDIA model documentation](https://docs.nvidia.com/nim/large-language-models/2.0.10/get-started/advanced/get-started-nemotron-3.5-lightning.html)
also describes template-based thinking control and a shared total output budget.
These sources support trying the explicit option; they do not prove the effect
in our account or guarantee JSON/candidate correctness. A genuine new response
must establish the actual observed result. No provider fallback or retry is added.

The existing 16,384-token diagnostic remains unchanged. The new private
no-thinking draft is `/tmp/aegis-nvidia-demo-nothinking-20261030`, bound to the
same owned ImageLab protected ELF and actual Ghidra report, with new trial/pair
identities and sampling digest. Only the protected request is proposed: one POST,
120-second request timeout, 16,384 total completion tokens, $0.10 ceiling,
$0.066847 conservative reservation at the approved price caps. The operator must
review the exact request/retention terms and grant a new single-use approval in
the designated credential-enabled runtime. No API key is requested by the agent.

No parser checks were weakened: `finish_reason=length`, non-JSON visible output,
refusals, unsupported fields, invalid envelopes and mismatched artifacts remain
explicit failures. Candidate text validation is separate from compilation and
behavioral scoring. No validated candidate execution runtime is established by
this change. The standalone experimental Wasm scorer is not a substitute for
validated isolation and is not invoked by inference or these instructions.
