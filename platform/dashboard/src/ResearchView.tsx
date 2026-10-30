import type { Comparison, Reconstruction, ResearchEvidence } from "./research";

const limitationText: Record<string, string> = {
  unsigned_local_evidence_not_provider_attestation: "Unsigned local evidence; hash consistency is not provider attestation.",
  candidate_text_is_not_reconstruction_success: "Generating candidate text is not reconstruction success.",
  no_candidate_compilation_execution_or_behavioral_score: "Candidates were not compiled or executed. Behavioral scoring is pending an authorized Core runtime.",
  no_established_protection_effect: "No protection or attack-resistance effect is established.",
  provider_identity_and_usage_are_reported_not_independently_measured: "Model identity and usage are provider-reported, not independently measured.",
  billing_unknown_reservations_are_not_invoice: "Provider billing is unknown. Budget reservations are not an invoice.",
  offline_scripted_no_model_inference: "Scripted offline generation; no model inference.",
  selected_function_only_decoy_inventory_not_disclosed: "Evaluation covers the selected function only; the decoy inventory was not disclosed.",
  variant_build_provenance_operator_declared: "Variant build provenance is declared by the operator.",
  synthetic_fixture_not_live_evidence: "Synthetic test fixture; these values are not live inference evidence.",
};
const number = (v: number | null) => v === null ? "Unknown" : v.toLocaleString();
const usd = (v: number | null) => v === null ? "Unknown" : `$${(v / 1e6).toFixed(6)}`;
const variantName = { baseline: "Baseline", shield: "Shield", mirage: "Shield + Mirage (operator declared)" };

function Limitations({ values }: { values: string[] }) {
  return <><h4>Scope and limitations</h4><ul>{values.map(v => <li key={v}>{limitationText[v]}</li>)}</ul></>;
}

function ReconstructionView({ summary: s }: { summary: Reconstruction }) {
  return <>
    <div className="row"><h3>Reconstruction experiment / result</h3><span className="badge">{s.evidence_label.replace(/_/g, " ")}</span></div>
    <div className="notice">{s.evidence_label === "synthetic_fixture" ? "Synthetic fixture · not live inference evidence." : s.provider === "FakeOffline" ? "Scripted offline provider · no live inference." : "Nebius provider record · identity and usage are reported, not independently measured."} Candidate generation remains behaviorally unscored.</div>
    <div className="metrics research-metrics"><div className="metric"><p>Provider</p><strong>{s.provider}</strong></div><div className="metric"><p>Reported total tokens</p><strong>{number(s.reported_tokens)}</strong></div><div className="metric"><p>Recorded steps</p><strong>{number(s.steps)}</strong></div><div className="metric"><p>Provider bill</p><strong>{usd(s.cost_microusd)}</strong></div></div>
    <dl>
      <div><dt>Requested model</dt><dd>{s.requested_model}</dd></div><div><dt>Reported model</dt><dd>{s.reported_model ?? "Not established"} · {s.reported_model_status}</dd></div>
      <div><dt>Reported identity SHA-256</dt><dd><code>{s.reported_identity_sha256 ?? "Not supplied"}</code></dd></div>
      <div><dt>Original generation state</dt><dd><code>{s.generation_status}</code></dd></div><div><dt>Original completion parser</dt><dd><code>{s.completion_parser ?? "Not recorded in this export"}</code></dd></div><div><dt>Usage completeness</dt><dd>{s.usage_status}</dd></div>
      <div><dt>Prompt / completion tokens</dt><dd>{number(s.prompt_tokens)} / {number(s.completion_tokens)}</dd></div><div><dt>Known reported tokens</dt><dd>{number(s.known_reported_tokens)} · may be partial</dd></div>
      <div><dt>Token budget charged</dt><dd>{number(s.charged_tokens)} · reservations, distinct from reported usage</dd></div>
      <div><dt>Reserved spend</dt><dd>{usd(s.reserved_spend_microusd)} · budget reservation</dd></div><div><dt>Estimated reported cost</dt><dd>{usd(s.estimated_reported_cost_microusd)} · estimate, not billing</dd></div>
      <div><dt>Trial / pair</dt><dd><code>{s.trial_id} / {s.pair_id}</code></dd></div><div><dt>Target artifact SHA-256</dt><dd><code>{s.artifact_sha256}</code></dd></div><div><dt>Original candidate SHA-256</dt><dd><code>{s.candidate_sha256 ?? "No candidate recorded"}</code></dd></div>
    </dl>
    {s.post_hoc_review && <section aria-label="Post-hoc parser review" className="result-card">
      <div className="row"><h4>Post-hoc parser review</h4><span className="badge">{s.post_hoc_review.post_hoc_status === "rejected" ? "Review rejected" : "Candidate text revalidated · unscored"}</span></div>
      <div className="notice">The original <code>invalid_output</code> result and its absent candidate remain unchanged. This later parser review does not establish compilation, execution or reconstruction success. No new inference request or spending occurred in this review.</div>
      <dl>
        <div><dt>Post-hoc status</dt><dd><code>{s.post_hoc_review.post_hoc_status}</code></dd></div>
        <div><dt>Historical parser</dt><dd><code>{s.post_hoc_review.historical_completion_parser}</code></dd></div>
        <div><dt>Revalidation parser</dt><dd><code>{s.post_hoc_review.revalidation_completion_parser}</code></dd></div>
        <div><dt>Candidate envelope</dt><dd>{s.post_hoc_review.candidate_envelope_valid ? "Valid text envelope; behavior unscored" : "Invalid text envelope"}</dd></div>
        <div><dt>Post-hoc candidate SHA-256</dt><dd><code>{s.post_hoc_review.candidate_sha256 ?? "No candidate accepted by this review"}</code></dd></div>
        <div><dt>Historical experiment SHA-256</dt><dd><code>{s.post_hoc_review.historical_experiment_sha256}</code></dd></div>
        <div><dt>Reviewed response SHA-256</dt><dd><code>{s.post_hoc_review.response_sha256}</code></dd></div>
        <div><dt>Review report SHA-256</dt><dd><code>{s.post_hoc_review.report_sha256}</code></dd></div>
      </dl>
      <p className="muted">Usage and estimated cost above belong to the original request. The provider bill remains unknown.</p>
    </section>}
    <Limitations values={s.limitations} />
  </>;
}

function ComparisonView({ summary: s }: { summary: Comparison }) {
  return <>
    <div className="row"><h3>Baseline / Shield / Shield + Mirage comparison</h3><span className="badge">{s.evidence_label.replace(/_/g, " ")}</span></div>
    {(s.evidence_label === "synthetic_fixture" || s.experiments.some(r => r.summary?.evidence_label === "synthetic_fixture")) && <div className="notice">Synthetic fixture · not live inference evidence.</div>}
    <p>Recorded execution order: {s.order.map(v => variantName[v]).join(" → ")} · order seed {s.order_seed}</p>
    <div className="notice">Reported model identity {s.reported_identity_comparable ? "is consistent across these records" : "is not comparable across all variants"}. Build provenance is operator declared. Behavioral scoring is pending; no protection effect is established.</div>
    <div className="table-scroll"><table><caption>Recorded generation and inference usage · no behavioral success measurement</caption><thead><tr><th>Variant</th><th>Generation state</th><th>Reported model</th><th>Reported tokens</th><th>Reserved spend</th><th>Provider bill</th></tr></thead><tbody>{s.experiments.map(row => <tr key={row.variant}><td>{variantName[row.variant]}</td><td>{row.generation_status.replace(/_/g, " ")}</td><td>{row.summary ? `${row.summary.requested_model} · ${row.summary.reported_model_status}` : "No verified record"}</td><td>{row.summary ? number(row.summary.reported_tokens) : "Unknown"}</td><td>{row.summary ? usd(row.summary.reserved_spend_microusd) : "Unknown"}</td><td>{row.summary ? usd(row.summary.cost_microusd) : "Unknown"}</td></tr>)}</tbody></table></div>
    <Limitations values={s.limitations} />
    {s.experiments.map(row => <details key={row.variant}><summary>Inspect {variantName[row.variant]}</summary>{row.summary ? <><p>Verified source record SHA-256 <code>{row.source_sha256}</code></p><ReconstructionView summary={row.summary} /></> : <p>No verified experiment record for this variant. State: {row.generation_status}.</p>}</details>)}
  </>;
}

export function ResearchView({ item }: { item: ResearchEvidence }) {
  return <article className="panel"><div className="eyebrow">HASH-CHECKED LOCAL RESEARCH SUMMARY</div><p className="muted">This file matches the digest you supplied. The exporter checked local bindings. No raw prompts, candidate source or private records are imported.</p>
    {item.kind === "reconstruction" ? <ReconstructionView summary={item.summary} /> : <ComparisonView summary={item.summary} />}
    <h4>Source record SHA-256</h4><code>{item.source_sha256}</code>
  </article>;
}
