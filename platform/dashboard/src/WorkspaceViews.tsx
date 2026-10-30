import { ArrowRight, Fingerprint, FlaskConical, Shield, ScanLine } from "lucide-react";
import type { Job, LocalEvidence, Report } from "./contracts";
import type { Attestation } from "./attestation";
import { ResearchView } from "./ResearchView";

export const workflow = [
  { title: "Protect", page: "Protect LLVM IR", description: "Choose a registered protection profile", icon: Shield },
  { title: "Verify", page: "Verify artifact", description: "Inspect provenance and rights decisions", icon: Fingerprint },
  { title: "Evaluate", page: "Research evidence", description: "Inspect verified research summaries", icon: FlaskConical },
  { title: "Results", page: "Results", description: "Review artifacts and evidence together", icon: ScanLine },
] as const;

export function Workflow({ page, navigate }: { page: string; navigate: (page: typeof workflow[number]["page"]) => void }) {
  return <div className="workflow" role="group" aria-label="Protection workflow">{workflow.map((step, index) => {
    const Icon = step.icon;
    return <button key={step.title} aria-current={page === step.page ? "step" : undefined} onClick={() => navigate(step.page)}>
      <span className="step-number">0{index + 1}</span><span><strong>{step.title}</strong><small>{step.description}</small></span><Icon size={19} />
    </button>;
  })}</div>;
}

export function ResultsView({ jobs, reports, attestations, evidence, navigate, verifyJob }: { jobs: Job[]; reports: Record<string, Report>; attestations: Record<string, Attestation>; evidence: LocalEvidence[]; navigate: (page: typeof workflow[number]["page"] | "Protection jobs") => void; verifyJob: (id: string) => void }) {
  return <>
    <section className="panel"><div className="eyebrow">ARTIFACTS & EVIDENCE</div><h2>Your protection results</h2><p>Pipeline completion, signature verification and evaluation evidence answer different questions. Inspect each result in its recorded scope.</p>
      {!jobs.length && <div className="empty">No job loaded. Protect an input or reopen a job by ID to begin.</div>}
      {jobs.map(job => {
        const report = reports[job.job_id];
        const verification = attestations[job.job_id];
        const matches = evidence.filter(item => item.kind === "reconstruction" && job.output_artifacts.some(a => a.sha256 === item.summary.artifact_sha256));
        return <article className="result-card" key={job.job_id}>
          <div className="row"><h3>{job.input_artifact.name}</h3><span className={`badge ${job.status}`}>{job.status}</span></div><code>{job.job_id}</code>
          <dl><div><dt>Protection pipeline</dt><dd>{report?.summary ?? (job.error?.message || "Report not loaded yet")}</dd></div><div><dt>Output artifacts</dt><dd>{job.output_artifacts.length} Core recorded artifact(s)</dd></div><div><dt>Linked reconstruction summaries</dt><dd>{matches.length ? `${matches.length} summary / summaries match an output SHA-256` : "No matching summary loaded"}</dd></div><div><dt>Attack resistance</dt><dd>Not established</dd></div></dl>
          {job.output_artifacts.map(a => <p key={a.sha256}><strong>{a.name}</strong><br /><code>{a.sha256}</code></p>)}
          {verification ? <><p className="muted">Last verification: {verification.checked_at}. Refresh Verify for current on-disk checks.</p>{verification.artifacts.map(a => <p key={a.artifact_id}>{a.name}: <span className={`badge ${a.signature.status}`}>{a.signature.status === "verified" ? "Signature verified" : a.signature.status === "failed" ? `Signature failed · ${a.signature.error_code}` : verification.signing.state === "not_configured" ? "Not signed (signing not configured)" : "Unsigned"}</span> · Policy {a.policy.status}</p>)}</> : <p className="muted">Signature and policy checks have not been loaded for this job.</p>}
          <div className="actions"><button onClick={() => navigate("Protection jobs")}>Inspect report <ArrowRight size={15} /></button><button onClick={() => verifyJob(job.job_id)}>Inspect verification for {job.input_artifact.name}</button></div>
        </article>;
      })}
      <div className="actions"><button onClick={() => navigate("Protect LLVM IR")}>Protect an input</button><button onClick={() => navigate("Verify artifact")}>Verify artifact</button><button onClick={() => navigate("Research evidence")}>Evaluate evidence</button></div>
    </section>
    <section className="panel"><h3>Baseline, Shield and Shield + Mirage</h3><p>Open the Adversarial Lab to inspect comparisons from hash-checked exports. Timing observations are shown only with their sample counts and measurement conditions. Imported evidence remains local to this browser session.</p><p className="muted">{evidence.length} local summary / summaries loaded. No reconstruction success rate, security score or GPU utilization is inferred.</p><button onClick={() => navigate("Research evidence")}>Inspect research evidence <ArrowRight size={15} /></button></section>
    {evidence.map((item, index) => item.schema === "aegis.product.evidence.v2" ? <ResearchView key={index} item={item} /> : null)}
  </>;
}
