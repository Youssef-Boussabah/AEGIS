import { useCallback, useEffect, useState } from "react";
import { Activity, ArrowRight, BookOpen, Box, CheckCircle2, FileJson, FlaskConical, RefreshCw, Shield, UploadCloud } from "lucide-react";
import { api, fetchHealth, loadEvidence, parseJob, parseReport, terminal } from "./contracts";
import { ResearchView } from "./ResearchView";
import { downloadArtifact } from "./attestation";
import type { Attestation } from "./attestation";
import { VerificationView } from "./VerificationView";
import { Workflow, ResultsView } from "./WorkspaceViews";
import type { Artifact, Health, Job, LocalEvidence, Report } from "./contracts";

const pages = ["Overview", "Protect LLVM IR", "Protection jobs", "Verify artifact", "Research evidence", "Results", "Capabilities"] as const;
type Page = typeof pages[number];
const icons = [Activity, UploadCloud, Box, Shield, FlaskConical, CheckCircle2, BookOpen];

function ArtifactView({ value }: { value: Artifact }) {
  return <div className="artifact"><div><strong>{value.name}</strong><span>{value.size_bytes.toLocaleString()} bytes</span></div><code>{value.sha256}</code></div>;
}

function ReportView({ report, token }: { report: Report; token: string }) {
  const [downloadStatus, setDownloadStatus] = useState("");
  const [downloadError, setDownloadError] = useState("");
  const [downloading, setDownloading] = useState(false);
  const sites = report.evidence.filter(e => e.source === "adapter" && typeof e.data.transformed_sites === "number");
  const decoys = report.evidence.filter(e => e.source === "adapter" && e.data.report_schema === "aegis.mirage.report.v1" && typeof e.data.inserted_count === "number");
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `aegis-${report.job_id}.json`; anchor.click(); URL.revokeObjectURL(url);
  }
  return <section className="report" aria-label="Protection report">
    <div className="row"><h3>Protection report</h3><button onClick={download}><FileJson size={16} /> Download report</button></div>
    <p>{report.summary}</p><div className="notice">A succeeded job means the transformation pipeline completed. Attack resistance is not established.</div>
    <h4>Input · Core recorded SHA-256</h4><ArtifactView value={report.input_artifact} />
    <h4>Outputs · Core recorded SHA-256</h4>{report.output_artifacts.length ? report.output_artifacts.map(a => <div key={a.sha256}><ArtifactView value={a} /><button disabled={downloading} onClick={() => {
      setDownloadStatus(""); setDownloadError(""); setDownloading(true);
      void downloadArtifact(report.job_id, a, token).then(setDownloadStatus).catch(e => setDownloadError(e instanceof Error ? e.message : "Download failed")).finally(() => setDownloading(false));
    }}>Download {a.name}</button></div>) : <p>No output artifacts registered.</p>}
    {downloadStatus && <p role="status">{downloadStatus}</p>}{downloadError && <div className="error" role="alert">{downloadError}</div>}
    <h4>Transformation counts · adapter claims</h4>{sites.length ? sites.map((e, i) => <p key={i} data-testid="transformation-count">{String(e.data.transformed_sites)} transformed sites · LLVM {String(e.data.llvm_version)}</p>) : <p>Not reported.</p>}
    {decoys.map((e, i) => <p key={i}>{String(e.data.inserted_count)} Mirage decoys inserted after Shield · final native retention requires an independent check.</p>)}
    <h4>Evidence</h4>{report.evidence.map((e, i) => <p key={i}><span className="badge">{e.source === "orchestrator" ? "Core observation" : "Adapter claim"}</span> {e.summary}</p>)}
    <p>Attack evaluations: {report.attack_evaluations.length ? `${report.attack_evaluations.length} recorded; inspect the downloaded report for scope and outcomes.` : "Not run."}</p>
    <h4>Report limitations</h4><ul>{report.limitations.map((v, i) => <li key={i}>{v}</li>)}</ul>
  </section>;
}

function EvidenceView({ item }: { item: LocalEvidence }) {
  if (item.schema === "aegis.product.evidence.v2") return <ResearchView item={item} />;
  const summary = item.summary;
  return <article className="panel">
    <div className="row"><h3>{item.kind === "reconstruction" ? "Reconstruction experiment / result" : item.kind === "mirage" ? "Mirage transformation" : "ImageLab benchmark"}</h3><span className="badge">Local evidence</span></div>
    <p className="muted">File matches the SHA-256 you supplied. The exporter reports offline binding checks. This unsigned record does not establish authorship or attack resistance.</p>
    <p>Source record SHA-256</p><code>{item.source_sha256}</code>
    {item.kind === "reconstruction" && <div className="notice">Scripted offline provider · no live inference · candidates were not compiled or executed · behavioral scoring pending.</div>}
    {item.kind === "mirage" && <div className="notice">Insertion into IR is recorded. Final binary retention needs an independent check. Attack effectiveness is not measured.</div>}
    {item.kind === "benchmark" && <div className="notice">Local timing observations and sampled correctness. These measurements do not establish protection.</div>}
    <dl>{Object.entries(summary).filter(([k]) => !["conditions", "settings", "measurements"].includes(k)).map(([key, value]) => <div key={key}><dt>{key.replace(/_/g, " ")}</dt><dd>{value === null ? "Not supplied" : String(value)}</dd></div>)}</dl>
    {item.kind === "benchmark" && <>
      <h4>Measurement conditions</h4><dl>{Object.entries(summary.conditions as object).map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v === null ? "Unknown" : String(v)}</dd></div>)}</dl>
      <h4>Sample configuration</h4><dl>{Object.entries(summary.settings as object).map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{String(v)}</dd></div>)}</dl>
      <div className="table-scroll"><table><thead><tr><th>Variant / operation</th><th>Samples</th><th>Median (ms)</th><th>Min / max (ms)</th></tr></thead><tbody>{(summary.measurements as { variant: string; operation: string; samples: number; median_ns: number; min_ns: number; max_ns: number }[]).map((m, i) => <tr key={i}><td>{m.variant} / {m.operation}</td><td>{m.samples}</td><td>{(m.median_ns / 1e6).toFixed(3)}</td><td>{(m.min_ns / 1e6).toFixed(3)} / {(m.max_ns / 1e6).toFixed(3)}</td></tr>)}</tbody></table></div>
    </>}
  </article>;
}

export default function App() {
  const [page, setPage] = useState<Page>("Overview");
  const [health, setHealth] = useState<Health | null>(null);
  const [token, setToken] = useState("");
  const [jobs, setJobs] = useState<Job[]>([]);
  const [reports, setReports] = useState<Record<string, Report>>({});
  const [attestations, setAttestations] = useState<Record<string, Attestation>>({});
  const [verificationJobId, setVerificationJobId] = useState("");
  const recordAttestation = useCallback((value: Attestation) => setAttestations(current => ({ ...current, [value.job_id]: value })), []);
  const [file, setFile] = useState<File | null>(null);
  const [backend, setBackend] = useState("llvm-shield");
  const [seed, setSeed] = useState("42");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [lookup, setLookup] = useState("");
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [expected, setExpected] = useState("");
  const [evidence, setEvidence] = useState<LocalEvidence[]>([]);
  const putJob = useCallback((job: Job) => setJobs(current => [job, ...current.filter(j => j.job_id !== job.job_id)]), []);
  const checkHealth = useCallback(async () => {
    try {
      setHealth(await fetchHealth());
    } catch (e) { setHealth(null); setError(`Backend health unavailable: ${String(e)}`); }
  }, []);
  useEffect(() => { void checkHealth(); }, [checkHealth]);
  const refresh = useCallback(async (id: string) => {
    const job = parseJob(await api(`/v1/jobs/${id}`, token));
    if (job.job_id !== id) throw new Error("Mismatched job ID from API");
    putJob(job);
    if (terminal(job.status)) {
      const report = parseReport(await api(`/v1/jobs/${id}/report`, token), id);
      if (report.status !== job.status) throw new Error("Job and report status disagree");
      setReports(current => ({ ...current, [id]: report }));
    }
  }, [token, putJob]);
  const pending = jobs.filter(j => !terminal(j.status)).map(j => j.job_id).join(",");
  useEffect(() => {
    if (!pending) return;
    const timer = window.setInterval(() => { for (const id of pending.split(",")) void refresh(id).catch(e => setError(`Status refresh failed: ${String(e)}. Use Refresh to retry.`)); }, 1500);
    return () => clearInterval(timer);
  }, [pending, refresh]);
  async function action(work: () => Promise<void>) {
    setError(""); setBusy(true);
    try { await work(); } catch (e) { setError(e instanceof Error ? e.message : "Operation failed"); } finally { setBusy(false); }
  }
  async function submit() {
    if (!health?.backends.some(b => b.name === backend && b.available && b.tasks.includes("protect"))) throw new Error("This protection profile is unavailable; check backend readiness");
    if (!file || !file.name.toLowerCase().endsWith(".ll")) throw new Error("Choose a textual LLVM IR (.ll) file");
    if (!file.size || file.size > 64 * 1024 * 1024) throw new Error("Input must be between 1 byte and 64 MiB");
    if (!/^[0-9]{1,20}$/.test(seed) || BigInt(seed) > 18446744073709551615n) throw new Error("Seed must be a uint64 decimal string");
    if (backend === "llvm-shield-mirage" && BigInt(seed) > 9223372036854775807n) throw new Error("Shield + Mirage requires a seed no greater than 9223372036854775807");
    const content = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader(); reader.onload = () => resolve(String(reader.result).split(",")[1]); reader.onerror = () => reject(new Error("Could not read selected file")); reader.readAsDataURL(file);
    });
    const job = parseJob(await api("/v1/jobs", token, { policy: { backend, task: "protect", options: { seed, "max-sites": 16 } }, input: { name: file.name, content_base64: content } }));
    putJob(job); setVerificationJobId(job.job_id); setPage("Protection jobs"); await refresh(job.job_id);
  }
  const ready = health?.backends.some(b => b.name === "llvm-shield" && b.available);
  return <div className="app-shell"><a className="skip-link" href="#main-content">Skip to content</a>
    <aside className="sidebar"><a className="brand" href="#" onClick={e => { e.preventDefault(); setPage("Overview"); }}><Shield size={30} /><span>AEGIS<small>PROTECTION WORKSPACE</small></span></a>
      <div className="nav-caption">WORKSPACE</div><nav aria-label="Main navigation">{pages.map((p, i) => { const Icon = icons[i]; return <button key={p} className={page === p ? "active" : ""} aria-current={page === p ? "page" : undefined} onClick={() => setPage(p)}><Icon size={18} />{p}</button>; })}</nav>
      <div className="sidebar-note"><span className="status-dot" /> Research preview<p>LLVM 22 · textual IR<br />Local files · explicit evidence</p></div>
    </aside>
    <div className="workspace"><header><span><span className={`status-dot ${health?.status === "ok" ? "ok" : ""}`} />{health ? `API ${health.status}` : "API unavailable"}</span><button onClick={() => { setError(""); void checkHealth(); }}><RefreshCw size={14} /> Check connection</button></header>
      <main id="main-content"><div className="page-heading"><div><div className="eyebrow">AEGIS / LOCAL WORKSPACE</div><h1>{page}</h1><p>Protect software. Verify its identity. Evaluate the evidence.</p></div><span className="badge">Research preview</span></div>
        <Workflow page={page} navigate={setPage} />
        {error && <div className="error" role="alert"><strong>Action needs attention</strong><p>{error}</p><button onClick={() => setError("")}>Dismiss</button></div>}
        {page === "Overview" && <>
          <section className="hero panel"><div className="eyebrow">FROM INPUT TO EVIDENCE</div><h2>A protection workspace.<br />From input to evidence.</h2><p>Protect an authorized input, follow its job, verify artifact identity and inspect evaluation evidence in one local workspace.</p><button className="primary" onClick={() => setPage("Protect LLVM IR")}>Create protection job <ArrowRight size={16} /></button><Shield className="hero-shield" size={155} /></section>
          <div className="metrics">{[["Jobs in this browser session", String(jobs.length)], ["Succeeded transformations", String(jobs.filter(j => j.status === "succeeded").length)], ["Failed jobs", String(jobs.filter(j => j.status === "failed").length)], ["Attack resistance", "Not measured"]].map(([label, value]) => <div className="panel metric" key={label}><p>{label}</p><strong>{value}</strong></div>)}</div>
          <div className="columns"><section className="panel"><h3><CheckCircle2 size={19} /> Backend readiness</h3><p>{ready ? "llvm-shield is registered; its adapter executable is available." : "llvm-shield is not available. Follow the release runbook to build and configure it."}</p>{health && health.problems.length > 0 && <div className="error" data-testid="health-problems"><strong>API health degraded</strong><ul>{health.problems.map((p, i) => <li key={i}>{p}</li>)}</ul></div>}<p className="muted">Health checks do not verify the plugin. A successful real job exercises the pipeline.</p><p>Attack-lab API gate: {health ? (health.attack_lab_enabled ? "Enabled by operator; per-request authorization still required" : "Disabled") : "Unknown"}</p></section><section className="panel"><h3><FlaskConical size={19} /> Research records</h3><p>Load verified local exports for reconstruction, Mirage and ImageLab. Import privacy-filtered summaries; model usage and comparisons retain their recorded scope.</p><button onClick={() => setPage("Research evidence")}>Inspect local evidence <ArrowRight size={16} /></button></section></div>
          <div className="notice">Security event telemetry and active-license counts are unavailable. This dashboard makes no claim of live monitoring.</div>
        </>}
        {page === "Protect LLVM IR" && <section className="panel"><div className="eyebrow">01 / PROTECT</div><h2>Choose your protection profile</h2><p>Supported: trusted textual LLVM 22 IR with eligible <code>aegis.protect</code> annotations. The adapter validates the contents. Arbitrary executables, websites and consoles need future backends.</p><label className="upload"><UploadCloud size={34} /><strong>Choose your LLVM IR</strong><span>Owned, authorized input only · .ll · up to 64 MiB</span><input aria-label="LLVM IR file" type="file" accept=".ll" onChange={e => setFile(e.target.files?.[0] ?? null)} /></label>{file && <p>{file.name} · {file.size.toLocaleString()} bytes</p>}
          <div className="form-grid"><label>Protection profile<select aria-label="Protection profile" value={backend} onChange={e => setBackend(e.target.value)}><option value="llvm-shield" disabled={!health?.backends.some(b => b.name === "llvm-shield" && b.available && b.tasks.includes("protect"))}>Shield · LLVM 22</option><option value="llvm-shield-mirage" disabled={!health?.backends.some(b => b.name === "llvm-shield-mirage" && b.available && b.tasks.includes("protect"))}>Shield + Mirage · LLVM 22 decoys</option>{health?.backends.filter(b => !["llvm-shield", "llvm-shield-mirage"].includes(b.name)).map(b => <option key={b.name} disabled>{b.name} · no dashboard input contract</option>)}<option disabled>Native binaries / web / mobile · unsupported</option></select><span className="muted">Profiles require a registered, available backend and a documented input contract.</span></label><label>Deterministic seed<input aria-label="Deterministic seed" value={seed} onChange={e => setSeed(e.target.value)} /></label></div>
          <p>Maximum Shield sites per function: 16. Zero-transform jobs fail explicitly.{backend === "llvm-shield-mirage" && " Mirage adds 3 arithmetic decoys after Shield; final native retention requires a separate check."}</p><p className="muted">Shield + Mirage is selectable only when Core registers an available llvm-shield-mirage protection backend. Native binaries, websites and mobile packages are unsupported inputs.</p><button className="primary" disabled={!file || busy || !health?.backends.some(b => b.name === backend && b.available && b.tasks.includes("protect"))} onClick={() => void action(submit)}>{busy ? "Submitting…" : "Submit protection job"}<ArrowRight size={16} /></button><p className="muted">If submission times out, acceptance is uncertain. Do not resubmit automatically; inspect the local store for a job ID first.</p>
        </section>}
        {page === "Protection jobs" && <>
          <section className="panel"><h3>Find an existing job</h3><p>Jobs accepted in this session appear below. To reopen a previous job, enter its ID from the local store or report.</p><form className="inline-form" onSubmit={e => { e.preventDefault(); void action(async () => { if (!/^[0-9a-f]{32}$/.test(lookup)) throw new Error("Job ID must be 32 lowercase hexadecimal characters"); await refresh(lookup); }); }}><input aria-label="Job ID" placeholder="32-character job ID" value={lookup} onChange={e => setLookup(e.target.value)} /><button disabled={busy}>Load job</button></form></section>
          {jobs.length === 0 && <div className="empty panel">No accepted jobs in this session. Create a job or load an existing ID.</div>}
          {jobs.map(job => <article className="panel" key={job.job_id}><div className="row"><h3>{job.input_artifact.name}</h3><span className={`badge ${job.status}`} data-testid="job-status">{job.status}</span></div><p className="muted">Job <code>{job.job_id}</code></p>{!terminal(job.status) && <p role="status">Waiting for Core; status refreshes every 1.5 seconds.</p>}{job.error && <div className="error"><strong>{job.error.code}</strong><p>{job.error.message}</p>{typeof (job.error.details?.adapter_error as { code?: string } | undefined)?.code === "string" && <p>Adapter: {String((job.error.details.adapter_error as { code: string }).code)}</p>}</div>}<button disabled={busy} onClick={() => void action(() => refresh(job.job_id))}><RefreshCw size={14} />Refresh status and report</button>{reports[job.job_id] && <ReportView report={reports[job.job_id]} token={token} />}</article>)}
        </>}
        {page === "Research evidence" && <>
          <section className="panel"><div className="eyebrow">03 / EVALUATE</div><h2>Adversarial Lab</h2><p>Inspect privacy-filtered reconstruction, transformation and benchmark summaries. Evaluation imports never initiate an attack or a model request.</p><h3>Load a verified local summary</h3><p>Run <code>scripts/export-product-evidence.py</code> locally first. It checks the existing Lab or Mirage bindings and exports only display fields. Choose the exported JSON and paste its SHA-256 from your trusted terminal.</p><div className="notice">Do not select private experiment archives, Core execution records, hidden suites or model request files. Imports stay in this browser’s memory and are never uploaded.</div><label>Exported summary JSON<input aria-label="Evidence JSON" type="file" accept=".json" onChange={e => setEvidenceFile(e.target.files?.[0] ?? null)} /></label><label>Expected summary SHA-256<input aria-label="Expected summary SHA-256" value={expected} onChange={e => setExpected(e.target.value.trim())} /></label><button className="primary" disabled={!evidenceFile || busy} onClick={() => void action(async () => { if (!evidenceFile || evidenceFile.size > 1024 * 1024) throw new Error("Choose a summary smaller than 1 MiB"); const item = await loadEvidence(await evidenceFile.text(), expected); setEvidence(current => [item, ...current]); })}>Verify and load summary</button></section>
          {evidence.length === 0 && <div className="empty panel">No research evidence loaded. Generation, scoring and resistance remain unmeasured here.</div>}{evidence.map((item, i) => <EvidenceView key={i} item={item} />)}
          <section className="panel"><h3>AI analysis · unavailable</h3><p>Live model requests run outside this browser through the operator-authorized Lab workflow. Import a hash-checked public summary to inspect recorded model identity and usage. No credentials belong in this dashboard, and no GPU hardware or utilization is inferred from a provider record.</p><p>Sentinel is a separate policy package, not an AI security analyst. Mirage inserts retained arithmetic decoys in LLVM IR; it does not provide web honeypot events.</p></section>
        </>}
        {page === "Results" && <ResultsView jobs={jobs} attestations={attestations} reports={reports} evidence={evidence} navigate={setPage} verifyJob={id => { setVerificationJobId(id); setPage("Verify artifact"); }} />}
        {page === "Verify artifact" && <VerificationView jobs={jobs} token={token} initialJobId={verificationJobId} onSelectJob={setVerificationJobId} onVerified={recordAttestation} onResults={() => setPage("Results")} />}
        {page === "Capabilities" && <>
          <section className="panel"><h2>Feature and limitation matrix</h2><div className="table-scroll"><table><thead><tr><th>Component</th><th>Available today</th><th>Boundary</th></tr></thead><tbody>{[
            ["Core + API + CLI", "Local protection jobs, hashes, reports and explicit failures", "Known job IDs reopen stored jobs; no job-list API"],
            ["LLVM Shield", "LLVM 22 textual IR arithmetic transformations", "Prototype; optimization may remove changes; no established security property"],
            ["ImageLab", "Owned image-processing harness and variant comparisons", "Sampled correctness and local benchmarks only"],
            ["Mirage", "LLVM 22 decoy transformer and combined adapter", "Combined profile requires registration; native retention checked separately"],
            ["Lab", "Bounded offline reconstruction and private evidence verification", "Operator-authorized live inference stays outside the browser; behavioral scoring requires an authorized runtime"],
            ["Provenance / Sentinel", "Offline signing, verification and cooperating policy tools", "Server-configured signing and trusted verification; cooperating rights policies only; no license telemetry"],
            ["Web / mobile / consoles / arbitrary binaries", "Future backends", "Unsupported today"],
          ].map(row => <tr key={row[0]}>{row.map((v, i) => <td key={i}>{v}</td>)}</tr>)}</tbody></table></div></section>
          <section className="panel"><h3>Optional local API authentication</h3><p>If the operator set AEGIS_API_TOKEN, enter the matching token here. It is kept in memory only and sent to same-origin /v1 requests. Health is public.</p><label>API bearer token<input aria-label="API bearer token" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} /></label></section>
        </>}
        <footer>AEGIS research preview · Local artifact evidence · No established security property</footer>
      </main>
    </div>
  </div>;
}
