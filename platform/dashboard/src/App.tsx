import { useCallback, useEffect, useState } from "react";
import { Activity, ArrowRight, BookOpen, Box, CheckCircle2, FileJson, FlaskConical, RefreshCw, Shield, UploadCloud } from "lucide-react";
import { api, loadEvidence, parseJob, parseReport, terminal } from "./contracts";
import type { Artifact, Health, Job, LocalEvidence, Report } from "./contracts";

const pages = ["Overview", "Protect LLVM IR", "Protection jobs", "Research evidence", "Capabilities"] as const;
type Page = typeof pages[number];
const icons = [Activity, UploadCloud, Box, FlaskConical, BookOpen];

function ArtifactView({ value }: { value: Artifact }) {
  return <div className="artifact"><div><strong>{value.name}</strong><span>{value.size_bytes.toLocaleString()} bytes</span></div><code>{value.sha256}</code></div>;
}

function ReportView({ report }: { report: Report }) {
  const sites = report.evidence.filter(e => e.source === "adapter" && typeof e.data.transformed_sites === "number");
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `aegis-${report.job_id}.json`; anchor.click(); URL.revokeObjectURL(url);
  }
  return <section className="report" aria-label="Protection report">
    <div className="row"><h3>Protection report</h3><button onClick={download}><FileJson size={16} /> Download report</button></div>
    <p>{report.summary}</p><div className="notice">A succeeded job means the transformation pipeline completed. Attack resistance is not established.</div>
    <h4>Input · Core recorded SHA-256</h4><ArtifactView value={report.input_artifact} />
    <h4>Outputs · Core recorded SHA-256</h4>{report.output_artifacts.length ? report.output_artifacts.map(a => <ArtifactView key={a.sha256} value={a} />) : <p>No output artifacts registered.</p>}
    <h4>Transformation counts · adapter claims</h4>{sites.length ? sites.map((e, i) => <p key={i} data-testid="transformation-count">{String(e.data.transformed_sites)} transformed sites · LLVM {String(e.data.llvm_version)}</p>) : <p>Not reported.</p>}
    <h4>Evidence</h4>{report.evidence.map((e, i) => <p key={i}><span className="badge">{e.source === "orchestrator" ? "Core observation" : "Adapter claim"}</span> {e.summary}</p>)}
    <p>Attack evaluations: {report.attack_evaluations.length ? `${report.attack_evaluations.length} recorded; inspect the downloaded report for scope and outcomes.` : "Not run."}</p>
    <h4>Report limitations</h4><ul>{report.limitations.map((v, i) => <li key={i}>{v}</li>)}</ul>
  </section>;
}

function EvidenceView({ item }: { item: LocalEvidence }) {
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
  const [file, setFile] = useState<File | null>(null);
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
      const data = await api("/healthz", "") as Health;
      if (!data || !Array.isArray(data.backends) || !Array.isArray(data.problems) || typeof data.status !== "string") throw new Error("Invalid health response");
      setHealth(data);
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
    if (!file || !file.name.toLowerCase().endsWith(".ll")) throw new Error("Choose a textual LLVM IR (.ll) file");
    if (!file.size || file.size > 64 * 1024 * 1024) throw new Error("Input must be between 1 byte and 64 MiB");
    if (!/^[0-9]{1,20}$/.test(seed) || BigInt(seed) > 18446744073709551615n) throw new Error("Seed must be a uint64 decimal string");
    const content = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader(); reader.onload = () => resolve(String(reader.result).split(",")[1]); reader.onerror = () => reject(new Error("Could not read selected file")); reader.readAsDataURL(file);
    });
    const job = parseJob(await api("/v1/jobs", token, { policy: { backend: "llvm-shield", task: "protect", options: { seed, "max-sites": 16 } }, input: { name: file.name, content_base64: content } }));
    putJob(job); setPage("Protection jobs"); await refresh(job.job_id);
  }
  const ready = health?.backends.some(b => b.name === "llvm-shield" && b.available);
  return <div className="app-shell">
    <aside className="sidebar"><a className="brand" href="#" onClick={e => { e.preventDefault(); setPage("Overview"); }}><Shield size={30} /><span>AEGIS<small>LOCAL PROTECTION LAB</small></span></a>
      <div className="nav-caption">WORKSPACE</div><nav aria-label="Main navigation">{pages.map((p, i) => { const Icon = icons[i]; return <button key={p} className={page === p ? "active" : ""} onClick={() => setPage(p)}><Icon size={18} />{p}</button>; })}</nav>
      <div className="sidebar-note"><span className="status-dot" /> Research preview<p>LLVM 22 · textual IR<br />Local files · explicit evidence</p></div>
    </aside>
    <div className="workspace"><header><span><span className={`status-dot ${health ? "ok" : ""}`} />{health ? `API ${health.status}` : "API unavailable"}</span><button onClick={() => { setError(""); void checkHealth(); }}><RefreshCw size={14} /> Check connection</button></header>
      <main><div className="page-heading"><div><div className="eyebrow">AEGIS / LOCAL WORKSPACE</div><h1>{page}</h1><p>Transform supported LLVM IR. Inspect the evidence and its limits.</p></div><span className="badge">Research preview</span></div>
        {error && <div className="error" role="alert"><strong>Action needs attention</strong><p>{error}</p><button onClick={() => setError("")}>Dismiss</button></div>}
        {page === "Overview" && <>
          <section className="hero panel"><div className="eyebrow">FROM INPUT TO EVIDENCE</div><h2>A traceable transformation.<br />An honest result.</h2><p>Submit owned, annotated LLVM IR to the real Shield adapter. Follow the job through Core and inspect hashed artifacts and adapter claims.</p><button className="primary" onClick={() => setPage("Protect LLVM IR")}>Create protection job <ArrowRight size={16} /></button><Shield className="hero-shield" size={155} /></section>
          <div className="metrics">{[["Jobs in this browser session", String(jobs.length)], ["Succeeded transformations", String(jobs.filter(j => j.status === "succeeded").length)], ["Failed jobs", String(jobs.filter(j => j.status === "failed").length)], ["Attack resistance", "Not measured"]].map(([label, value]) => <div className="panel metric" key={label}><p>{label}</p><strong>{value}</strong></div>)}</div>
          <div className="columns"><section className="panel"><h3><CheckCircle2 size={19} /> Backend readiness</h3><p>{ready ? "llvm-shield is registered; its adapter executable is available." : "llvm-shield is not available. Follow the release runbook to build and configure it."}</p><p className="muted">Health checks do not verify the plugin. A successful real job exercises the pipeline.</p><p>Attack-lab API gate: {health ? (health.attack_lab_enabled ? "Enabled by operator; per-request authorization still required" : "Disabled") : "Unknown"}</p></section><section className="panel"><h3><FlaskConical size={19} /> Research records</h3><p>Load verified local exports for reconstruction, Mirage and ImageLab. No research-report API exists in this checkout.</p><button onClick={() => setPage("Research evidence")}>Inspect local evidence <ArrowRight size={16} /></button></section></div>
          <div className="notice">Security event telemetry and active-license counts are unavailable. This dashboard makes no claim of live monitoring.</div>
        </>}
        {page === "Protect LLVM IR" && <section className="panel"><h2>Submit a real Shield job</h2><p>Supported: trusted textual LLVM 22 IR with eligible <code>aegis.protect</code> annotations. The adapter validates the contents. Arbitrary executables, websites and consoles need future backends.</p><label className="upload"><UploadCloud size={34} /><strong>Choose your LLVM IR</strong><span>Owned, authorized input only · .ll · up to 64 MiB</span><input aria-label="LLVM IR file" type="file" accept=".ll" onChange={e => setFile(e.target.files?.[0] ?? null)} /></label>{file && <p>{file.name} · {file.size.toLocaleString()} bytes</p>}
          <div className="form-grid"><label>Backend<input readOnly value="llvm-shield" /></label><label>Deterministic seed<input aria-label="Deterministic seed" value={seed} onChange={e => setSeed(e.target.value)} /></label></div>
          <p>Maximum sites per function: 16. Zero-transform jobs fail explicitly.</p><button className="primary" disabled={!file || busy} onClick={() => void action(submit)}>{busy ? "Submitting…" : "Submit protection job"}<ArrowRight size={16} /></button><p className="muted">If submission times out, acceptance is uncertain. Do not resubmit automatically; inspect the local store for a job ID first.</p>
        </section>}
        {page === "Protection jobs" && <>
          <section className="panel"><h3>Find an existing job</h3><p>Jobs accepted in this session appear below. To reopen a previous job, enter its ID from the local store or report.</p><form className="inline-form" onSubmit={e => { e.preventDefault(); void action(async () => { if (!/^[0-9a-f]{32}$/.test(lookup)) throw new Error("Job ID must be 32 lowercase hexadecimal characters"); await refresh(lookup); }); }}><input aria-label="Job ID" placeholder="32-character job ID" value={lookup} onChange={e => setLookup(e.target.value)} /><button disabled={busy}>Load job</button></form></section>
          {jobs.length === 0 && <div className="empty panel">No accepted jobs in this session. Create a job or load an existing ID.</div>}
          {jobs.map(job => <article className="panel" key={job.job_id}><div className="row"><h3>{job.input_artifact.name}</h3><span className={`badge ${job.status}`} data-testid="job-status">{job.status}</span></div><p className="muted">Job <code>{job.job_id}</code></p>{!terminal(job.status) && <p role="status">Waiting for Core; status refreshes every 1.5 seconds.</p>}{job.error && <div className="error"><strong>{job.error.code}</strong><p>{job.error.message}</p>{typeof (job.error.details?.adapter_error as { code?: string } | undefined)?.code === "string" && <p>Adapter: {String((job.error.details.adapter_error as { code: string }).code)}</p>}</div>}<button disabled={busy} onClick={() => void action(() => refresh(job.job_id))}><RefreshCw size={14} />Refresh status and report</button>{reports[job.job_id] && <ReportView report={reports[job.job_id]} />}</article>)}
        </>}
        {page === "Research evidence" && <>
          <section className="panel"><h2>Load a verified local summary</h2><p>Run <code>scripts/export-product-evidence.py</code> locally first. It checks the existing Lab or Mirage bindings and exports only display fields. Choose the exported JSON and paste its SHA-256 from your trusted terminal.</p><div className="notice">Do not select private experiment archives, Core execution records, hidden suites or model request files. Imports stay in this browser’s memory and are never uploaded.</div><label>Exported summary JSON<input aria-label="Evidence JSON" type="file" accept=".json" onChange={e => setEvidenceFile(e.target.files?.[0] ?? null)} /></label><label>Expected summary SHA-256<input aria-label="Expected summary SHA-256" value={expected} onChange={e => setExpected(e.target.value.trim())} /></label><button className="primary" disabled={!evidenceFile || busy} onClick={() => void action(async () => { if (!evidenceFile || evidenceFile.size > 1024 * 1024) throw new Error("Choose a summary smaller than 1 MiB"); const item = await loadEvidence(await evidenceFile.text(), expected); setEvidence(current => [item, ...current]); })}>Verify and load summary</button></section>
          {evidence.length === 0 && <div className="empty panel">No research evidence loaded. Generation, scoring and resistance remain unmeasured here.</div>}{evidence.map((item, i) => <EvidenceView key={i} item={item} />)}
          <section className="panel"><h3>AI analysis · unavailable</h3><p>The merged Lab supports bounded, scripted offline reconstruction and an offline-tested Nebius transport. No live model call or NVIDIA GPU run is verified in the Role B handoff. Live inference remains gated; no credentials belong in this dashboard.</p><p>Sentinel is a separate policy package, not an AI security analyst. Mirage inserts retained arithmetic decoys in LLVM IR; it does not provide web honeypot events.</p></section>
        </>}
        {page === "Capabilities" && <>
          <section className="panel"><h2>Feature and limitation matrix</h2><div className="table-scroll"><table><thead><tr><th>Component</th><th>Available today</th><th>Boundary</th></tr></thead><tbody>{[
            ["Core + API + CLI", "Local protection jobs, hashes, reports and explicit failures", "No job-list or artifact-download API"],
            ["LLVM Shield", "LLVM 22 textual IR arithmetic transformations", "Prototype; optimization may remove changes; no established security property"],
            ["ImageLab", "Owned image-processing harness and variant comparisons", "Sampled correctness and local benchmarks only"],
            ["Mirage", "Standalone LLVM 22 / ELF decoy transformer", "Not registered as a Core backend; retention checked separately"],
            ["Lab", "Bounded offline reconstruction and private evidence verification", "Scripted provider; live inference and real candidate scoring pending"],
            ["Provenance / Sentinel", "Offline signing, verification and cooperating policy tools", "Separate CLIs; no automatic signing or license telemetry here"],
            ["Web / mobile / consoles / arbitrary binaries", "Future backends", "Unsupported today"],
          ].map(row => <tr key={row[0]}>{row.map((v, i) => <td key={i}>{v}</td>)}</tr>)}</tbody></table></div></section>
          <section className="panel"><h3>Optional local API authentication</h3><p>If the operator set AEGIS_API_TOKEN, enter the matching token here. It is kept in memory only and sent to same-origin /v1 requests. Health is public.</p><label>API bearer token<input aria-label="API bearer token" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} /></label></section>
        </>}
        <footer>AEGIS research preview · Local artifact evidence · No established security property</footer>
      </main>
    </div>
  </div>;
}
