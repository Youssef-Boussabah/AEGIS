import { useCallback, useEffect, useRef, useState } from "react";
import { Download, RefreshCw } from "lucide-react";
import { api } from "./contracts";
import type { Job } from "./contracts";
import { downloadArtifact, parseAttestation, parseDecision, parseTrustConfig, policyActions, saveBlob } from "./attestation";
import type { Attestation, Decision, PolicyAction, TrustConfig } from "./attestation";

export function VerificationView({ jobs, token, initialJobId, onSelectJob, onResults, onVerified }: { jobs: Job[]; token: string; initialJobId: string; onSelectJob: (id: string) => void; onResults: () => void; onVerified: (value: Attestation) => void }) {
  const [config, setConfig] = useState<TrustConfig | null>(null);
  const [selected, setSelected] = useState(initialJobId);
  const [attestation, setAttestation] = useState<Attestation | null>(null);
  const [action, setAction] = useState<PolicyAction>("redistribute");
  const [decisions, setDecisions] = useState<Record<string, Decision>>({});
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const requestNumber = useRef(0);
  const job = jobs.find(j => j.job_id === selected) ?? jobs[0];
  const jobId = job?.job_id;
  const jobStatus = job?.status;
  const load = useCallback(async () => {
    const request = ++requestNumber.current;
    setError(""); setBusy(true); setConfig(null); setAttestation(null); setDecisions({}); setNotice("");
    try {
      const trust = parseTrustConfig(await api("/v1/attestation", token));
      if (request !== requestNumber.current) return;
      setConfig(trust);
      if (job) {
        const value = parseAttestation(await api(`/v1/jobs/${job.job_id}/attestation`, token), job);
        if (request !== requestNumber.current) return;
        setAttestation(value); onVerified(value);
      }
    } catch (e) { if (request === requestNumber.current) setError(e instanceof Error ? e.message : "Verification request failed"); }
    finally { if (request === requestNumber.current) setBusy(false); }
  }, [token, job, onVerified]);
  // Refetch when the selected job becomes terminal. No verified result is carried across jobs.
  useEffect(() => { void load(); return () => { requestNumber.current++; }; }, [load, jobId, jobStatus]);

  async function run(work: () => Promise<void>) {
    setBusy(true); setError(""); setNotice("");
    try { await work(); } catch (e) { setError(e instanceof Error ? e.message : "Operation failed"); } finally { setBusy(false); }
  }
  return <>
    <section className="panel"><div className="eyebrow">02 / VERIFY</div><div className="row"><h2>Provenance & Sentinel</h2><button disabled={busy} onClick={() => void load()}><RefreshCw size={15} /> Refresh verification</button></div>
      <p>Verify artifact bytes against a trusted signer’s attestation, then inspect the cooperating rights policy. Signing keys stay on the server.</p>
      {error && <div className="error" role="alert"><strong>Verification or policy request failed</strong><p>{error}</p></div>}
      {notice && <div className="notice" role="status">{notice}</div>}
      {busy && <p role="status">Checking the recorded artifact and policy…</p>}
      {config && <div className="columns">
        <div className="verification-status"><div><strong>Signature configuration</strong><p>{config.signing.state === "not_configured" ? "Not signed (signing not configured)" : `Configured · ${config.signing.signer_name ?? "Unnamed signer"}`}</p><p className="muted">{config.signing.state === "configured" ? (config.signing.signer_trusted ? "Signing key is in the operator’s trusted set. Per-artifact verification is shown below." : "Signing key is untrusted. Signatures will fail verification.") : "No automatic signature is claimed."}</p><p className="muted">{config.verification.trusted_key_ids.length} trusted verification key(s)</p></div></div>
        <div className="verification-status"><div><strong>Sentinel configuration</strong><p>{config.sentinel.state === "not_configured" ? "Unconfigured · no policy created" : `Configured · ${config.sentinel.enforcement_mode}`}</p><p className="muted">Cooperating rights metadata. Enforcement applies to AEGIS’s download route; third-party tools are not bound by this policy.</p></div></div>
      </div>}
      <label>Job to verify<select aria-label="Job to verify" value={job?.job_id ?? ""} disabled={!jobs.length || busy} onChange={e => { setSelected(e.target.value); onSelectJob(e.target.value); setAttestation(null); setDecisions({}); }}>
        {!jobs.length && <option value="">No job loaded</option>}{jobs.map(j => <option key={j.job_id} value={j.job_id}>{j.input_artifact.name} · {j.job_id}</option>)}
      </select></label>
      {!jobs.length && <div className="empty">Protect an input or load an existing job in Protection jobs to verify its outputs.</div>}
      {attestation && <>
        <p className="muted">Checked at {attestation.checked_at} · Job {attestation.job_id}</p>
        <p><strong>{({ signed: "Signing recorded; check each signature below", not_configured: "Signing not configured for this job", signing_failed: "Signing failed", not_applicable: "Signing not applicable", pending: "Signing pending" })[attestation.signing.state]}</strong></p>
        <p><strong>{({ created: "Sentinel policies created; evaluate for a current decision", not_configured: "Sentinel not configured for this job", creation_failed: "Sentinel policy creation failed", not_applicable: "Sentinel not applicable", pending: "Sentinel pending" })[attestation.sentinel.state]}</strong></p>
        <p>{attestation.signing.message}</p><p>{attestation.sentinel.message}</p>
        {!attestation.artifacts.length && <div className="notice">{attestation.job_status === "failed" ? "Not applicable: this job failed and has no output artifacts." : "Pending: verification awaits successful output artifacts."}</div>}
        {attestation.artifacts.map(a => {
          const decision = decisions[a.artifact_id];
          return <article className="result-card" key={a.artifact_id}>
            <div className="row"><h3>{a.name}</h3><span className={`badge ${a.signature.status}`}>{a.signature.status === "verified" ? "Signature verified" : a.signature.status === "failed" ? "Signature failed" : "Unsigned"}</span></div><code>{a.sha256}</code>
            {a.signature.error_code && <div className="error"><strong>{a.signature.error_code}</strong><p>{a.signature.message}</p></div>}
            <dl><div><dt>Signature</dt><dd>{a.signature.message}</dd></div><div><dt>Signer</dt><dd>{a.signature.signer_name ?? "None"}</dd></div><div><dt>Key fingerprint</dt><dd><code>{a.signature.key_id ?? "None"}</code></dd></div><div><dt>Sentinel policy</dt><dd>{a.policy.status === "absent" ? (attestation.sentinel.state === "not_configured" ? "Unconfigured · no policy" : "Absent · no policy available") : a.policy.status}{a.policy.enforcement_mode && ` · ${a.policy.enforcement_mode}`}</dd></div></dl>
            {a.policy.disclaimer && <div className="notice">{a.policy.disclaimer}</div>}
            {a.policy.errors.length > 0 && <div className="error"><strong>Policy invalid</strong><ul>{a.policy.errors.map((e, i) => <li key={i}>{e}</li>)}</ul></div>}
            {a.policy.permissions.length > 0 && <div className="table-scroll"><table><caption>Declared policy permissions · use Evaluate for a current decision</caption><thead><tr><th>Action</th><th>Declared permission</th></tr></thead><tbody>{a.policy.permissions.map(p => <tr key={p.action}><td>{p.action}</td><td>{p.allowed ? "Allowed" : "Denied"}</td></tr>)}</tbody></table></div>}
            {a.policy.status !== "absent" && <div className="actions"><label>Policy action<select aria-label={`Policy action for ${a.name}`} value={action} onChange={e => { setAction(e.target.value as PolicyAction); setDecisions({}); }}>{policyActions.map(p => <option key={p}>{p}</option>)}</select></label><button disabled={busy} onClick={() => void run(async () => {
              setDecisions(current => { const next = { ...current }; delete next[a.artifact_id]; return next; });
              const result = parseDecision(await api(`/v1/jobs/${attestation.job_id}/artifacts/${a.sha256}/evaluate`, token, { action }), attestation.job_id, a.sha256, action);
              setDecisions(current => ({ ...current, [a.artifact_id]: result }));
            })}>Evaluate Sentinel policy for {a.name}</button></div>}
            {decision && <div className="verification-status" role="status"><span className={`badge ${decision.permitted ? "verified" : "denied"}`}>{decision.permitted ? "Permitted" : "Denied"}</span><div><p>{decision.action} · {decision.enforcement_mode}</p><p>{decision.reason}</p><p className="muted">Evaluated {decision.evaluated_at}. Caller identity is not authenticated. This decision never authorizes attack-lab execution.</p></div></div>}
            <div className="actions"><button disabled={busy} onClick={() => void run(async () => setNotice(await downloadArtifact(attestation.job_id, { ...a, role: "output" }, token)))}><Download size={15} /> Download {a.name}</button>
              {(["manifest", "policy"] as const).map(kind => <button key={kind} disabled={busy || (kind === "manifest" ? !a.signature.manifest_sha256 : a.policy.status === "absent")} onClick={() => void run(async () => {
                const doc = await api(`/v1/jobs/${attestation.job_id}/artifacts/${a.sha256}/${kind}`, token);
                saveBlob(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" }), `${a.name}.${kind}.json`);
              })}>Download {kind} for {a.name}</button>)}
            </div>
          </article>;
        })}
        <h3>Verification limitations</h3><ul>{attestation.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
      </>}
      <div className="notice">A valid signature proves a trusted key holder attested to the bytes and metadata. It does not establish originality, ownership or attack resistance.</div>
      <button onClick={onResults}>Continue to Results</button>
    </section>
  </>;
}
