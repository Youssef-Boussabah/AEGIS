import { useMemo, useState } from "react";
import {
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Check,
  ChevronDown,
  ChevronRight,
  Code2,
  Eye,
  Fingerprint,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  Plus,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X,
  CircleHelp,
} from "lucide-react";

type Event = {
  id: string;
  time: string;
  title: string;
  detail: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  source: string;
};
const initialEvents: Event[] = [
  {
    id: "EVT-2048",
    time: "10:42:18",
    title: "Decoy endpoint accessed",
    detail: "Unauthorized request to /api/internal/keys",
    severity: "Critical",
    source: "Honeypot",
  },
  {
    id: "EVT-2047",
    time: "10:38:04",
    title: "Repeated license validation failures",
    detail: "12 failed attempts from a single client",
    severity: "High",
    source: "Licensing",
  },
  {
    id: "EVT-2046",
    time: "10:25:51",
    title: "Unusual API request pattern",
    detail: "Request frequency exceeded baseline",
    severity: "Medium",
    source: "AI Monitor",
  },
  {
    id: "EVT-2045",
    time: "10:12:33",
    title: "License validated successfully",
    detail: "Client SDK verified an active license",
    severity: "Low",
    source: "Licensing",
  },
  {
    id: "EVT-2044",
    time: "09:54:10",
    title: "Protected application heartbeat",
    detail: "SDK reported healthy status",
    severity: "Low",
    source: "Protection",
  },
];
const trends = [
  { time: "00:00", blocked: 14, detected: 20 },
  { time: "02:00", blocked: 19, detected: 27 },
  { time: "04:00", blocked: 13, detected: 18 },
  { time: "06:00", blocked: 30, detected: 37 },
  { time: "08:00", blocked: 24, detected: 32 },
  { time: "10:00", blocked: 46, detected: 55 },
  { time: "12:00", blocked: 38, detected: 48 },
  { time: "14:00", blocked: 59, detected: 69 },
  { time: "16:00", blocked: 49, detected: 62 },
  { time: "18:00", blocked: 72, detected: 81 },
  { time: "20:00", blocked: 61, detected: 73 },
  { time: "22:00", blocked: 80, detected: 91 },
];
const initialLicenses = [
  {
    id: "LIC-1001",
    product: "Sentinel SDK Pro",
    owner: "Acme Development",
    status: "Active",
    expiry: "2027-04-18",
  },
  {
    id: "LIC-1002",
    product: "Sentinel SDK Pro",
    owner: "Northstar Labs",
    status: "Active",
    expiry: "2027-06-02",
  },
  {
    id: "LIC-1003",
    product: "Sentinel SDK Starter",
    owner: "Orbit Systems",
    status: "Expired",
    expiry: "2026-10-20",
  },
];
const menu = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Protection jobs", icon: ShieldAlert },
  { name: "Software upload", icon: KeyRound },
  { name: "Shield & Mirage", icon: Fingerprint },
  { name: "AI analysis", icon: Sparkles },
];
function App() {
  const [page, setPage] = useState("Overview");
  const [events, setEvents] = useState(initialEvents);
  const [licenses] = useState(initialLicenses);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [menuOpen, setMenuOpen] = useState(false);
  const [notification, setNotification] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [protectionJobs, setProtectionJobs] = useState<
    { id: string; status: string; filename: string }[]
  >([]);

  const filtered = useMemo(
    () =>
      events.filter(
        (e) =>
          (filter === "All" || e.severity === filter) &&
          `${e.title} ${e.detail} ${e.source}`
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [events, filter, search],
  );
  function notify(message: string) {
    setNotification(message);
    window.setTimeout(() => setNotification(""), 3500);
  }
  
async function submitProtectionJob() {
  if (!selectedFile || submitting) return;

  setSubmitting(true);

  try {
    const bytes = new Uint8Array(await selectedFile.arrayBuffer());
    let binary = "";

    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }

    const contentBase64 = btoa(binary);

    const response = await fetch("/v1/jobs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        policy: {
          name: "dashboard-default",
          backend: "llvm-shield",
          task: "protect",
          options: {},
        },
        input: {
          name: selectedFile.name,
          content_base64: contentBase64,
        },
      }),
    });

    const result = await response.json();

    if (!response.ok) {
      const message =
        result.error?.message ||
        result.detail ||
        "Protection job submission failed";

      throw new Error(
         typeof message === "string"
          ? message
          : JSON.stringify(message)
      );
    }

    setProtectionJobs((previousJobs) => [
  {
    id: result.id,
    status: result.status,
    filename: selectedFile.name,
  },
  ...previousJobs,
]);

    notify(`Job submitted: ${result.id}`);
    setPage("Protection jobs");
  } catch (error) {
    notify(
      error instanceof Error
        ? error.message
        : "Unable to submit protection job"
    );
  } finally {
    setSubmitting(false);
  }
}
  
async function refreshProtectionJob(jobId: string) {
  try {
    const response = await fetch(
      `/v1/jobs/${encodeURIComponent(jobId)}`
    );

    const result = await response.json();

    if (!response.ok) {
      throw new Error(
        result.error?.message ||
        result.detail ||
        "Unable to refresh protection job"
      );
    }

    setProtectionJobs((previousJobs) =>
      previousJobs.map((job) =>
        job.id === jobId
          ? { ...job, status: result.status }
          : job
      )
    );

    notify(`Job status updated: ${result.status}`);
  } catch (error) {
    notify(
      error instanceof Error
        ? error.message
        : "Unable to refresh protection job"
    );
  }
}
  
async function viewProtectionReport(jobId: string) {
  try {
    const response = await fetch(
      `/v1/jobs/${encodeURIComponent(jobId)}/report`
    );

    const result = await response.json();

    if (!response.ok) {
      const message =
        result.error?.message ||
        result.detail ||
        "Protection report is not available yet";

      throw new Error(
        typeof message === "string"
          ? message
          : JSON.stringify(message)
      );
    }

    const reportText = JSON.stringify(result, null, 2);
    const blob = new Blob([reportText], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `aegis-report-${jobId}.json`;
    link.click();
    URL.revokeObjectURL(url);

    notify("Protection report downloaded successfully");
  } catch (error) {
    notify(
      error instanceof Error
        ? error.message
        : "Unable to retrieve protection report"
    );
  }
}

  function simulate() {
    const e: Event = {
      id: `EVT-${Math.floor(2050 + Math.random() * 9000)}`,
      time: new Date().toLocaleTimeString("en-US", { hour12: false }),
      title: "Simulated suspicious request detected",
      detail: "Demo-only request triggered a decoy endpoint",
      severity: "High",
      source: "Honeypot",
    };
    setEvents((prev) => [e, ...prev]);
    notify("Demo event generated — no real attack occurred");
    setPage("Protection jobs");
  }
  function runAnalysis() {
    setAnalyzing(true);
    window.setTimeout(() => {
      setAnalyzing(false);
      notify(
        "Demo analysis complete — connect an AI backend for live insights",
      );
    }, 700);
  }
  return (
    <div className="app">
      <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={23} />
          </div>
          <div>
            <strong>AEGIS</strong>
            <small>SECURITY PLATFORM</small>
          </div>
        </div>
        <div className="workspace">
          <div className="workspace-icon">S</div>
          <div>
            <b>Sentinel Workspace</b>
            <small>Free demo environment</small>
          </div>
          <ChevronDown size={15} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {menu.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={`nav-item ${page === name ? "active" : ""}`}
              onClick={() => {
                setPage(name);
                setMenuOpen(false);
              }}
            >
              <Icon size={19} />
              <span>{name}</span>
              {name === "Protection jobs" && <i>5</i>}
            </button>
          ))}
        </nav>
        <div className="nav-label nav-label-lower">MANAGEMENT</div>
        <nav>
          <button
            className="nav-item"
            onClick={() => notify("Settings are not configured in demo mode")}
          >
            <Settings2 size={19} />
            Settings
          </button>
          <button
            className="nav-item"
            onClick={() => notify("Docs: see README.md in project source")}
          >
            <CircleHelp size={19} />
            Help & documentation
          </button>
        </nav>
        <div className="sidebar-bottom">
          <div className="status-orb">
            <span className="pulse" />
            <div>
              <b>Demo environment</b>
              <small>Mock data · no backend</small>
            </div>
          </div>
          <div className="profile">
            <div className="avatar">SD</div>
            <div>
              <b>Security Developer</b>
              <small>Hackathon workspace</small>
            </div>
            <MoreHorizontal size={18} />
          </div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              className="mobile-menu"
              onClick={() => setMenuOpen(!menuOpen)}
            >
              <Menu size={21} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={14} />
            <b>{page}</b>
          </div>
          <div className="top-actions">
            <div className="demo-pill">
              <span /> DEMO MODE
            </div>
            <button
              aria-label="Notifications"
              onClick={() => notify("You are viewing demo data")}
            >
              <Bell size={19} />
            </button>
            <div className="avatar mini">SD</div>
          </div>
        </header>
        <main className="content">
          <div className="page-head">
            <div>
              <div className="eyebrow">
                <span className="eyebrow-dot" /> SECURITY COMMAND CENTER{" "}
                <span className="slash">/</span> LIVE PREVIEW
              </div>
              <h1>{page === "Overview" ? "Security overview" : page}</h1>
              <p>
                {page === "Overview"
                  ? "Monitor your software, defend your assets, and stay one step ahead."
                  : page === "Protection jobs"
                    ? "Investigate suspicious activity and monitor security events."
                    : page === "Software upload"
                      ? "Control access to protected software with cloud-ready licensing."
                      : page === "Shield & Mirage"
                        ? "Monitor decoy resources designed to reveal suspicious behavior."
                        : "Review Protection jobs with your AI security copilot."}
              </p>
            </div>
            <div className="head-buttons">
              <button
                className="secondary"
                onClick={() =>
                  notify("Demo data only — no live report is available")
                }
              >
                <ArrowDownRight size={16} /> Export report
              </button>
              <button className="primary" onClick={simulate}>
                <Plus size={17} /> Simulate event
              </button>
            </div>
          </div>
          {page === "Overview" ? (
            <>
              <div className="hero">
                <div className="hero-text">
                  <div className="hero-label">
                    <span className="pulse" /> SYSTEM STATUS · DEMO
                  </div>
                  <h2>
                    Your software.
                    <br />
                    <em>Protected by intelligence.</em>
                  </h2>
                  <p>
                    A unified view of threats, software licenses, and decoy
                    activity — designed for proactive defense.
                  </p>
                  <button onClick={() => setPage("AI analysis")}>
                    Explore AI insights <ArrowRight size={16} />
                  </button>
                </div>
                <div className="hero-art">
                  <div className="orbit o1" />
                  <div className="orbit o2" />
                  <div className="orbit o3" />
                  <div className="hero-shield">
                    <ShieldCheck size={92} strokeWidth={1.3} />
                  </div>
                  <div className="float-chip chip-one">
                    <Shield size={15} /> Protection active
                  </div>
                  <div className="float-chip chip-two">
                    <Sparkles size={15} /> AI monitoring
                  </div>
                </div>
              </div>
              <div className="section-line">
                <h3>At a glance</h3>
                <span>Illustrative metrics · last 24 hours</span>
              </div>
              <div className="stats">
                <Metric
                  icon={ShieldAlert}
                  color="pink"
                  label="Threats detected"
                  value="1,284"
                  change="+12.8%"
                  trend="up"
                />
                <Metric
                  icon={ShieldCheck}
                  color="purple"
                  label="Requests blocked"
                  value="1,096"
                  change="85.4% blocked"
                  trend="neutral"
                />
                <Metric
                  icon={KeyRound}
                  color="blue"
                  label="Active licenses"
                  value={String(
                    licenses.filter((l) => l.status === "Active").length,
                  )}
                  change="Demo records"
                  trend="neutral"
                />
                <Metric
                  icon={Fingerprint}
                  color="orange"
                  label="Decoy triggers"
                  value={String(
                    events.filter((e) => e.source === "Honeypot").length,
                  )}
                  change="Demo events"
                  trend="neutral"
                />
              </div>
              <div className="dashboard-grid">
                <div className="panel chart-panel">
                  <div className="panel-heading">
                    <div>
                      <h3>Threat activity</h3>
                      <p>Detected vs. blocked requests</p>
                    </div>
                    <span className="tiny-tag">
                      24 HOURS <ChevronDown size={13} />
                    </span>
                  </div>
                  <div className="legend">
                    <span>
                      <i className="legend-purple" /> Detected
                    </span>
                    <span>
                      <i className="legend-cyan" /> Blocked
                    </span>
                  </div>
                  <div className="chart-wrap">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart
                        data={trends}
                        margin={{ top: 8, right: 8, left: -30, bottom: 0 }}
                      >
                        <defs>
                          <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                            <stop
                              offset="0%"
                              stopColor="#8a6cff"
                              stopOpacity={0.32}
                            />
                            <stop
                              offset="100%"
                              stopColor="#8a6cff"
                              stopOpacity={0}
                            />
                          </linearGradient>
                          <linearGradient id="g2" x1="0" y1="0" x2="0" y2="1">
                            <stop
                              offset="0%"
                              stopColor="#37d5e9"
                              stopOpacity={0.2}
                            />
                            <stop
                              offset="100%"
                              stopColor="#37d5e9"
                              stopOpacity={0}
                            />
                          </linearGradient>
                        </defs>
                        <CartesianGrid
                          vertical={false}
                          stroke="#27304a"
                          strokeDasharray="4 6"
                        />
                        <XAxis
                          dataKey="time"
                          stroke="#7d8ca8"
                          tickLine={false}
                          axisLine={false}
                          tick={{ fontSize: 11 }}
                        />
                        <YAxis
                          stroke="#7d8ca8"
                          tickLine={false}
                          axisLine={false}
                          tick={{ fontSize: 11 }}
                        />
                        <Tooltip
                          contentStyle={{
                            background: "#151e35",
                            border: "1px solid #39435d",
                            borderRadius: 12,
                            color: "#fff",
                          }}
                        />
                        <Area
                          type="monotone"
                          dataKey="detected"
                          stroke="#9475ff"
                          fill="url(#g1)"
                          strokeWidth={2.5}
                        />
                        <Area
                          type="monotone"
                          dataKey="blocked"
                          stroke="#3ed9e9"
                          fill="url(#g2)"
                          strokeWidth={2.5}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div className="panel distribution">
                  <div className="panel-heading">
                    <div>
                      <h3>Threat breakdown</h3>
                      <p>By severity level</p>
                    </div>
                    <MoreHorizontal size={20} />
                  </div>
                  <div className="donut">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={[
                            { name: "Critical", value: 18 },
                            { name: "High", value: 32 },
                            { name: "Medium", value: 35 },
                            { name: "Low", value: 15 },
                          ]}
                          dataKey="value"
                          innerRadius={73}
                          outerRadius={96}
                          paddingAngle={4}
                          stroke="none"
                        >
                          <Cell fill="#ff638c" />
                          <Cell fill="#a17bff" />
                          <Cell fill="#43cfe0" />
                          <Cell fill="#f6b66c" />
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="donut-center">
                      <strong>1,284</strong>
                      <small>Total events</small>
                    </div>
                  </div>
                  <div className="severity-legend">
                    <span>
                      <i style={{ background: "#ff638c" }} />
                      Critical <b>18%</b>
                    </span>
                    <span>
                      <i style={{ background: "#a17bff" }} />
                      High <b>32%</b>
                    </span>
                    <span>
                      <i style={{ background: "#43cfe0" }} />
                      Medium <b>35%</b>
                    </span>
                    <span>
                      <i style={{ background: "#f6b66c" }} />
                      Low <b>15%</b>
                    </span>
                  </div>
                </div>
              </div>
              <div className="dashboard-grid lower">
                <EventsPanel
                  events={events.slice(0, 4)}
                  onView={() => setPage("Protection jobs")}
                  onSelect={setSelectedEvent}
                />
                <div className="panel ai-card">
                  <div className="ai-icon">
                    <Sparkles size={23} />
                  </div>
                  <span className="tiny-tag">
                    POWERED BY AI · INTEGRATION READY
                  </span>
                  <h3>Meet your AI security analyst</h3>
                  <p>
                    Turn raw event logs into actionable security insights.
                    Connect your team's Nebius + NVIDIA model to enable live
                    analysis.
                  </p>
                  <button
                    className="primary"
                    onClick={() => setPage("AI analysis")}
                  >
                    Open AI analysis <ArrowRight size={16} />
                  </button>
                  <div className="ai-glow" />
                </div>
              </div>
            </>
          ) : page === "Protection jobs" ? (
            <>
              
<div className="section-line">
  <h3>AEGIS protection jobs</h3>
  <span>{protectionJobs.length} jobs submitted this session</span>
</div>

<div className="panel full" style={{ padding: "24px", marginBottom: "24px" }}>
  {protectionJobs.length === 0 ? (
    <p>
      No protection jobs have been accepted yet.
      Upload an LLVM IR (.ll) file to create a job once
      a protection backend is registered.
    </p>
  ) : (
    <div>
      {protectionJobs.map((job) => (
        <div
          key={job.id}
          style={{
            padding: "16px",
            marginBottom: "12px",
            border: "1px solid #62618f",
            borderRadius: "10px",
          }}
        >
          <p><strong>File:</strong> {job.filename}</p>
          <p><strong>Job ID:</strong> {job.id}</p>
          <p><strong>Status:</strong> {job.status}</p>
          <button
            className="secondary"
            onClick={() => refreshProtectionJob(job.id)}
            style={{ marginTop: "12px" }}
          >
            Refresh status
          </button>
          <button
            className="secondary"
            onClick={() => viewProtectionReport(job.id)}
            disabled={!["succeeded", "failed"].includes(job.status)}
            style={{ marginTop: "12px", marginLeft: "10px" }}
        >
          Download report
        </button>
        </div>
      ))}
    </div>
  )}
</div>
              <div className="section-line">
                <h3>Security events</h3>
                <span>{filtered.length} matching demo events</span>
              </div>
              <div className="panel full">
                <div className="filters">
                  <label className="search">
                    <Search size={18} />
                    <input
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="Search events, source, details..."
                    />
                  </label>
                  <select
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                  >
                    <option>All</option>
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                  </select>
                </div>
                <EventsTable events={filtered} onSelect={setSelectedEvent} />
              </div>
            </>
          ) : page === "Software upload" ? (
            
<>
  <div className="section-line">
    <h3>Upload software for protection</h3>
    <span>AEGIS Protection Platform</span>
  </div>

  <div className="panel full" style={{ padding: "28px" }}>
    <h3>New protection job</h3>
    <p style={{ marginTop: "8px", marginBottom: "24px" }}>
      Select an LLVM IR file to prepare it for the AEGIS
      protection pipeline.
    </p>

    <div
      style={{
        border: "2px dashed #62618f",
        borderRadius: "14px",
        padding: "45px 24px",
        textAlign: "center",
        background: "rgba(138, 108, 255, 0.05)",
      }}
    >
      <ShieldCheck size={42} color="#a17bff" />

      <h3 style={{ marginTop: "16px" }}>
        Select your software file
      </h3>

      <p style={{ marginTop: "10px", marginBottom: "20px" }}>
        Supported format: LLVM Intermediate Representation (.ll)
      </p>

      
<input
  type="file"
  accept=".ll"
  onChange={(e) => {
    const file = e.target.files?.[0] ?? null;

    if (file && !file.name.toLowerCase().endsWith(".ll")) {
      setSelectedFile(null);
      e.target.value = "";
      notify("Please select a valid LLVM IR (.ll) file");
      return;
    }

    setSelectedFile(file);

    if (file) {
      notify(`Selected file: ${file.name}`);
    }
  }}
/>

{selectedFile && (
  <p style={{ marginTop: "18px", color: "#a17bff" }}>
    Selected: {selectedFile.name} (
    {(selectedFile.size / 1024).toFixed(1)} KB)
  </p>
)}
    </div>

    <div style={{ marginTop: "28px" }}>
      <h3>Protection configuration</h3>

      <p style={{ marginTop: "10px" }}>
        Protection options will be connected to the AEGIS
        backend after we confirm the API requirements.
      </p>
    </div>

    <div style={{ marginTop: "28px" }}>
      <button
        className="primary"
        disabled={!selectedFile || submitting}
        onClick={submitProtectionJob}
        title="Submit your LLVM IR file to AEGIS"
      >
        <ShieldCheck size={17} />
        Submit protection job
      </button>

      <p style={{ marginTop: "12px", fontSize: "12px" }}>
        Select an LLVM IR (.ll) file, then submit it to the AEGIS API. Actual protection requires a registered backend.
      </p>
    </div>
  </div>
</>

          ) : page === "Shield & Mirage" ? (
            <>
              <div className="decoy-grid">
                {[
                  {
                    path: "/api/internal/keys",
                    hits: 12,
                    type: "Credential decoy",
                    color: "pink",
                  },
                  {
                    path: "/admin/debug",
                    hits: 8,
                    type: "Admin decoy",
                    color: "purple",
                  },
                  {
                    path: "/assets/config.backup",
                    hits: 3,
                    type: "File decoy",
                    color: "blue",
                  },
                ].map((d) => (
                  <div className="panel decoy" key={d.path}>
                    <div className={`metric-icon ${d.color}`}>
                      <Eye size={21} />
                    </div>
                    <span className="tag high">DEMO HONEYPOT</span>
                    <h3>{d.path}</h3>
                    <p>{d.type}</p>
                    <div className="decoy-footer">
                      <strong>
                        {d.hits} <small>simulated hits</small>
                      </strong>
                      <button onClick={simulate}>
                        Trigger demo <ArrowRight size={15} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
              <div className="notice">
                <LockKeyhole size={19} /> These are simulated endpoints, not
                real exposed routes. Your backend team can implement safe decoys
                and stream actual events.
              </div>
            </>
          ) : (
            <div className="analyst-layout">
              <div className="panel analyst-main">
                <div className="analyst-title">
                  <div className="ai-icon">
                    <Sparkles size={22} />
                  </div>
                  <div>
                    <h3>Sentinel AI analysis</h3>
                    <p>Threat explanation and response guidance</p>
                  </div>
                  <span className="tag medium">DEMO</span>
                </div>
                <div className="chat-msg">
                  <div className="ai-icon small">
                    <Sparkles size={17} />
                  </div>
                  <div>
                    <b>Sentinel AI</b>
                    <p>
                      Welcome to your security command center. I can help
                      interpret threat signals and suggest next steps. This
                      preview uses a scripted response; connect Nebius + an
                      NVIDIA open-source model for real AI analysis.
                    </p>
                  </div>
                </div>
                <div className="chat-msg user-msg">
                  <div className="ai-icon small">
                    <Code2 size={17} />
                  </div>
                  <div>
                    <b>Example prompt</b>
                    <p>
                      Analyze the recent decoy endpoint access and failed
                      license validations.
                    </p>
                  </div>
                </div>
                {analyzing && (
                  <p className="loading">Processing demo analysis…</p>
                )}
                <div className="chat-msg">
                  <div className="ai-icon small">
                    <Sparkles size={17} />
                  </div>
                  <div>
                    <b>Example analysis · Not model-generated</b>
                    <p>
                      Decoy endpoint access and repeated license failures may
                      indicate unauthorized probing. Recommended actions: verify
                      request logs, rate-limit repeated failures, rotate any
                      exposed test credentials, and review source IPs. No
                      real-world incident is confirmed.
                    </p>
                  </div>
                </div>
                <button className="primary" onClick={runAnalysis}>
                  <Sparkles size={16} /> Run demo analysis
                </button>
              </div>
              <div className="panel analyst-side">
                <h3>AI integration checklist</h3>
                <div className="checklist">
                  <p>
                    <Check size={16} /> Connect event API
                  </p>
                  <p>
                    <Check size={16} /> Define structured event schema
                  </p>
                  <p>
                    <span className="unchecked" /> Configure Nebius credentials
                    on server
                  </p>
                  <p>
                    <span className="unchecked" /> Call an NVIDIA open-source
                    model
                  </p>
                  <p>
                    <span className="unchecked" /> Display model-generated
                    response
                  </p>
                </div>
                <div className="notice mini-notice">
                  Never expose API keys in React frontend code.
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
      {selectedEvent && (
        <div className="modal-backdrop" onClick={() => setSelectedEvent(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <button className="close" onClick={() => setSelectedEvent(null)}>
              <X size={20} />
            </button>
            <div className="eyebrow">SECURITY EVENT · DEMO</div>
            <h2>{selectedEvent.title}</h2>
            <span className={`tag ${selectedEvent.severity.toLowerCase()}`}>
              {selectedEvent.severity}
            </span>
            <p>{selectedEvent.detail}</p>
            <div className="modal-meta">
              <span>
                ID <b>{selectedEvent.id}</b>
              </span>
              <span>
                Time <b>{selectedEvent.time}</b>
              </span>
              <span>
                Source <b>{selectedEvent.source}</b>
              </span>
            </div>
            <button
              className="primary"
              onClick={() => {
                setSelectedEvent(null);
                setPage("AI analysis");
              }}
            >
              Investigate with AI <ArrowRight size={16} />
            </button>
          </div>
        </div>
      )}
      {notification && (
        <div className="toast">
          <Check size={17} />
          {notification}
          <button onClick={() => setNotification("")}>
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}
function Metric({
  icon: Icon,
  color,
  label,
  value,
  change,
  trend,
}: {
  icon: typeof Shield;
  color: string;
  label: string;
  value: string;
  change: string;
  trend: string;
}) {
  return (
    <div className="metric panel">
      <div className="metric-top">
        <div className={`metric-icon ${color}`}>
          <Icon size={21} />
        </div>
        <ArrowUpRight size={17} className="metric-arrow" />
      </div>
      <p>{label}</p>
      <div className="metric-bottom">
        <strong>{value}</strong>
        <span className={trend === "up" ? "up" : ""}>{change}</span>
      </div>
    </div>
  );
}
function EventsPanel({
  events,
  onView,
  onSelect,
}: {
  events: Event[];
  onView: () => void;
  onSelect: (e: Event) => void;
}) {
  return (
    <div className="panel events-panel">
      <div className="panel-heading">
        <div>
          <h3>Recent security events</h3>
          <p>Latest simulated activity across your apps</p>
        </div>
        <button className="link-button" onClick={onView}>
          View all <ArrowRight size={15} />
        </button>
      </div>
      <div className="event-list">
        {events.map((e) => (
          <button className="event" key={e.id} onClick={() => onSelect(e)}>
            <span className={`event-dot ${e.severity.toLowerCase()}`} />
            <div>
              <b>{e.title}</b>
              <small>
                {e.source} · {e.time}
              </small>
            </div>
            <span className={`tag ${e.severity.toLowerCase()}`}>
              {e.severity}
            </span>
            <ChevronRight size={15} />
          </button>
        ))}
      </div>
    </div>
  );
}
function EventsTable({
  events,
  onSelect,
}: {
  events: Event[];
  onSelect: (e: Event) => void;
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>EVENT</th>
            <th>SOURCE</th>
            <th>SEVERITY</th>
            <th>TIME</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id} onClick={() => onSelect(e)} className="click-row">
              <td>
                <b>{e.title}</b>
                <small>{e.detail}</small>
              </td>
              <td>{e.source}</td>
              <td>
                <span className={`tag ${e.severity.toLowerCase()}`}>
                  {e.severity}
                </span>
              </td>
              <td className="mono">{e.time}</td>
              <td>
                <ChevronRight size={17} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {events.length === 0 && (
        <p className="empty">No events match your search.</p>
      )}
    </div>
  );
}
export default App;
