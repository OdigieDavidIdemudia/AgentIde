import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useAgentContext } from "../../context/AgentContext.jsx";
import { apiFetch, buildStartAssessment } from "../../api.js";
import styles from "./Assessments.module.css";
import { EmptyState, Toast } from "../../components/ui.jsx";

const ALL_MODULES = [
  { id: "malware", name: "Malware (EICAR)", desc: "Drop EICAR test file, measure quarantine time", mitre: "T1059" },
  { id: "antitamper", name: "Anti-Tamper", desc: "Attempt to stop/kill EDR processes and services", mitre: "T1562.001" },
  { id: "lolbin", name: "LOLBin", desc: "Test Living-off-the-Land binary execution", mitre: "T1218" },
  { id: "network", name: "Network", desc: "Test outbound C2 simulation and DNS tunneling", mitre: "T1071" },
  { id: "identity", name: "Identity", desc: "Test credential access and token manipulation", mitre: "T1003" },
  { id: "reboot", name: "Reboot / Boot Gap", desc: "Test ELAM driver survival across reboot", mitre: "T1547" },
  { id: "performance", name: "Performance", desc: "Measure CPU/RAM/IO impact during assessment", mitre: "N/A" },
  { id: "falsepositive", name: "False Positive", desc: "Test benign activity classification accuracy", mitre: "N/A" },
];

const TEST_TYPES = [
  { id: "blackbox", name: "Blackbox", desc: "No EDR pre-authorization. Tests autonomous prevention and deployment survival." },
  { id: "whitebox", name: "Whitebox", desc: "Agent pre-provisioned and allowlisted in EDR. Tests behavioral detection fidelity." },
  { id: "blackbox_deployment_test", name: "Deployment Test", desc: "Full deployment survival test including install, reboot, and persistence." },
];

const PROFILES = [
  { id: "rapid", name: "Rapid-Fire", desc: "All modules run back-to-back immediately" },
  { id: "apt", name: "Low & Slow APT", desc: "Modules distributed across N day(s) with random jitter" },
  { id: "baseline", name: "Performance Baseline", desc: "CPU/RAM/network monitoring only for N day(s)" },
];

export default function Assessments() {
  const { hostname } = useParams();
  const navigate = useNavigate();
  const { state, sendCommand } = useAgentContext();
  const [profile, setProfile] = useState("rapid");
  const [testType, setTestType] = useState("blackbox");
  const [durationDays, setDurationDays] = useState(1);
  const [selectedModules, setSelectedModules] = useState(ALL_MODULES.map(m => m.id));
  const [singleModule, setSingleModule] = useState("");
  const [allowReboot, setAllowReboot] = useState(false);
  const [toast, setToast] = useState(null);
  const showToast = (next) => {
    setToast(next);
    setTimeout(() => setToast(null), 5000);
  };

  const agent = state.agents.find(a => a.hostname === hostname);

  if (!hostname) {
    return (
      <div>
        <h2>Assessments</h2>
        <EmptyState
          title="No agent selected"
          message="Select a specific agent from the Fleet View to configure an assessment."
          action={<button className="btn-primary" onClick={() => navigate("/")}>Go to Fleet View</button>}
        />
      </div>
    );
  }

  const isAptOrBaseline = profile === "apt" || profile === "baseline";
  const isDeploymentTest = testType === "blackbox_deployment_test";

  const handleLaunch = async () => {
    try {
      const res = await apiFetch(`/api/assessments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          agent_id: agent?.id || hostname, 
          profile, 
          test_type: testType, 
          duration_days: isAptOrBaseline ? durationDays : 1, 
          modules: modulesToRun,
          allow_reboot: allowReboot
        })
      });
      if (res.ok) {
        // Every operator choice must travel with the command. Previously only
        // profile and test_type were sent, so the agent always ran all modules
        // at its own startup -days and its own reboot flag, while the DB and
        // the report claimed the dashboard's selection. That mismatch is fixed
        // now; keep this list in step with the agent's start_assessment handler.
        sendCommand(buildStartAssessment({
          hostname,
          profile,
          testType,
          modules: modulesToRun,
          days: isAptOrBaseline ? durationDays : 1,
          allowReboot,
        }));
        navigate("/console");
      } else {
        const body = await res.json().catch(() => ({}));
        showToast({ tone: "error", message: body.error || `Launch failed (${res.status})` });
      }
    } catch (err) { console.error("Failed to launch", err); }
  };

  const isWhitebox = testType === "whitebox";
  const modulesToRun = singleModule ? [singleModule] : selectedModules;
  const canLaunch = agent && agent.status !== "offline" && modulesToRun.length > 0;

  return (
    <div className={styles.container}>
      <header className={styles.header}><h2>Configure Assessment</h2></header>
      <div className="card">
        <h3>Target: <span style={{ color: "var(--accent)" }}>{hostname}</span></h3>
        {agent && <p style={{ marginBottom: "var(--spacing-lg)", color: "var(--n-400)" }}>Discovered EDR: <strong style={{ color: "var(--accent)" }}>{agent.vendor || "Scanning..."}</strong></p>}

        <div className={styles.formGroup}>
          <label>Test Category</label>
          <div style={{ display: "flex", gap: "var(--spacing-md)", marginTop: "var(--spacing-xs)", flexWrap: "wrap" }}>
            {TEST_TYPES.map(t => (
              <button key={t.id} onClick={() => setTestType(t.id)} style={{ padding: "var(--spacing-sm) var(--spacing-lg)", border: `1px solid ${testType === t.id ? "var(--accent)" : "var(--border)"}`, background: testType === t.id ? "var(--accent)" : "transparent", color: testType === t.id ? "#000" : "var(--n-300)", borderRadius: "4px", cursor: "pointer", fontFamily: "inherit", fontWeight: testType === t.id ? "700" : "400", textTransform: "capitalize", transition: "all 150ms", minWidth: "140px" }}>{t.name}</button>
            ))}
          </div>
          <p style={{ marginTop: "var(--spacing-xs)", fontSize: "0.8rem", color: "var(--n-500)" }}>
            {TEST_TYPES.find(t => t.id === testType)?.desc}
          </p>
        </div>

        <div className={styles.formGroup} style={{ marginTop: "var(--spacing-lg)" }}>
          <label>Assessment Profile</label>
          <select value={profile} onChange={e => setProfile(e.target.value)} className={styles.select}>
            {PROFILES.map(p => <option key={p.id} value={p.id}>{p.name} — {p.desc}</option>)}
          </select>
        </div>

        {isAptOrBaseline && (
          <div className={styles.formGroup} style={{ marginTop: "var(--spacing-lg)" }}>
            <label>Duration (Days)</label>
            <input type="number" min="1" max="30" value={durationDays} onChange={e => setDurationDays(parseInt(e.target.value) || 1)} className={styles.input} style={{ width: "100px" }} />
            <p style={{ marginTop: "var(--spacing-xs)", fontSize: "0.8rem", color: "var(--n-500)" }}>
              {profile === "apt" ? "Modules will be spread across this many days with random jitter." : "Performance monitoring only for this duration."}
            </p>
          </div>
        )}

        <div className={styles.formGroup} style={{ marginTop: "var(--spacing-lg)" }}>
          <label>Module Selection</label>
          <div style={{ display: "flex", gap: "var(--spacing-sm)", marginBottom: "var(--spacing-sm)" }}>
            <button type="button" onClick={() => setSelectedModules(ALL_MODULES.map(m => m.id))} className="btn-secondary" style={{ fontSize: "0.8rem" }}>Select All</button>
            <button type="button" onClick={() => setSelectedModules([])} className="btn-secondary" style={{ fontSize: "0.8rem" }}>Clear All</button>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "var(--spacing-sm)" }}>
            {ALL_MODULES.map(m => (
              <label key={m.id} style={{ display: "flex", alignItems: "flex-start", gap: "var(--spacing-sm)", padding: "var(--spacing-sm)", border: "1px solid var(--border)", borderRadius: "4px", cursor: "pointer", background: selectedModules.includes(m.id) ? "rgba(var(--accent-rgb, 0,188,140), 0.08)" : "transparent" }}>
                <input type="checkbox" checked={selectedModules.includes(m.id)} onChange={e => setSelectedModules(prev => e.target.checked ? [...prev, m.id] : prev.filter(x => x !== m.id))} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, color: "var(--n-100)" }}>{m.name}</div>
                  <div style={{ fontSize: "0.75rem", color: "var(--n-500)" }}>{m.desc}</div>
                  <div style={{ fontSize: "0.7rem", color: "var(--n-600)", marginTop: "2px" }}>MITRE: {m.mitre}</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        {isDeploymentTest && (
          <div className={styles.formGroup} style={{ marginTop: "var(--spacing-lg)" }}>
            <label>
              <input type="checkbox" checked={allowReboot} onChange={e => setAllowReboot(e.target.checked)} style={{ marginRight: "var(--spacing-sm)" }} />
              Allow system reboot (tests ELAM boot survival)
            </label>
            <p style={{ marginTop: "var(--spacing-xs)", fontSize: "0.8rem", color: "var(--n-500)" }}>
              The agent will reboot the system to test if the EDR survives the boot gap. This consent is sent with the assessment and applies to this run only — the agent's own --allow-reboot flag is not required.
            </p>
          </div>
        )}

        {!singleModule && !isDeploymentTest && (
          <div className={styles.formGroup} style={{ marginTop: "var(--spacing-lg)" }}>
            <label>Run Single Module (optional)</label>
            <select value={singleModule} onChange={e => setSingleModule(e.target.value)} className={styles.select}>
              <option value="">— Select a module to run only that one —</option>
              {ALL_MODULES.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}
            </select>
            <p style={{ marginTop: "var(--spacing-xs)", fontSize: "0.8rem", color: "var(--n-500)" }}>
              Overrides the module selection above. Useful for targeted testing.
            </p>
          </div>
        )}

        <div style={{ marginTop: "var(--spacing-xl)", display: "flex", gap: "var(--spacing-sm)" }}>
          <button className="btn-secondary" onClick={() => navigate("/")}>Cancel</button>
          <button className="btn-primary" onClick={handleLaunch} disabled={!canLaunch}>Launch {TEST_TYPES.find(t => t.id === testType)?.name || testType} Assessment</button>
        </div>
      </div>
      {toast && <Toast tone={toast.tone} message={toast.message} />}
    </div>
  );
}