import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useAgentContext } from "../../context/AgentContext.jsx";
import { apiFetch } from "../../api.js";
import { EmptyState } from "../../components/ui.jsx";
import styles from "./Assessments.module.css";
import { showToast } from "../../components/ui.jsx";

const ALL_MODULES = [
  { id: "malware", name: "Malware (EICAR)", desc: "Drop EICAR test file, measure quarantine time", mitre: "T1059" },
  { id: "antitamper", name: "Anti-Tamper", desc: "Attempt to stop/kill EDR processes and services", mitre: "T1562.001" },
  { id: "lolbin", name: "LOLBin", desc: "Test Living-off-the-Land binary execution", mitre: "T1218" },
  { id: "network", name: "Network", desc: "Test outbound C2 simulation and DNS tunneling", mitre: "T1071" },
  { id: "identity", name: "Identity", desc: "Test credential access and token manipulation", mitre: "T1003" },
  { id: "reboot", name: "Reboot / Boot Gap", desc: "Test ELAM driver survival across reboot", mitre: "T1547" },
  { id: "performance", name: "Performance", desc: "Measure CPU/RAM/IO impact during assessment", mitre: "T1082" },
  { id: "falsepositive", name: "False Positive", desc: "Test benign activity classification accuracy", mitre: "T1562" },
  { id: "disable_etw", name: "Disable ETW", desc: "Disable Event Tracing for Windows providers", mitre: "T1562.002" },
  { id: "disable_amsi", name: "Disable AMSI", desc: "Attempt to disable AMSI via patching/registry", mitre: "T1562.001" },
  { id: "disable_etw_tamper", name: "Disable ETW Tamper", desc: "Advanced ETW tampering (providers, consumers, trace files)", mitre: "T1562.002" },
  { id: "unload_driver", name: "Unload Driver", desc: "Attempt to stop/disable EDR kernel drivers", mitre: "T1562.001" },
  { id: "modify_registry_policies", name: "Modify Registry Policies", desc: "Modify registry policies to disable security features", mitre: "T1112" },
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
  const { state } = useAgentContext();
  const [profile, setProfile] = useState("rapid");
  const [testType, setTestType] = useState("blackbox");
  const [durationDays, setDurationDays] = useState(1);
  const [selectedModules, setSelectedModules] = useState(ALL_MODULES.map(m => m.id));
  const [singleModule, setSingleModule] = useState("");
  const [allowReboot, setAllowReboot] = useState(false);
  const [toast, setToast] = useState(null);

  const agent = state.agents.find(a => a.hostname === hostname);

  const isAptOrBaseline = profile === "apt" || profile === "baseline";
  const isDeploymentTest = testType === "blackbox_deployment_test";

  const modulesToRun = singleModule ? [singleModule] : selectedModules;
  const canLaunch = agent && agent.status !== "offline" && modulesToRun.length > 0;

  const showToast = (nextToast) => {
    setToast(nextToast);
    setTimeout(() => setToast(null), 5000);
  };

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
        // POST /api/assessments now dispatches start_assessment to the agent
        // server-side. The browser used to send a second copy over the socket,
        // which raced the server's send and could launch the run twice. One
        // dispatch path only — and it is the one that can resolve the agent's
        // hostname correctly.
        navigate("/console");
      } else {
        const body = await res.json().catch(() => ({}));
        showToast({ tone: "error", message: body.error || `Launch failed (${res.status})` });
      }
    } catch (err) { console.error("Failed to launch", err); }
  };

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

  if (!agent) {
    return (
      <div>
        <h2>Assessments</h2>
        <EmptyState
          title="Agent not found"
          message="The selected agent is no longer available."
          action={<button className="btn-primary" onClick={() => navigate("/")}>Back to Fleet View</button>}
        />
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>Configure Assessment</h2>
        <span className={styles.count}>Target: <strong style={{ color: "var(--accent)" }}>{hostname}</strong></span>
      </header>

      {agent && (
        <p style={{ marginBottom: "var(--spacing-lg)", color: "var(--n-400)" }}>
          Discovered EDR: <strong style={{ color: "var(--accent)" }}>{agent.vendor || "Scanning..."}</strong>
        </p>
      )}

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
            Modules will be distributed across this many days with random jitter.
          </p>
        </div>
      )}

      <div className={styles.formGroup} style={{ marginTop: "var(--spacing-lg)" }}>
        <label>Module Selection</label>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--spacing-sm)" }}>
          {ALL_MODULES.map(m => (
            <label key={m.id} style={{ display: "flex", alignItems: "center", gap: "var(--spacing-xs)", padding: "var(--spacing-sm) var(--spacing-md)", border: `1px solid ${selectedModules.includes(m.id) ? "var(--accent)" : "var(--border)"}`, background: selectedModules.includes(m.id) ? "rgba(var(--accent-rgb), 0.08)" : "transparent", borderRadius: "4px", marginBottom: "var(--spacing-xs)", cursor: "pointer", transition: "all 150ms" }}>
              <input
                type="checkbox"
                checked={selectedModules.includes(m.id)}
                onChange={e => {
                  if (e.target.checked) {
                    setSelectedModules([...selectedModules, m.id]);
                  } else {
                    setSelectedModules(selectedModules.filter(id => id !== m.id));
                  }
                }}
                style={{ accentColor: "var(--accent)" }}
              />
              <span style={{ fontSize: "0.85rem", color: "var(--n-200)" }}>{m.name}</span>
              <span style={{ fontSize: "0.7rem", color: "var(--accent)", marginLeft: "var(--spacing-xs)" }}>{m.mitre}</span>
            </label>
          ))}
        </div>
      </div>

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

      {isDeploymentTest && (
        <div className={styles.formGroup} style={{ marginTop: "var(--spacing-lg)" }}>
          <label>
            <input type="checkbox" checked={allowReboot} onChange={e => setAllowReboot(e.target.checked)} style={{ marginRight: "var(--spacing-sm)" }} />
            Allow system reboot (tests ELAM boot survival)
          </label>
          <p style={{ marginTop: "var(--spacing-xs)", fontSize: "0.8rem", color: "var(--n-500)" }}>
            The agent will reboot the system to test if the EDR survives the boot gap. Requires --allow-reboot on the agent.
          </p>
        </div>
      )}

      <div style={{ marginTop: "var(--spacing-xl)", display: "flex", gap: "var(--spacing-sm)" }}>
        <button className="btn-secondary" onClick={() => navigate("/")}>Cancel</button>
        <button className="btn-primary" onClick={handleLaunch} disabled={!canLaunch}>Launch {TEST_TYPES.find(t => t.id === testType)?.name || testType} Assessment</button>
      </div>

      {toast && <div className={`toast ${toast.tone}`} onClick={() => setToast(null)}>{toast.message}</div>}
    </div>
  );
}