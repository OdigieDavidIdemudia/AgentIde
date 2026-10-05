import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useAgentContext } from "../../context/AgentContext.jsx";
import { apiFetch } from "../../api.js";
import styles from "./Assessments.module.css";

export default function Assessments() {
  const { hostname } = useParams();
  const navigate = useNavigate();
  const { state, sendCommand } = useAgentContext();
  const [profile, setProfile] = useState("rapid");
  const [testType, setTestType] = useState("blackbox");

  const agent = state.agents.find(a => a.hostname === hostname);

  if (!hostname) {
    return (
      <div>
        <h2>Assessments</h2>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "var(--spacing-2xl)", border: "1px dashed var(--border)", borderRadius: "4px", textAlign: "center", marginTop: "var(--spacing-xl)" }}>
          <h3>No agent selected</h3>
          <p style={{ margin: "var(--spacing-md) 0" }}>Select a specific agent from the Fleet View to configure an assessment.</p>
          <button className="btn-primary" onClick={() => navigate("/")}>Go to Fleet View</button>
        </div>
      </div>
    );
  }

  const handleLaunch = async () => {
    try {
      const res = await apiFetch(`/api/assessments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_id: agent?.id || hostname, profile, test_type: testType, duration_days: 1, modules: ["malware","lolbin","network","identity","antitamper","reboot","falsepositive","performance"] })
      });
      if (res.ok) {
        sendCommand("start_assessment", { agent_id: hostname, profile, test_type: testType });
        navigate("/console");
      }
    } catch (err) { console.error("Failed to launch", err); }
  };

  const isWhitebox = testType === "whitebox";

  return (
    <div className={styles.container}>
      <header className={styles.header}><h2>Configure Assessment</h2></header>
      <div className="card">
        <h3>Target: <span style={{ color: "var(--accent)" }}>{hostname}</span></h3>
        {agent && <p style={{ marginBottom: "var(--spacing-lg)", color: "var(--n-400)" }}>Discovered EDR: <strong style={{ color: "var(--accent)" }}>{agent.vendor || "Scanning..."}</strong></p>}

        <div className={styles.formGroup}>
          <label>Test Category</label>
          <div style={{ display: "flex", gap: "var(--spacing-md)", marginTop: "var(--spacing-xs)" }}>
            {["blackbox", "whitebox"].map(t => (
              <button key={t} onClick={() => setTestType(t)} style={{ padding: "var(--spacing-sm) var(--spacing-lg)", border: `1px solid ${testType === t ? "var(--accent)" : "var(--border)"}`, background: testType === t ? "var(--accent)" : "transparent", color: testType === t ? "#000" : "var(--n-300)", borderRadius: "4px", cursor: "pointer", fontFamily: "inherit", fontWeight: testType === t ? "700" : "400", textTransform: "capitalize", transition: "all 150ms" }}>{t}</button>
            ))}
          </div>
          <p style={{ marginTop: "var(--spacing-xs)", fontSize: "0.8rem", color: "var(--n-500)" }}>
            {isWhitebox ? "Whitebox: Agent pre-provisioned and allowlisted in EDR. Tests behavioral detection fidelity." : "Blackbox: No EDR pre-authorization. Tests autonomous prevention and deployment survival."}
          </p>
        </div>

        <div className={styles.formGroup} style={{ marginTop: "var(--spacing-lg)" }}>
          <label>Assessment Profile</label>
          <select value={profile} onChange={e => setProfile(e.target.value)} className={styles.select}>
            <option value="rapid">Rapid-Fire (All modules immediately)</option>
            <option value="apt">Low &amp; Slow APT (Over 1 Day)</option>
            <option value="baseline">Performance Baseline Only</option>
          </select>
        </div>

        <div style={{ marginTop: "var(--spacing-xl)", display: "flex", gap: "var(--spacing-sm)" }}>
          <button className="btn-secondary" onClick={() => navigate("/")}>Cancel</button>
          <button className="btn-primary" onClick={handleLaunch}>Launch {isWhitebox ? "Whitebox" : "Blackbox"} Assessment</button>
        </div>
      </div>
    </div>
  );
}
