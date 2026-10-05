import React, { useMemo, useState } from "react";
import { useAgentContext } from "../../context/AgentContext.jsx";
import { apiFetch } from "../../api.js";
import styles from "./Reports.module.css";

// ─── Static session findings from the Cortex XDR assessment ──────────────────
// These are pre-seeded because they were observed manually before the
// automated tamper_event / module_result pipeline was in place.
const SESSION_FINDINGS = [
  {
    id: "FIND-001", agent_id: "TestVPC", category: "blackbox",
    phase: "Installation", result: "BLOCKED",
    title: "Cortex XDR silently killed unsigned installer process",
    detail: "agentide.exe --install returned zero output. Process terminated before service registration.",
    mitre: "T1562.001", timestamp: "2026-09-23T19:31:00+01:00",
    edr_action: "PROCESS_KILL",
  },
  {
    id: "FIND-002", agent_id: "TestVPC", category: "blackbox",
    phase: "Persistence / Boot Survival", result: "BLOCKED",
    title: "ELAM driver quarantined agent binary on system restart",
    detail: "Unsigned binary quarantined and removed from disk during Windows boot phase. All 3 resilience layers negated.",
    mitre: "T1547", timestamp: "2026-09-23T19:39:00+01:00",
    edr_action: "QUARANTINE_FILE",
  },
  {
    id: "FIND-003", agent_id: "TestVPC", category: "blackbox",
    phase: "Certificate Trust", result: "BLOCKED",
    title: "Cortex XDR blocked cert import into TrustedPublisher store",
    detail: "Import-Certificate denied with E_ACCESSDENIED (0x80070005) even as NT AUTHORITY\\SYSTEM.",
    mitre: "T1553.004", timestamp: "2026-09-23T20:18:00+01:00",
    edr_action: "BLOCK_CERTIFICATE_STORE_WRITE",
  },
  {
    id: "FIND-004", agent_id: "TestVPC", category: "whitebox",
    phase: "Discovery", result: "PASS",
    title: "AgentIde successfully discovered Cortex XDR (CyveraService)",
    detail: "Vendor name, PID, and service name extracted and reported to dashboard in real time.",
    mitre: "T1518.001", timestamp: "2026-09-23T14:00:00+01:00",
    edr_action: "N/A",
  },
  {
    id: "FIND-005", agent_id: "TestVPC", category: "internal",
    phase: "Fingerprinting", result: "FIXED",
    title: "OS version misreported: Windows 10 Pro instead of Windows 11 Pro",
    detail: "ProductName registry key returns Windows 10 for Windows 11. Fixed by checking CurrentBuild >= 22000.",
    mitre: "N/A", timestamp: "2026-09-23T13:00:00+01:00",
    edr_action: "N/A",
  },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function resultBadge(result, styles) {
  const map = {
    PASS: styles.badgePASS, FAIL: styles.badgeFAIL,
    BLOCKED: styles.badgeBLOCKED, FIXED: styles.badgeFIXED,
    INFO: styles.badgeINFO, AGENT_RECOVERED: styles.badgePASS,
    BLOCKED_BY_EDR: styles.badgeBLOCKED, // EDR killed the process — technique was blocked
    TIMEOUT: styles.badgeFAIL, ERROR: styles.badgeFAIL,
  };
  return <span className={`${styles.badge} ${map[result] || styles.badgeINFO}`}>{result}</span>;
}

function typeBadge(category, styles) {
  const map = {
    whitebox: [styles.typeWhitebox, "WB"],
    blackbox: [styles.typeBlackbox, "BB"],
    internal: [styles.typeInternal, "INT"],
  };
  const [cls, label] = map[category] || [styles.typeInternal, category || "—"];
  return <span className={`${styles.typeBadge} ${cls}`}>{label}</span>;
}

function fmtTime(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
}

// ─── Component ───────────────────────────────────────────────────────────────

function extractTactic(mitreId) {
  if (!mitreId || mitreId === "N/A" || mitreId === "Unknown") return null;
  if (mitreId.startsWith("T1562") || mitreId.startsWith("T1553")) return "Defense Evasion";
  if (mitreId.startsWith("T1547")) return "Persistence / Boot Survival";
  if (mitreId.startsWith("T1518") || mitreId.startsWith("T1082")) return "Discovery";
  if (mitreId.startsWith("T1059")) return "Execution";
  if (mitreId.startsWith("T1055")) return "Privilege Escalation";
  if (mitreId.startsWith("T1003") || mitreId.startsWith("T1110")) return "Credential Access";
  if (mitreId.startsWith("T1071") || mitreId.startsWith("T1090")) return "Command and Control";
  return "Other Tactics";
}

export default function Reports() {
  const { state } = useAgentContext();
  const [activeAgent, setActiveAgent] = useState(null);
  const [remediations, setRemediations] = useState({});
  const [loadingRemediation, setLoadingRemediation] = useState({});

  // Collect unique agent IDs from live events + session findings
  const agentIds = useMemo(() => {
    const ids = new Set(SESSION_FINDINGS.map(f => f.agent_id));
    state.events.forEach(e => { if (e.agent_id) ids.add(e.agent_id); });
    state.agents.forEach(a => { if (a.hostname) ids.add(a.hostname); });
    return [...ids];
  }, [state.events, state.agents]);

  const selected = activeAgent || agentIds[0] || null;

  // Live module results for selected agent
  const moduleResults = useMemo(() =>
    state.events.filter(e => e.type === "module_result" && e.agent_id === selected),
    [state.events, selected]
  );

  // Live tamper events for selected agent
  const tamperEvents = useMemo(() =>
    state.events.filter(e => e.type === "tamper_event" && e.agent_id === selected),
    [state.events, selected]
  );

  // Latest assessment_done for summary
  const assessmentDone = useMemo(() => {
    const matches = state.events.filter(e => e.type === "assessment_done" && e.agent_id === selected);
    return matches[matches.length - 1] || null;
  }, [state.events, selected]);

  // Session findings for selected agent
  const sessionFindings = SESSION_FINDINGS.filter(f => f.agent_id === selected);

  // Summary counts
  const totalModules = moduleResults.length;
  const passedModules = moduleResults.filter(e => e.payload?.passed).length;
  const failedModules = totalModules - passedModules;
  const totalTampers = tamperEvents.length;

  // MITRE Calculation
  const mitreStats = useMemo(() => {
    const stats = {};
    const addStat = (mitreId, isPass) => {
      const tactic = extractTactic(mitreId);
      if (!tactic) return;
      if (!stats[tactic]) stats[tactic] = { total: 0, passed: 0 };
      stats[tactic].total += 1;
      if (isPass) stats[tactic].passed += 1;
    };
    
    sessionFindings.forEach(f => addStat(f.mitre, f.result === "BLOCKED"));
    moduleResults.forEach(m => {
        const isPassed = m.payload?.passed || m.payload?.result === 'BLOCKED_BY_EDR';
        addStat(m.payload?.mitre, isPassed);
      });
    return stats;
  }, [sessionFindings, moduleResults]);

  if (agentIds.length === 0) {
    return (
      <div className={styles.container}>
        <header className={styles.header}><h2>Reports</h2></header>
        <div className={styles.emptyState}>
          <h3>No assessment data yet</h3>
          <p>Complete an assessment from the Fleet View to generate a report here.</p>
        </div>
      </div>
    );
  }

  const [isGenerating, setIsGenerating] = useState(false);

  const getReportPayload = () => ({
    agent: selected,
    exported_at: new Date().toISOString(),
    summary: { totalModules, passedModules, failedModules, totalTampers },
    deployment_integrity: [
      ...sessionFindings.filter(f => f.result === 'BLOCKED'),
      ...tamperEvents.map(e => ({ ...e.payload, timestamp: e.timestamp, result: 'AGENT_RECOVERED' }))
    ],
    module_results: moduleResults.map(e => ({ ...e.payload, timestamp: e.timestamp })),
    session_findings: sessionFindings.filter(f => f.result !== 'BLOCKED'),
  });

  const handleExport = () => {
    const report = getReportPayload();
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agentide-report-${selected}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    try {
      const response = await apiFetch('/api/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(getReportPayload())
      });
      const data = await response.json();
      if (data.error) throw new Error(data.error);
      
      const blob = new Blob([data.html], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `agentide-standalone-report-${selected}-${Date.now()}.html`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Report generation failed: ${err.message}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleGenerateRemediation = async (findingId, findingData) => {
    setLoadingRemediation(prev => ({ ...prev, [findingId]: true }));
    try {
      const res = await apiFetch('/api/generate-remediation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(findingData)
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setRemediations(prev => ({ ...prev, [findingId]: data.remediation }));
    } catch (err) {
      alert("Failed to generate remediation: " + err.message);
    } finally {
      setLoadingRemediation(prev => ({ ...prev, [findingId]: false }));
    }
  };

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <div className={styles.headerLeft}>
          <h2>Reports</h2>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px' }}>
          <button
            onClick={handleGenerateReport}
            disabled={isGenerating}
            style={{ background: 'var(--accent)', border: 'none', color: '#fff', padding: '6px var(--spacing-md)', borderRadius: '4px', cursor: isGenerating ? 'wait' : 'pointer', fontSize: '0.82rem', fontFamily: 'inherit', fontWeight: 'bold' }}
          >
            {isGenerating ? "Generating..." : "Generate Report"}
          </button>
          <button
            onClick={handleExport}
            style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--n-300)', padding: '6px var(--spacing-md)', borderRadius: '4px', cursor: 'pointer', fontSize: '0.82rem', fontFamily: 'inherit' }}
          >
            ↓ Export JSON
          </button>
        </div>
      </header>

      {/* Agent tabs */}
      <div className={styles.agentTabs}>
        {agentIds.map(id => (
          <button
            key={id}
            className={`${styles.tab} ${selected === id ? styles.tabActive : ""}`}
            onClick={() => setActiveAgent(id)}
          >{id}</button>
        ))}
      </div>

      {/* Summary row */}
      <div className={styles.summary}>
        <div className={styles.summaryCard}>
          <div className={styles.summaryLabel}>Modules Run</div>
          <div className={`${styles.summaryValue} ${styles.neutral}`}>{totalModules || assessmentDone?.payload?.total_modules || "—"}</div>
        </div>
        <div className={styles.summaryCard}>
          <div className={styles.summaryLabel}>Passed</div>
          <div className={`${styles.summaryValue} ${styles.pass}`}>{passedModules || assessmentDone?.payload?.passed || "—"}</div>
        </div>
        <div className={styles.summaryCard}>
          <div className={styles.summaryLabel}>Failed / Blocked</div>
          <div className={`${styles.summaryValue} ${styles.fail}`}>{failedModules || assessmentDone?.payload?.failed || "—"}</div>
        </div>
        <div className={styles.summaryCard}>
          <div className={styles.summaryLabel}>Kill / Recovery Events</div>
          <div className={`${styles.summaryValue} ${totalTampers > 0 ? styles.fail : styles.neutral}`}>{totalTampers}</div>
        </div>
      </div>

      {/* MITRE ATT&CK Gap Analysis */}
      {Object.keys(mitreStats).length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>MITRE ATT&CK Gap Analysis</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', padding: '16px', background: 'var(--n-900)', borderRadius: '8px', border: '1px solid var(--border)' }}>
            {Object.entries(mitreStats).map(([tactic, stat]) => {
              const pct = Math.round((stat.passed / stat.total) * 100);
              return (
                <div key={tactic} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
                    <span style={{ color: 'var(--n-100)' }}>{tactic}</span>
                    <span style={{ color: pct === 100 ? 'var(--pass)' : pct > 50 ? 'var(--warn)' : 'var(--fail)' }}>{pct}% Blocked</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'var(--n-800)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: pct === 100 ? 'var(--pass)' : pct > 50 ? 'var(--warn)' : 'var(--fail)' }} />
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--n-500)' }}>{stat.passed} / {stat.total} Modules Blocked</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Deployment Integrity — tamper events */}
      {(tamperEvents.length > 0 || sessionFindings.filter(f => f.result === "BLOCKED").length > 0) && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Deployment Integrity (Blackbox)</div>

          {/* Static session findings — BLOCKED */}
          {sessionFindings.filter(f => f.result === "BLOCKED").map(f => (
            <div key={f.id} className={`${styles.findingRow} ${styles.tamperRow}`}>
              <div>{resultBadge(f.result, styles)}</div>
              <div style={{ flex: 1 }}>
                <div className={styles.findingTitle}>{f.title}</div>
                <div className={styles.findingDetail}>{f.detail}</div>
                <div className={styles.mitre} style={{ marginTop: 4 }}>EDR Action: {f.edr_action} · MITRE: {f.mitre}</div>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {typeBadge(f.category, styles)}
                <span className={styles.mitre}>{f.phase}</span>
              </div>
              <div className={styles.mitre}>{fmtTime(f.timestamp)}</div>
            </div>
          ))}

          {/* Live tamper events */}
          {tamperEvents.map((e, i) => (
            <div key={i} className={`${styles.findingRow} ${styles.tamperRow}`}>
              <div>{resultBadge("AGENT_RECOVERED", styles)}</div>
              <div style={{ flex: 1 }}>
                <div className={styles.findingTitle}>Agent killed and recovered</div>
                <div className={styles.findingDetail}>
                  Downtime: {e.payload?.downtime_str || `${e.payload?.downtime_sec}s`} · Recovery #{e.payload?.recovery_num} · Total kills: {e.payload?.total_kills}
                </div>
                <div className={styles.mitre}>Killed: {fmtTime(e.payload?.killed_at)} → Recovered: {fmtTime(e.payload?.recovered_at)}</div>
              </div>
              <div>{typeBadge("blackbox", styles)}</div>
              <div className={styles.mitre}>{fmtTime(e.timestamp)}</div>
            </div>
          ))}
        </div>
      )}

      {/* Assessment Modules */}
      {moduleResults.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Assessment Modules</div>
          {moduleResults.map((e, i) => {
            const isGap = !e.payload?.passed; // EDR Failed to block
            const fid = `mod-${i}`;
            return (
              <div key={i} style={{ display: 'flex', flexDirection: 'column' }}>
                <div className={styles.findingRow}>
                  <div>{resultBadge(e.payload?.result || (e.payload?.passed ? "PASS" : "FAIL"), styles)}</div>
                  <div style={{ flex: 1 }}>
                    <div className={styles.findingTitle}>{e.payload?.module}</div>
                    <div className={styles.findingDetail}>{e.payload?.detail}</div>
                    {e.payload?.duration_ms && <div className={styles.mitre} style={{marginTop:2}}>Duration: {e.payload.duration_ms}ms</div>}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: 'flex-end' }}>
                    {typeBadge(e.payload?.test_type, styles)}
                    {isGap && !remediations[fid] && (
                      <button 
                        onClick={() => handleGenerateRemediation(fid, { module: e.payload?.module, detail: e.payload?.detail, mitre: e.payload?.mitre })}
                        disabled={loadingRemediation[fid]}
                        style={{ marginTop: 4, background: 'var(--accent)', border: 'none', color: '#fff', padding: '4px 8px', borderRadius: '4px', cursor: loadingRemediation[fid] ? 'wait' : 'pointer', fontSize: '0.75rem', fontWeight: 'bold' }}
                      >
                        {loadingRemediation[fid] ? "Generating..." : "Generate Remediation"}
                      </button>
                    )}
                  </div>
                  <div className={styles.mitre}>{fmtTime(e.timestamp)}</div>
                </div>
                
                {/* AI Remediation Output */}
                {remediations[fid] && (
                  <div style={{ margin: '0 16px 16px 16px', padding: '16px', background: '#1e293b', borderLeft: '4px solid var(--accent)', borderRadius: '4px', color: '#f8fafc', fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>
                    <div style={{ fontWeight: 'bold', marginBottom: '8px', color: 'var(--accent)' }}>AI-Generated Remediation Strategy</div>
                    {remediations[fid]}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Discovery & other session findings */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Session Findings</div>
        {sessionFindings.filter(f => f.result !== "BLOCKED").map(f => {
          const isGap = f.result === "PASS"; // e.g. discovery succeeded (EDR missed it)
          return (
            <div key={f.id} style={{ display: 'flex', flexDirection: 'column' }}>
              <div className={styles.findingRow}>
                <div>{resultBadge(f.result, styles)}</div>
                <div style={{ flex: 1 }}>
                  <div className={styles.findingTitle}>{f.title}</div>
                  <div className={styles.findingDetail}>{f.detail}</div>
                  {f.mitre !== "N/A" && <div className={styles.mitre} style={{marginTop:4}}>MITRE: {f.mitre}</div>}
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: 'flex-end' }}>
                  {typeBadge(f.category, styles)}
                  <span className={styles.mitre}>{f.phase}</span>
                  {isGap && !remediations[f.id] && (
                    <button 
                      onClick={() => handleGenerateRemediation(f.id, { module: f.title, detail: f.detail, mitre: f.mitre })}
                      disabled={loadingRemediation[f.id]}
                      style={{ marginTop: 4, background: 'var(--accent)', border: 'none', color: '#fff', padding: '4px 8px', borderRadius: '4px', cursor: loadingRemediation[f.id] ? 'wait' : 'pointer', fontSize: '0.75rem', fontWeight: 'bold' }}
                    >
                      {loadingRemediation[f.id] ? "Generating..." : "Generate Remediation"}
                    </button>
                  )}
                </div>
                <div className={styles.mitre}>{fmtTime(f.timestamp)}</div>
              </div>
              
              {/* AI Remediation Output */}
              {remediations[f.id] && (
                <div style={{ margin: '0 16px 16px 16px', padding: '16px', background: '#1e293b', borderLeft: '4px solid var(--accent)', borderRadius: '4px', color: '#f8fafc', fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>
                  <div style={{ fontWeight: 'bold', marginBottom: '8px', color: 'var(--accent)' }}>AI-Generated Remediation Strategy</div>
                  {remediations[f.id]}
                </div>
              )}
            </div>
          );
        })}

        {sessionFindings.filter(f => f.result !== "BLOCKED").length === 0 && moduleResults.length === 0 && (
          <div style={{ padding: "var(--spacing-lg)", color: "var(--n-500)", textAlign: "center", fontSize: "0.83rem" }}>
            No findings yet for {selected}. Launch an assessment to populate this view.
          </div>
        )}
      </div>
    </div>
  );
}
