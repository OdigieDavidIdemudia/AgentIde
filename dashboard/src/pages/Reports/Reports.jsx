import React, { useEffect, useMemo, useState } from "react";
import { useAgentContext } from "../../context/AgentContext.jsx";
import { apiFetch } from "../../api.js";
import styles from "./Reports.module.css";
import { Toast } from "../../components/ui.jsx";

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
    live: [styles.typeInternal, "LIVE"],
  };
  const [cls, label] = map[category] || [styles.typeInternal, category || "—"];
  return <span className={`${styles.typeBadge} ${cls}`}>{label}</span>;
}

// Results that are informational, not a pass/fail verdict. A module that
// acks with INFO (remote_control restarting itself, agent_update applying a
// build) is reporting an action taken, not a control that was tested - so it
// must never be counted or rendered as a failure.
const NON_VERDICT_RESULTS = new Set(["INFO", "SKIPPED", "BLOCKED", "FIXED", "AGENT_RECOVERED"]);

// Derive the display result from a payload. Prefers the module's own `result`
// field when present, because `passed` is only a boolean and cannot express
// BLOCKED_BY_EDR, TIMEOUT, ERROR or INFO.
function deriveResult(payload) {
  if (!payload) return "INFO";
  const r = payload.result;
  if (r) return r;
  if (payload.passed === true) return "PASS";
  if (payload.passed === false) return "FAIL";
  return "INFO";
}

// The verdict a row contributes to the pass/fail tally. Only real test
// outcomes count; an INFO acknowledgement must not drag the score down.
function isVerdictPass(result) {
  return result === "PASS" || result === "BLOCKED" || result === "BLOCKED_BY_EDR" || result === "AGENT_RECOVERED";
}

// Turn a raw event payload into one readable sentence. Falls back to the
// event type instead of JSON.stringify(payload), which used to dump a raw
// object into the detail column whenever a module sent no `detail` field.
function humaniseDetail(payload) {
  if (!payload) return "";
  if (payload.detail) return payload.detail;

  const parts = [];
  const add = (k, v) => {
    if (v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0)) {
      parts.push(`${k.replace(/_/g, " ")}: ${Array.isArray(v) ? v.join(", ") : v}`);
    }
  };
  add("result", payload.result);
  add("status", payload.status);
  add("vendor", payload.vendor);
  add("mitre", payload.mitre);
  add("duration", payload.elapsed_ms != null ? `${payload.elapsed_ms}ms` : null);
  add("version", payload.version);

  // Nothing human-readable in the payload at all.
  if (parts.length === 0) return "No additional detail reported.";

  // Cap the length so a large payload cannot blow out the row.
  const text = parts.join(" · ");
  return text.length > 220 ? `${text.slice(0, 217)}…` : text;
}

function fmtTime(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
}

// ─── Finding presentation ────────────────────────────────────────────────────

const SEVERITY_COLOURS = {
  CRITICAL: { bg: '#7f1d1d', fg: '#ffffff' },
  HIGH: { bg: '#b42318', fg: '#ffffff' },
  MEDIUM: { bg: '#9a6700', fg: '#ffffff' },
  LOW: { bg: '#1a7f37', fg: '#ffffff' },
  INFO: { bg: '#57606a', fg: '#ffffff' },
};

function SeverityBadge({ severity }) {
  const c = SEVERITY_COLOURS[severity] || SEVERITY_COLOURS.INFO;
  return (
    <span style={{
      background: c.bg, color: c.fg, padding: '1px 8px', borderRadius: '3px',
      fontSize: '0.7rem', fontWeight: 'bold', letterSpacing: '0.04em',
      whiteSpace: 'nowrap',
    }}>
      {severity}
    </span>
  );
}

// Counts up front so a reader sees the shape of the assessment before
// scrolling, which is the convention in the reference report format.
function SeveritySummary({ counts }) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  return (
    <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '14px' }}>
      {order.map((k) => (
        <div key={k} style={{
          display: 'flex', alignItems: 'center', gap: '6px',
          padding: '4px 10px', borderRadius: '4px',
          background: 'var(--surface)', border: '1px solid var(--border)',
        }}>
          <SeverityBadge severity={k} />
          <span style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>{counts[k] ?? 0}</span>
        </div>
      ))}
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div style={{ marginTop: '10px' }}>
      <div style={{
        display: 'inline-block', background: 'var(--accent)', color: '#fff',
        padding: '2px 8px', fontSize: '0.7rem', fontWeight: 'bold',
        letterSpacing: '0.04em', textTransform: 'uppercase',
        borderRadius: '3px 3px 0 0', marginBottom: '4px',
      }}>
        {label}
      </div>
      <div style={{
        padding: '8px 12px', background: 'var(--surface)',
        borderLeft: '3px solid var(--accent)', borderRadius: '0 4px 4px 0',
        fontSize: '0.85rem', color: 'var(--text-primary)',
      }}>
        {children}
      </div>
    </div>
  );
}

// Execution metadata belongs with the observation, not as loose columns.
function MetaLine({ finding, artifacts }) {
  const bits = [];
  if (finding.executedAt) bits.push(`Executed ${fmtTime(finding.executedAt)}`);
  if (finding.elapsedMs) bits.push(`${finding.elapsedMs}ms`);
  if (finding.result) bits.push(`Verdict ${finding.result}`);
  return (
    <div style={{ marginTop: '6px' }}>
      <div className={styles.mitre}>{bits.join('  ·  ')}</div>
      {artifacts.length > 0 && (
        <div className={styles.mitre} style={{ marginTop: '4px' }}>
          Files created:
          {artifacts.map((a, i) => (
            <code key={i} style={{ display: 'block', wordBreak: 'break-all', color: 'var(--text-secondary)' }}>{a}</code>
          ))}
        </div>
      )}
    </div>
  );
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
  // Which assessment run is being viewed. Without this the page merged every
  // run for an agent into one undifferentiated list, so there was no way to
  // tell which assessment you were looking at.
  const [runs, setRuns] = useState([]);
  const [activeRunId, setActiveRunId] = useState(null);
  const [runResults, setRunResults] = useState([]);
  // Structured findings from /findings: each carries a deterministic severity
  // plus observation / impact / recommendation. Null until loaded, and null
  // again if the run has no results.
  const [runFindings, setRunFindings] = useState(null);
  const [loadingRun, setLoadingRun] = useState(false);
  const [remediations, setRemediations] = useState({});
  const [loadingRemediation, setLoadingRemediation] = useState({});
  const [isGenerating, setIsGenerating] = useState(false);
  const [toast, setToast] = useState(null);
  const showToast = (nextToast) => {
    setToast(nextToast);
    setTimeout(() => setToast(null), 5000);
  };

  // Collect unique agent IDs from live events and agents
  const agentIds = useMemo(() => {
    const ids = new Set();
    state.events.forEach(e => { if (e.agent_id) ids.add(e.agent_id); });
    state.agents.forEach(a => { if (a.hostname) ids.add(a.hostname); });
    return [...ids];
  }, [state.events, state.agents]);

  const selected = activeAgent || agentIds[0] || null;

  // Load the assessment runs for the selected agent and default to the newest.
  // Sourced from the database rather than live WebSocket events so the page
  // survives a dashboard restart and always shows a complete, labelled run.
  useEffect(() => {
    if (!selected) {
      setRuns([]);
      setRunResults([]);
      setActiveRunId(null);
      return;
    }
    let cancelled = false;
    setLoadingRun(true);
    apiFetch(`/api/agents/${encodeURIComponent(selected)}/assessments`)
      .then((res) => (res.ok ? res.json() : []))
      .then((rows) => {
        if (cancelled) return;
        const list = Array.isArray(rows) ? rows : [];
        setRuns(list);
        setActiveRunId((prev) => {
          if (prev && list.some((r) => r.id === prev)) return prev;
          return list.length ? list[0].id : null;
        });
      })
      .catch(() => {
        if (!cancelled) setRuns([]);
      })
      .finally(() => {
        if (!cancelled) setLoadingRun(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  // Load the structured findings for the chosen run.
  //
  // This replaces the raw /results rows: the server now derives severity,
  // observation, impact and recommendation deterministically, so the report
  // does not depend on an LLM inventing a severity per run.
  useEffect(() => {
    if (!activeRunId) {
      setRunResults([]);
      setRunFindings(null);
      return;
    }
    let cancelled = false;
    setLoadingRun(true);
    apiFetch(`/api/assessments/${activeRunId}/findings`)
      .then((res) => (res.ok ? res.json() : null))
      .then((payload) => {
        if (cancelled) return;
        if (!payload) {
          setRunFindings(null);
          setRunResults([]);
          return;
        }
        setRunFindings(payload);
        setRunResults(Array.isArray(payload.findings) ? payload.findings : []);
      })
      .catch(() => {
        if (!cancelled) {
          setRunFindings(null);
          setRunResults([]);
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingRun(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeRunId]);

  const activeRun = runs.find((r) => r.id === activeRunId) || null;

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

  // Session findings for selected agent (from live events)
  const sessionFindings = useMemo(() => {
    // Get findings from module_result and other event types
    const findings = state.events
      .filter(e => e.agent_id === selected && 
        (e.type === "module_result" || e.type === "assessment_done" || e.type === "preflight_result" || e.type === "pre_scan_result"))
      .map(e => ({
        id: e.payload?.module || e.type,
        agent_id: selected,
        category: e.payload?.test_type || "live",
        phase: e.payload?.module ? "Assessment" : "System",
        result: deriveResult(e.payload),
        title: e.payload?.module || e.type,
        detail: humaniseDetail(e.payload),
        mitre: e.payload?.mitre || "N/A",
        artifacts: e.payload?.artifacts || [],
        timestamp: e.timestamp,
        edr_action: e.payload?.result,
      }));
    return findings;
  }, [state.events, selected]);

  // Summary counts come from the selected run's persisted results, so they
  // describe exactly one labelled assessment instead of every run ever made.
  // Only real verdicts count: an INFO ack (a restart, a self-update) is not a
  // module that was tested, so including it would post a phantom failure.
  const runVerdicts = runResults.filter((r) => !NON_VERDICT_RESULTS.has(r.action));
  const totalModules = runVerdicts.length;
  const passedModules = runVerdicts.filter((r) => isVerdictPass(r.action)).length;
  const failedModules = runVerdicts.filter((r) => !isVerdictPass(r.action)).length;
  const totalTampers = tamperEvents.length;

  // MITRE Calculation - use module results and tamper events
  const mitreStats = useMemo(() => {
    const stats = {};
    const addStat = (mitreId, isPass) => {
      const tactic = extractTactic(mitreId);
      if (!tactic) return;
      if (!stats[tactic]) stats[tactic] = { total: 0, passed: 0 };
      stats[tactic].total += 1;
      if (isPass) stats[tactic].passed += 1;
    };
    
    // Use the selected run's results for MITRE stats. Informational acks are
    // skipped so they cannot register as a failed technique.
    runVerdicts.forEach((r) => {
      addStat(r.mitre, isVerdictPass(r.action));
    });
    tamperEvents.forEach(e => {
      addStat(e.payload?.mitre, true); // tamper events are BLOCKED_BY_EDR = pass
    });
    return stats;
  }, [runResults, tamperEvents]);

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

  const getReportPayload = () => {
    // Collect all assessments for this agent to build scope
    const allAssessments = state.events
      .filter(e => e.agent_id === selected && e.type === 'assessment_done')
      .map(e => e.payload);
    
    const testTypes = [...new Set(allAssessments.map(a => a.test_type).filter(Boolean))];
    const profiles = [...new Set(allAssessments.map(a => a.profile).filter(Boolean))];
    // Modules actually executed in this run, taken from the persisted results.
    const executedModules = [...new Set(runResults.map(r => r.module_name).filter(Boolean))];
    const vendors = [...new Set(state.events.filter(e => e.agent_id === selected && e.payload?.vendor).map(e => e.payload.vendor))];
    const dateRange = activeRun?.started_at
      ? { first: activeRun.started_at, last: activeRun.completed_at || activeRun.started_at }
      : null;

    return {
      agent: selected,
      assessment_id: activeRunId,
      exported_at: new Date().toISOString(),
      // Scope is reported from what the run actually did. It previously fell
      // back to hardcoded values ('Microsoft Defender', all 8 modules) when
      // the data was missing, so an export could describe an assessment that
      // never happened - and those invented values were fed straight into the
      // AI report prompt. Unknown is now reported as unknown.
      scope: {
        profile: activeRun?.profile ?? null,
        test_types: activeRun?.test_type ? [activeRun.test_type] : [],
        modules_requested: Array.isArray(activeRun?.modules) ? activeRun.modules : [],
        modules_tested: executedModules,
        target_vendors: vendors,
        vendor_detected: vendors.length > 0 ? vendors[0] : null,
        started_at: activeRun?.started_at ?? null,
        completed_at: activeRun?.completed_at ?? null,
        status: activeRun?.status ?? null,
        score: activeRun?.score != null ? Math.round(activeRun.score) : null,
      },
      summary: {
        totalModules,
        passedModules,
        failedModules,
        totalTampers,
        score: activeRun?.score != null ? Math.round(activeRun.score) : null,
      },
      deployment_integrity: [
        ...sessionFindings.filter(f => f.result === 'BLOCKED' || f.result === 'BLOCKED_BY_EDR'),
        ...tamperEvents.map(e => ({ ...e.payload, timestamp: e.timestamp, result: 'AGENT_RECOVERED' }))
      ],
      // Persisted results, not the volatile live-event buffer. Exporting from
      // live events meant a page reload produced an empty module_results for a
      // run whose results were visible on screen.
      module_results: runResults.map(r => ({
        module: r.module_name,
        result: r.action,
        passed: r.passed,
        detail: r.detail,
        mitre: r.mitre,
        duration_ms: r.elapsed_ms,
        test_type: r.test_type,
        notes: r.notes,
        artifacts: r.artifacts,
        timestamp: r.recorded_at,
      })),
      session_findings: sessionFindings.filter(f => f.result !== 'BLOCKED' && f.result !== 'BLOCKED_BY_EDR'),
    };
  };

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

  const handleExportMarkdown = async () => {
    try {
      const report = getReportPayload();
      const response = await apiFetch('/api/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...report, format: 'markdown' })
      });
      const data = await response.json();
      if (data.error) throw new Error(data.error);
      
      const blob = new Blob([data.markdown], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `agentide-report-${selected}-${Date.now()}.md`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      showToast({ tone: 'error', message: `Markdown export failed: ${err.message}` });
    }
  };

  const handleExportDocx = async () => {
    try {
      const report = getReportPayload();
      const response = await apiFetch('/api/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...report, format: 'docx' })
      });
      const data = await response.json();
      if (data.error) throw new Error(data.error);
      
      const blob = new Blob([data.docx], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `agentide-report-${selected}-${Date.now()}.docx`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      showToast({ tone: 'error', message: `Docx export failed: ${err.message}` });
    }
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
      showToast({ tone: 'error', message: `Report generation failed: ${err.message}` });
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
      showToast({ tone: 'error', message: `Failed to generate remediation: ${err.message}` });
    } finally {
      setLoadingRemediation(prev => ({ ...prev, [findingId]: false }));
    }
  };

  return (
    <div className={styles.container}>
      <Toast message={toast?.message} tone={toast?.tone} />
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
            {isGenerating ? "Generating..." : "Generate HTML Report"}
          </button>
          <button
            onClick={handleExportMarkdown}
            style={{ background: 'var(--accent)', border: 'none', color: '#fff', padding: '6px var(--spacing-md)', borderRadius: '4px', cursor: 'pointer', fontSize: '0.82rem', fontFamily: 'inherit', fontWeight: 'bold' }}
          >
            Export Markdown
          </button>
          <button
            onClick={handleExportDocx}
            style={{ background: 'var(--accent)', border: 'none', color: '#fff', padding: '6px var(--spacing-md)', borderRadius: '4px', cursor: 'pointer', fontSize: '0.82rem', fontFamily: 'inherit', fontWeight: 'bold' }}
          >
            Export Docx
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

      {/* Which run are we looking at? Without this the page merged every run
          for the agent together and there was no way to tell which assessment
          you were reading. */}
      <div className={styles.agentTabs} role="group" aria-label="Assessment run">
        {loadingRun && runs.length === 0 && <span style={{ padding: '8px', color: 'var(--text-secondary)' }}>Loading runs…</span>}
        {!loadingRun && runs.length === 0 && (
          <span style={{ padding: '8px', color: 'var(--text-secondary)' }}>No assessments recorded for this agent yet.</span>
        )}
        {runs.map((r) => {
          const when = r.started_at ? new Date(r.started_at) : null;
          const label = when
            ? `${when.toLocaleDateString()} ${when.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
            : 'unknown time';
          const isActive = activeRunId === r.id;
          return (
            <button
              key={r.id}
              role="radio"
              aria-checked={isActive}
              className={`${styles.tab} ${isActive ? styles.tabActive : ''}`}
              onClick={() => setActiveRunId(r.id)}
              style={r.status !== 'completed' ? { opacity: 0.75 } : undefined}
              title={`Run ${r.id.slice(0, 8)} — ${r.status} — profile ${r.profile || 'unknown'} — ${r.result_count ?? 0} results`}
            >
              {label} · {r.profile || 'unknown'}
              {r.status !== 'completed' && (
                <button
                  style={{
                    marginLeft: 6,
                    padding: '2px 8px',
                    fontSize: '0.7em',
                    background: '#ef476f',
                    border: 'none',
                    color: '#fff',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontFamily: 'var(--font-mono)',
                  }}
                  onClick={() => sendCommand('stop_assessment', { assessment_id: r.id })}
                  title="Stop this running assessment"
                >
                  Stop
                </button>
              )}
            </button>
          );
        })}
      </div>

      {/* What exactly this run was */}
      {activeRun && (
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '8px 20px',
            padding: '10px 12px',
            marginBottom: '4px',
            background: 'var(--surface)',
            borderLeft: '3px solid var(--accent)',
            borderRadius: '4px',
            fontSize: '0.82rem',
            color: 'var(--text-secondary)',
          }}
        >
          <span><strong style={{ color: 'var(--text-primary)' }}>Run</strong> {activeRun.id.slice(0, 8)}</span>
          <span><strong style={{ color: 'var(--text-primary)' }}>Agent</strong> {activeRun.hostname || selected}</span>
          <span><strong style={{ color: 'var(--text-primary)' }}>Profile</strong> {activeRun.profile || 'unknown'}</span>
          <span><strong style={{ color: 'var(--text-primary)' }}>Test type</strong> {activeRun.test_type || 'unknown'}</span>
          <span><strong style={{ color: 'var(--text-primary)' }}>Started</strong> {activeRun.started_at ? new Date(activeRun.started_at).toLocaleString() : '—'}</span>
          {activeRun.completed_at && (
            <span><strong style={{ color: 'var(--text-primary)' }}>Finished</strong> {new Date(activeRun.completed_at).toLocaleString()}</span>
          )}
          <span>
            <strong style={{ color: 'var(--text-primary)' }}>Status</strong>{' '}
            <span style={{ color: activeRun.status === 'completed' ? 'var(--accent)' : '#ef476f' }}>
              {activeRun.status}
            </span>
          </span>
          {activeRun.modules?.length > 0 && (
            <span><strong style={{ color: 'var(--text-primary)' }}>Modules</strong> {activeRun.modules.join(', ')}</span>
          )}
        </div>
      )}

      {/* Summary row */}
      <div className={styles.summary}>
        <div className={styles.summaryCard}>
          <div className={styles.summaryLabel}>Modules Run</div>
          <div className={`${styles.summaryValue} ${styles.neutral}`}>{totalModules || "—"}</div>
        </div>
        <div className={styles.summaryCard}>
          <div className={styles.summaryLabel}>Passed</div>
          <div className={`${styles.summaryValue} ${styles.pass}`}>{totalModules ? passedModules : "—"}</div>
        </div>
        <div className={styles.summaryCard}>
          <div className={styles.summaryLabel}>Failed / Blocked</div>
          <div className={`${styles.summaryValue} ${styles.fail}`}>{totalModules ? failedModules : "—"}</div>
        </div>
        <div className={styles.summaryCard}>
          <div className={styles.summaryLabel}>Score</div>
          <div className={`${styles.summaryValue} ${styles.neutral}`}>
            {activeRun?.score != null ? Math.round(activeRun.score) : "—"}
          </div>
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
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', padding: '16px', background: 'var(--surface)', borderRadius: '4px', border: '1px solid var(--border)' }}>
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
      {(tamperEvents.length > 0 || sessionFindings.filter(f => f.result === "BLOCKED" || f.result === "BLOCKED_BY_EDR").length > 0) && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Deployment Integrity (Blackbox)</div>

          {/* Live module results showing BLOCKED_BY_EDR */}
          {sessionFindings.filter(f => f.result === "BLOCKED" || f.result === "BLOCKED_BY_EDR").map(f => (
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

      {/* Findings — structured per the consulting format: numbered, severity-rated,
          each with Observation / Impact / Recommendation. Severity comes from the
          server taxonomy, not from a model. */}
      {runResults.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Findings</div>

          {runFindings?.counts && <SeveritySummary counts={runFindings.counts} />}

          {runResults.map((f) => {
            const fid = `finding-${f.index}`;
            const artifacts = Array.isArray(f.artifacts) ? f.artifacts : [];
            return (
              <div key={`${f.module}-${f.index}`} className={styles.findingCard}>
                <div className={styles.findingHeader}>
                  <span className={styles.findingIndex}>{f.index}.</span>
                  <span className={styles.findingTitle}>{f.title || f.module}</span>
                  <SeverityBadge severity={f.severity} />
                  {f.mitre && <span className={styles.mitre}>MITRE: {f.mitre}</span>}
                  <span className={styles.mitre}>{resultBadge(f.result, styles)}</span>
                </div>

                <Field label="Observation">
                  <div>{f.observation}</div>
                  <MetaLine finding={f} artifacts={artifacts} />
                </Field>

                <Field label="Impact">
                  <div>{f.impact}</div>
                </Field>

                <Field label="Recommendation">
                  <div>{f.recommendation}</div>
                </Field>

                {/* The taxonomy's recommendation is the deterministic baseline.
                    The LLM option stays available for a bespoke write-up but is
                    explicitly secondary so it cannot be mistaken for the finding. */}
                {f.isFinding && !remediations[fid] && (
                  <button
                    onClick={() => handleGenerateRemediation(fid, { module: f.module, detail: f.observation, mitre: f.mitre, severity: f.severity })}
                    disabled={loadingRemediation[fid]}
                    style={{
                      alignSelf: 'flex-start', background: 'transparent',
                      border: '1px solid var(--accent)', color: 'var(--accent)',
                      padding: '4px 10px', borderRadius: '4px',
                      cursor: loadingRemediation[fid] ? 'wait' : 'pointer',
                      fontSize: '0.75rem', fontWeight: 'bold',
                    }}
                  >
                    {loadingRemediation[fid] ? 'Generating…' : 'Draft tailored guidance (AI)'}
                  </button>
                )}

                {remediations[fid] && (
                  <div style={{
                    padding: '12px', background: 'var(--surface)',
                    borderLeft: '4px solid var(--accent)', borderRadius: '4px',
                    color: 'var(--text-primary)', fontSize: '0.85rem', whiteSpace: 'pre-wrap',
                  }}>
                    <div style={{ fontWeight: 'bold', marginBottom: '8px', color: 'var(--accent)' }}>
                      AI-drafted guidance (review before use)
                    </div>
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
        {sessionFindings.filter(f => f.result !== "BLOCKED" && f.result !== "BLOCKED_BY_EDR").map(f => {
          // Inverted on purpose, unlike module results. These are discovery findings:
          // a PASS means the discovery itself succeeded, i.e. the EDR did NOT
          // flag the activity — which is the gap worth remediating.
          const isGap = f.result === "PASS";
          return (
            <div key={f.id} style={{ display: 'flex', flexDirection: 'column' }}>
              <div className={styles.findingRow}>
                <div>{resultBadge(f.result, styles)}</div>
                <div style={{ flex: 1 }}>
                  <div className={styles.findingTitle}>{f.title}</div>
                  <div className={styles.findingDetail}>{f.detail}</div>
                  {f.mitre !== "N/A" && <div className={styles.mitre} style={{marginTop:4}}>MITRE: {f.mitre}</div>}
                  {f.artifacts?.length > 0 && (
                    <div className={styles.mitre} style={{ marginTop: 4 }}>
                      Files created:
                      {f.artifacts.map((a, ai) => (
                        <code key={ai} style={{ display: 'block', wordBreak: 'break-all', color: 'var(--text-secondary)' }}>{a}</code>
                      ))}
                    </div>
                  )}
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
                <div style={{ margin: '0 16px 16px 16px', padding: '16px', background: 'var(--surface)', borderLeft: '4px solid var(--accent)', borderRadius: '4px', color: 'var(--text-primary)', fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>
                  <div style={{ fontWeight: 'bold', marginBottom: '8px', color: 'var(--accent)' }}>AI-Generated Remediation Strategy</div>
                  {remediations[f.id]}
                </div>
              )}
            </div>
          );
        })}

        {sessionFindings.filter(f => f.result !== "BLOCKED" && f.result !== "BLOCKED_BY_EDR").length === 0 && moduleResults.length === 0 && (
          <div style={{ padding: "var(--spacing-lg)", color: "var(--n-500)", textAlign: "center", fontSize: "0.83rem" }}>
            No findings yet for {selected}. Launch an assessment to populate this view.
          </div>
        )}
      </div>
    </div>
  );
}