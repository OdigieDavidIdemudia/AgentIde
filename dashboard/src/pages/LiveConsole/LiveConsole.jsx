import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAgentContext } from '../../context/AgentContext.jsx';
import styles from './LiveConsole.module.css';

const EVENT_COLORS = {
  fingerprint:          'var(--accent)',
  heartbeat:            'var(--n-400)',
  discovery:            '#60d394',
  module_start:         '#ffd166',
  module_result:        '#06d6a0',
  assessment_done:      'var(--accent)',
  assessment_resumed:   '#ff9f1c',   // bright orange — EDR kill detected, resuming
  passive_alert:        '#ef476f',
  agent_disconnected:   '#ef476f',
  tamper_event:         '#ff0055',
  pre_scan_result:      '#c77dff',
  assessment_ready:     '#48cae4',
  report_status:        '#a8dadc',
  preflight_result:     '#a8dadc',
};

function formatPayload(payload) {
  if (!payload) return '';
  try { return JSON.stringify(payload, null, 2); }
  catch { return String(payload); }
}

export default function LiveConsole() {
  const { state, dispatch, sendCommand } = useAgentContext();
  const navigate = useNavigate();
  const bottomRef = useRef(null);

  // Pre-scan confirmation modal state
  const [preScan, setPreScan] = useState(null);   // { agentId, agents, supportedDisabling, profile, testType }
  const [selectedVendor, setSelectedVendor] = useState('none');

  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [state.events]);

  // Listen for pre_scan_result events from the agent
  useEffect(() => {
    const latest = state.events[state.events.length - 1];
    if (!latest || latest.type !== 'pre_scan_result') return;

    const p = latest.payload || {};
    const agentId = latest.agent_id;
    setPreScan({
      agentId,
      agents: p.discovered_agents || [],
      supportedDisabling: p.supported_disabling || [],
      profile: p.profile,
      testType: p.test_type,
    });
    setSelectedVendor('none');
  }, [state.events]);

  const handleConfirm = () => {
    if (!preScan) return;
    sendCommand('confirm_assessment', {
      agent_id: preScan.agentId,
      disable_vendor: selectedVendor,
    });
    setPreScan(null);
  };

  const handleAbort = () => {
    setPreScan(null);
  };

  const handleClear = () => dispatch({ type: 'CLEAR_EVENTS' });

  // Calculate ongoing assessment progress
  const ongoingAssessment = [...state.events].reverse().find(e => 
    e.type === 'module_start' || e.type === 'assessment_done' || e.type === 'assessment_ready'
  );

  let progressData = null;
  if (ongoingAssessment && ongoingAssessment.type === 'module_start') {
    const { index, total, module } = ongoingAssessment.payload || {};
    if (index && total) {
      progressData = {
        agentId: ongoingAssessment.agent_id,
        module,
        index,
        total,
        percentage: Math.round(((index - 1) / total) * 100)
      };
    }
  } else if (ongoingAssessment && ongoingAssessment.type === 'assessment_ready') {
     progressData = {
        agentId: ongoingAssessment.agent_id,
        module: 'Initializing modules...',
        index: 0,
        total: 8,
        percentage: 0
     };
  }

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>Live Console</h2>
        <span className={styles.count}>{state.events.length} events</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--spacing-sm)' }}>
          <button
            onClick={() => navigate('/')}
            style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--n-400)', padding: '4px var(--spacing-sm)', borderRadius: '4px', cursor: 'pointer', fontSize: '0.8rem', fontFamily: 'inherit' }}
          >
            ← Fleet View
          </button>
          {state.events.length > 0 && (
            <button
              onClick={handleClear}
              style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--n-400)', padding: '4px var(--spacing-sm)', borderRadius: '4px', cursor: 'pointer', fontSize: '0.8rem', fontFamily: 'inherit' }}
            >
              Clear
            </button>
          )}
        </div>
      </header>

      {/* ── Pre-Scan Confirmation Modal ──────────────────────────── */}
      {preScan && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 9999,
        }}>
          <div style={{
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: '8px', padding: 'var(--spacing-xl)',
            width: '520px', maxWidth: '95vw',
            fontFamily: 'var(--font-mono)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)', marginBottom: 'var(--spacing-lg)' }}>
              <span style={{ fontSize: '1.2rem' }}>🔍</span>
              <h3 style={{ margin: 0, fontFamily: 'var(--font-heading)', color: 'var(--n-100)' }}>
                Pre-Assessment Scan Complete
              </h3>
            </div>

            {/* Discovered agents */}
            <p style={{ color: 'var(--n-400)', fontSize: '0.85rem', marginBottom: 'var(--spacing-md)' }}>
              The endpoint was rescanned. The following security agents are currently active:
            </p>

            {preScan.agents.length === 0 ? (
              <div style={{ padding: 'var(--spacing-md)', background: 'var(--bg)', borderRadius: '4px', color: 'var(--n-500)', fontSize: '0.85rem', marginBottom: 'var(--spacing-lg)' }}>
                No security agents detected on the endpoint.
              </div>
            ) : (
              <div style={{ marginBottom: 'var(--spacing-lg)' }}>
                {preScan.agents.map((a, i) => (
                  <div key={i} style={{
                    padding: 'var(--spacing-sm) var(--spacing-md)',
                    background: 'var(--bg)',
                    border: '1px solid var(--border)',
                    borderRadius: '4px',
                    marginBottom: 'var(--spacing-xs)',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  }}>
                    <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{a.vendor}</span>
                    <span style={{ color: 'var(--n-500)', fontSize: '0.78rem' }}>
                      PID: {a.pid || 'N/A'} · {a.service_name || a.process_name || '—'}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {/* Disable selection */}
            <p style={{ color: 'var(--n-400)', fontSize: '0.85rem', marginBottom: 'var(--spacing-sm)' }}>
              Select a vendor to <strong style={{ color: '#f4a261' }}>temporarily disable</strong> before the assessment.
              It will be <strong style={{ color: '#06d6a0' }}>automatically re-enabled</strong> when tests complete.
            </p>

            <div style={{ marginBottom: 'var(--spacing-lg)' }}>
              {/* No disable option */}
              <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)', padding: 'var(--spacing-sm) var(--spacing-md)', cursor: 'pointer', borderRadius: '4px', border: `1px solid ${selectedVendor === 'none' ? 'var(--accent)' : 'var(--border)'}`, marginBottom: 'var(--spacing-xs)', background: selectedVendor === 'none' ? 'rgba(var(--accent-rgb, 0,188,140), 0.08)' : 'transparent' }}>
                <input type="radio" name="vendor" value="none" checked={selectedVendor === 'none'} onChange={() => setSelectedVendor('none')} style={{ accentColor: 'var(--accent)' }} />
                <span style={{ color: 'var(--n-200)', fontSize: '0.88rem' }}>Don't disable anything — run as-is</span>
              </label>

              {/* One option per discovered agent that is in the supported disable list */}
              {preScan.agents.filter(a =>
                preScan.supportedDisabling.some(s => s.toLowerCase().includes(a.vendor.toLowerCase()) || a.vendor.toLowerCase().includes(s.toLowerCase()))
              ).map((a, i) => (
                <label key={i} style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)', padding: 'var(--spacing-sm) var(--spacing-md)', cursor: 'pointer', borderRadius: '4px', border: `1px solid ${selectedVendor === a.vendor ? '#f4a261' : 'var(--border)'}`, marginBottom: 'var(--spacing-xs)', background: selectedVendor === a.vendor ? 'rgba(244,162,97,0.08)' : 'transparent' }}>
                  <input type="radio" name="vendor" value={a.vendor} checked={selectedVendor === a.vendor} onChange={() => setSelectedVendor(a.vendor)} style={{ accentColor: '#f4a261' }} />
                  <span style={{ color: '#f4a261', fontSize: '0.88rem', fontWeight: 600 }}>Disable {a.vendor}</span>
                  <span style={{ color: 'var(--n-500)', fontSize: '0.78rem', marginLeft: 'auto' }}>will be re-enabled after</span>
                </label>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 'var(--spacing-sm)', justifyContent: 'flex-end' }}>
              <button
                onClick={handleAbort}
                style={{ padding: 'var(--spacing-sm) var(--spacing-lg)', background: 'transparent', border: '1px solid var(--border)', color: 'var(--n-400)', borderRadius: '4px', cursor: 'pointer', fontFamily: 'inherit' }}
              >
                Abort Assessment
              </button>
              <button
                onClick={handleConfirm}
                style={{ padding: 'var(--spacing-sm) var(--spacing-lg)', background: 'var(--accent)', border: 'none', color: '#000', borderRadius: '4px', cursor: 'pointer', fontFamily: 'inherit', fontWeight: 700 }}
              >
                Proceed →
              </button>
            </div>
          </div>
        </div>
      )}

      {progressData && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '4px', padding: 'var(--spacing-md)', marginBottom: 'var(--spacing-md)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--spacing-sm)' }}>
            <span style={{ fontSize: '0.88rem', color: 'var(--n-400)' }}>
              Ongoing Assessment: <strong style={{ color: 'var(--accent)' }}>{progressData.agentId}</strong>
            </span>
            <span style={{ fontSize: '0.88rem', color: 'var(--n-300)' }}>
              Module {progressData.index} of {progressData.total}
            </span>
          </div>
          <div style={{ background: 'var(--bg-body)', height: '8px', borderRadius: '4px', overflow: 'hidden' }}>
            <div style={{ 
              background: 'var(--accent)', 
              height: '100%', 
              width: `${progressData.percentage}%`,
              transition: 'width 0.4s ease'
            }} />
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--n-500)', marginTop: 'var(--spacing-xs)', textTransform: 'uppercase' }}>
            Running: {progressData.module}
          </div>
        </div>
      )}

      {state.events.length === 0 ? (
        <div className={styles.emptyState}>
          <h3>No active stream</h3>
          <p>Launch an assessment from the Fleet View to view real-time telemetry here.</p>
          <button
            className="btn-primary"
            style={{ marginTop: 'var(--spacing-lg)' }}
            onClick={() => navigate('/')}
          >
            Go to Fleet View
          </button>
        </div>
      ) : (
        <div className={styles.terminal}>
          {state.events.map((ev, i) => (
            <div key={i} className={styles.eventRow}>
              <span className={styles.ts}>{ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : ''}</span>
              <span className={styles.type} style={{ color: EVENT_COLORS[ev.type] || 'var(--n-200)' }}>
                [{ev.type}]
              </span>
              <span className={styles.agent}>{ev.agent_id}</span>
              {ev.payload && (
                <pre className={styles.payload}>{formatPayload(ev.payload)}</pre>
              )}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      )}
    </div>
  );
}
