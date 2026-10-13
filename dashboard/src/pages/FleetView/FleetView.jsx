import React from 'react';
import { useAgentContext } from '../../context/AgentContext.jsx';
import { apiFetch, apiUrl } from '../../api.js';
import { useNavigate } from 'react-router-dom';
import styles from './FleetView.module.css';
import { EmptyState, ConfirmModal } from '../../components/ui.jsx';
import AgentContextMenu from '../../components/AgentContextMenu.jsx';

// Mirrors compareVersions in server/agent-update.js — compares dotted numeric
// versions component-wise so 0.10.0 correctly sorts above 0.9.0.
function compareVersions(a, b) {
  const pa = String(a || '0').split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b || '0').split('.').map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

export default function FleetView() {
  const { state, dispatch } = useAgentContext();
  const navigate = useNavigate();

  const [pendingDelete, setPendingDelete] = React.useState(null);
  const [latestVersion, setLatestVersion] = React.useState(null);
  // Right-click menu state: which agent it targets and where it was opened.
  const [menu, setMenu] = React.useState(null); // { hostname, x, y }
  const [actionStatus, setActionStatus] = React.useState({});
  const [pendingCommand, setPendingCommand] = React.useState(null); // { hostname, command }
  const [configAgent, setConfigAgent] = React.useState(null);

  // Run a management command (restart / update / uninstall) against an agent.
  // This is the same REST surface the Agent Management page uses, so both
  // entry points stay in sync.
  const runCommand = async (hostname, command) => {
    setActionStatus((prev) => ({ ...prev, [hostname]: `${command}...` }));
    try {
      const res = await apiFetch(
        apiUrl(`/api/agents/${hostname}/${command}`),
        { method: 'POST' }
      );
      if (res.ok) {
        setActionStatus((prev) => ({ ...prev, [hostname]: `${command} sent` }));
      } else {
        let msg = 'Unknown error';
        try {
          const body = await res.json();
          msg = body.error || msg;
        } catch { /* non-JSON error body */ }
        setActionStatus((prev) => ({ ...prev, [hostname]: `${command} failed: ${msg}` }));
      }
    } catch (err) {
      setActionStatus((prev) => ({ ...prev, [hostname]: `${command} error: ${err.message}` }));
    }
    setTimeout(() => setActionStatus((prev) => ({ ...prev, [hostname]: null })), 6000);
  };

  const viewConfig = async (hostname) => {
    try {
      const res = await apiFetch(apiUrl(`/api/agents/${hostname}/config`));
      if (res.ok) {
        setConfigAgent({ hostname, config: await res.json() });
      } else {
        setActionStatus((prev) => ({ ...prev, [hostname]: 'Could not load config' }));
      }
    } catch (err) {
      setActionStatus((prev) => ({ ...prev, [hostname]: `Config error: ${err.message}` }));
    }
  };

  // Destructive/impactful commands go through a confirmation; restart and
  // config are read-mostly and run immediately.
  const requestCommand = (hostname, command) => {
    if (command === 'uninstall' || command === 'update' || command === 'restart') {
      setPendingCommand({ hostname, command });
    } else {
      command(hostname);
    }
  };

  const confirmCommand = () => {
    if (pendingCommand) runCommand(pendingCommand.hostname, pendingCommand.command);
    setPendingCommand(null);
  };

  // Fetch the build the dashboard is currently serving so lagging agents can
  // be flagged before an operator has to push an update to find out.
  React.useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await apiFetch(apiUrl('/api/agent/version'));
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled && data && data.version) setLatestVersion(data.version);
      } catch {
        // Version endpoint unavailable — the column still shows what agents report.
      }
    };
    load();
    const id = setInterval(load, 30000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const handleDelete = async () => {
    const hostname = pendingDelete;
    setPendingDelete(null);
    if (!hostname) return;
    try {
      const res = await apiFetch(apiUrl(`/api/agents/${hostname}`), {
        method: 'DELETE'
      });
      if (res.ok) {
        dispatch({ type: 'REMOVE_AGENT', payload: { hostname } });
      } else {
        console.error('Failed to delete agent');
      }
    } catch (err) {
      console.error('Delete request failed:', err);
    }
  };

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>Fleet View</h2>
        <div className={styles.status}>
          {state.connectionStatus === 'connected' ? (
            <span className={styles.online}>● Server Connected</span>
          ) : (
            <span className={styles.offline}>○ Server Disconnected</span>
          )}
        </div>
      </header>

      {pendingDelete && (
        <ConfirmModal
          title="Delete agent?"
          message={`Are you sure you want to delete the agent "${pendingDelete}" and all its history?`}
          confirmLabel="Delete"
          danger
          onCancel={() => setPendingDelete(null)}
          onConfirm={handleDelete}
        />
      )}

      {pendingCommand && (
        <ConfirmModal
          title={`Confirm ${pendingCommand.command}`}
          message={
            pendingCommand.command === 'uninstall'
              ? `This will uninstall the AgentIde service from "${pendingCommand.hostname}" and remove it from the fleet. Continue?`
              : pendingCommand.command === 'update'
                ? `This will push the current build to "${pendingCommand.hostname}". The agent will restart as part of the update. Continue?`
                : `This will restart the AgentIde service on "${pendingCommand.hostname}". Continue?`
          }
          confirmLabel={
            pendingCommand.command === 'uninstall' ? 'Uninstall'
              : pendingCommand.command === 'update' ? 'Push Update'
                : 'Restart'
          }
          danger={pendingCommand.command === 'uninstall'}
          onCancel={() => setPendingCommand(null)}
          onConfirm={confirmCommand}
        />
      )}

      {menu && (
        <AgentContextMenu
          x={menu.x}
          y={menu.y}
          title={menu.hostname}
          status={actionStatus[menu.hostname] || undefined}
          items={(() => {
            const agent = state.agents.find((a) => a.hostname === menu.hostname);
            if (!agent) return [];
            const online = agent.status === 'online';
            const outdated = latestVersion && agent.agent_version
              && compareVersions(latestVersion, agent.agent_version) > 0;
            return [
              {
                label: 'Launch Assessment',
                disabled: !online,
                hint: agent.agent_version ? `v${agent.agent_version}` : undefined,
                onSelect: () => navigate(`/assessment/${agent.hostname}`),
              },
              { dividerBefore: true },
              { label: 'View Config', onSelect: () => viewConfig(agent.hostname) },
              {
                label: 'Restart Agent',
                hint: 'restart',
                disabled: !online,
                onSelect: () => requestCommand(agent.hostname, 'restart'),
              },
              {
                label: outdated ? `Update to v${latestVersion}` : 'Push Update',
                hint: 'update',
                disabled: !online || !latestVersion,
                onSelect: () => requestCommand(agent.hostname, 'update'),
              },
              { dividerBefore: true },
              {
                label: 'Uninstall Agent',
                hint: 'uninstall',
                danger: true,
                disabled: !online,
                onSelect: () => requestCommand(agent.hostname, 'uninstall'),
              },
            ].filter((it) => it.label);
          })()}
          onClose={() => setMenu(null)}
        />
      )}

      {configAgent && (
        <div
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100,
          }}
          onClick={() => setConfigAgent(null)}
        >
          <div
            className="card"
            style={{ maxWidth: 720, maxHeight: '80vh', overflow: 'auto', minWidth: 420 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3>Agent Configuration: {configAgent.hostname}</h3>
            <pre style={{ fontSize: 'var(--font-xs)', overflowX: 'auto' }}>
              {JSON.stringify(configAgent.config, null, 2)}
            </pre>
            <div style={{ marginTop: 'var(--spacing-md)', textAlign: 'right' }}>
              <button className="btn-secondary" onClick={() => setConfigAgent(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
      {state.agents.length === 0 ? (
        <EmptyState
          title="No agents connected"
          message="Install AgentIde on a virtual machine to get started."
          action={<div className={styles.installCommand}><code>.\agentide.exe --dashboard wss://192.168.x.x:8080 --mode passive</code></div>}
        />
      ) : (
        <div className="card">
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>OS</th>
                <th>OS Version</th>
                <th>Discovered Agent</th>
                <th>Agent Version</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {state.agents.map((agent) => {
                // `vendors` holds every match; fall back to the single `vendor`
                // column for rows reported by older agents.
                const vendors = (agent.vendors && agent.vendors.length > 0)
                  ? agent.vendors
                  : (agent.vendor ? [agent.vendor] : []);
                // Once the agent has reported at least once, an empty vendor
                // list is a real result ("nothing detected"), not an in-flight
                // scan. Say so, instead of showing "Scanning..." forever.
                const hasReported = Boolean(agent.agent_version || agent.last_seen);
                const outdated = latestVersion && agent.agent_version
                  && compareVersions(latestVersion, agent.agent_version) > 0;
                const isMenuTarget = menu && menu.hostname === agent.hostname;
                return (
                <tr
                  key={agent.hostname}
                  className={`${styles.rowActionable} ${isMenuTarget ? styles.rowSelected : ''}`}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setMenu({ hostname: agent.hostname, x: e.clientX, y: e.clientY });
                  }}
                >
                  <td className={styles.hostname}>{agent.hostname}</td>
                  <td className={styles.mono}>{agent.ip}</td>
                  <td>{agent.os || 'Unknown'}</td>
                  <td>{agent.os_version || <span className={styles.noVendor}>Unknown</span>}</td>
                  <td>
                    {vendors.length > 0 ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {vendors.map((v) => (
                          <span key={v} className={styles.vendorBadge}>{v}</span>
                        ))}
                      </div>
                    ) : (
                      <span className={styles.noVendor}>
                        {hasReported ? 'None detected' : 'Scanning...'}
                      </span>
                    )}
                  </td>
                  <td className={styles.mono}>
                    {agent.agent_version ? (
                      <span>
                        v{agent.agent_version}
                        {outdated && (
                          <span
                            className={styles.noVendor}
                            style={{ marginLeft: '6px' }}
                            title={`Agent is behind the served build v${latestVersion}`}
                          >
                            ↑ v{latestVersion}
                          </span>
                        )}
                      </span>
                    ) : (
                      <span className={styles.noVendor}>Unknown</span>
                    )}
                  </td>
                  <td>
                    <span className={`${styles.statusBadge} ${styles[agent.status] || ''}`}>
                      {agent.status.toUpperCase()}
                    </span>
                  </td>
                  <td className={styles.actions} style={{ display: 'flex', gap: '8px' }}>
                    <button 
                      className="btn-primary"
                      onClick={() => navigate(`/assessment/${agent.hostname}`)}
                    >
                      Launch Assessment
                    </button>
                    <button 
                      className="btn-danger"
                      style={{ padding: '0 var(--spacing-sm)' }}
                      onClick={() => setPendingDelete(agent.hostname)}
                    >
                      ✕
                    </button>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
