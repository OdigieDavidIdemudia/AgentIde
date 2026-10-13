import React, { useState, useEffect } from "react";
import { useAgentContext } from "../../context/AgentContext.jsx";
import { apiFetch } from "../../api.js";
import styles from "./AgentManagement.module.css";
import { ConfirmModal } from "../../components/ui.jsx";

export default function AgentManagement() {
  const { state, dispatch } = useAgentContext();
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [actionStatus, setActionStatus] = useState({});
  const [pendingAction, setPendingAction] = useState(null);

  useEffect(() => {
    loadAgents();
  }, []);

  const loadAgents = async () => {
    try {
      const res = await apiFetch(`/api/agents`);
      if (res.ok) {
        const data = await res.json();
        setAgents(data);
      }
    } catch (err) {
      console.error("Failed to load agents", err);
    } finally {
      setLoading(false);
    }
  };

  const requestAction = (hostname, action) => {
    setPendingAction({ hostname, action });
  };

  const handleAction = async (hostname, action) => {
    setPendingAction(null);
    setActionStatus(prev => ({ ...prev, [hostname]: `${action}...` }));
    try {
      const res = await apiFetch(`/api/agents/${hostname}/${action}`, { method: "POST" });
      if (res.ok) {
        setActionStatus(prev => ({ ...prev, [hostname]: `${action} succeeded` }));
        loadAgents();
      } else {
        const err = await res.json();
        setActionStatus(prev => ({ ...prev, [hostname]: `Failed: ${err.error || "Unknown error"}` }));
      }
    } catch (err) {
      setActionStatus(prev => ({ ...prev, [hostname]: `Error: ${err.message}` }));
    }
    setTimeout(() => setActionStatus(prev => ({ ...prev, [hostname]: null })), 5000);
  };

  const handleViewConfig = async (hostname) => {
    try {
      const res = await apiFetch(`/api/agents/${hostname}/config`);
      if (res.ok) {
        const config = await res.json();
        setSelectedAgent({ hostname, config });
      }
    } catch (err) {
      console.error("Failed to load config", err);
    }
  };

  const handleCloseConfig = () => setSelectedAgent(null);

  if (loading) {
    return <div className={styles.loading}>Loading agents...</div>;
  }

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>Agent Management</h2>
        <button className="btn-secondary" onClick={loadAgents}>Refresh</button>
      </header>

      {agents.length === 0 ? (
        <div className={styles.emptyState}>
          <h3>No agents registered</h3>
          <p>Agents will appear here once they connect to the dashboard.</p>
        </div>
      ) : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Hostname</th>
                <th>OS</th>
                <th>OS Version</th>
                <th>EDR Vendor</th>
                <th>Status</th>
                <th>Mode</th>
                <th>Last Seen</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {agents.map(agent => (
                <tr key={agent.hostname}>
                  <td style={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}>{agent.hostname}</td>
                  <td>{agent.os || 'Unknown'}</td>
                  <td>{agent.os_version || <span style={{ color: "var(--n-500)" }}>Unknown</span>}</td>
                  <td>{agent.vendor || <span style={{ color: "var(--n-500)" }}>Unknown</span>}</td>
                  <td>
                    <span className={`${styles.status} ${agent.status === "online" ? styles.online : styles.offline}`}>
                      {agent.status}
                    </span>
                  </td>
                  <td>{agent.mode || "passive"}</td>
                  <td style={{ fontSize: "0.8rem", color: "var(--n-400)" }}>
                    {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : "Never"}
                  </td>
                  <td>
                    <div className={styles.actions}>
                      <button className={styles.btn} onClick={() => requestAction(agent.hostname, "restart")} disabled={actionStatus[agent.hostname]}>Restart</button>
                      <button className={styles.btn} onClick={() => requestAction(agent.hostname, "update")} disabled={actionStatus[agent.hostname]}>Update</button>
                      <button className={styles.btn} onClick={() => requestAction(agent.hostname, "uninstall")} disabled={actionStatus[agent.hostname]}>Uninstall</button>
                      <button className={styles.btn} onClick={() => handleViewConfig(agent.hostname)}>Config</button>
                    </div>
                    {actionStatus[agent.hostname] && <div className={styles.actionStatus}>{actionStatus[agent.hostname]}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {pendingAction && (
        <ConfirmModal
          title={`Confirm ${pendingAction.action}`}
          message={`Are you sure you want to ${pendingAction.action} agent "${pendingAction.hostname}"?`}
          confirmLabel={pendingAction.action === 'uninstall' ? 'Uninstall' : pendingAction.action === 'update' ? 'Update' : 'Restart'}
          danger={pendingAction.action === 'uninstall'}
          onCancel={() => setPendingAction(null)}
          onConfirm={() => handleAction(pendingAction.hostname, pendingAction.action)}
        />
      )}

      {/* Config Modal */}
      {selectedAgent && (
        <div className={styles.modalOverlay} onClick={handleCloseConfig}>
          <div className={styles.modal} onClick={e => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <h3>Agent Configuration: {selectedAgent.hostname}</h3>
              <button className={styles.closeBtn} onClick={handleCloseConfig}>×</button>
            </div>
            <pre className={styles.configJson}>{JSON.stringify(selectedAgent.config, null, 2)}</pre>
            <div className={styles.modalFooter}>
              <button className="btn-secondary" onClick={handleCloseConfig}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}