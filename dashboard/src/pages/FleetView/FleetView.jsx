import React from 'react';
import { useAgentContext } from '../../context/AgentContext.jsx';
import { apiFetch } from '../../api.js';
import { useNavigate } from 'react-router-dom';
import styles from './FleetView.module.css';

export default function FleetView() {
  const { state, dispatch } = useAgentContext();
  const navigate = useNavigate();

  const handleDelete = async (hostname) => {
    if (!window.confirm(`Are you sure you want to delete the agent "${hostname}" and all its history?`)) {
      return;
    }
    try {
      const res = await apiFetch(`https://${window.location.host}/api/agents/${hostname}`, {
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

      {state.agents.length === 0 ? (
        <div className={styles.emptyState}>
          <h3>No agents connected</h3>
          <p>Install AgentIde on a virtual machine to get started.</p>
          <div className={styles.installCommand}>
            <code>.\agentide.exe --dashboard wss://192.168.x.x:8080 --mode passive</code>
          </div>
        </div>
      ) : (
        <div className="card">
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>OS</th>
                <th>Discovered Agent</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {state.agents.map((agent) => (
                <tr key={agent.hostname}>
                  <td className={styles.hostname}>{agent.hostname}</td>
                  <td className={styles.mono}>{agent.ip}</td>
                  <td>{agent.os} {agent.os_version}</td>
                  <td>
                    {agent.vendor ? (
                       <span className={styles.vendorBadge}>{agent.vendor}</span>
                    ) : (
                       <span className={styles.noVendor}>Scanning...</span>
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
                      onClick={() => handleDelete(agent.hostname)}
                    >
                      ✕
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
