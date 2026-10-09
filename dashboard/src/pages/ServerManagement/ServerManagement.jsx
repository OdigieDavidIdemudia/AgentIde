import React, { useState, useEffect } from "react";
import { apiFetch } from "../../api.js";
import styles from "./ServerManagement.module.css";
import { ConfirmModal, Toast } from "../../components/ui.jsx";

export default function ServerManagement() {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [serverConfig, setServerConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [eventRetention, setEventRetention] = useState(30);
  const [saving, setSaving] = useState(false);
  const [confirmPrune, setConfirmPrune] = useState(false);
  const [toast, setToast] = useState(null);
  const showToast = (nextToast) => {
    setToast(nextToast);
    setTimeout(() => setToast(null), 5000);
  };

  useEffect(() => {
    loadHealth();
    loadStats();
    loadServerConfig();
  }, []);

  const loadServerConfig = async () => {
    try {
      const res = await apiFetch(`/api/admin/config`);
      if (res.ok) setServerConfig(await res.json());
    } catch (err) {
      console.error("Failed to load server config", err);
    }
  };

  const loadHealth = async () => {
    try {
      const res = await apiFetch(`/api/health`);
      if (res.ok) setHealth(await res.json());
    } catch (err) {
      console.error("Failed to load health", err);
    }
  };

  const loadStats = async () => {
    try {
      const res = await apiFetch(`/api/stats`);
      if (res.ok) setStats(await res.json());
    } catch (err) {
      console.error("Failed to load stats", err);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveRetention = async () => {
    setSaving(true);
    try {
      const res = await apiFetch(`/api/admin/retention`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ days: eventRetention })
      });
      if (res.ok) {
        showToast({ tone: "success", message: "Event retention updated. Changes take effect on next prune cycle." });
      }
    } catch (err) {
      showToast({ tone: "error", message: `Failed to save: ${err.message}` });
    } finally {
      setSaving(false);
    }
  };

  const handlePrune = async () => {
    setConfirmPrune(true);
  };

  const executePrune = async () => {
    setConfirmPrune(false);
    try {
      const res = await apiFetch(`/api/admin/prune`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        showToast({ tone: "success", message: `Pruned ${data.deleted} events` });
        loadStats();
      }
    } catch (err) {
      showToast({ tone: "error", message: `Failed to prune: ${err.message}` });
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const formatUptime = (seconds) => {
    if (!seconds) return "—";
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${d}d ${h}h ${m}m`;
  };

  if (loading) {
    return <div className={styles.loading}>Loading server info...</div>;
  }

  return (
    <div className={styles.container}>
      <Toast message={toast?.message} tone={toast?.tone} />
      <header className={styles.header}>
        <h2>Server Management</h2>
        <button className="btn-secondary" onClick={() => { loadHealth(); loadStats(); }}>Refresh</button>
      </header>

      <div className={styles.grid}>
        {/* Health Card */}
        <div className={styles.card}>
          <h3>Server Health</h3>
          {health ? (
            <div className={styles.health}>
              <div className={styles.healthItem}>
                <span className={styles.label}>Status</span>
                <span className={`${styles.value} ${health.status === "ok" ? styles.ok : styles.error}`}>
                  {health.status?.toUpperCase() || "UNKNOWN"}
                </span>
              </div>
              <div className={styles.healthItem}>
                <span className={styles.label}>Uptime</span>
                <span className={styles.value}>{formatUptime(health.uptime)}</span>
              </div>
              <div className={styles.healthItem}>
                <span className={styles.label}>Version</span>
                <span className={styles.value} style={{ fontFamily: "var(--font-mono)" }}>{health.version || "—"}</span>
              </div>
              <div className={styles.healthItem}>
                <span className={styles.label}>Node</span>
                <span className={styles.value}>{health.node_version || "—"}</span>
              </div>
              <div className={styles.healthItem}>
                <span className={styles.label}>Memory</span>
                <span className={styles.value}>
                  {formatBytes(health.memory?.heapUsed)} / {formatBytes(health.memory?.heapTotal)}
                </span>
              </div>
              <div className={styles.healthItem}>
                <span className={styles.label}>Database</span>
                <span className={`${styles.value} ${health.db_connected ? styles.ok : styles.error}`}>
                  {health.db_connected ? "Connected" : "Disconnected"}
                </span>
              </div>
            </div>
          ) : (
            <p style={{ color: "var(--n-500)" }}>Unable to load health</p>
          )}
        </div>

        {/* Stats Card */}
        <div className={styles.card}>
          <h3>Statistics</h3>
          {stats ? (
            <div className={styles.stats}>
              <div className={styles.statRow}>
                <span className={styles.statLabel}>Total Agents</span>
                <span className={styles.statValue}>{stats.total_agents || 0}</span>
              </div>
              <div className={styles.statRow}>
                <span className={styles.statLabel}>Online Agents</span>
                <span className={styles.statValue} style={{ color: "var(--accent)" }}>{stats.online_agents || 0}</span>
              </div>
              <div className={styles.statRow}>
                <span className={styles.statLabel}>Total Assessments</span>
                <span className={styles.statValue}>{stats.total_assessments || 0}</span>
              </div>
              <div className={styles.statRow}>
                <span className={styles.statLabel}>Running Assessments</span>
                <span className={styles.statValue} style={{ color: "#ffd166" }}>{stats.running_assessments || 0}</span>
              </div>
              <div className={styles.statRow}>
                <span className={styles.statLabel}>Total Events</span>
                <span className={styles.statValue}>{stats.total_events || 0}</span>
              </div>
              <div className={styles.statRow}>
                <span className={styles.statLabel}>DB Size</span>
                <span className={styles.statValue}>{formatBytes(stats.db_size)}</span>
              </div>
              <div className={styles.statRow}>
                <span className={styles.statLabel}>Events Table Size</span>
                <span className={styles.statValue}>{formatBytes(stats.events_table_size)}</span>
              </div>
            </div>
          ) : (
            <p style={{ color: "var(--n-500)" }}>Unable to load stats</p>
          )}
        </div>

        {/* Configuration Card */}
        <div className={styles.card}>
          <h3>Configuration</h3>
          <div className={styles.configItem}>
            <label>Event Retention (Days)</label>
            <input
              type="number"
              min="1"
              max="365"
              value={eventRetention}
              onChange={e => setEventRetention(parseInt(e.target.value) || 30)}
              className={styles.input}
              style={{ width: "80px" }}
            />
            <p className={styles.help}>Raw telemetry events older than this will be pruned automatically.</p>
          </div>
          <div className={styles.configActions}>
            <button className="btn-primary" onClick={handleSaveRetention} disabled={saving}>
              {saving ? "Saving..." : "Save Retention"}
            </button>
            <button className="btn-secondary" onClick={handlePrune}>
              Prune Now
            </button>
          </div>
        </div>

        {/* Environment Card */}
        <div className={styles.card}>
          <h3>Environment</h3>
          <pre className={styles.env}>
{serverConfig ? [
  "NODE_ENV=" + serverConfig.node_env,
  "PORT=" + serverConfig.port,
  "PGHOST=" + serverConfig.pghost,
  "PGPORT=" + serverConfig.pgport,
  "PGDATABASE=" + serverConfig.pgdatabase,
  "CORS_ORIGINS=" + serverConfig.cors_origins,
  "EVENT_RETENTION_DAYS=" + serverConfig.event_retention_days,
].join("\n") : "Loading..."}
          </pre>
          <p className={styles.help}>Sensitive values (passwords, tokens) are hidden.</p>
        </div>
      </div>

      {confirmPrune && (
        <ConfirmModal
          title="Prune events?"
          message={`Prune events older than ${eventRetention} days now?`}
          confirmLabel="Prune"
          danger
          onCancel={() => setConfirmPrune(false)}
          onConfirm={executePrune}
        />
      )}
    </div>
  );
}