// Authenticated JSON fetch helper for the dashboard API.
// Attaches the session token from localStorage as a Bearer header.

/**
 * Resolve an API path to an absolute URL in production and leave it relative
 * in development.
 *
 * Callers previously built `https://${window.location.host}/api/...`. That
 * works when the app is served by the same TLS host as the API, but in dev the
 * Vite server on :3000 speaks plain HTTP, so https://localhost:3000 is a TLS
 * handshake against a non-TLS port and every call — plus the wss:// dashboard
 * socket — fails. Relative paths let the Vite proxy (vite.config.ts) do the
 * TLS hop to :8443.
 */
/**
 * Build the start_assessment command frame.
 *
 * Every operator choice must be included. Previously only `profile` and
 * `test_type` were sent, so the agent always ran all modules at its own
 * startup -days and its own reboot flag while the DB and the report recorded
 * the dashboard's selection — the report described an assessment that never
 * happened. Kept as a pure function so it can be tested directly.
 */
export function buildStartAssessment({ hostname, profile, testType, modules, days, allowReboot }) {
  return {
    type: 'start_assessment',
    agent_id: hostname,
    profile,
    test_type: testType,
    modules: Array.isArray(modules) ? modules : [],
    days,
    allow_reboot: Boolean(allowReboot),
  };
}

export function apiUrl(path) {
  const isDev = import.meta.env && import.meta.env.DEV;
  if (isDev) return path;
  // Guard for non-browser contexts (e.g. a unit test importing this module),
  // where window is not defined.
  if (typeof window === 'undefined' || !window.location) return path;
  return `${window.location.origin}${path}`;
}

/** Absolute wss:// URL for the browser dashboard socket, respecting dev proxying. */
export function dashboardSocketUrl(token) {
  const isDev = import.meta.env && import.meta.env.DEV;
  if (isDev) {
    // Relative path through the Vite ws proxy rather than wss://<dev host>.
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/dashboard?token=${encodeURIComponent(token || '')}`;
  }
  return `wss://${window.location.host}/dashboard?token=${encodeURIComponent(token || '')}`;
}

export function getToken() {
  return localStorage.getItem('agentide-token');
}

export function setToken(token) {
  if (token) {
    localStorage.setItem('agentide-token', token);
  } else {
    localStorage.removeItem('agentide-token');
  }
}

export async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = {
    ...(options.headers || {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    // Session expired or invalid — drop the token and force re-login.
    // App renders <Login/> when no token is present.
    setToken(null);
    window.location.href = '/';
  }
  return res;
}
