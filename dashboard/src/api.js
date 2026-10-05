// Authenticated JSON fetch helper for the dashboard API.
// Attaches the session token from localStorage as a Bearer header.

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
