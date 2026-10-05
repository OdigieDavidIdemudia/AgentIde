import crypto from 'crypto';

const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // dashboard session tokens live 24h

// In-memory session token store: token -> expiry timestamp.
const sessions = new Map();

// Issue a new dashboard session token (browser clients).
export function issueToken() {
  const token = crypto.randomUUID();
  sessions.set(token, Date.now() + TOKEN_TTL_MS);
  return token;
}

export function revokeToken(token) {
  if (token) sessions.delete(token);
}

export function isValidSessionToken(token) {
  if (!token) return false;
  const expires = sessions.get(token);
  if (!expires) return false;
  if (Date.now() > expires) {
    sessions.delete(token);
    return false;
  }
  return true;
}

// Bearer-token middleware for REST routes.
export function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!isValidSessionToken(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Shared secret for agent WebSocket connections (set via AGENT_TOKEN).
// Fail closed: if unset, no agent can connect.
export function isAgentTokenValid(token) {
  const expected = process.env.AGENT_TOKEN || '';
  return expected !== '' && token === expected;
}

// Admin login credentials (set via ADMIN_EMAIL / ADMIN_PASSWORD).
export function checkAdminCredentials(email, password) {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@agentide.local';
  const adminPassword = process.env.ADMIN_PASSWORD || 'agentide-dev';
  return email === adminEmail && password === adminPassword;
}

// Per-agent tokens, bound to a hostname in the agents table.
// Issued when an agent first bootstraps with the shared AGENT_TOKEN.
export function issueAgentToken() {
  return crypto.randomUUID();
}

// ── Login rate limiting ────────────────────────────────────────
const MAX_LOGIN_FAILURES = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
const loginAttempts = new Map(); // ip -> { count, lockedUntil }

export function isLoginAllowed(ip) {
  const rec = loginAttempts.get(ip);
  if (!rec) return true;
  if (rec.lockedUntil && Date.now() < rec.lockedUntil) return false;
  if (rec.lockedUntil) loginAttempts.delete(ip); // lockout expired
  return true;
}

export function registerLoginFailure(ip) {
  const rec = loginAttempts.get(ip) || { count: 0, lockedUntil: null };
  rec.count += 1;
  if (rec.count >= MAX_LOGIN_FAILURES) {
    rec.lockedUntil = Date.now() + LOCKOUT_MS;
  }
  loginAttempts.set(ip, rec);
}
