import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// ── Agent self-update manifest ─────────────────────────────────────────────
// The dashboard advertises the newest agent build to connected agents so they
// can update themselves. The build lives in the repository's agent/ folder
// (agentide.exe + version.json); AGENT_DIST_DIR can point somewhere else for
// a packaged deployment. The manifest is re-read periodically so a rebuilt
// binary is picked up without restarting the dashboard.

const CACHE_TTL_MS = 30 * 1000;
const distDir = path.resolve(process.env.AGENT_DIST_DIR || path.join(process.cwd(), '..', 'agent'));

let cache = { at: 0, value: null };

function readLatest() {
  const now = Date.now();
  if (now - cache.at < CACHE_TTL_MS) return cache.value;

  let value = null;
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(distDir, 'version.json'), 'utf8'));
    const binPath = path.join(distDir, 'agentide.exe');
    const buf = fs.readFileSync(binPath);
    const version = String(manifest.version || '').trim();
    if (version) {
      value = {
        version,
        path: binPath,
        size: buf.length,
        sha256: crypto.createHash('sha256').update(buf).digest('hex'),
      };
    }
  } catch {
    // No build present (e.g. dashboard-only deployment) — updates disabled.
    value = null;
  }

  cache = { at: now, value };
  return value;
}

export function getLatestAgent() {
  return readLatest();
}

// compareVersions returns 1 if a > b, -1 if a < b, 0 if equal.
export function compareVersions(a, b) {
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

// buildUpdateCommand returns the update_agent command for an agent, or null if
// no update is available/needed. `host` is the request's Host header, used to
// build a download URL the agent can actually reach.
export function buildUpdateCommand(host, agentVersion) {
  const latest = getLatestAgent();
  if (!latest) return null;
  if (agentVersion && compareVersions(latest.version, agentVersion) <= 0) return null;

  const base = `https://${host || 'localhost'}`;
  return {
    type: 'update_agent',
    version: latest.version,
    sha256: latest.sha256,
    size: latest.size,
    url: `${base}/api/agent/download`,
  };
}
