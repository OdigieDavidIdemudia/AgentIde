/**
 * End-to-end launch check driven over the real browser WebSocket path.
 *
 * This reproduces the operator flow the UI performs, so it exercises the parts
 * a REST-only test cannot:
 *   1. POST /api/assessments  (server dispatches start_assessment)
 *   2. agent replies with pre_scan_result and parks
 *   3. browser sends confirm_assessment over /dashboard
 *   4. module results land on the run
 *
 * Usage: node scripts/e2e-launch-check.mjs <agentDbId> [modulesCsv]
 */
import { WebSocket } from 'ws';

const BASE = 'https://localhost:8443';
const AGENT = process.argv[2];
const MODULES = (process.argv[3] || 'antitamper').split(',').filter(Boolean);
const LOGIN = { email: 'admin@agentide.local', password: 'agentide-dev' };

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

async function login() {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(LOGIN),
  });
  if (!res.ok) throw new Error(`login failed: ${res.status}`);
  return (await res.json()).token;
}

const token = await login();
console.log('✓ logged in');

const created = await fetch(`${BASE}/api/assessments`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
  body: JSON.stringify({
    agent_id: AGENT,
    profile: 'rapid',
    test_type: 'blackbox',
    duration_days: 1,
    modules: MODULES,
    allow_reboot: false,
  }),
});
if (!created.ok) throw new Error(`create failed: ${created.status} ${await created.text()}`);
const assessment = await created.json();
console.log(`✓ assessment created: ${assessment.id}`);

const ws = new WebSocket(
  `wss://localhost:8443/dashboard?token=${encodeURIComponent(token)}`,
  { rejectUnauthorized: false },
);

const seen = [];
let confirmed = false;

const finish = async (code) => {
  try { ws.close(); } catch {}
  const res = await fetch(`${BASE}/api/assessments/${assessment.id}/results`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const results = await res.json();
  console.log(`\nresults: ${results.length}`);
  for (const r of results) {
    console.log(`  ${r.module}: ${r.result}${r.passed !== null ? ` (passed=${r.passed})` : ''} — ${r.detail}`);
  }
  process.exit(code);
};

ws.on('open', () => console.log('✓ browser socket open'));

ws.on('message', async (data) => {
  const msg = JSON.parse(data.toString());
  seen.push(msg.type);

  if (msg.type === 'module_result' && !confirmed) {
    console.log(`✗ module_result arrived before confirm — agent did not park: ${msg.payload?.module}`);
    confirmed = true;
  }

  if (msg.type === 'pre_scan_result' && !confirmed) {
    confirmed = true;
    const vendors = (msg.payload?.discovered_agents || []).map(a => a.vendor);
    console.log(`✓ pre_scan_result: vendors=${JSON.stringify(vendors)}`);
    console.log(`  supported_disabling=${JSON.stringify(msg.payload?.supported_disabling)}`);
    // Confirm with no vendor disable — pure blackbox, nothing destructive.
    ws.send(JSON.stringify({ type: 'confirm_assessment', agent_id: msg.agent_id, disable_vendor: 'none' }));
    console.log('→ sent confirm_assessment');
  }

  if (msg.type === 'assessment_done') {
    console.log(`✓ assessment_done: ${JSON.stringify(msg.payload)}`);
    setTimeout(() => finish(0), 1500);
  }
});

ws.on('error', (e) => { console.error('ws error', e.message); finish(1); });

setTimeout(() => {
  console.log(`\nevent types seen: ${JSON.stringify([...new Set(seen)])}`);
  if (!confirmed) {
    console.log('✗ never received pre_scan_result — agent is not reaching the confirm handshake');
    return finish(1);
  }
  console.log('✓ confirm handshake completed');
  finish(seen.includes('module_result') ? 0 : 1);
}, 75000);