import { WebSocketServer } from 'ws';
import { registry } from './agent-registry.js';
import { pool } from './db.js';
import { isAgentTokenValid, isValidSessionToken, issueAgentToken } from './auth.js';

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

export function setupWebSockets(server) {
  const wssAgents = new WebSocketServer({ noServer: true });
  const wssDashboard = new WebSocketServer({ noServer: true });

  server.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url, `https://${request.headers.host || 'localhost'}`);
    const token = url.searchParams.get('token') || '';

    if (url.pathname === '/agent') {
      // Agents authenticate with the shared AGENT_TOKEN secret.
      // Connections are rejected when the token is missing/invalid.
      if (!isAgentTokenValid(token)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
      wssAgents.handleUpgrade(request, socket, head, (ws) => {
        wssAgents.emit('connection', ws, request);
      });
    } else if (url.pathname === '/dashboard') {
      // Browsers authenticate with a session token from /api/auth/login.
      if (!isValidSessionToken(token)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
      // Browsers always send Origin on WS handshakes — enforce same-site.
      const origin = request.headers.origin;
      const selfOrigin = `https://${request.headers.host}`;
      if (origin && origin !== selfOrigin && !allowedOrigins.includes(origin)) {
        socket.destroy();
        return;
      }
      wssDashboard.handleUpgrade(request, socket, head, (ws) => {
        wssDashboard.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  // --- Browser Connections ---
  wssDashboard.on('connection', (ws) => {
    registry.addBrowser(ws);
    console.log('💻 Browser dashboard connected');

    ws.on('close', () => {
      registry.removeBrowser(ws);
      console.log('💻 Browser dashboard disconnected');
    });

    ws.on('message', async (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'start_assessment') {
          console.log(`📋 start_assessment → agent_id="${msg.agent_id}" profile="${msg.profile}" test_type="${msg.test_type}"`);
          const agentExists = !!registry.getAgent(msg.agent_id);
          console.log(`📋 Agent in registry: ${agentExists}`);
          registry.sendToAgent(msg.agent_id, msg);
        } else if (msg.type === 'confirm_assessment') {
          console.log(`✅ confirm_assessment → agent_id="${msg.agent_id}" disable_vendor="${msg.disable_vendor}"`);
          registry.sendToAgent(msg.agent_id, msg);
        }
      } catch (err) {
        console.error('Failed to parse browser message', err);
      }
    });
  });

  // --- Agent Connections ---
  wssAgents.on('connection', (ws, request) => {
    console.log('🛡️  Agent connected');

    // The token the agent presented at upgrade time (shared bootstrap
    // token or a per-agent token). Captured here so the fingerprint
    // handler can bind identity to it.
    const upgradeUrl = new URL(request.url, `https://${request.headers.host || 'localhost'}`);
    const agentTokenUsed = upgradeUrl.searchParams.get('token') || '';

    ws.on('message', async (data) => {
      try {
        const msg = JSON.parse(data.toString());
        
        if (msg.type === 'fingerprint') {
          // Validate identity before registering:
          //  - shared AGENT_TOKEN → bootstrap: issue (or re-send) a per-agent token
          //  - per-agent token → must belong to the claimed hostname
          const auth = await authorizeAgent(msg.agent_id, agentTokenUsed);
          if (!auth.ok) {
            ws.close(4001, 'invalid agent token');
            return;
          }
          registry.addAgent(ws, msg.agent_id);
          await handleFingerprint(msg, auth.agentToken);
          if (auth.agentToken) {
            ws.send(JSON.stringify({ type: 'agent_token', token: auth.agentToken }));
          }
        }

        await updateLastSeen(msg.agent_id);
        await recordEvent(msg);
        if (msg.type === 'module_result') await recordModuleResult(msg);
        if (msg.type === 'assessment_done') await completeAssessment(msg);
        registry.broadcastToBrowsers(msg);

      } catch (err) {
        console.error('Failed to process agent message', err);
      }
    });

    ws.on('close', () => {
      const agentId = registry.removeAgent(ws);
      console.log('🛡️  Agent disconnected:', agentId);
      if (agentId) {
        registry.broadcastToBrowsers({ type: 'agent_disconnected', agent_id: agentId });
      }
    });
  });
}

async function handleFingerprint(msg, agentToken) {
  const p = msg.payload;
  const res = await pool.query(`
    INSERT INTO agents (hostname, ip, mac, os, os_version, kernel_build, arch, status, mode, last_seen, token)
    VALUES ($1, $2, $3, $4, $5, $6, $7, 'online', 'passive', NOW(), $8)
    ON CONFLICT (hostname, mac) DO UPDATE SET
      ip = EXCLUDED.ip,
      os = EXCLUDED.os,
      os_version = EXCLUDED.os_version,
      status = 'online',
      last_seen = NOW()
    RETURNING id
  `, [msg.agent_id, p.ip, p.mac, p.os, p.os_version, p.kernel_build, p.arch, agentToken || null]);
  
  if (res.rows.length > 0) {
    registry.setAgentDbId(msg.agent_id, res.rows[0].id);
  }
}

// authorizeAgent validates an agent's identity for the claimed hostname.
// Bootstrap (shared AGENT_TOKEN): accept and issue/re-send a per-agent token.
// Otherwise: the token must be the per-agent token bound to this hostname.
// Returns { ok, agentToken } — agentToken is set when the dashboard issued one.
async function authorizeAgent(hostname, tokenUsed) {
  if (isAgentTokenValid(tokenUsed)) {
    const res = await pool.query('SELECT token FROM agents WHERE hostname = $1', [hostname]);
    const existing = res.rows[0]?.token;
    return { ok: true, agentToken: existing || issueAgentToken() };
  }

  const res = await pool.query('SELECT token FROM agents WHERE hostname = $1', [hostname]);
  if (!res.rows[0]?.token || res.rows[0].token !== tokenUsed) {
    console.warn('🛡️  Agent rejected: invalid per-agent token for', hostname);
    return { ok: false };
  }
  return { ok: true };
}

// recordModuleResult persists a module result row and links it to the
// running assessment (by session_id, or the agent's latest running one).
async function recordModuleResult(msg) {
  const agent = registry.getAgent(msg.agent_id);
  if (!agent || !agent.dbId) return;
  const p = msg.payload || {};
  const sessionId = p.session_id || null;

  const assessmentId = await findAssessmentId(agent.dbId, sessionId);
  if (!assessmentId) return;

  await pool.query(`
    INSERT INTO results (assessment_id, module_name, action, passed, detail, elapsed_ms, notes)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
  `, [
    assessmentId,
    p.module || 'unknown',
    p.result || 'UNKNOWN',
    !!p.passed,
    p.detail || '',
    p.duration_ms || 0,
    JSON.stringify({ mitre: p.mitre, test_type: p.test_type, timestamp: p.timestamp }),
  ]);
}

// completeAssessment marks the assessment row completed with the
// summary the agent sends in assessment_done.
async function completeAssessment(msg) {
  const agent = registry.getAgent(msg.agent_id);
  if (!agent || !agent.dbId) return;
  const p = msg.payload || {};

  const assessmentId = await findAssessmentId(agent.dbId, p.session_id || null);
  if (!assessmentId) return;

  const total = Number(p.total_modules) || 0;
  const passed = Number(p.passed) || 0;
  const failed = Number(p.failed) || 0;
  const score = total > 0 ? Math.round((passed / total) * 100) : null;

  await pool.query(`
    UPDATE assessments
    SET status = 'completed', completed_at = NOW(), passed = $1, failed = $2, score = $3
    WHERE id = $4
  `, [passed, failed, score, assessmentId]);

  console.log(`✅ Assessment completed for ${msg.agent_id}: ${passed}/${total} passed (score ${score})`);
}

async function findAssessmentId(agentDbId, sessionId) {
  if (sessionId) {
    const r = await pool.query('SELECT id FROM assessments WHERE session_id = $1', [sessionId]);
    if (r.rows[0]) return r.rows[0].id;
  }
  // Fall back to the agent's most recent running assessment and
  // stamp the session_id onto it so later messages link up.
  const r = await pool.query(
    `SELECT id FROM assessments WHERE agent_id = $1 AND status = 'running' ORDER BY started_at DESC LIMIT 1`,
    [agentDbId],
  );
  if (!r.rows[0]) return null;
  if (sessionId) {
    await pool.query('UPDATE assessments SET session_id = $1 WHERE id = $2', [sessionId, r.rows[0].id]);
  }
  return r.rows[0].id;
}

async function updateLastSeen(hostname) {
  await pool.query(`UPDATE agents SET status='online', last_seen=NOW() WHERE hostname=$1`, [hostname]);
}

async function recordEvent(msg) {
  const agent = registry.getAgent(msg.agent_id);
  if (!agent || !agent.dbId) return;

  await pool.query(`
    INSERT INTO events (agent_id, type, payload)
    VALUES ($1, $2, $3)
  `, [agent.dbId, msg.type, msg.payload]);
}
