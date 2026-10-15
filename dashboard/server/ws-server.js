import { WebSocketServer } from 'ws';
import { registry } from './agent-registry.js';
import { pool } from './db.js';
import { isAgentTokenValid, isValidSessionToken, issueAgentToken, tokenFingerprint } from './auth.js';
import { buildUpdateCommand } from './agent-update.js';

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

export function setupWebSockets(server) {
  const wssAgents = new WebSocketServer({ noServer: true, clientTracking: true, pingInterval: 25000 });
  const wssDashboard = new WebSocketServer({ noServer: true, clientTracking: true, pingInterval: 25000 });

  server.on('upgrade', async (request, socket, head) => {
    const url = new URL(request.url, `https://${request.headers.host || 'localhost'}`);
    const token = url.searchParams.get('token') || '';

    if (url.pathname === '/agent') {
      // Agents may present the shared AGENT_TOKEN (bootstrap) or the
      // per-agent token the dashboard issued them on first connect. Both must
      // be accepted here, otherwise a registered agent can never reconnect.
      if (!(await isAgentTokenAccepted(token))) {
        console.warn(
          `🛡️  Agent connection REJECTED (missing/invalid token) from ${request.socket.remoteAddress} — ` +
          `received=${tokenFingerprint(token)} expected=${tokenFingerprint(process.env.AGENT_TOKEN)}. ` +
          `Verify the agent's -token (per-agent tokens must exist in the agents table).`,
        );
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
        console.warn(
          `💻 Dashboard socket rejected (invalid/expired session) from ${request.socket.remoteAddress}`,
        );
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

    ws.on('close', (code, reason) => {
      registry.removeBrowser(ws);
      console.log('💻 Browser dashboard disconnected:', code, reason?.toString());
    });

    ws.on('error', (err) => {
      console.error('💻 Browser dashboard error:', err.message);
    });

    // Send a welcome message to verify connection is working
    ws.send(JSON.stringify({ type: 'welcome', message: 'Connected to AgentIde Dashboard' }));

    ws.on('message', async (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'start_assessment') {
          // Log the full operator scope, not just profile/test_type: the
          // module selection, duration and reboot consent are what the report
          // is later built from, so a mismatch must be visible in the log.
          const modules = Array.isArray(msg.modules) && msg.modules.length ? msg.modules.join(',') : 'all';
          console.log(`📋 start_assessment → agent_id="${msg.agent_id}" profile="${msg.profile}" test_type="${msg.test_type}" days="${msg.days ?? 1}" modules="${modules}" allow_reboot="${msg.allow_reboot ?? false}"`);
          const agentExists = !!registry.getAgent(msg.agent_id);
          console.log(`📋 Agent in registry: ${agentExists}`);
          registry.sendToAgent(msg.agent_id, msg);
        } else if (msg.type === 'confirm_assessment') {
          console.log(`✅ confirm_assessment → agent_id="${msg.agent_id}" disable_vendor="${msg.disable_vendor}"`);
          registry.sendToAgent(msg.agent_id, msg);
        } else if (msg.type === 'stop_assessment') {
          console.log(`🛑 stop_assessment → agent_id="${msg.agent_id}" assessment_id="${msg.assessment_id}"`);
          registry.sendToAgent(msg.agent_id, msg);
        } else {
          // Previously unknown browser commands vanished with no trace, so a
          // protocol drift was invisible from both ends. Log it.
          console.warn(`⚠️  Unhandled browser command type: "${msg.type}"`);
        }
      } catch (err) {
        console.error('Failed to parse browser message', err);
      }
    });
  });

  // --- Agent Connections ---
  wssAgents.on('connection', (ws, request) => {
    console.log(`🛡️  Agent connected from ${request.socket.remoteAddress}`);

    // The token the agent presented at upgrade time (shared bootstrap
    // token or a per-agent token). Captured here so the fingerprint
    // handler can bind identity to it.
    const upgradeUrl = new URL(request.url, `https://${request.headers.host || 'localhost'}`);
    const agentTokenUsed = upgradeUrl.searchParams.get('token') || '';

    // Register the socket immediately, keyed by the agent_id it claims. The
    // agent_id travels in the URL query string. Registering here — rather than
    // only inside the fingerprint handler — means a reconnecting agent stays
    // addressable for outbound commands even if it has not re-sent its
    // fingerprint yet; otherwise sendToAgent silently drops commands.
    const claimedId = upgradeUrl.searchParams.get('agent_id') || '';
    if (claimedId) {
      registry.addAgent(ws, claimedId);
    }

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
          console.log(`🛡️  Agent registered & fingerprinted: ${msg.agent_id}`);
          if (auth.agentToken) {
            try {
              ws.send(JSON.stringify({ type: 'agent_token', token: auth.agentToken }));
            } catch (err) {
              console.error('Failed to send agent_token:', err);
            }
          }

          // Offer a self-update when the dashboard has a newer build — but never while
          // an assessment is running. Applying an update swaps the agent binary
          // and restarts the service, which kills an in-flight assessment
          // mid-run and can re-offer the same update on reconnect, producing a
          // restart loop that looks like an assessment failure to the operator.
          // The agent is asked again on its next connect once the run finishes.
          const agentVersion = (msg.payload && msg.payload.version) || '';
          const busy = await isAgentBusy(msg.agent_id);
          if (busy) {
            console.log(`⏸️  Skipping agent update for ${msg.agent_id} — assessment in progress`);
          } else {
            const update = buildUpdateCommand(request.headers.host, agentVersion);
            if (update) {
              try {
                ws.send(JSON.stringify(update));
              } catch (err) {
                console.error('Failed to send update_agent:', err);
              }
              console.log(`⬆️  Offered agent update v${update.version} to ${msg.agent_id} (currently v${agentVersion || 'unknown'})`);
              registry.broadcastToBrowsers({
                type: 'agent_update_offered',
                agent_id: msg.agent_id,
                version: update.version,
                from_version: agentVersion,
              });
            }
          }
        }

        await updateLastSeen(msg.agent_id);
        if (msg.type === 'discovery') await handleDiscovery(msg);
        await recordEvent(msg);
        if (msg.type === 'module_result') await recordModuleResult(msg);
        if (msg.type === 'assessment_done') await completeAssessment(msg);
        registry.broadcastToBrowsers(msg);

      } catch (err) {
        console.error('Failed to process agent message', err);
      }
    });

    ws.on('close', (code, reason) => {
      const agentId = registry.removeAgent(ws);
      console.log(`🛡️  Agent disconnected: ${agentId} (code: ${code}, reason: ${reason?.toString() || 'none'})`);
      if (agentId) {
        registry.broadcastToBrowsers({ type: 'agent_disconnected', agent_id: agentId });
      }
    });

    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
    });
  });
}

async function handleFingerprint(msg, agentToken) {
  const p = msg.payload;
  const res = await pool.query(`
    INSERT INTO agents (hostname, ip, mac, os, os_version, kernel_build, arch, status, mode, last_seen, token, dashboard_url, log_path, allow_reboot, agent_version)
    VALUES ($1, $2, $3, $4, $5, $6, $7, 'online', 'passive', NOW(), $8, $9, $10, $11, $12)
    ON CONFLICT (hostname, mac) DO UPDATE SET
      ip = EXCLUDED.ip,
      os = EXCLUDED.os,
      os_version = EXCLUDED.os_version,
      status = 'online',
      last_seen = NOW(),
      dashboard_url = COALESCE(EXCLUDED.dashboard_url, agents.dashboard_url),
      log_path = COALESCE(EXCLUDED.log_path, agents.log_path),
      allow_reboot = COALESCE(EXCLUDED.allow_reboot, agents.allow_reboot),
      agent_version = COALESCE(EXCLUDED.agent_version, agents.agent_version)
    RETURNING id
  `, [
    msg.agent_id, p.ip, p.mac, p.os, p.os_version, p.kernel_build, p.arch,
    agentToken || null, p.dashboard_url || null, p.log_path || null, p.allow_reboot ?? null,
    p.version || null,
  ]);
  
  if (res.rows.length > 0) {
    registry.setAgentDbId(msg.agent_id, res.rows[0].id);
  }
}

// handleDiscovery persists the security vendors an agent found on the host.
// `vendor` keeps the first match for backwards compatibility with the fleet
// view; `vendors` holds every match so layered estates stay visible.
async function handleDiscovery(msg) {
  const agent = registry.getAgent(msg.agent_id);
  if (!agent || !agent.dbId) return;

  // Accept both the single-object (older agents) and array (multi-vendor,
  // v0.4.1+) shapes of the discovery payload.
  const entries = Array.isArray(msg.payload)
    ? msg.payload
    : [msg.payload];
  const vendors = entries
    .map((e) => (e && (e.discovered_vendor || e.vendor)) || null)
    .filter(Boolean);

  if (vendors.length === 0) return;

  try {
    await pool.query(
      `UPDATE agents SET vendor = $2, vendors = $3 WHERE id = $1`,
      [agent.dbId, vendors[0], vendors],
    );
  } catch (err) {
    console.error('Failed to persist discovery for agent:', err.message);
  }
}

// Accept either the shared bootstrap token or a per-agent token already bound
// to a hostname in the agents table. Called at WebSocket upgrade time.
async function isAgentTokenAccepted(token) {
  if (isAgentTokenValid(token)) return true;
  if (!token) return false;
  try {
    const res = await pool.query('SELECT 1 FROM agents WHERE token = $1 LIMIT 1', [token]);
    return res.rowCount > 0;
  } catch (err) {
    console.error('Agent token lookup failed:', err.message);
    return false;
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

  const artifacts = Array.isArray(p.artifacts) ? p.artifacts : [];

  await pool.query(`
    INSERT INTO results (assessment_id, module_name, action, passed, detail, elapsed_ms, notes, artifacts, test_type, category)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
  `, [
    assessmentId,
    p.module || 'unknown',
    p.result || 'UNKNOWN',
    !!p.passed,
    p.detail || '',
    p.duration_ms || 0,
    // `notes` keeps the metadata JSON for backwards compatibility with rows
    // written before the artifacts/test_type columns existed; new readers
    // should prefer the dedicated columns.
    JSON.stringify({ mitre: p.mitre, test_type: p.test_type, timestamp: p.timestamp }),
    JSON.stringify(artifacts),
    // test_type and category are now first-class columns so reports can group
    // by them. test_type falls back to the parent assessment's value, because
    // older agents only send it in the notes blob.
    p.test_type || null,
    p.category || p.module || 'unknown',
  ]);

  // Promote the assessment's test_type from the first module result that
  // carries one, so the run is classifiable even if the start command didn't
  // include it.
  await pool.query(`
    UPDATE assessments SET test_type = $1
    WHERE id = $2 AND test_type IS NULL AND $1 IS NOT NULL
  `, [p.test_type || null, assessmentId]);
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

  // Recompute the score from what actually landed in the results table rather
  // than trusting the agent's own summary. The agent counts what it believes it
  // ran; the results table counts what was recorded. Where they disagree the
  // recorded value is the defensible one, and score_source records it.
  const agg = await pool.query(`
    SELECT COUNT(*)::int AS recorded,
           COUNT(*) FILTER (WHERE passed)::int AS recorded_passed,
           COUNT(*) FILTER (WHERE NOT passed)::int AS recorded_failed
    FROM results WHERE assessment_id = $1
  `, [assessmentId]);

  const recorded = agg.rows[0]?.recorded ?? 0;
  const recordedPassed = agg.rows[0]?.recorded_passed ?? 0;
  const recordedFailed = agg.rows[0]?.recorded_failed ?? 0;

  const agentScore = total > 0 ? Math.round((passed / total) * 100) : null;
  const recordedScore = recorded > 0 ? Math.round((recordedPassed / recorded) * 100) : null;
  const agree = agentScore !== null && recordedScore !== null && agentScore === recordedScore;

  // Score of 0 is meaningful (every module failed) — never coerce it to null.
  const score = recordedScore !== null ? recordedScore : agentScore;
  const scoreSource = recordedScore !== null
    ? (agree ? 'agreed' : 'recomputed_from_results')
    : (agentScore !== null ? 'agent_reported' : 'unavailable');

  if (!agree && agentScore !== null && recordedScore !== null) {
    console.warn(
      `⚠️ Score mismatch for assessment ${assessmentId}: agent reported ${agentScore} ` +
      `(${passed}/${total}) but results show ${recordedScore} (${recordedPassed}/${recorded}). ` +
      `Using recorded results.`
    );
  }

  await pool.query(`
    UPDATE assessments
    SET status = 'completed', completed_at = NOW(),
        passed = $1, failed = $2, score = $3,
        score_source = $4, skipped = $5
    WHERE id = $6
  `, [passed, failed, score, scoreSource, total - passed - failed || 0, assessmentId]);

  // Drop the agent back to 'watch' — it is alive but no longer under test.
  await pool.query(
    `UPDATE agents SET state = 'watch', assessment_id = NULL WHERE id = $1`,
    [agent.dbId],
  );

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

// True when the agent has an assessment in flight. Used to withhold
// disruptive self-updates until the run finishes. Fails closed on error so a
// database hiccup cannot cause a mid-assessment restart.
async function isAgentBusy(hostname) {
  try {
    const r = await pool.query(
      `SELECT EXISTS (
         SELECT 1 FROM assessments s
          WHERE s.agent_id = a.id
            AND s.status = 'running'
       ) AS busy
         FROM agents a
        WHERE a.hostname = $1
        LIMIT 1`,
      [hostname],
    );
    return !!(r.rows[0] && r.rows[0].busy);
  } catch (err) {
    console.error('isAgentBusy check failed; withholding update', err);
    return true;
  }
}

async function updateLastSeen(hostname) {
  await pool.query(`UPDATE agents SET status='online', last_seen=NOW() WHERE hostname=$1`, [hostname]);
}

async function recordEvent(msg) {
  const agent = registry.getAgent(msg.agent_id);
  if (!agent || !agent.dbId) return;

  // pg serializes plain objects to JSON for a jsonb column, but treats a
  // JavaScript array as a Postgres array literal (which is not valid JSON).
  // Events whose payload is an array — e.g. multi-vendor discovery — must
  // therefore be stringified explicitly.
  const payload =
    typeof msg.payload === 'string' ? msg.payload : JSON.stringify(msg.payload ?? null);

  await pool.query(`
    INSERT INTO events (agent_id, type, payload)
    VALUES ($1, $2, $3)
  `, [agent.dbId, msg.type, payload]);
}
