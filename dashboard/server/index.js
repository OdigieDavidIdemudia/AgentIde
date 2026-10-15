import './env.js'; // must load .env before db.js creates the connection pool
import express from 'express';
import https from 'https';
import fs from 'fs';
import os from 'os';
import path from 'path';
import cors from 'cors';
import { setupWebSockets } from './ws-server.js';
import { pool } from './db.js';
import { issueToken, revokeToken, requireAuth, checkAdminCredentials, isLoginAllowed, registerLoginFailure } from './auth.js';
import { getLatestAgent, buildUpdateCommand } from './agent-update.js';
import { resolveAgentIdentity } from './agent-identity.js';
import { buildFindings, summariseBySeverity } from './finding-taxonomy.js';

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const app = express();
// Same-origin by default; widen via CORS_ORIGINS (comma-separated).
app.use(cors(allowedOrigins.length > 0 ? { origin: allowedOrigins } : { origin: false }));
app.use(express.json());

// â”€â”€ Auth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/auth/login', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!isLoginAllowed(ip)) {
    return res.status(429).json({ error: 'Too many failed attempts â€” try again later' });
  }
  const { email, password } = req.body || {};
  if (checkAdminCredentials(email, password)) {
    res.json({ token: issueToken() });
  } else {
    registerLoginFailure(ip);
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const header = req.headers.authorization || '';
  revokeToken(header.startsWith('Bearer ') ? header.slice(7) : '');
  res.json({ success: true });
});

// Session validity check â€” used by the frontend to detect expiry.
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ ok: true }));

// Public liveness probe â€” deliberately unauthenticated so you can verify the
// dashboard is reachable from an agent host before wiring up the agent:
//   curl -k https://<dashboard-ip>:8443/healthz
app.get('/healthz', (req, res) =>
  res.json({ status: 'ok', service: 'AgentIde', time: new Date().toISOString() }),
);

// Public agent self-update endpoints. An agent may need to fetch an update
// before it has an authenticated session, so these are unauthenticated; the
// payload is integrity-checked with SHA-256 on the agent side.
app.get('/api/agent/version', (req, res) => {
  const latest = getLatestAgent();
  if (!latest) return res.status(503).json({ error: 'No agent build available' });
  res.json({
    version: latest.version,
    sha256: latest.sha256,
    size: latest.size,
    url: '/api/agent/download',
  });
});

app.get('/api/agent/download', (req, res) => {
  const latest = getLatestAgent();
  if (!latest) return res.status(503).json({ error: 'No agent build available' });
  res.type('application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment; filename="agentide.exe"');
  res.sendFile(latest.path);
});

// Every other API route requires a valid session token.
app.use('/api', requireAuth);

app.get('/api/agents', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM agents ORDER BY last_seen DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

app.get('/api/agents/:hostname', async (req, res) => {
  try {
    const { hostname } = req.params;
    const result = await pool.query('SELECT * FROM agents WHERE hostname = $1', [hostname]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Failed to get agent:', err);
    res.status(500).json({ error: 'Database query failed' });
  }
});

app.get('/api/events', async (req, res) => {
  try {
    const { hostname } = req.query;
    let query;
    let params;
    if (hostname) {
      query = `
        SELECT e.type, e.payload, e.received_at, a.hostname
        FROM events e
        JOIN agents a ON e.agent_id = a.id
        WHERE a.hostname = $1
        ORDER BY e.received_at ASC
        LIMIT 2000
      `;
      params = [hostname];
    } else {
      query = `
        SELECT e.type, e.payload, e.received_at, a.hostname
        FROM events e
        JOIN agents a ON e.agent_id = a.id
        ORDER BY e.received_at ASC
        LIMIT 2000
      `;
      params = [];
    }
    const result = await pool.query(query, params);
    const formatted = result.rows.map(r => ({
      type: r.type,
      agent_id: r.hostname,
      payload: r.payload,
      timestamp: r.received_at
    }));
    res.json(formatted);
  } catch (err) {
    console.error("Events fetch failed:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});

app.get('/api/assessments', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT a.*, ag.hostname 
      FROM assessments a 
      JOIN agents ag ON a.agent_id = ag.id 
      ORDER BY a.started_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Get single assessment by ID
app.get('/api/assessments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(`
      SELECT a.*, ag.hostname 
      FROM assessments a 
      JOIN agents ag ON a.agent_id = ag.id 
      WHERE a.id = $1
    `, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Assessment not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Failed to get assessment:', err);
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Assessment history for one agent, newest first. The Reports UI used to build
// its whole view from live WebSocket events, which meant a dashboard restart
// wiped the visible history â€” the rows below survive restarts.
app.get('/api/agents/:hostname/assessments', async (req, res) => {
  try {
    const { hostname } = req.params;
    const agentRes = await pool.query('SELECT id FROM agents WHERE hostname = $1', [hostname]);
    if (agentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    const result = await pool.query(`
      SELECT a.*,
             (SELECT COUNT(*) FROM results r WHERE r.assessment_id = a.id) AS result_count
      FROM assessments a
      WHERE a.agent_id = $1
      ORDER BY a.started_at DESC
    `, [agentRes.rows[0].id]);
    res.json(result.rows);
  } catch (err) {
    console.error('Failed to get agent assessments:', err);
    res.status(500).json({ error: 'Failed to get agent assessments' });
  }
});

// Every module result for one assessment. Returns artifacts and notes as
// separate columns so historical rows written before the artifacts column
// existed (where paths were JSON-encoded into notes) can still be read back.
app.get('/api/assessments/:id/results', async (req, res) => {
  try {
    const { id } = req.params;
    const assessmentRes = await pool.query('SELECT id FROM assessments WHERE id = $1', [id]);
    if (assessmentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Assessment not found' });
    }
    const result = await pool.query(`
      SELECT r.*, a.profile, a.started_at, a.modules, ag.hostname
      FROM results r
      JOIN assessments a ON a.id = r.assessment_id
      JOIN agents ag ON ag.id = a.agent_id
      WHERE r.assessment_id = $1
      ORDER BY r.recorded_at ASC
    `, [id]);
    // `mitre` has no dedicated column: the agent's MITRE ID is stored JSON-encoded
    // inside `notes`. Surface it as a real field so the report can group by
    // technique instead of every row showing a blank MITRE. Falls back to the
    // recorded timestamp when the blob predates it.
    res.json(result.rows.map((row) => {
      let mitre = null;
      if (row.notes) {
        try {
          const parsed = JSON.parse(row.notes);
          mitre = parsed && parsed.mitre ? parsed.mitre : null;
        } catch {
          // notes is plain prose, not JSON â€” leave mitre null.
        }
      }
      return {
        ...row,
        mitre,
        recorded_ts: row.recorded_at,
      };
    }));
  } catch (err) {
    console.error('Failed to get assessment results:', err);
    res.status(500).json({ error: 'Failed to get assessment results' });
  }
});

// Structured findings for one assessment run, in the consulting-report shape:
// each result becomes a finding with a deterministic severity plus
// observation / impact / recommendation.
//
// This exists because the only place that structure lived was a Gemini prompt,
// so severities were whatever the model wrote for a given run and could not
// be filtered, compared or reproduced. Severity here is derived from the
// recorded verdict (see finding-taxonomy.js) and never invented.
app.get('/api/assessments/:id/findings', async (req, res) => {
  try {
    const { id } = req.params;
    const assessmentRes = await pool.query(`
      SELECT a.id, a.profile, a.duration_days, a.modules, a.test_type,
             a.started_at, a.completed_at, a.status, a.score, a.passed, a.failed,
             ag.hostname, ag.vendor
      FROM assessments a
      JOIN agents ag ON ag.id = a.agent_id
      WHERE a.id = $1
    `, [id]);
    if (assessmentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Assessment not found' });
    }
    const assessment = assessmentRes.rows[0];

    const result = await pool.query(`
      SELECT r.*, a.started_at
      FROM results r
      JOIN assessments a ON a.id = r.assessment_id
      WHERE r.assessment_id = $1
      ORDER BY r.recorded_at ASC
    `, [id]);

    // results rows have no mitre column — the agent's ID is JSON-encoded inside
    // `notes`. Parse it out here so the taxonomy can group by technique.
    const rows = result.rows.map((row) => {
      let mitre = null;
      if (row.notes) {
        try {
          const parsed = JSON.parse(row.notes);
          mitre = parsed && parsed.mitre ? parsed.mitre : null;
        } catch {
          // notes is prose, not JSON — leave mitre null.
        }
      }
      return { ...row, mitre };
    });

    const findings = buildFindings(rows);
    const counts = summariseBySeverity(findings);

    res.json({
      assessment: {
        id: assessment.id,
        hostname: assessment.hostname,
        vendor: assessment.vendor || null,
        profile: assessment.profile,
        test_type: assessment.test_type,
        duration_days: assessment.duration_days,
        modules: assessment.modules,
        status: assessment.status,
        score: assessment.score,
        passed: assessment.passed,
        failed: assessment.failed,
        started_at: assessment.started_at,
        completed_at: assessment.completed_at,
      },
      counts,
      total: findings.length,
      findings,
    });
  } catch (err) {
    console.error('Failed to build assessment findings:', err);
    res.status(500).json({ error: 'Failed to build assessment findings' });
  }
});

// Aggregated view for one agent: one row per assessment run, grouped by
// profile so a rapid and a performance run stay distinguishable over time.
app.get('/api/agents/:hostname/summary', async (req, res) => {
  try {
    const { hostname } = req.params;
    const agentRes = await pool.query('SELECT id FROM agents WHERE hostname = $1', [hostname]);
    if (agentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    const agentId = agentRes.rows[0].id;
    const runs = await pool.query(`
      SELECT a.id, a.profile, a.test_type, a.status, a.score, a.score_source,
             a.passed, a.failed, a.skipped,
             a.started_at, a.completed_at,
             COUNT(r.id) AS result_count,
             COUNT(r.id) FILTER (WHERE r.passed)  AS pass_count,
             COUNT(r.id) FILTER (WHERE NOT r.passed) AS fail_count
      FROM assessments a
      LEFT JOIN results r ON r.assessment_id = a.id
      WHERE a.agent_id = $1
      GROUP BY a.id
      ORDER BY a.started_at DESC
    `, [agentId]);

    const byProfile = await pool.query(`
      SELECT a.profile,
             COUNT(*)              AS run_count,
             AVG(a.score)::float   AS avg_score,
             MAX(a.started_at)     AS last_run
      FROM assessments a
      WHERE a.agent_id = $1 AND a.score IS NOT NULL
      GROUP BY a.profile
      ORDER BY last_run DESC
    `, [agentId]);

    // Blackbox vs whitebox comparison â€” these measure different things, so a
    // single blended score would be misleading.
    const byTestType = await pool.query(`
      SELECT COALESCE(a.test_type, 'unspecified') AS test_type,
             COUNT(DISTINCT a.id)   AS run_count,
             AVG(a.score)::float    AS avg_score,
             MIN(a.score)::float    AS min_score,
             MAX(a.score)::float    AS max_score,
             MAX(a.started_at)      AS last_run
      FROM assessments a
      WHERE a.agent_id = $1 AND a.score IS NOT NULL
      GROUP BY COALESCE(a.test_type, 'unspecified')
      ORDER BY last_run DESC
    `, [agentId]);

    // Per-module-category pass rate across all runs, so "which module family is
    // consistently failing" is answerable without pulling every result row.
    const byCategory = await pool.query(`
      SELECT COALESCE(r.category, r.module_name, 'unknown') AS category,
             COUNT(*)::int                                AS total,
             COUNT(*) FILTER (WHERE r.passed)::int         AS passed,
             COUNT(*) FILTER (WHERE NOT r.passed)::int     AS failed,
             ROUND(100.0 * COUNT(*) FILTER (WHERE r.passed) / NULLIF(COUNT(*), 0), 1) AS pass_rate
      FROM results r
      JOIN assessments a ON a.id = r.assessment_id
      WHERE a.agent_id = $1
      GROUP BY COALESCE(r.category, r.module_name, 'unknown')
      ORDER BY pass_rate ASC NULLS LAST, total DESC
    `, [agentId]);

    // Cross-tab: category performance split by test type. This is the view that
    // answers "does this EDR behave differently when it knows the agent is there".
    const categoryByTestType = await pool.query(`
      SELECT COALESCE(r.category, r.module_name, 'unknown')          AS category,
             COALESCE(r.test_type, a.test_type, 'unspecified')       AS test_type,
             COUNT(*)::int                                           AS total,
             ROUND(100.0 * COUNT(*) FILTER (WHERE r.passed) / NULLIF(COUNT(*), 0), 1) AS pass_rate
      FROM results r
      JOIN assessments a ON a.id = r.assessment_id
      WHERE a.agent_id = $1
      GROUP BY COALESCE(r.category, r.module_name, 'unknown'),
               COALESCE(r.test_type, a.test_type, 'unspecified')
      ORDER BY category, test_type
    `, [agentId]);

    // Overall 0-100 scope score across all recorded results.
    const overall = await pool.query(`
      SELECT COUNT(*)::int AS total,
             COUNT(*) FILTER (WHERE r.passed)::int AS passed,
             COUNT(*) FILTER (WHERE NOT r.passed)::int AS failed,
             ROUND(100.0 * COUNT(*) FILTER (WHERE r.passed) / NULLIF(COUNT(*), 0), 1) AS score
      FROM results r
      JOIN assessments a ON a.id = r.assessment_id
      WHERE a.agent_id = $1
    `, [agentId]);

    res.json({
      hostname,
      overall: overall.rows[0],
      runs: runs.rows,
      by_profile: byProfile.rows,
      by_test_type: byTestType.rows,
      by_category: byCategory.rows,
      category_by_test_type: categoryByTestType.rows,
    });
  } catch (err) {
    console.error('Failed to get agent summary:', err);
    res.status(500).json({ error: 'Failed to get agent summary' });
  }
});

// After creating assessment, send start_assessment command via WebSocket
app.post('/api/assessments', async (req, res) => {
  let { agent_id, profile, duration_days, modules, allow_reboot, test_type } = req.body;
  try {
    // Two different identifiers are in play and must not be confused:
    //  - the DB primary key (a UUID) used for the assessments row
    //  - the hostname, which is what the WebSocket registry keys sockets on
    // Resolving one into the other used to overwrite agent_id with the UUID and
    // then pass that UUID to sendToAgent, which found no socket and dropped the
    // command: the row was created but the agent never ran.
    const identity = await resolveAgentIdentity(agent_id, async (value, byUuid) => {
      const r = await pool.query(
        byUuid
          ? 'SELECT id, hostname FROM agents WHERE id = $1'
          : 'SELECT id, hostname FROM agents WHERE hostname = $1',
        [value],
      );
      return r.rows[0];
    });
    if (!identity) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    agent_id = identity.dbId;
    const socketId = identity.socketId;

    const result = await pool.query(`
      INSERT INTO assessments (agent_id, profile, duration_days, modules, status, allow_reboot, test_type)
      VALUES ($1, $2, $3, $4, 'running', $5, $6)
      RETURNING *
    `, [agent_id, profile, duration_days, modules, allow_reboot || false, test_type || null]);

    // Mark the endpoint as under test. ws-server drops this back to 'watch'
    // when assessment_done arrives.
    await pool.query(
      `UPDATE agents SET state = 'assessment', assessment_id = $1 WHERE id = $2`,
      [result.rows[0].id, agent_id],
    );

    // Send start_assessment command via WebSocket
    const { registry } = await import('./agent-registry.js');
    const modulesStr = Array.isArray(modules) && modules.length ? modules.join(',') : 'all';
    console.log(`📋 start_assessment → agent="${socketId}" profile="${profile}" test_type="${test_type}" days="${duration_days ?? 1}" modules="${modulesStr}" allow_reboot="${allow_reboot ?? false}"`);
    const sent = registry.sendToAgent(socketId, {
      type: 'start_assessment',
      agent_id: socketId,
      profile,
      test_type: test_type || 'blackbox',
      modules,
      days: duration_days || 1,
      allow_reboot: allow_reboot || false,
    });
    if (!sent.ok) {
      console.error('Failed to send start_assessment:', sent.error);
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Failed to create assessment:', err);
    res.status(500).json({ error: 'Failed to create assessment' });
  }
});

// Stop a running assessment. Flips the assessment row to 'stopped' and
// sends a stop_assessment command to the agent over the WebSocket so the
// runner can exit cleanly. Returns 409 if the assessment is not running
// (already stopped/completed) or the agent is offline.
app.post('/api/assessments/:id/stop', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `UPDATE assessments SET status = 'stopped', completed_at = NOW()
       WHERE id = $1 AND status = 'running'
       RETURNING id, agent_id`,
      [id],
    );
    if (result.rows.length === 0) {
      return res.status(409).json({ error: 'Assessment not running or does not exist' });
    }
    // assessments.agent_id is the DB UUID; the WebSocket registry is keyed by
    // hostname, so join for it rather than sending to a key that does not exist.
    const { agent_id } = result.rows[0];
    const hostRes = await pool.query('SELECT hostname FROM agents WHERE id = $1', [agent_id]);
    const socketId = hostRes.rows[0]?.hostname;
    const { registry } = await import('./agent-registry.js');
    const sent = socketId
      ? registry.sendToAgent(socketId, { type: 'stop_assessment', assessment_id: id })
      : { ok: false, error: `No hostname for agent ${agent_id}` };
    if (!sent.ok) {
      return res.status(409).json({ error: sent.error });
    }
    res.json({ success: true, message: 'Stop command sent to agent' });
  } catch (err) {
    console.error('Failed to stop assessment:', err);
    res.status(500).json({ error: 'Failed to stop assessment' });
  }
});

app.delete('/api/agents/:hostname', async (req, res) => {
  const { hostname } = req.params;
  try {
    const agentRes = await pool.query('SELECT id FROM agents WHERE hostname = $1', [hostname]);
    if (agentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    const agentId = agentRes.rows[0].id;
    
    // Manual cascade since foreign keys might not have ON DELETE CASCADE.
    // results references assessments, so it must be cleared first.
    await pool.query('DELETE FROM events WHERE agent_id = $1', [agentId]);
    await pool.query(
      'DELETE FROM results WHERE assessment_id IN (SELECT id FROM assessments WHERE agent_id = $1)',
      [agentId],
    );
    await pool.query('DELETE FROM assessments WHERE agent_id = $1', [agentId]);
    await pool.query('DELETE FROM agents WHERE id = $1', [agentId]);
    
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to delete agent:', err);
    res.status(500).json({ error: 'Database delete failed' });
  }
});

app.post('/api/generate-report', async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'GEMINI_API_KEY environment variable is not set in .env' });
  }
  
  const { format = 'html', ...reportData } = req.body;
  
  const basePrompt = `You are an elite Security Assessor. 
You are performing a standalone configuration review and EDR assessment based on AgentIde telemetry.
You will be given raw test results in JSON format.

You must generate a professional report that strictly follows the GTCO Standalone Configuration Review format.

Requirements:
- Include an "Introduction" and "Scope of Assessment" section.
- Scope of Assessment must include: the profile, the test type, the modules actually tested, the target EDR vendor, and the start/finish timestamps.
- CRITICAL: report ONLY what is present in the JSON below. If a field is null or empty (for example target_vendors is empty because no vendor was detected), state plainly that it was not recorded or not detected. NEVER infer, guess, or substitute a plausible vendor, module list, or profile. A fabricated scope makes the whole report unreliable.
- For each finding (especially FAILED tests), structure it exactly as:
  <h3>[Index]. [Module Name: Action] - [SEVERITY]</h3>
  (Severity should be CRITICAL or HIGH for fails, colored red. LOW for passes, colored green).
  <div style="background-color: #2E5FA2; color: white; padding: 4px 8px; font-weight: bold; margin-top: 10px;">Observation</div>
  <ul><li><strong>Time of Execution:</strong> [Extract EXACT timestamp from the JSON]</li><li>[Explain what happened]</li></ul>
  <div style="background-color: #2E5FA2; color: white; padding: 4px 8px; font-weight: bold; margin-top: 10px;">Impact</div>
  <ul><li>[Explain the risk]</li></ul>
  <div style="background-color: #2E5FA2; color: white; padding: 4px 8px; font-weight: bold; margin-top: 10px;">Recommendation</div>
  <ul><li>[Remediation step]</li></ul>

Raw Data:
${JSON.stringify(reportData, null, 2)}`;

  let prompt = basePrompt;
  if (format === 'markdown') {
    prompt += '\n\nReturn ONLY valid Markdown. Use proper Markdown syntax with headers, tables, code blocks, and proper formatting.';
  } else if (format === 'docx') {
    prompt += '\n\nReturn ONLY valid Markdown that can be converted to DOCX. Use proper Markdown syntax with headers, tables, code blocks, and proper formatting. The output will be converted to DOCX format.';
  } else {
    prompt += '\n\nReturn ONLY valid HTML inside <html><body>...</body></html> tags. Do not include markdown blocks like ```html.';
  }

  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.2 }
      })
    });
    const data = await response.json();
    if (!data.candidates || data.candidates.length === 0) {
      throw new Error(data.error?.message || 'Empty AI response');
    }
    let content = data.candidates[0].content.parts[0].text;
    if (content.startsWith('```html')) content = content.substring(7);
    if (content.startsWith('```markdown')) content = content.substring(10);
    if (content.startsWith('```')) content = content.substring(3);
    if (content.endsWith('```')) content = content.slice(0, -3);
    
    if (format === 'markdown') {
      res.json({ markdown: content.trim() });
    } else if (format === 'docx') {
      res.json({ docx: content.trim() });
    } else {
      res.json({ html: content.trim() });
    }
  } catch (err) {
    console.error('AI Generation error:', err);
    res.status(500).json({ error: 'Failed to generate AI report' });
  }
});


app.post('/api/generate-remediation', async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'GEMINI_API_KEY environment variable is not set in .env' });
  }
  
  const finding = req.body;
  const prompt = `You are an elite Blue Team / Defensive Security Engineer.
An EDR assessment has identified a security gap on a Windows endpoint. 
The EDR FAILED to block the following adversarial behavior:

Module/Test: ${finding.title || finding.module}
Details: ${finding.detail}
MITRE ATT&CK: ${finding.mitre || 'Unknown'}

Please provide a highly actionable, technical remediation to close this gap. 
Provide the exact Group Policy Object (GPO) configuration, PowerShell remediation script, or Intune policy logic needed to prevent this technique from succeeding in the future.

Keep it concise. Use Markdown formatting. Return ONLY the markdown.`;

  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.1 }
      })
    });
    const data = await response.json();
    if (!data.candidates || data.candidates.length === 0) {
      throw new Error(data.error?.message || 'Empty AI response');
    }
    const markdown = data.candidates[0].content.parts[0].text;
    res.json({ remediation: markdown.trim() });
  } catch (err) {
    console.error('AI Remediation Generation error:', err);
    res.status(500).json({ error: 'Failed to generate remediation' });
  }
});

// â”€â”€ Agent Management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/agents/:hostname/restart', async (req, res) => {
  try {
    const { hostname } = req.params;
    const agentRes = await pool.query('SELECT id FROM agents WHERE hostname = $1', [hostname]);
    if (agentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    // Send restart command via WebSocket. The registry reports whether the
    // command was actually delivered â€” an offline agent must return an error,
    // not a "success" that silently did nothing.
    const { registry } = await import('./agent-registry.js');
    const sent = registry.sendToAgent(hostname, { type: 'restart_agent' });
    if (!sent.ok) {
      return res.status(409).json({ error: sent.error });
    }
    res.json({ success: true, message: 'Restart command sent' });
  } catch (err) {
    console.error('Failed to send restart:', err);
    res.status(500).json({ error: 'Failed to send restart command' });
  }
});

// Manual agent self-update push. The browser's Host header identifies the
// dashboard address the agent can reach (agents commonly connect to the same
// address the operator uses).
app.post('/api/agents/:hostname/update', async (req, res) => {
  try {
    const { hostname } = req.params;
    const agentRes = await pool.query('SELECT id FROM agents WHERE hostname = $1', [hostname]);
    if (agentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    const cmd = buildUpdateCommand(req.headers.host, '');
    if (!cmd) {
      return res.status(503).json({ error: 'No agent build available to push' });
    }
    const { registry } = await import('./agent-registry.js');
    const sent = registry.sendToAgent(hostname, cmd);
    if (!sent.ok) {
      return res.status(409).json({ error: sent.error });
    }
    res.json({ success: true, message: `Update to v${cmd.version} sent` });
  } catch (err) {
    console.error('Failed to send update:', err);
    res.status(500).json({ error: 'Failed to send update command' });
  }
});

app.post('/api/agents/:hostname/uninstall', async (req, res) => {
  try {
    const { hostname } = req.params;
    const agentRes = await pool.query('SELECT id FROM agents WHERE hostname = $1', [hostname]);
    if (agentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    // Send uninstall command via WebSocket
    const { registry } = await import('./agent-registry.js');
    const sent = registry.sendToAgent(hostname, { type: 'uninstall_agent' });
    if (!sent.ok) {
      return res.status(409).json({ error: sent.error });
    }
    res.json({ success: true, message: 'Uninstall command sent' });
  } catch (err) {
    console.error('Failed to send uninstall:', err);
    res.status(500).json({ error: 'Failed to send uninstall command' });
  }
});

app.get('/api/agents/:hostname/config', async (req, res) => {
  try {
    const { hostname } = req.params;
    const agentRes = await pool.query('SELECT * FROM agents WHERE hostname = $1', [hostname]);
    if (agentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    const agent = agentRes.rows[0];
    // Return config (mask sensitive fields)
    res.json({
      dashboard_url: agent.dashboard_url,
      log_path: agent.log_path,
      allow_reboot: agent.allow_reboot,
      // token is intentionally not returned
    });
  } catch (err) {
    console.error('Failed to get agent config:', err);
    res.status(500).json({ error: 'Failed to get agent config' });
  }
});

// â”€â”€ Server Management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/health', async (req, res) => {
  try {
    const dbRes = await pool.query('SELECT 1');
    const mem = process.memoryUsage();
    res.json({
      status: 'ok',
      uptime: process.uptime(),
      version: process.env.npm_package_version || '0.1.0',
      node_version: process.version,
      memory: {
        heapUsed: mem.heapUsed,
        heapTotal: mem.heapTotal,
        external: mem.external,
      },
      db_connected: dbRes.rowCount === 1,
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const [
      agentsRes,
      onlineAgentsRes,
      assessmentsRes,
      runningAssessmentsRes,
      eventsRes,
      dbSizeRes,
      eventsTableSizeRes,
    ] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM agents'),
      pool.query("SELECT COUNT(*) FROM agents WHERE status = 'online'"),
      pool.query('SELECT COUNT(*) FROM assessments'),
      pool.query("SELECT COUNT(*) FROM assessments WHERE status = 'running'"),
      pool.query('SELECT COUNT(*) FROM events'),
      pool.query('SELECT pg_database_size(current_database()) as size'),
      pool.query("SELECT pg_total_relation_size('events') as size"),
    ]);
    res.json({
      total_agents: parseInt(agentsRes.rows[0].count),
      online_agents: parseInt(onlineAgentsRes.rows[0].count),
      total_assessments: parseInt(assessmentsRes.rows[0].count),
      running_assessments: parseInt(runningAssessmentsRes.rows[0].count),
      total_events: parseInt(eventsRes.rows[0].count),
      db_size: parseInt(dbSizeRes.rows[0].size),
      events_table_size: parseInt(eventsTableSizeRes.rows[0].size),
    });
  } catch (err) {
    console.error('Failed to get stats:', err);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

app.post('/api/admin/retention', async (req, res) => {
  try {
    const { days } = req.body;
    if (!days || days < 1 || days > 365) {
      return res.status(400).json({ error: 'Invalid retention days (1-365)' });
    }
    // Update environment variable (runtime only, persists until restart)
    process.env.EVENT_RETENTION_DAYS = String(days);
    res.json({ success: true, days });
  } catch (err) {
    console.error('Failed to set retention:', err);
    res.status(500).json({ error: 'Failed to set retention' });
  }
});

app.post('/api/admin/prune', async (req, res) => {
  try {
    const retentionDays = Number(process.env.EVENT_RETENTION_DAYS) || 30;
    const result = await pool.query(
      `DELETE FROM events WHERE received_at < NOW() - ($1 * INTERVAL '1 day')`,
      [retentionDays],
    );
    res.json({ deleted: result.rowCount });
  } catch (err) {
    console.error('Failed to prune events:', err);
    res.status(500).json({ error: 'Failed to prune events' });
  }
});

// Sanitized server config for the UI (no secrets)
app.get('/api/admin/config', async (req, res) => {
  res.json({
    node_env: process.env.NODE_ENV || 'development',
    port: process.env.PORT || '8443',
    pghost: process.env.PGHOST || 'localhost',
    pgport: process.env.PGPORT || '5432',
    pgdatabase: process.env.PGDATABASE || 'postgres',
    cors_origins: process.env.CORS_ORIGINS || '',
    event_retention_days: process.env.EVENT_RETENTION_DAYS || '30',
    // Secrets are intentionally omitted: PGPASSWORD, AGENT_TOKEN, ADMIN_PASSWORD, GEMINI_API_KEY
  });
});

// Serve the compiled React UI
const distPath = path.join(process.cwd(), 'dist');
app.use(express.static(distPath));

// Catch-all route for React Router (sends index.html for any unrecognized path)
app.get('*', (req, res) => {
  res.sendFile(path.join(distPath, 'index.html'));
});

const certsDir = path.join(process.cwd(), 'certs');
const keyPath = path.join(certsDir, 'key.pem');
const certPath = path.join(certsDir, 'cert.pem');

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  console.error('âŒ TLS certificates not found. Run `npm run cert:generate` first.');
  process.exit(1);
}

const options = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath)
};

const server = https.createServer(options, app);
setupWebSockets(server);

// â”€â”€ Event retention â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Prune raw telemetry older than EVENT_RETENTION_DAYS (default 30)
// so the events table doesn't grow unboundedly.
const retentionDays = Number(process.env.EVENT_RETENTION_DAYS) || 30;
async function pruneEvents() {
  try {
    await pool.query(
      `DELETE FROM events WHERE received_at < NOW() - ($1 * INTERVAL '1 day')`,
      [retentionDays],
    );
  } catch (err) {
    console.error('Event retention prune failed:', err);
  }
}
await pruneEvents();
const retentionTimer = setInterval(pruneEvents, 60 * 60 * 1000);
retentionTimer.unref();

const PORT = process.env.PORT || 8443;
if (!process.env.AGENT_TOKEN) {
  console.warn('âš ï¸  AGENT_TOKEN is not set â€” agent connections to /agent will be REJECTED. Set it in ../.env');
}
if (!process.env.ADMIN_PASSWORD) {
  console.warn('âš ï¸  ADMIN_PASSWORD not set â€” using insecure default "agentide-dev". Set it in ../.env');
}

// Collect non-internal IPv4 addresses so we can print the exact URLs an
// operator must hand to `agentide.exe -install -dashboard ...`. This is the
// single most common reason an agent never shows up: it was pointed at the
// wrong IP (or at localhost, which resolve to the agent itself).
function lanAddresses() {
  const addrs = [];
  for (const ifaces of Object.values(os.networkInterfaces())) {
    for (const iface of ifaces || []) {
      if (iface.family === 'IPv4' && !iface.internal) addrs.push(iface.address);
    }
  }
  return addrs;
}

server.listen(PORT, () => {
  console.log(`ðŸš€ AgentIde Dashboard (TLS) running on https://localhost:${PORT}`);
  console.log(`ðŸ”Œ WebSocket Hub running on wss://localhost:${PORT}/dashboard and /agent`);

  const addrs = lanAddresses();
  // Prefer the hostname: it resolves to whatever IP the host currently has,
  // so it survives roaming Wi-Fi / bridged VMs that jump subnets.
  const hostname = os.hostname();
  console.log(`ðŸ›¡ï¸  Agent must connect to the dashboard host, NOT localhost.`);
  console.log(`      (preferred â€” survives IP changes)  agentide.exe -install -dashboard wss://${hostname}:${PORT} -token <AGENT_TOKEN>`);
  if (addrs.length === 0) {
    console.log('      (no external IPv4 interface detected â€” agents on other hosts cannot reach this server)');
  } else {
    console.log('      or by IP (use if the agent cannot resolve the hostname):');
    for (const ip of addrs) {
      console.log(`      agentide.exe -install -dashboard wss://${ip}:${PORT} -token <AGENT_TOKEN>`);
    }
  }
  console.log(`ðŸ©º From the agent host, verify reachability with: curl -k https://${hostname}:${PORT}/healthz`);
});
