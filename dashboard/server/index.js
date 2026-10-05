import './env.js'; // must load .env before db.js creates the connection pool
import express from 'express';
import https from 'https';
import fs from 'fs';
import path from 'path';
import cors from 'cors';
import { setupWebSockets } from './ws-server.js';
import { pool } from './db.js';
import { issueToken, revokeToken, requireAuth, checkAdminCredentials, isLoginAllowed, registerLoginFailure } from './auth.js';

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const app = express();
// Same-origin by default; widen via CORS_ORIGINS (comma-separated).
app.use(cors(allowedOrigins.length > 0 ? { origin: allowedOrigins } : { origin: false }));

// DEBUG: log every request BEFORE body parsing
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

app.use(express.json());

// DEBUG: log after body parsing
app.use((req, res, next) => {
  if (Object.keys(req.body || {}).length > 0) {
    console.log(`[${new Date().toISOString()}] BODY:`, req.body);
  }
  next();
});

// ── Auth ──────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!isLoginAllowed(ip)) {
    return res.status(429).json({ error: 'Too many failed attempts — try again later' });
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

// Session validity check — used by the frontend to detect expiry.
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ ok: true }));

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

app.post('/api/assessments', async (req, res) => {
  let { agent_id, profile, duration_days, modules } = req.body;
  try {
    // If agent_id is a hostname instead of a UUID, resolve it
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(agent_id)) {
      const agentRes = await pool.query('SELECT id FROM agents WHERE hostname = $1', [agent_id]);
      if (agentRes.rows.length === 0) {
        return res.status(404).json({ error: 'Agent not found' });
      }
      agent_id = agentRes.rows[0].id;
    }

    const result = await pool.query(`
      INSERT INTO assessments (agent_id, profile, duration_days, modules, status)
      VALUES ($1, $2, $3, $4, 'running')
      RETURNING *
    `, [agent_id, profile, duration_days, modules]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Failed to create assessment:', err);
    res.status(500).json({ error: 'Failed to create assessment' });
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
    
    // Manual cascade since foreign keys might not have ON DELETE CASCADE
    await pool.query('DELETE FROM events WHERE agent_id = $1', [agentId]);
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
  
  const reportData = req.body;
  const prompt = `You are an elite Security Assessor. 
You are performing a standalone configuration review and EDR assessment based on AgentIde telemetry.
You will be given raw test results in JSON format.

You must generate a professional HTML report that strictly follows the GTCO Standalone Configuration Review format.

Requirements:
- Use the Abadi font family (or Arial as fallback).
- Include an "Introduction" and "Scope of Assessment" section.
- For each finding (especially FAILED tests), structure it exactly as:
  <h3>[Index]. [Module Name: Action] - [SEVERITY]</h3>
  (Severity should be CRITICAL or HIGH for fails, colored red. LOW for passes, colored green).
  <div style="background-color: #2E5FA2; color: white; padding: 4px 8px; font-weight: bold; margin-top: 10px;">Observation</div>
  <ul><li><strong>Time of Execution:</strong> [Extract EXACT timestamp from the JSON]</li><li>[Explain what happened]</li></ul>
  <div style="background-color: #2E5FA2; color: white; padding: 4px 8px; font-weight: bold; margin-top: 10px;">Impact</div>
  <ul><li>[Explain the risk]</li></ul>
  <div style="background-color: #2E5FA2; color: white; padding: 4px 8px; font-weight: bold; margin-top: 10px;">Recommendation</div>
  <ul><li>[Remediation step]</li></ul>

Return ONLY valid HTML inside <html><body>...</body></html> tags. Do not include markdown blocks like \`\`\`html.

Raw Data:
${JSON.stringify(reportData, null, 2)}`;

  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
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
    let htmlContent = data.candidates[0].content.parts[0].text;
    if (htmlContent.startsWith('```html')) htmlContent = htmlContent.substring(7);
    if (htmlContent.endsWith('```')) htmlContent = htmlContent.slice(0, -3);
    
    res.json({ html: htmlContent.trim() });
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
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
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
  console.error('❌ TLS certificates not found. Run `npm run cert:generate` first.');
  process.exit(1);
}

const options = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath)
};

const server = https.createServer(options, app);
setupWebSockets(server);

// ── Event retention ─────────────────────────────────────────────
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

const PORT = process.env.PORT || 8080;
if (!process.env.AGENT_TOKEN) {
  console.warn('⚠️  AGENT_TOKEN is not set — agent connections to /agent will be REJECTED. Set it in ../.env');
}
if (!process.env.ADMIN_PASSWORD) {
  console.warn('⚠️  ADMIN_PASSWORD not set — using insecure default "agentide-dev". Set it in ../.env');
}
server.listen(PORT, () => {
  console.log(`🚀 AgentIde Dashboard (TLS) running on https://localhost:${PORT}`);
  console.log(`🔌 WebSocket Hub running on wss://localhost:${PORT}/dashboard and /agent`);
});
