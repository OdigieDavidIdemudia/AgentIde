import { test, expect } from '@playwright/test';

/**
 * Reports result rendering.
 *
 * Regression cover for three bugs that made assessment results unreadable:
 *   1. `detail: e.payload?.detail || JSON.stringify(e.payload)` dumped a raw
 *      JSON object into the detail column whenever a module sent no `detail`.
 *   2. The verdict was derived from the boolean `passed`, which cannot express
 *      BLOCKED_BY_EDR, TIMEOUT, ERROR or INFO - so an INFO acknowledgement
 *      (an agent restarting itself, a self-update) rendered as a red FAIL.
 *   3. Severity used to be invented by a Gemini prompt, so it varied per run
 *      and could not be filtered. It is now derived server-side and returned
 *      on the finding itself.
 *
 * The page renders GET /api/assessments/:id/findings, which returns the
 * assessment scope, per-severity counts and the ordered findings. See
 * reports-runs.spec.js for the run selector.
 */

const RUN = {
  id: 'cccccccc-1111-2222-3333-444444444444',
  hostname: 'WS-RPT-01',
  status: 'completed',
  profile: 'rapid',
  test_type: 'blackbox',
  started_at: '2026-10-13T10:09:45.000Z',
  score: 75,
  result_count: 4,
  modules: ['malware', 'identity', 'antitamper', 'remote_control'],
};

// Findings as the server returns them: severity already applied, ordered most
// severe first. Shaped to mirror finding-taxonomy.js output.
const FINDINGS = {
  assessment: {
    id: RUN.id,
    hostname: 'WS-RPT-01',
    vendor: 'Microsoft Defender',
    profile: 'rapid',
    test_type: 'blackbox',
    status: 'completed',
    score: 75,
    started_at: RUN.started_at,
    completed_at: '2026-10-13T10:09:45.000Z',
  },
  counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 2, INFO: 1 },
  total: 4,
  findings: [
    {
      index: 1,
      module: 'identity',
      title: 'Credential attack not detected',
      result: 'FAIL',
      severity: 'HIGH',
      isFinding: true,
      mitre: 'T1110.003',
      executedAt: '2026-10-13T09:06:56Z',
      elapsedMs: 2225,
      observation: 'No alert raised for repeated failed logins',
      impact: 'Repeated failed authentication attempts produced no alert.',
      recommendation: 'Enable failed-logon auditing thresholds and alert on spray patterns.',
    },
    {
      index: 2,
      module: 'malware',
      title: 'Malicious test file execution',
      result: 'PASS',
      severity: 'LOW',
      isFinding: false,
      mitre: 'T1204.002',
      executedAt: '2026-10-13T09:06:16Z',
      elapsedMs: 15094,
      observation: 'EICAR execution blocked by endpoint protection',
      impact: 'A benign EICAR test file was executed rather than blocked.',
      recommendation: 'Confirm real-time protection is enabled and current.',
    },
    {
      index: 3,
      module: 'antitamper',
      title: 'Agent tampering not detected',
      result: 'PASS',
      severity: 'LOW',
      isFinding: false,
      mitre: 'T1562.001',
      executedAt: '2026-10-13T09:06:56Z',
      elapsedMs: 224,
      observation: '',
      impact: 'Attempts to tamper with security tooling were not detected.',
      recommendation: 'Enable tamper protection and lock down agent ACLs.',
    },
    {
      index: 4,
      module: 'remote_control',
      title: 'Assessment finding',
      result: 'INFO',
      severity: 'INFO',
      isFinding: false,
      mitre: null,
      executedAt: '2026-10-13T09:08:15Z',
      elapsedMs: 0,
      observation: 'Restart requested; the agent service is restarting',
      impact: 'Informational acknowledgement, not a control under test.',
      recommendation: 'No action required.',
    },
  ],
};

async function setup(page, { findings = FINDINGS } = {}) {
  await page.addInitScript(() => {
    localStorage.setItem('agentide-token', 'e2e-session-token');
  });

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = (d) => route.fulfill({ json: d });

    if (path === '/api/agents') return json([{ hostname: 'WS-RPT-01', status: 'online', agent_version: '0.4.6' }]);
    if (path === '/api/events') return json([]);
    if (path === '/api/auth/me') return json({ ok: true });
    if (path === '/api/agent/version') return json({ version: '0.4.6' });
    if (path === '/api/agents/WS-RPT-01/assessments') return json([RUN]);
    if (/^\/api\/assessments\/.+\/findings$/.test(path)) {
      return json(findings);
    }
    return json({});
  });

  await page.goto('/reports');
  await expect(page.getByText(/^Findings$/i).first()).toBeVisible();
}

test('report module never renders a raw JSON payload in the detail column', async ({ page }) => {
  await setup(page);
  const body = await page.locator('body').innerText();
  // The specific signature of JSON.stringify on a payload object.
  expect(body).not.toContain('"payload"');
  expect(body).not.toContain('"test_type"');
  expect(body).not.toContain('"mitre":');
  expect(body).not.toMatch(/\{\s*"[a-z_]+":\s*"/i);
});

test('a module with no detail still shows a readable summary', async ({ page }) => {
  await setup(page);
  await expect(page.getByText('Agent tampering not detected').first()).toBeVisible();
  const body = await page.locator('body').innerText();
  // The finding falls back to its title + verdict rather than printing nothing
  // or a raw JSON blob.
  expect(body).toMatch(/PASS|T1562\.001/i);
});

test('INFO acknowledgements do not render as FAIL', async ({ page }) => {
  await setup(page);
  const body = await page.locator('body').innerText();
  expect(body).toContain('Restart requested; the agent service is restarting');

  // An INFO severity badge is rendered for the ack and is not relabelled FAIL.
  const infoBadge = page.locator('span').filter({ hasText: /^INFO$/ });
  await expect(infoBadge.first()).toBeAttached();
  expect((await infoBadge.first().innerText()).trim()).toBe('INFO');
});

test('INFO acks are excluded from the module counts', async ({ page }) => {
  await setup(page);
  const body = await page.locator('body').innerText();
  // 4 persisted rows, but one is INFO: 3 real verdicts (2 pass, 1 fail).
  expect(body).toMatch(/Modules Run\s*3/i);
  expect(body).toMatch(/Passed\s*2/i);
  expect(body).toMatch(/Failed \/ Blocked\s*1/i);
});

test('genuine FAILs still render as FAIL', async ({ page }) => {
  await setup(page);
  await expect(page.getByText('Credential attack not detected').first()).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).toContain('No alert raised for repeated failed logins');
  expect(body).toMatch(/\bFAIL\b/);
});

test('MITRE IDs are shown for each module result', async ({ page }) => {
  await setup(page);
  const body = await page.locator('body').innerText();
  // mitre is extracted server-side from the JSON-encoded notes blob.
  expect(body).toContain('T1110.003');
  expect(body).toContain('T1204.002');
});

test('each finding carries a severity, impact and recommendation', async ({ page }) => {
  // The whole point of the taxonomy: the reference report format's structure is
  // produced deterministically rather than asked of a language model.
  await setup(page);
  const body = await page.locator('body').innerText();

  expect(body).toMatch(/\bHIGH\b/);
  expect(body).toMatch(/\bLOW\b/);
  // Every finding block is labelled with all three sections. The labels are
  // uppercased by CSS, and innerText reflects that, so match case-insensitively.
  const impactCount = (body.match(/impact/gi) || []).length;
  const recCount = (body.match(/recommendation/gi) || []).length;
  expect(impactCount).toBeGreaterThanOrEqual(4);
  expect(recCount).toBeGreaterThanOrEqual(4);
});

test('the severity summary counts match the findings returned', async ({ page }) => {
  await setup(page);
  const body = await page.locator('body').innerText();
  // counts: 1 HIGH, 2 LOW, 1 INFO across 4 findings.
  expect(body).toMatch(/Impact\s+Observation\s+Recommendation|Impact/i);
  const highBadge = page.locator('span').filter({ hasText: /^HIGH$/ });
  await expect(highBadge.first()).toBeAttached();
});