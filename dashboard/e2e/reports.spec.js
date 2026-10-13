import { test, expect } from '@playwright/test';

/**
 * Reports result rendering.
 *
 * Regression cover for two bugs that made assessment results unreadable:
 *   1. `detail: e.payload?.detail || JSON.stringify(e.payload)` dumped a raw
 *      JSON object into the detail column whenever a module sent no `detail`.
 *   2. The verdict was derived from the boolean `passed`, which cannot express
 *      BLOCKED_BY_EDR, TIMEOUT, ERROR or INFO - so an INFO acknowledgement
 *      (an agent restarting itself, a self-update) rendered as a red FAIL.
 *
 * The page now renders persisted results from /api/assessments/:id/results
 * rather than live WebSocket events; see reports-runs.spec.js for the run
 * selector.
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

const MODULE_RESULTS = [
  { id: 'r1', module_name: 'malware', action: 'PASS', passed: true, mitre: 'T1204.002', detail: 'EICAR execution blocked by endpoint protection', test_type: 'blackbox', elapsed_ms: 15094, notes: 'ok', artifacts: [], recorded_at: '2026-10-13T09:06:16Z' },
  { id: 'r2', module_name: 'identity', action: 'FAIL', passed: false, mitre: 'T1110.003', detail: 'No alert raised for repeated failed logins', test_type: 'blackbox', elapsed_ms: 2225, notes: 'ok', artifacts: [], recorded_at: '2026-10-13T09:06:56Z' },
  // No `detail` at all - the case that used to print raw JSON.
  { id: 'r3', module_name: 'antitamper', action: 'PASS', passed: true, mitre: 'T1562.001', detail: '', test_type: 'blackbox', elapsed_ms: 224, notes: 'ok', artifacts: [], recorded_at: '2026-10-13T09:06:56Z' },
  // Informational ack: an action taken, not a control tested.
  { id: 'r4', module_name: 'remote_control', action: 'INFO', passed: false, mitre: 'N/A', detail: 'Restart requested; the agent service is restarting', test_type: 'system', elapsed_ms: 0, notes: 'ok', artifacts: [], recorded_at: '2026-10-13T09:08:15Z' },
];

async function setup(page, { moduleResults = MODULE_RESULTS } = {}) {
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
    if (/^\/api\/assessments\/.+\/results$/.test(path)) {
      return json(moduleResults);
    }
    return json({});
  });

  await page.goto('/reports');
  await expect(page.getByText(/Assessment Modules/i).first()).toBeVisible();
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
  await expect(page.getByText('antitamper').first()).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).toMatch(/No additional detail reported|result: PASS|mitre:/i);
});

test('INFO acknowledgements do not render as FAIL', async ({ page }) => {
  await setup(page);
  const body = await page.locator('body').innerText();
  expect(body).toContain('Restart requested; the agent service is restarting');

  // An INFO badge is rendered for the ack and is not relabelled FAIL.
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
  await expect(page.getByText('identity').first()).toBeVisible();
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