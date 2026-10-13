import { test, expect } from '@playwright/test';

/**
 * Reports module rendering.
 *
 * Regression cover for two bugs that made the report unreadable:
 *   1. `detail: e.payload?.detail || JSON.stringify(e.payload)` dumped a raw
 *      JSON object into the detail column whenever a module sent no `detail`.
 *   2. `passed` was treated as the verdict, so an INFO acknowledgement (a
 *      restart, a self-update) rendered as a red FAIL and dragged the score.
 */

const MODULE_RESULTS = [
  { module: 'malware', passed: true, result: 'PASS', mitre: 'T1204.002', detail: 'EICAR execution blocked by endpoint protection', test_type: 'blackbox', timestamp: '2026-10-13T09:06:16Z' },
  { module: 'identity', passed: false, result: 'FAIL', mitre: 'T1110.003', detail: 'No alert raised for repeated failed logins', test_type: 'blackbox', timestamp: '2026-10-13T09:06:56Z' },
  // No `detail` at all - this is the case that used to print raw JSON.
  { module: 'antitamper', passed: true, result: 'PASS', mitre: 'T1562.001', test_type: 'blackbox', timestamp: '2026-10-13T09:06:56Z' },
  // Informational ack: an action taken, not a control tested.
  { module: 'remote_control', passed: false, result: 'INFO', mitre: 'N/A', detail: 'Restart requested; the agent service is restarting', test_type: 'system', timestamp: '2026-10-13T09:08:15Z' },
];

async function setup(page, { moduleResults = MODULE_RESULTS } = {}) {
  await page.addInitScript(() => {
    localStorage.setItem('agentide-token', 'e2e-session-token');
  });

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = (data) => route.fulfill({ json: data });

    if (path === '/api/agents') return json([{ hostname: 'WS-RPT-01', status: 'online', os: 'windows', agent_version: '0.4.6' }]);
    if (path === '/api/events') {
      // Bare array, matching server/index.js (`res.json(result.rows)`).
      return json(
        moduleResults.map((payload, i) => ({
          id: `ev-${i}`,
          agent_id: 'WS-RPT-01',
          type: 'module_result',
          payload,
          received_at: payload.timestamp,
        }))
      );
    }
    if (path === '/api/auth/me') return json({ ok: true });
    if (path === '/api/agent/version') return json({ version: '0.4.6' });
    return json({});
  });

  // Navigate straight to the route: the sidebar link depends on the agent
  // list having rendered, which these mocks deliberately keep minimal.
  await page.goto('/reports');
  // Reports requires a selected agent; it auto-selects the only one.
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

  // antitamper sent no detail - it must still render prose, not nothing.
  await expect(page.getByText(/antitamper/i).first()).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).toMatch(/No additional detail reported|result: PASS|mitre:/i);
});

test('INFO acknowledgements do not render as FAIL', async ({ page }) => {
  await setup(page);

  const body = await page.locator('body').innerText();

  // The ack is present.
  expect(body).toContain('Restart requested; the agent service is restarting');
  expect(body).toMatch(/remote_control/);

  // An INFO badge is rendered for it. (FAIL badges legitimately appear for the
  // identity finding elsewhere on the page, so assert on the INFO badge itself
  // rather than counting FAILs globally.)
  const infoBadge = page.locator('span').filter({ hasText: /^INFO$/ });
  await expect(infoBadge.first()).toBeAttached();
  expect(await infoBadge.count()).toBeGreaterThan(0);

  // The INFO badge's own text is exactly INFO - it was not relabelled FAIL.
  expect((await infoBadge.first().innerText()).trim()).toBe('INFO');
});

test('genuine FAILs still render as FAIL', async ({ page }) => {
  await setup(page);

  // identity is a real failure and must remain visible as one.
  await expect(page.getByText(/identity/i).first()).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).toContain('No alert raised for repeated failed logins');
  expect(body).toMatch(/\bFAIL\b/);
});
