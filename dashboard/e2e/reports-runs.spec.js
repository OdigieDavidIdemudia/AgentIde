import { test, expect } from '@playwright/test';

/**
 * Reports run selector.
 *
 * Regression cover for the central usability problem: the report built its
 * whole view from live WebSocket events, so every run for an agent was merged
 * into one list and there was no way to tell which assessment you were
 * reading. It now loads persisted runs from
 * /api/agents/:hostname/assessments and scopes to one via
 * /api/assessments/:id/results.
 */

const RUNS = [
  {
    id: 'aaaaaaaa-1111-2222-3333-444444444444',
    hostname: 'WS-RPT-01',
    status: 'completed',
    profile: 'rapid',
    test_type: 'blackbox',
    started_at: '2026-10-13T10:09:45.000Z',
    completed_at: '2026-10-13T10:11:06.000Z',
    score: 75,
    result_count: 3,
    modules: ['malware', 'identity', 'network'],
  },
  {
    id: 'bbbbbbbb-1111-2222-3333-444444444444',
    hostname: 'WS-RPT-01',
    status: 'completed',
    profile: 'apt',
    test_type: 'blackbox',
    started_at: '2026-10-12T09:00:00.000Z',
    score: 60,
    result_count: 1,
    modules: ['lolbin'],
  },
];

const RESULTS_BY_RUN = {
  'aaaaaaaa-1111-2222-3333-444444444444': [
    { id: 'r1', module_name: 'malware', action: 'PASS', passed: true, mitre: 'T1204.002', detail: 'EICAR execution blocked', elapsed_ms: 15094, test_type: 'blackbox', notes: 'ok', artifacts: [], recorded_at: '2026-10-13T10:10:21.000Z' },
    { id: 'r2', module_name: 'identity', action: 'FAIL', passed: false, mitre: 'T1110.003', detail: 'No alert raised for repeated failed logins', elapsed_ms: 2240, test_type: 'blackbox', notes: 'ok', artifacts: [], recorded_at: '2026-10-13T10:11:01.000Z' },
    { id: 'r3', module_name: 'network', action: 'PASS', passed: true, mitre: 'T1071.001', detail: 'Outbound C2 blocked', elapsed_ms: 35488, test_type: 'blackbox', notes: 'ok', artifacts: [], recorded_at: '2026-10-13T10:10:59.000Z' },
  ],
  'bbbbbbbb-1111-2222-3333-444444444444': [
    { id: 'r4', module_name: 'lolbin', action: 'PASS', passed: true, mitre: 'T1059.001', detail: 'LOLBin execution blocked', elapsed_ms: 3407, test_type: 'blackbox', notes: 'ok', artifacts: [], recorded_at: '2026-10-12T09:10:00.000Z' },
  ],
};

// Lookup keys for the results map: the request URL contains the run id with
// dashes intact, so key the fixture on the raw id and compare loosely.
// Results are keyed on the raw run id; the request URL keeps the dashes.

async function setup(page) {
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
    if (path === '/api/agents/WS-RPT-01/assessments') return json(RUNS);

    const results = path.match(/^\/api\/assessments\/(.+)\/results$/);
    if (results) return json(RESULTS_BY_RUN[results[1]] ?? []);

    return json({});
  });

  await page.goto('/reports');
}

test('lists every run for the agent with its date and profile', async ({ page }) => {
  await setup(page);
  const group = page.getByRole('group', { name: /assessment run/i });
  await expect(group.getByRole('radio')).toHaveCount(2);
  await expect(group).toContainText('rapid');
  await expect(group).toContainText('apt');
});

test('defaults to the newest run and identifies it explicitly', async ({ page }) => {
  await setup(page);
  const body = await page.locator('body').innerText();
  // Run id prefix, agent, profile, test type and status must all be visible,
  // so the operator can tell exactly which assessment they are reading.
  expect(body).toContain(RUNS[0].id.slice(0, 8));
  expect(body).toContain('WS-RPT-01');
  expect(body).toMatch(/Profile\s*rapid/i);
  expect(body).toMatch(/Test type\s*blackbox/i);
  expect(body).toMatch(/Status\s*completed/i);
});

test('shows only the selected run’s results, not every run merged together', async ({ page }) => {
  await setup(page);
  const body = await page.locator('body').innerText();
  // The newest run has 3 modules; lolbin belongs to the older apt run.
  expect(body).toContain('EICAR execution blocked');
  expect(body).not.toContain('LOLBin execution blocked');
});

test('switching runs loads that run’s results', async ({ page }) => {
  await setup(page);
  const group = page.getByRole('group', { name: /assessment run/i });
  await group.getByRole('radio').nth(1).click();

  await expect(page.getByText(RUNS[1].id.slice(0, 8)).first()).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).toContain('LOLBin execution blocked');
  expect(body).not.toContain('EICAR execution blocked');
});

test('summary counts and score match the selected run', async ({ page }) => {
  await setup(page);
  const body = await page.locator('body').innerText();
  // Newest run: 3 modules, 2 passed, 1 failed, score 75.
  expect(body).toMatch(/Modules Run\s*3/i);
  expect(body).toMatch(/Passed\s*2/i);
  expect(body).toMatch(/Failed \/ Blocked\s*1/i);
  expect(body).toMatch(/Score\s*75/i);
});

test('summary recomputes when switching to a different run', async ({ page }) => {
  await setup(page);
  const group = page.getByRole('group', { name: /assessment run/i });
  await group.getByRole('radio').nth(1).click();
  await expect(page.getByText(RUNS[1].id.slice(0, 8)).first()).toBeVisible();

  const body = await page.locator('body').innerText();
  // Older run: 1 module, 1 passed, 0 failed, score 60.
  expect(body).toMatch(/Modules Run\s*1/i);
  expect(body).toMatch(/Passed\s*1/i);
  expect(body).toMatch(/Score\s*60/i);
});

test('shows an explicit empty state when there are no runs', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('agentide-token', 'e2e-session-token'));
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = (d) => route.fulfill({ json: d });
    if (path === '/api/agents') return json([{ hostname: 'WS-EMPTY', status: 'online' }]);
    if (path === '/api/events') return json([]);
    if (path === '/api/auth/me') return json({ ok: true });
    if (path === '/api/agents/WS-EMPTY/assessments') return json([]);
    return json({});
  });
  await page.goto('/reports');
  await expect(page.getByText(/No assessments recorded/i)).toBeVisible();
});