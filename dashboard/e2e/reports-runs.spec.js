import { test, expect } from '@playwright/test';

/**
 * Reports run selector.
 *
 * Regression cover for the central usability problem: the report built its
 * whole view from live WebSocket events, so every run for an agent was merged
 * into one list and there was no way to tell which assessment you were
 * reading. It now loads persisted runs from
 * /api/agents/:hostname/assessments and scopes to one via
 * /api/assessments/:id/findings.
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

// Findings per run, shaped as GET /api/assessments/:id/findings returns them:
// the assessment scope, per-severity counts, and findings already ordered most
// severe first with severity applied server-side.
const FINDINGS_BY_RUN = {
  'aaaaaaaa-1111-2222-3333-444444444444': {
    assessment: {
      id: 'aaaaaaaa-1111-2222-3333-444444444444',
      hostname: 'WS-RPT-01',
      profile: 'rapid',
      test_type: 'blackbox',
      status: 'completed',
      score: 75,
      passed: 2,
      failed: 1,
      started_at: '2026-10-13T10:09:45.000Z',
      completed_at: '2026-10-13T10:11:06.000Z',
    },
    counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 2, INFO: 0 },
    total: 3,
    findings: [
      {
        index: 1, module: 'identity', title: 'Credential attack not detected',
        result: 'FAIL', severity: 'HIGH', isFinding: true, mitre: 'T1110.003',
        executedAt: '2026-10-13T10:11:01.000Z', elapsedMs: 2240,
        observation: 'No alert raised for repeated failed logins',
        impact: 'Repeated failed authentication attempts produced no alert.',
        recommendation: 'Enable failed-logon auditing thresholds.',
      },
      {
        index: 2, module: 'malware', title: 'Malicious test file execution',
        result: 'PASS', severity: 'LOW', isFinding: false, mitre: 'T1204.002',
        executedAt: '2026-10-13T10:10:21.000Z', elapsedMs: 15094,
        observation: 'EICAR execution blocked',
        impact: 'A benign EICAR test file was executed rather than blocked.',
        recommendation: 'Confirm real-time protection is enabled.',
      },
      {
        index: 3, module: 'network', title: 'Outbound command-and-control traffic',
        result: 'PASS', severity: 'LOW', isFinding: false, mitre: 'T1071.001',
        executedAt: '2026-10-13T10:10:59.000Z', elapsedMs: 35488,
        observation: 'Outbound C2 blocked',
        impact: 'The endpoint initiated an outbound connection that was not blocked.',
        recommendation: 'Enforce egress filtering to deny unapproved destinations.',
      },
    ],
  },
  'bbbbbbbb-1111-2222-3333-444444444444': {
    assessment: {
      id: 'bbbbbbbb-1111-2222-3333-444444444444',
      hostname: 'WS-RPT-01',
      profile: 'apt',
      test_type: 'blackbox',
      status: 'completed',
      score: 100,
      passed: 1,
      failed: 0,
      started_at: '2026-10-12T09:00:00.000Z',
    },
    counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 1, INFO: 0 },
    total: 1,
    findings: [
      {
        index: 1, module: 'lolbin', title: 'Living-off-the-land binary abuse',
        result: 'PASS', severity: 'LOW', isFinding: false, mitre: 'T1059.001',
        executedAt: '2026-10-12T09:10:00.000Z', elapsedMs: 3407,
        observation: 'LOLBin execution blocked',
        impact: 'A signed Microsoft binary executed without detection.',
        recommendation: 'Apply WDAC/AppLocker rules restricting LOLBin execution.',
      },
    ],
  },
};

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

    const findings = path.match(/^\/api\/assessments\/(.+)\/findings$/);
    if (findings) {
      return json(FINDINGS_BY_RUN[findings[1]] ?? {
        assessment: {}, counts: {}, total: 0, findings: [],
      });
    }

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