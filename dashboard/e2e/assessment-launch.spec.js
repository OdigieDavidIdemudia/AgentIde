import { test, expect } from '@playwright/test';

/**
 * Report export honesty.
 *
 * Regression cover for the report fabricating its own scope: the export
 * previously fell back to hardcoded values ('Microsoft Defender', all 8
 * modules) whenever the data was missing, so an export could describe an
 * assessment that never happened — and those invented values were fed
 * straight into the AI report prompt.
 *
 * The launch payload itself is covered by unit tests (src/api.test.js)
 * because sendCommand() only transmits on a genuinely OPEN socket, which a
 * WebSocket mock does not provide; asserting it here would test the harness,
 * not the code. The Playwright suite additionally runs against the real Vite
 * dev server, which covers the apiUrl dev-proxy fix.
 */

const RUN = {
  id: 'dddddddd-1111-2222-3333-444444444444',
  hostname: 'WS-LAUNCH',
  status: 'completed',
  profile: 'rapid',
  test_type: 'blackbox',
  started_at: '2026-10-13T10:09:45.000Z',
  completed_at: '2026-10-13T10:11:06.000Z',
  score: 75,
  result_count: 2,
  modules: ['malware', 'identity'],
};

// Findings as GET /api/assessments/:id/findings returns them: severity already
// applied server-side, ordered most severe first.
const FINDINGS = {
  assessment: {
    id: RUN.id,
    hostname: 'WS-LAUNCH',
    profile: 'rapid',
    test_type: 'blackbox',
    status: 'completed',
    score: 75,
    passed: 1,
    failed: 1,
    started_at: RUN.started_at,
    completed_at: RUN.completed_at,
  },
  counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 1, INFO: 0 },
  total: 2,
  findings: [
    {
      index: 1, module: 'identity', title: 'Credential attack not detected',
      result: 'FAIL', severity: 'HIGH', isFinding: true, mitre: 'T1110.003',
      executedAt: '2026-10-13T10:11:01.000Z', elapsedMs: 2240,
      observation: 'No alert raised',
      impact: 'Repeated failed authentication attempts produced no alert.',
      recommendation: 'Enable failed-logon auditing thresholds.',
    },
    {
      index: 2, module: 'malware', title: 'Malicious test file execution',
      result: 'PASS', severity: 'LOW', isFinding: false, mitre: 'T1204.002',
      executedAt: '2026-10-13T10:10:21.000Z', elapsedMs: 15094,
      observation: 'EICAR blocked',
      impact: 'A benign EICAR test file was executed rather than blocked.',
      recommendation: 'Confirm real-time protection is enabled.',
    },
  ],
};

async function setup(page, { vendorEvents = [] } = {}) {
  await page.addInitScript(() => {
    localStorage.setItem('agentide-token', 'e2e-session-token');
  });

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = (d) => route.fulfill({ json: d });

    if (path === '/api/agents') {
      return json([{ hostname: 'WS-LAUNCH', status: 'online', os: 'windows', agent_version: '0.4.6' }]);
    }
    if (path === '/api/events') return json(vendorEvents);
    if (path === '/api/auth/me') return json({ ok: true });
    if (path === '/api/agent/version') return json({ version: '0.4.6' });
    if (path === '/api/agents/WS-LAUNCH/assessments') return json([RUN]);
    if (/^\/api\/assessments\/.+\/findings$/.test(path)) return json(FINDINGS);
    return json({});
  });
}

/** Read and parse the Export JSON download. */
async function readJsonExport(page) {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: /Export JSON/i }).click(),
  ]);
  const stream = await download.createReadStream();
  const chunks = [];
  for await (const c of stream) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

test('report export does not fabricate a vendor or module list', async ({ page }) => {
  await setup(page);
  await page.goto('/reports');
  await expect(page.getByText(/^Findings$/i).first()).toBeVisible();

  const payload = await readJsonExport(page);

  // No vendor was detected in this fixture, so the export must say so rather
  // than assert "Microsoft Defender".
  expect(payload.scope.target_vendors).toEqual([]);
  expect(payload.scope.vendor_detected).toBeNull();

  // Modules tested must be what actually ran (2), not the full 8-module list.
  expect(payload.scope.modules_tested.sort()).toEqual(['identity', 'malware']);
  expect(payload.scope.modules_tested).not.toContain('network');

  // Real scope values, taken from the run itself.
  expect(payload.scope.profile).toBe('rapid');
  expect(payload.scope.test_types).toEqual(['blackbox']);
  expect(payload.summary.score).toBe(75);
  expect(payload.assessment_id).toBe(RUN.id);
});

test('report export is built from persisted results, not live events', async ({ page }) => {
  // No vendor events at all: a page reload in the real app leaves the WS
  // buffer empty, which previously emptied module_results on export.
  await setup(page, { vendorEvents: [] });
  await page.goto('/reports');
  await expect(page.getByText(/^Findings$/i).first()).toBeVisible();

  const payload = await readJsonExport(page);

  expect(payload.module_results).toHaveLength(2);
  expect(payload.module_results.map((r) => r.module).sort()).toEqual(['identity', 'malware']);
  // Each result carries the fields the AI report prompt reads.
  const malware = payload.module_results.find((r) => r.module === 'malware');
  expect(malware.mitre).toBe('T1204.002');
  expect(malware.timestamp).toBeTruthy();
  expect(malware.duration_ms).toBe(15094);
  // Severity and the narrative blocks travel with the export so a generated
  // document is grounded in derived data rather than re-invented severity.
  expect(malware.severity).toBe('LOW');
  expect(malware.impact).toBeTruthy();
  expect(malware.recommendation).toBeTruthy();
});

test('assessment page loads its agent scope without hardcoded URLs', async ({ page }) => {
  // Regression for the absolute-URL bug: FleetView and AgentContext built
  // `https://${window.location.host}/...`, which attempted TLS against the
  // plain-HTTP Vite dev server and killed the WebSocket and every API call.
  const requested = [];
  page.on('request', (r) => {
    if (r.url().includes('/api/')) requested.push(r.url());
  });

  await setup(page);
  await page.goto('/assessment/WS-LAUNCH');

  await expect(page.getByText('Configure Assessment')).toBeVisible();
  // Targets the dev host over HTTP, never https:// against a non-TLS port.
  const offenders = requested.filter((u) => u.startsWith('https://localhost:3000'));
  expect(offenders, `absolute HTTPS dev URLs: ${offenders.join(', ')}`).toHaveLength(0);
  expect(requested.length).toBeGreaterThan(0);
});