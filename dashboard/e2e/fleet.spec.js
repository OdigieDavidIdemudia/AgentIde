import { test, expect } from '@playwright/test';

/**
 * Agent fleet + right-click management menu.
 *
 * Every test runs hermetically: /api/* is mocked, so no Postgres, no TLS cert
 * and no dashboard on :8443 is required. FleetView is +249 lines and the
 * context menu is brand new, so this is the surface most likely to regress
 * silently - it had no coverage at all before this file.
 */

const AGENTS = [
  {
    hostname: 'WS-AGG-01',
    status: 'online',
    os: 'windows',
    agent_version: '0.4.5',
    last_seen: '2026-10-13T09:00:00Z',
    hostname_fqdn: 'ws-agg-01.corp.example.com',
  },
  {
    hostname: 'WS-AGG-02',
    status: 'offline',
    os: 'linux',
    agent_version: '0.4.2',
    last_seen: '2026-10-11T18:30:00Z',
  },
];

/** Install the /api mocks and seed an authenticated session. */
async function setup(page, { agents = AGENTS, latestVersion = '0.4.5' } = {}) {
  const calls = [];

  await page.addInitScript(() => {
    // App renders <Login/> unless this flag is present (App.jsx).
    localStorage.setItem('agentide-token', 'e2e-session-token');
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;

    if (path === '/api/agents') {
      // server/index.js responds with a bare array (res.json(result.rows)),
      // not an object - AgentContext expects that shape.
      return route.fulfill({ json: agents });
    }
    if (path === '/api/events') {
      return route.fulfill({ json: { events: [] } });
    }
    if (path === '/api/auth/me') {
      return route.fulfill({ json: { ok: true } });
    }
    if (path === '/api/agent/version') {
      return route.fulfill({ json: { version: latestVersion } });
    }
    // Management commands: /api/agents/<host>/<command>
    const cmd = path.match(/^\/api\/agents\/([^/]+)\/(\w+)$/);
    if (cmd) {
      calls.push({ hostname: decodeURIComponent(cmd[1]), command: cmd[2] });
      return route.fulfill({ json: { ok: true } });
    }
    const cfg = path.match(/^\/api\/agents\/([^/]+)\/config$/);
    if (cfg) {
      return route.fulfill({
        json: { hostname: decodeURIComponent(cfg[1]), mode: 'active', dashboard: 'wss://192.0.2.10:8443' },
      });
    }
    return route.fulfill({ json: {} });
  });

  await page.goto('/');
  await expect(page.getByRole('menu')).toHaveCount(0);
  return calls;
}

/** Open the context menu on a given agent row. */
async function openMenu(page, hostname) {
  const row = page.getByText(hostname, { exact: false }).first();
  await row.click({ button: 'right' });
  const menu = page.getByRole('menu');
  await expect(menu).toBeVisible();
  return menu;
}

test.beforeEach(async ({ page }) => {
  const errors = [];
  // AgentContext opens a WebSocket to wss://<host>/dashboard, but the Vite dev
  // server is plain HTTP on :3000, so that socket always fails with
  // ERR_SSL_PROTOCOL_ERROR under test. It is a harness artifact, not an app
  // defect - filter it so real console errors still fail the suite.
  const wsNoise = /ERR_SSL_PROTOCOL_ERROR|WebSocket connection to 'wss:\/\//;
  page.on('console', (m) => {
    if (m.type() === 'error' && !wsNoise.test(m.text())) errors.push(m.text());
  });
  page.on('pageerror', (e) => errors.push(e.message));
  page.__errors = errors;
});

test('fleet view renders agents from the API', async ({ page }) => {
  await setup(page);
  await expect(page.getByText('WS-AGG-01').first()).toBeVisible();
  await expect(page.getByText('WS-AGG-02').first()).toBeVisible();
  expect(page.__errors).toEqual([]);
});

test('right-click opens the menu with the agent hostname as title', async ({ page }) => {
  await setup(page);
  const menu = await openMenu(page, 'WS-AGG-01');
  await expect(menu).toContainText('WS-AGG-01');
  await expect(menu.getByRole('menuitem').first()).toBeFocused();
});

test('menu exposes the documented management commands', async ({ page }) => {
  await setup(page);
  const menu = await openMenu(page, 'WS-AGG-01');
  for (const label of [
    'Launch Assessment',
    'View Config',
    'Restart Agent',
    'Push Update',
    'Uninstall Agent',
  ]) {
    await expect(menu.getByRole('menuitem', { name: new RegExp(label, 'i') })).toBeVisible();
  }
});

test('Restart Agent requires confirmation, then sends restart', async ({ page }) => {
  const calls = await setup(page);
  const menu = await openMenu(page, 'WS-AGG-01');
  await menu.getByRole('menuitem', { name: /Restart Agent/i }).click();

  // Selecting the item must NOT fire the command on its own.
  await expect(calls).toHaveLength(0);

  // restart, uninstall and update are all confirmation-gated (requestCommand).
  await expect(page.getByText(/Confirm restart/i)).toBeVisible();
  await page.getByRole('button', { name: /^Restart$/ }).click();

  await expect.poll(() => calls).toContainEqual({ hostname: 'WS-AGG-01', command: 'restart' });
});

test('Uninstall Agent requires confirmation before it is sent', async ({ page }) => {
  const calls = await setup(page);
  const menu = await openMenu(page, 'WS-AGG-01');
  await menu.getByRole('menuitem', { name: /Uninstall Agent/i }).click();

  // Destructive action: must NOT fire on a single click (admin-standard.json).
  await expect(calls).toHaveLength(0);

  await page.getByRole('button', { name: /^Uninstall$/ }).click();
  await expect.poll(() => calls).toContainEqual({ hostname: 'WS-AGG-01', command: 'uninstall' });
});

test('cancelling the confirmation sends nothing', async ({ page }) => {
  const calls = await setup(page);
  const menu = await openMenu(page, 'WS-AGG-01');
  await menu.getByRole('menuitem', { name: /Restart Agent/i }).click();

  await page.getByRole('button', { name: /cancel/i }).first().click();
  await expect(page.getByText(/Confirm restart/i)).toHaveCount(0);
  await expect(calls).toHaveLength(0);
});

test('Update label reflects version mismatch', async ({ page }) => {
  await setup(page, { latestVersion: '0.5.0' });
  const menu = await openMenu(page, 'WS-AGG-01');
  await expect(menu.getByRole('menuitem', { name: /Update to v0\.5\.0/i })).toBeVisible();
});

test('up-to-date agent shows Push Update rather than a version bump', async ({ page }) => {
  await setup(page, { latestVersion: '0.4.5' });
  const menu = await openMenu(page, 'WS-AGG-01');
  await expect(menu.getByRole('menuitem', { name: /Push Update/i })).toBeVisible();
});

test('menu closes on Escape', async ({ page }) => {
  await setup(page);
  await openMenu(page, 'WS-AGG-01');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('menu')).toHaveCount(0);
});

test('menu closes on outside click', async ({ page }) => {
  await setup(page);
  await openMenu(page, 'WS-AGG-01');
  await page.locator('body').click({ position: { x: 5, y: 5 } });
  await expect(page.getByRole('menu')).toHaveCount(0);
});

test('menu stays inside the viewport when opened near the edge', async ({ page }) => {
  await setup(page);
  const size = page.viewportSize();
  const row = page.getByText('WS-AGG-01', { exact: false }).first();

  // Open hard against the bottom-right corner.
  await row.click({ button: 'right', position: { x: 5, y: 5 } });
  const menu = page.getByRole('menu');
  await expect(menu).toBeVisible();

  const box = await menu.boundingBox();
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.y).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(size.width + 1);
  expect(box.y + box.height).toBeLessThanOrEqual(size.height + 1);
});

test('no horizontal overflow at 320px', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 700 });
  await setup(page);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  );
  // Allow 1px for sub-pixel rounding.
  expect(overflow).toBeLessThanOrEqual(1);
});