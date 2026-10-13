import { defineConfig, devices } from '@playwright/test';

/**
 * E2E config for the AgentIde dashboard.
 *
 * The dev server is Vite only (`npm run dev:client`, plain HTTP on :3000).
 * The API is not started: every test installs a route mock for /api/*, so the
 * suite is hermetic and needs no Postgres, no TLS cert and no :8443 listener.
 * That also keeps it from racing a real dashboard for the port.
 *
 * The self-signed dev cert is deliberately not exercised here. Browsers reject
 * it before the app loads, so it cannot be covered by a page-level test.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],

  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

  webServer: {
    command: 'npm run dev:client',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});