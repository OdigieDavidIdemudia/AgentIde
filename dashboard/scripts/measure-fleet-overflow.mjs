/**
 * Measures real table overflow in the Fleet View.
 *
 * The existing e2e check only asserts the *document* does not scroll, which is
 * trivially true because body sets overflow:hidden and .main-content sets
 * overflow-x:hidden. That hides the real problem: when a table is wider than
 * its container the extra columns are clipped with no way to reach them. This
 * measures the table against its scroll container instead.
 *
 * Usage: node scripts/measure-fleet-overflow.mjs [width] [height]
 */
import { chromium } from 'playwright';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const width = Number(process.argv[2] || 1440);
const height = Number(process.argv[3] || 900);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width, height } });

await page.addInitScript(() => {
  localStorage.setItem('agentide-token', 'e2e-session-token');
});

await page.route('**/api/**', async (route) => {
  const path = new URL(route.request().url()).pathname;
  const json = (d) => route.fulfill({ json: d });

  if (path === '/api/agents') {
    // A realistic worst case: long hostname, long OS string, vendor, buttons.
    return json([
      {
        hostname: 'DESKTOP-L07M1SS', ip: '192.168.0.5', os: 'windows',
        os_version: 'Windows 10 Pro 19045.6456', vendor: 'Microsoft Defender',
        agent_version: '0.4.8', status: 'online',
      },
    ]);
  }
  if (path === '/api/events') return json([]);
  if (path === '/api/auth/me') return json({ ok: true });
  if (path === '/api/agent/version') return json({ version: '0.4.8' });
  return json({});
});

await page.goto(`${BASE}/`);
await page.getByText('DESKTOP-L07M1SS').first().waitFor({ timeout: 15000 });

const m = await page.evaluate(() => {
  const table = document.querySelector('table');
  if (!table) return { error: 'no table found' };
  const parent = table.parentElement;
  const cs = getComputedStyle(table);
  const ps = parent ? getComputedStyle(parent) : null;
  return {
    tableWidth: Math.round(table.getBoundingClientRect().width),
    tableScrollWidth: table.scrollWidth,
    parentClientWidth: parent ? parent.clientWidth : null,
    parentScrollWidth: parent ? parent.scrollWidth : null,
    parentOverflowX: ps ? ps.overflowX : null,
    docScrollWidth: document.documentElement.scrollWidth,
    docClientWidth: document.documentElement.clientWidth,
    headers: [...table.querySelectorAll('th')].map((th) => ({
      text: th.textContent.trim(),
      w: Math.round(th.getBoundingClientRect().width),
    })),
    fontFamily: cs.fontFamily,
    thFont: table.querySelector('th') ? getComputedStyle(table.querySelector('th')).fontFamily : null,
  };
});

console.log(JSON.stringify(m, null, 2));
await browser.close();