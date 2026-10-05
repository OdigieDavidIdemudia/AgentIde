# AgentIde — EDR/XDR POC Assessment Framework

AgentIde is a security assessment toolkit for evaluating EDR/XDR products on
endpoints. A Go agent runs assessment modules (EICAR quarantine timing, LOLBin
use, network/identity checks, anti-tamper resilience, boot-gap testing) and
streams results to a central dashboard, which scores findings against MITRE
ATT&CK techniques and can generate AI-assisted reports.

> ⚠️ **Dual-use tooling.** The agent can attempt to stop security services,
> terminate vendor processes, and delete vendor binaries. Only run it on
> systems you own or have written authorization to test.

## Architecture

```
agent/          Go agent (Windows service / Linux daemon / CLI)
  core/         config, logger, scheduler
  discovery/    security-vendor fingerprinting
  modules/      assessment modules (malware, antitamper, lolbin, …)
  modes/        passive (command-driven) and active runners
  transport/    WebSocket client (auto-reconnect, event queue)
  disabler/     vendor disable/restore helpers
  resilience/   kill-event detection (tamper evidence)
dashboard/      Node.js server + React (Vite) UI + PostgreSQL
design/         assessment standard definitions (JSON)
```

## Setup

### 1. Postgres

```bash
cd dashboard
docker compose up -d          # agentide / agentide_password / agentide DB
```

### 2. Configure environment

```bash
cp .env.example .env          # from the project root
# Edit .env — at minimum set AGENT_TOKEN and ADMIN_PASSWORD
node -e "console.log(require('crypto').randomUUID())"   # generate an agent token
```

### 3. Dashboard

```bash
cd dashboard
npm install
npm run db:migrate
npm run cert:generate         # self-signed TLS for dev
npm run dev                   # API on :8080, Vite dev server on :3000
```

Or run the whole stack (Postgres + dashboard) with Docker:

```bash
cd dashboard
docker compose up --build
```

Production: `npm run build && npm start`.

### 4. Agent

```bash
cd agent
go build -o agentide.exe .
./agentide.exe -install -dashboard wss://192.168.1.10:8080 -token <AGENT_TOKEN>
./agentide.exe -mode active -profile rapid
```

CLI flags: `-install/-uninstall`, `-mode passive|active`, `-profile
rapid|apt|baseline`, `-days N`, `-module <name>`, `-dashboard <url>`,
`-token <secret>`, `-allow-reboot`.

## Security model

- **Agents** authenticate to `wss://…/agent`. On first connect they
  present the shared `AGENT_TOKEN`; the dashboard then issues a
  **per-agent token** bound to that hostname (stored in the DB and
  persisted to the agent's `config.json`), and subsequent connects
  use it. A shared token alone can't impersonate an existing host.
- **Browsers** log in via `POST /api/auth/login` (credentials from
  `ADMIN_EMAIL`/`ADMIN_PASSWORD`, rate-limited to 5 failures per
  15 minutes per IP), receive a 24h session token, and present
  it as a Bearer header on REST calls and a query param on the
  `wss://…/dashboard` socket, which also enforces an Origin check.
  The frontend detects expiry (401) and returns to the login page.
- CORS is same-origin by default; widen with `CORS_ORIGINS`.
- TLS is self-signed in dev (`npm run cert:generate`); the agent
  skips cert verification by default, or set `DASHBOARD_CERT_PIN`
  (hex SHA-256 of the cert's SPKI) via `-cert-pin` to pin the
  dashboard certificate instead.
- **Re-enable watchdog:** whenever a vendor is disabled for an assessment,
  the agent spawns a detached watchdog process. If the agent is killed or
  hangs mid-assessment (which is what several EDRs do), the watchdog
  re-enables the vendor automatically — heartbeat timeout 90s, absolute
  deadline = assessment duration + 1h. On normal completion the watchdog
  is disarmed quietly.

## Assessment lifecycle

The dashboard tracks the full loop: `POST /api/assessments` creates a
`running` row → the agent streams `module_result` events (persisted to the
`results` table and linked via `session_id`) → `assessment_done` marks the
assessment `completed` with pass/fail counts and a score. Raw telemetry in
the `events` table is pruned after `EVENT_RETENTION_DAYS` (default 30).

## Environment variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` / `PG*` | Postgres connection (see `.env.example`) |
| `AGENT_TOKEN` | Shared bootstrap secret for agents |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Dashboard login |
| `CORS_ORIGINS` | Allowed browser origins |
| `EVENT_RETENTION_DAYS` | Raw telemetry retention (default 30) |
| `GEMINI_API_KEY` | AI report generation |
| `PORT` | Dashboard HTTPS port (default 8080) |

## Tests

```bash
cd agent && go test ./...          # watchdog logic
cd dashboard && npm test           # auth module
```
