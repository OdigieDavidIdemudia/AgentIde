# AgentIde — EDR/XDR POC Assessment Framework

AgentIde is a security assessment toolkit for evaluating EDR/XDR products on
endpoints. A Go agent runs assessment modules (EICAR drop **and execution**
timing, LOLBin use, network/identity checks, anti-tamper resilience, boot-gap
testing) and streams results to a central dashboard, which scores findings
against MITRE ATT&CK techniques and can generate AI-assisted reports. Every
file a module creates is reported back with its full path.

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
npm run dev                   # API on :8443, Vite dev server on :3000
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
./agentide.exe -check -dashboard wss://192.168.1.10:8443 -token <AGENT_TOKEN>  # verify first
./agentide.exe -install -dashboard wss://192.168.1.10:8443 -token <AGENT_TOKEN>
./agentide.exe -mode active -profile rapid
```

`-check` connects once and exits `0` if the dashboard is reachable **and**
accepts the token, or `1` otherwise — run it before/after installing to catch a
wrong address or token immediately.

`-dashboard` accepts a **comma-separated list** of addresses; the agent tries
them in order and reconnects to the first that answers. This is the simplest way
to survive a changing IP:

```bash
./agentide.exe -install \
  -dashboard "wss://10.0.0.5:8443,wss://192.168.1.168:8443" \
  -token <AGENT_TOKEN>
```

CLI flags: `-install/-uninstall`, `-check`, `-mode passive|active`, `-profile
rapid|apt|baseline`, `-days N`, `-module <name>`, `-dashboard <url[,url]>`,
`-token <secret>`, `-cert-pin <hex>`, `-allow-reboot`.

Prebuilt installers (both run the `-check` above and warn if it fails):

- `agent/msi_output/AgentIDE_0.4.0.msi` — silent MSI:
  ```powershell
  msiexec /i AgentIDE_0.4.0.msi /qn DASHBOARD="wss://192.168.1.168:8443" TOKEN="<AGENT_TOKEN>"
  ```
- `agent/msi_output/AgentIDE_Setup.exe` / `AgentIDE_Installer_v0.4.0.exe` —
  interactive wizard, with silent support:
  ```powershell
  AgentIDE_Setup.exe /VERYSILENT /DASHBOARDURL="wss://192.168.1.168:8443" /AGENTTOKEN="<AGENT_TOKEN>"
  ```

### Agent self-update

Agents **auto-update** from the dashboard. On connect they send their version;
if the dashboard has a newer build it replies with an `update_agent` command, and
the agent downloads it, verifies the SHA-256, and swaps its own executable via a
detached helper (pause guardian → stop service → replace → restart). Updates can
also be pushed per agent from **Agent Management → Update**. The guardian is
paused via an update lock during the swap so it never restores the old binary.

The dashboard serves whatever build is in `agent/` (`agentide.exe` +
`version.json`); rebuild the binary and bump `version.json` (done automatically
by `build_pro.bat`) to publish a new version. Set `AGENT_DIST_DIR` to serve a
build from another directory.

> Note: self-update requires an agent built from v0.3.0 or later (the first
> release with the `update_agent` command). Older agents — including v0.2.0 —
> need a one-time reinstall of the current 0.4.0 build; from v0.3.0 onward the
> agent keeps itself up to date.


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
- **Service self-protection:** the installed Windows service is deliberately
  hard to stop or uninstall, so a SYSTEM-level EDR (for example Cortex XDR)
  cannot disable it:
  - **Locked DACL** — the service descriptor denies `SERVICE_STOP`,
    `SERVICE_CHANGE_CONFIG`, and `DELETE` to `NT AUTHORITY\SYSTEM`, and grants
    only query/start to other accounts. Administrators retain full control.
  - **Aggressive recovery:** the SCM restarts the service after 1s/2s/5s/15s,
    including on non-crash termination (i.e. when an EDR's kernel driver kills
    the process).
  - **Guardian service** (`AgentIdeGuard`): a second service that every 15s
    starts the main service if stopped, recreates its registration if deleted,
    resets its start type to Automatic if an EDR disabled it, and restores the
    binary from `%ProgramData%\AgentIde\agentide.backup.exe` if removed. It has
    its own hardened DACL and recovery actions.
  - **Scheduled tasks** (`AgentIde Watchdog`, `AgentIde Service Guard`) run once
    per minute as a tertiary safety net and invoke `agentide.exe -repair`.
  Only a full uninstall (`agentide.exe -uninstall`, or the MSI/uninstaller)
  removes the guardian and tasks first, so the agent does not fight a
  deliberate removal. Self-update pauses the guardian via an update lock so it
  never restores the old binary mid-swap.

> Note: this raises the bar for a **user-mode** actor calling the SCM. A
> kernel-mode EDR driver can still terminate any user-mode process; that is
> what the service recovery actions, guardian service and scheduled task are
> for — the agent comes back automatically.

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
| `AGENT_DIST_DIR` | Directory served for agent self-update (default `agent/`) |
| `PORT` | Dashboard HTTPS port (default 8443) |

## Troubleshooting: agent not showing up on the dashboard

The dashboard prints the exact URL(s) to use at startup, for example:

```
🛡️  Agent must connect to the dashboard host, NOT localhost.
      (preferred — survives IP changes)  agentide.exe -install -dashboard wss://MY-DASHBOARD-HOST:8443 -token <AGENT_TOKEN>
      or by IP (pick the one the agent can reach):
      agentide.exe -install -dashboard wss://192.168.1.168:8443 -token <AGENT_TOKEN>
```

> **Dynamic IP / bridged VM:** if the dashboard host's IP changes (roaming
> Wi-Fi, or a VM bridged to the host's Wi-Fi that jumps between `192.168.1.x`
> and `192.168.0.x`), point the agent at the host's **hostname** instead of an
> IP — it re-resolves on every connect, so it survives the change:
> `-dashboard wss://MY-DASHBOARD-HOST:8443`. Verify from the agent host with
> `curl -k https://MY-DASHBOARD-HOST:8443/healthz`.

Work through this checklist:

1. **Dashboard is running.** `npm start` (or `npm run dev`) must be up. On the
   server, `Get-NetTCPConnection -LocalPort 8443 -State Listen` should show a
   listener.
2. **Use the LAN IP, not `localhost`.** The agent must dial the dashboard
   host's reachable IP — `localhost`/`127.0.0.1` resolve to the agent itself.
3. **Reachability.** From the agent host:
   - `Test-NetConnection <dashboard-ip> -Port 8443` → `TcpTestSucceeded: True`
   - `curl -k https://<dashboard-ip>:8443/healthz` → `{"status":"ok",...}`

   If either fails, allow inbound TCP `8443` in Windows Firewall on the
   dashboard host.
4. **Token matches.** The agent's `-token` must equal `AGENT_TOKEN` in the
   project-root `.env`. A mismatch/empty token is logged on the server as
   `Agent connection REJECTED (missing/invalid token) ...`.
5. **Check the agent log:** `C:\ProgramData\AgentIde\agentide.log` (service) or
   `%TEMP%\agentide.log`. `Transport: connected to dashboard` means the socket
   is up; failures log the attempted URL and backoff.
6. **Force a re-point.** Re-run this on the agent host with the correct URL — it
   rewrites `config.json` next to the exe and restarts the service:
   `agentide.exe -install -dashboard wss://<dashboard-ip>:8443 -token <AGENT_TOKEN>`

## Tests

```bash
cd agent && go test ./...          # watchdog logic
cd dashboard && npm test           # auth module
```
