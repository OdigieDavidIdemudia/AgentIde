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

Prebuilt installers (both verify connectivity before reporting success):

- `agent/msi_output/AgentIDE_<version>.msi` — silent MSI. An interactive (GUI)
  install prompts for the dashboard URL, token and optional cert pin:
  ```powershell
  msiexec /i AgentIDE_0.4.5.msi /qn DASHBOARD="wss://192.168.1.168:8443" TOKEN="<AGENT_TOKEN>"
  ```
  After registering the service the MSI runs `agentide.exe -check` as SYSTEM
  and records the outcome in the MSI log, so an unreachable dashboard or a
  rejected token is visible instead of producing a silent no-op install. Pass
  `VALIDATE=0` to skip it (offline/deployment images).
- `agent/msi_output/AgentIDE_Installer_v<version>.exe` — interactive wizard with a
  visible connectivity check, also supporting silent mode:
  ```powershell
  AgentIDE_Installer_v0.4.5.exe /VERYSILENT /DASHBOARDURL="wss://192.168.1.168:8443" /AGENTTOKEN="<AGENT_TOKEN>"
  ```

Both are produced from `version.json` by `build_pro.bat`, so the agent binary
and the installers cannot drift apart.

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
> release with the `update_agent` command). Agents older than that need a
> one-time reinstall of the current build (`0.4.5`); from v0.3.0 onward the
> agent keeps itself up to date.
>
> To publish a new version: bump `agent/version.json` and rebuild both the agent
> binary and the installers with `build_pro.bat`. Publishing is therefore a
> single-version operation — never bump `version.json` without rebuilding, or
> the dashboard will serve a version string that does not match the binary.


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

## Remote agent management

Operators can act on an agent from the dashboard without console access to the
endpoint. In **Fleet View**, right-clicking an agent row opens a context menu
(position-clamped to the viewport, dismisses on Escape / outside click / scroll
/ resize):

- **Restart agent** — issues a `restart_agent` command. See the note below.
- **Uninstall agent** — issues an `uninstall_agent` command, which removes the
  guardian service and scheduled tasks first, then the main service.
- **Update agent** — pushes the current build (see *Agent self-update*).
- **Start / stop assessment**.

> **Why restart is not just "stop and start".** The hardened service descriptor
> denies `SERVICE_STOP` to SYSTEM — that is what stops an EDR from disabling the
> agent — but it means the agent cannot stop *itself*, because SYSTEM is the
> caller. The guardian re-applies the hardened descriptor every 15s, so briefly
> widening it isn't enough either.
>
> The supported path is therefore the same one self-update already uses: take
> the update lock so the guardian stands down, widen the descriptor via
> `service.Unprotect()`, and let a detached helper issue the stop/start pair.
> The helper clears the lock even on failure, so a failed restart can't leave
> self-protection disabled for the lock's expiry window.
>
> `restartSelf` is **Windows-only**. On other platforms the agent runs under a
> supervisor and returns `remote restart is not implemented on <goos>` rather
> than silently doing nothing.

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

The single guard runs everything relevant and is what CI executes:

```bash
scripts\verify.bat          # Windows
```

It runs, in order:

1. `go vet ./...` — shadowed errors, bad printf verbs, unreachable code
2. `go build ./...` with `GOOS=windows`
3. `go build ./...` with `GOOS=linux`
4. `go test ./...` — watchdog, service, state, modules
5. `go test -race ./...`

Steps 2 and 3 exist because `modules/helpers_windows.go` and
`modules/helpers_linux.go` implement the same surface for two platforms. A
change that only compiles on the host OS otherwise looks green locally while
breaking the other target — the cross-compile is what catches that.

Step 5 requires cgo and is **skipped with a warning** when no C compiler is on
PATH, rather than failing the run. On this machine it does skip: the watchdog,
guardian and transport goroutines are the most concurrency-heavy code in the
repo and have never been race-checked. To run it:

```bash
# install a mingw-w64 toolchain, then
cd agent && CGO_ENABLED=1 go test -race ./...
```

Individually:

```bash
cd agent && go test ./...          # watchdog logic
cd dashboard && npm test           # auth module
cd dashboard && npm run build      # frontend production build
```

> `dashboard` `npm test` runs `node --test "server/**/*.test.js"`. Do **not**
> change this back to `node --test server/` — that form executes every `.js`
> file in the directory, which imports `server/index.js` and starts the real
> dashboard: it binds `:8443`, opens the WebSocket hub, and connects to
> Postgres, then never exits. The glob keeps it to actual test files.
