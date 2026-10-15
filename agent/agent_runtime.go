// Platform-neutral agent runtime shared by the Windows service and the
// foreground / Linux execution paths.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"agentide/core"
	"agentide/disabler"
	"agentide/discovery"
	"agentide/fingerprint"
	"agentide/modes"
	"agentide/resilience"
	"agentide/state"
	"agentide/transport"
	"agentide/updater"
	"agentide/watchdog"
)

// decodeStringList reads a module selection from a decoded JSON command.
// The dashboard sends a []string, but a comma-separated string is also
// accepted so an older or hand-rolled client still works. Returns nil for an
// absent or empty value, which the caller treats as "run everything".
func decodeStringList(v interface{}) []string {
	switch t := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(t))
		for _, s := range t {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		var out []string
		for _, s := range strings.Split(t, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// handleRemoteControl implements the management commands the dashboard sends
// over the WebSocket (Agent Management → Restart / Uninstall, and the Fleet
// view's right-click menu). These were previously accepted by the dashboard
// and silently ignored by the agent: the command loop only understood
// agent_token, update_agent and the assessment commands, so the API returned
// "success" while nothing happened on the endpoint.
//
// Every command acknowledges the outcome back to the dashboard before acting,
// so a failure is visible instead of silent.
func handleRemoteControl(cmdType string, logger *core.Logger, sender transport.Sender) bool {
	// `passed` must only be false for an actual FAIL. An INFO acknowledgement
	// is not a failure, and treating it as one made every successful restart,
	// uninstall and update render as a red FAIL row in the Live Console.
	ack := func(result, detail string) {
		if sender != nil {
			sender.Send(transport.EventModuleResult, map[string]interface{}{
				"module":    "remote_control",
				"passed":    result == "OK",
				"result":    result,
				"detail":    detail,
				"test_type": "system",
				"mitre":     "N/A",
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
	}

	switch cmdType {
	case "restart_agent":
		logger.Info("restart_agent received — restarting service", nil)
		ack("INFO", "Restart requested; the agent service is restarting")
		// Give the socket a moment to flush the acknowledgement before the
		// service stops, then let the SCM bring us back up.
		go func() {
			time.Sleep(2 * time.Second)
			if err := restartSelf(logger); err != nil {
				logger.Error("Remote restart failed", map[string]interface{}{"error": err.Error()})
				return
			}
			logger.Info("Remote restart issued", nil)
		}()
		return true

	case "uninstall_agent":
		logger.Info("uninstall_agent received — removing service", nil)
		ack("INFO", "Uninstall requested; removing the AgentIde service")
		go func() {
			time.Sleep(2 * time.Second)
			if err := uninstallSelf(logger); err != nil {
				logger.Error("Remote uninstall failed", map[string]interface{}{"error": err.Error()})
				ack("ERROR", "Uninstall failed: "+err.Error())
				return
			}
			ack("OK", "AgentIde service removed")
		}()
		return true

	case "rescan":
		// Re-run discovery immediately and report every vendor found. Useful
		// after an EDR is installed while the agent is already running.
		logger.Info("rescan received — re-running discovery", nil)
		go func() {
			found, err := discovery.Scan()
			if err != nil {
				logger.Warn("Rescan failed", map[string]interface{}{"error": err.Error()})
				ack("ERROR", "Discovery scan failed: "+err.Error())
				return
			}
			entries := make([]map[string]interface{}, 0, len(found))
			for _, a := range found {
				entries = append(entries, map[string]interface{}{
					"discovered_vendor": a.Vendor,
					"process_name":      a.ProcessName,
					"service_name":      a.ServiceName,
					"pid":               a.PID,
				})
			}
			if sender != nil && len(entries) > 0 {
				sender.SendDiscovery(entries)
			}
			if len(entries) == 0 {
				ack("OK", "Rescan complete: no known security agents detected")
			} else {
				names := make([]string, 0, len(entries))
				for _, e := range entries {
					names = append(names, e["discovered_vendor"].(string))
				}
				ack("OK", "Rescan complete: "+strings.Join(names, ", "))
			}
		}()
		return true
	}
	return false
}

// fingerprintPayload extends the raw endpoint fingerprint with the agent's
// current config so the dashboard can display it (Fleet → agent config) and
// operators can confirm at a glance which dashboard URL an endpoint dialed.
func fingerprintPayload(fp *fingerprint.Fingerprint, cfg *core.Config) map[string]interface{} {
	m := fp.ToMap()
	m["dashboard_url"] = cfg.DashboardURL
	m["log_path"] = cfg.LogPath
	m["allow_reboot"] = cfg.AllowReboot
	m["version"] = version
	return m
}

// runAgent contains all the actual startup logic shared between
// interactive CLI mode and Windows Service mode.
func runAgent(cfg *core.Config, mode, profile string, days int, module string) {
	// When running as a Windows Service, the working directory is System32.
	// Always write logs to the system temp directory to ensure write access.
	logPath := cfg.LogPath
	if logPath == "" || logPath == "agentide.log" {
		logPath = filepath.Join(os.TempDir(), "agentide.log")
	}

	logger, err := core.NewLogger(logPath)
	if err != nil {
		// Last-resort: cannot log, but still attempt to connect
		logger, _ = core.NewLogger(filepath.Join(os.TempDir(), "agentide_fallback.log"))
		if logger == nil {
			return
		}
	}
	defer logger.Close()

	logger.Info("AgentIde starting", map[string]interface{}{
		"version":          version,
		"mode":             mode,
		"profile":          profile,
		"dashboard_url":    cfg.DashboardURL,
		"token_configured": cfg.AgentToken != "",
	})

	// Fingerprint
	fp, err := fingerprint.Collect()
	if err != nil {
		logger.Warn("Fingerprinting partially failed", map[string]interface{}{"error": err.Error()})
		fp = &fingerprint.Fingerprint{Hostname: "unknown"}
	} else {
		logger.Info("Endpoint fingerprint collected", fp.ToMap())
	}

	// Discovery
	agents, _ := discovery.Scan()

	// Resilience — detect if we were killed since the last heartbeat.
	// Runs before anything else so we can immediately queue the event on connect.
	killEvent, agentState := resilience.CheckAndUpdate(fp.Hostname)
	logger.Info("Agent startup state", map[string]interface{}{
		"start_count": agentState.StartCount,
		"kill_count":  agentState.KillCount,
	})

	// Transport
	sender := transport.NewSender(cfg.DashboardURL, fp.Hostname, cfg.AgentToken, cfg.CertPin, logger)
	sender.Connect()
	defer sender.Disconnect()

	sender.SendFingerprint(fingerprintPayload(fp, cfg))
	sender.StartHeartbeat()

	// Report every vendor found. Sending a synthetic "None Detected" vendor
	// would be wrong: the dashboard treats the first entry as the primary
	// agent, so a placeholder would overwrite a real vendor on the next scan.
	if len(agents) > 0 {
		found := make([]map[string]interface{}, 0, len(agents))
		for _, a := range agents {
			found = append(found, map[string]interface{}{
				"discovered_vendor": a.Vendor,
				"process_name":      a.ProcessName,
				"service_name":      a.ServiceName,
				"pid":               a.PID,
			})
		}
		sender.SendDiscovery(found)
	}

	// Report kill/recovery event to dashboard immediately
	if killEvent != nil {
		logger.Warn("Kill event detected", map[string]interface{}{
			"killed_at":    killEvent.KilledAt.Format(time.RFC3339),
			"recovered_at": killEvent.RecoveredAt.Format(time.RFC3339),
			"downtime_sec": killEvent.Downtime.Seconds(),
		})
		sender.SendTamperEvent(map[string]interface{}{
			"event":        "agent_kill_detected",
			"description":  "Agent was externally terminated and auto-recovered",
			"killed_at":    killEvent.KilledAt.Format(time.RFC3339),
			"recovered_at": killEvent.RecoveredAt.Format(time.RFC3339),
			"downtime_sec": killEvent.Downtime.Seconds(),
			"downtime_str": killEvent.Downtime.String(),
			"recovery_num": killEvent.StartCount,
			"total_kills":  agentState.KillCount,
			"result":       "AGENT_RECOVERED",
		})
	}

	// Start heartbeat file writer so we can detect the next kill
	stopCh := make(chan struct{})
	defer close(stopCh)
	resilience.StartHeartbeatWriter(fp.Hostname, stopCh)

	// Scheduler + Mode dispatch
	scheduler := core.NewScheduler(profile, days)

	// assessMu serializes assessment execution between the startup
	// auto-resume path and dashboard-confirmed runs — two assessments
	// must never write to the checkpoint state concurrently.
	var assessMu sync.Mutex

	// currentRunner holds the ActiveRunner for the currently running
	// assessment so that a stop_assessment command can signal it.
	var currentRunner *modes.ActiveRunner

	switch strings.ToLower(mode) {
	case "passive":
		logger.Info("Starting Passive Mode", nil)
		core.SetStatus("connected", "Monitoring passively")

		// Auto-resume any assessment that was interrupted by an EDR kill.
		// Runs in the background so dashboard commands (pre-scan requests)
		// are still accepted while it works; assessMu keeps it mutually
		// exclusive with a confirm_assessment that arrives meanwhile.
		go func() {
			assessMu.Lock()
			defer assessMu.Unlock()
			autoResumeAssessment(cfg, logger, sender)
		}()

		// Listen for start_assessment commands from the dashboard in the background
		go func() {
			// pendingConfirm holds context from a start_assessment while we wait for confirm_assessment
			type pendingAssessment struct {
				profile  string
				testType string
				days     int
				// modules is the operator's explicit selection. Empty means
				// "run everything", which is also what the dashboard sends when
				// no selection was made.
				modules []string
				// allowReboot lets the reboot/boot-gap module run. Previously
				// this could only come from the agent's own --allow-reboot
				// flag, so the dashboard checkbox had no effect at all.
				allowReboot bool
			}
			var pending *pendingAssessment

			for cmd := range sender.Commands() {
				cmdType, _ := cmd["type"].(string)

				// ── Management commands (restart / uninstall / rescan) ──
				// Handled before anything else and acknowledged to the
				// dashboard, so the UI can report the real outcome instead of
				// a command that silently did nothing.
				if handleRemoteControl(cmdType, logger, sender) {
					continue
				}

				// ── Dashboard assigned a per-agent token ────────────────
				// Persist it so subsequent reconnects use the bound token
				// instead of the shared bootstrap token.
				if cmdType == "agent_token" {
					newToken, _ := cmd["token"].(string)
					if newToken != "" && newToken != cfg.AgentToken {
						cfg.AgentToken = newToken
						exePath, _ := os.Executable()
						if err := core.SaveConfig(filepath.Join(filepath.Dir(exePath), "config.json"), cfg); err != nil {
							logger.Warn("Could not persist assigned agent token", map[string]interface{}{"error": err.Error()})
						} else {
							logger.Info("Persisted per-agent token assigned by dashboard", nil)
						}
					}
					continue
				}

				// ── Self-update ────────────────────────────────────────────────
				// The dashboard advertises a newer agent build; download it,
				// verify the hash, and swap the running executable in place.
				if cmdType == "update_agent" {
					ver, _ := cmd["version"].(string)
					url, _ := cmd["url"].(string)
					sum, _ := cmd["sha256"].(string)
					logger.Info("update_agent received — starting self-update", map[string]interface{}{
						"version": ver, "url": url,
					})
					sender.Send(transport.EventModuleResult, map[string]interface{}{
						"module":    "agent_update",
						"passed":    true,
						"result":    "INFO",
						"detail":    fmt.Sprintf("Downloading agent update %s", ver),
						"test_type": "system",
						"mitre":     "N/A",
						"timestamp": time.Now().Format(time.RFC3339),
					})
					manifest := updater.Manifest{Version: ver, URL: url, SHA256: sum}
					go func() {
						if err := updater.Apply(manifest, logger); err != nil {
							logger.Error("Self-update failed", map[string]interface{}{"error": err.Error()})
						}
					}()
					continue
				}

				// ── Phase 1: Initial launch request ──────────────────────────────
				if cmdType == "start_assessment" {
					cmdProfile, _ := cmd["profile"].(string)
					if cmdProfile == "" {
						cmdProfile = profile
					}
					cmdTestType, _ := cmd["test_type"].(string)
					if cmdTestType == "" {
						cmdTestType = "blackbox"
					}

					// The operator's module selection. The dashboard has always
					// collected this and persisted it to the assessments row, but it
					// was never sent on the wire - the runner was hardcoded to
					// "all", so the report claimed modules ran that never did.
					cmdModules := decodeStringList(cmd["modules"])

					// Duration in days. Previously taken only from the agent's own
					// -days startup flag, so the dashboard's Duration picker was dead.
					cmdDays := days
					if v, ok := cmd["days"].(float64); ok && v > 0 {
						cmdDays = int(v)
					}

					// Reboot consent. Accept both the boolean and a string form so
					// either dashboard shape works. Absent key falls back to the
					// agent's own --allow-reboot flag.
					cmdAllowReboot := cfg.AllowReboot
					switch v := cmd["allow_reboot"].(type) {
					case bool:
						cmdAllowReboot = v
					case string:
						cmdAllowReboot = v == "true"
					}

					logger.Info("start_assessment received — scanning for security agents", nil)

					// Re-scan the endpoint right now
					liveAgents, _ := discovery.Scan()

					// Build the agent list payload
					agentList := []map[string]interface{}{}
					for _, a := range liveAgents {
						agentList = append(agentList, map[string]interface{}{
							"vendor":       a.Vendor,
							"process_name": a.ProcessName,
							"service_name": a.ServiceName,
							"pid":          a.PID,
						})
					}

					// Send pre_scan_result back to dashboard — this triggers the confirmation modal
					sender.Send(transport.EventPreScanResult, map[string]interface{}{
						"discovered_agents":   agentList,
						"supported_disabling": disabler.SupportedVendors(),
						"profile":             cmdProfile,
						"test_type":           cmdTestType,
					})

					// Park the pending context so we can resume when confirm arrives
					pending = &pendingAssessment{
						profile:     cmdProfile,
						testType:    cmdTestType,
						days:        cmdDays,
						modules:     cmdModules,
						allowReboot: cmdAllowReboot,
					}

					logger.Info("Pre-scan complete — waiting for user confirmation", map[string]interface{}{
						"agents_found": len(liveAgents),
					})
					continue
				}

				// ── Stop assessment: operator requested a graceful abort ─────────
				if cmdType == "stop_assessment" {
					logger.Info("stop_assessment received — signalling active runner to stop", nil)
					ack := func(result, detail string) {
						if sender != nil {
							sender.Send(transport.EventModuleResult, map[string]interface{}{
								"module":    "remote_control",
								"passed":    result == "OK",
								"result":    result,
								"detail":    detail,
								"test_type": "system",
								"mitre":     "N/A",
								"timestamp": time.Now().Format(time.RFC3339),
							})
						}
					}
					if currentRunner != nil {
						currentRunner.Stop()
						ack("OK", "Stop signal sent to assessment runner")
					} else {
						ack("INFO", "No active assessment to stop")
					}
					continue
				}

				// ── Phase 2: User confirmed — proceed with optional disable ───────
				if cmdType == "confirm_assessment" && pending != nil {
					// Serialize with the startup auto-resume path so two
					// assessments can never run concurrently.
					assessMu.Lock()

					disableVendor, _ := cmd["disable_vendor"].(string)

					// Persist the operator's choices *before* the assessment
					// starts: if the EDR kills us mid-run, the next startup
					// needs this intent to replay the exact same context
					// (vendor disable, profile, test type, duration).
					_ = state.SaveIntent(state.Intent{
						DisableVendor: disableVendor,
						Profile:       pending.profile,
						TestType:      pending.testType,
						Days:          pending.days,
						CreatedAt:     time.Now(),
					})

					liveAgents, _ := discovery.Scan()
					target := discovery.DiscoveredAgent{Vendor: "None", ServiceName: "N/A", ProcessName: "N/A"}
					if len(liveAgents) > 0 {
						target = liveAgents[0]
					}

					var restoreFn func()
					var guard *watchdog.Guard
					if disableVendor != "" && strings.ToLower(disableVendor) != "none" {
						logger.Info("Disabling vendor before assessment", map[string]interface{}{
							"vendor": disableVendor,
						})
						result, restore := disabler.Disable(disableVendor)
						restoreFn = restore
						// Arm the watchdog so the vendor is re-enabled even if this
						// process is killed or hangs mid-assessment. The deadline is
						// the assessment duration plus a grace period.
						maxDuration := time.Duration(pending.days)*24*time.Hour + time.Hour
						g, err := watchdog.Start(disableVendor, 90*time.Second, maxDuration)
						if err != nil {
							logger.Warn("Failed to arm re-enable watchdog", map[string]interface{}{"error": err.Error()})
						} else {
							guard = g
						}
						sender.Send(transport.EventAssessmentReady, map[string]interface{}{
							"vendor_disabled": result.Vendor,
							"disabled":        result.Disabled,
							"notes":           result.Notes,
							"target":          target.Vendor,
							"profile":         pending.profile,
						})
						logger.Info("Vendor disable result", map[string]interface{}{
							"vendor":   result.Vendor,
							"disabled": result.Disabled,
							"notes":    result.Notes,
						})
					} else {
						sender.Send(transport.EventAssessmentReady, map[string]interface{}{
							"vendor_disabled": "none",
							"disabled":        false,
							"notes":           "Running without disabling any vendor",
							"target":          target.Vendor,
							"profile":         pending.profile,
						})
					}

					logger.Info("Launching Active Assessment", map[string]interface{}{
						"target":  target.Vendor,
						"profile": pending.profile,
					})

					sched := core.NewScheduler(pending.profile, pending.days)

					// The reboot/boot-gap module gates on cfg.AllowReboot, which
					// previously could only be set by the agent's --allow-reboot
					// flag — so the dashboard's consent checkbox did nothing.
					// Apply it for the duration of this run and restore after.
					prevAllowReboot := cfg.AllowReboot
					if pending.allowReboot != prevAllowReboot {
						logger.Info("Applying reboot consent from dashboard", map[string]interface{}{
							"allow_reboot": pending.allowReboot, "previous": prevAllowReboot,
						})
						cfg.AllowReboot = pending.allowReboot
					}

					// Honour the operator's module selection. An empty selection
					// means "everything", which is what the dashboard sends when
					// no boxes were ticked.
					selector := "all"
					if len(pending.modules) > 0 {
						selector = strings.Join(pending.modules, ",")
					}
					logger.Info("Module selection resolved", map[string]interface{}{
						"selector": selector, "modules": pending.modules,
					})
					runner := modes.NewActiveRunner(cfg, logger, sched, target, selector, sender, pending.testType)

					// Register the runner so a stop_assessment command can signal it.
					currentRunner = runner
					core.SetStatus("assessing", fmt.Sprintf("Running %s assessment against %s", pending.profile, target.Vendor))
					if err := runner.Run(); err != nil {
						logger.Error("Assessment failed", map[string]interface{}{"error": err.Error()})
					}
					core.SetStatus("connected", "Monitoring passively")
					// Clear the runner reference so a subsequent stop command
					// doesn't try to signal a finished runner.
					currentRunner = nil
					// Restore the reboot consent the agent started with, so a
					// one-off dashboard approval does not persist into later runs.
					if pending.allowReboot != prevAllowReboot {
						cfg.AllowReboot = prevAllowReboot
					}

					// Always re-enable the vendor after the assessment, whether it passed or failed
					if restoreFn != nil {
						logger.Info("Re-enabling vendor after assessment", map[string]interface{}{
							"vendor": disableVendor,
						})
						restoreFn()
					}
					// Normal restore happened — disarm the watchdog so its child exits quietly
					if guard != nil {
						guard.Stop()
					}

					// Assessment finished (or failed) — its context is no
					// longer needed for auto-resume.
					state.ClearIntent()
					assessMu.Unlock()

					pending = nil
					continue
				}
			}
		}()

		runner := modes.NewPassiveRunner(cfg, logger, scheduler, sender)
		_ = runner.Run()

	case "active":
		if len(agents) == 0 {
			logger.Warn("Active Mode: no agents discovered", nil)
			return
		}
		target := agents[0]
		logger.Info("Starting Active Mode", map[string]interface{}{
			"target":  target.Vendor,
			"profile": profile,
			"module":  module,
		})
		runner := modes.NewActiveRunner(cfg, logger, scheduler, target, module, sender, "blackbox")
		_ = runner.Run()
	}
}

// ── Auto-resume ─────────────────────────────────────────────────────────────

const (
	// maxAutoResumes caps how many times an interrupted assessment is
	// automatically relaunched before giving up and asking the operator
	// to relaunch it from the dashboard. Prevents an endless kill/resume
	// loop against an EDR that kills the agent on sight.
	maxAutoResumes = 5

	// autoResumeDelay is a short backoff before resuming so the endpoint
	// (and the EDR under test) has a moment to settle after the kill.
	autoResumeDelay = 20 * time.Second
)

// autoResumeAssessment restarts an assessment that the EDR interrupted by
// killing the agent process. Called at startup in passive mode. The state
// checkpoint tells us what already completed; the resume intent tells us
// how the operator launched it. ActiveRunner then skips completed modules,
// records the kill on the module that was in flight as BLOCKED_BY_EDR
// (a pass for the EDR), and reports the session as resumed.
func autoResumeAssessment(cfg *core.Config, logger *core.Logger, sender transport.Sender) {
	st := state.Load()
	if st == nil || st.Status != state.StatusRunning {
		// Nothing in flight — drop any stale intent left behind.
		state.ClearIntent()
		return
	}

	if st.EDRKillCount >= maxAutoResumes {
		msg := fmt.Sprintf(
			"Auto-resume gave up after %d kill(s) — relaunch the assessment from the dashboard",
			st.EDRKillCount,
		)
		logger.Warn(msg, map[string]interface{}{"session_id": st.SessionID})
		fmt.Printf("[ACTIVE] %s\n", msg)
		sender.Send(transport.EventAssessmentAborted, map[string]interface{}{
			"session_id":     st.SessionID,
			"edr_kill_count": st.EDRKillCount,
			"target":         st.TargetVendor,
			"detail":         msg,
			"timestamp":      time.Now().Format(time.RFC3339),
		})
		return
	}

	// Restore the operator's original choices; fall back to the values
	// stored in the state file when no intent was persisted.
	profile, testType, days, disableVendor := st.Profile, st.TestType, 1, ""
	if intent := state.LoadIntent(); intent != nil {
		if intent.Profile != "" {
			profile = intent.Profile
		}
		if intent.TestType != "" {
			testType = intent.TestType
		}
		if intent.Days > 0 {
			days = intent.Days
		}
		disableVendor = intent.DisableVendor
	}

	logger.Info("Auto-resuming interrupted assessment", map[string]interface{}{
		"session_id":        st.SessionID,
		"target":            st.TargetVendor,
		"edr_kill_count":    st.EDRKillCount + 1,
		"completed_modules": st.CompletedModules,
	})
	fmt.Printf("\n[ACTIVE] *** Interrupted assessment found — auto-resuming (kill #%d) ***\n", st.EDRKillCount+1)
	fmt.Printf("[ACTIVE] Session: %s | Completed so far: %v\n", st.SessionID, st.CompletedModules)

	// Back off briefly so the endpoint settles after the kill.
	time.Sleep(autoResumeDelay)

	// Re-discover the target; prefer the vendor the assessment ran
	// against so the runner's resume guard (same vendor + test type)
	// matches and the checkpoint is kept instead of reset.
	liveAgents, _ := discovery.Scan()
	target := discovery.DiscoveredAgent{
		Vendor:      st.TargetVendor,
		ServiceName: "N/A",
		ProcessName: "N/A",
	}
	for _, a := range liveAgents {
		if a.Vendor == st.TargetVendor {
			target = a
			break
		}
	}

	// Re-apply the vendor disable and re-arm the restore watchdog exactly
	// like the dashboard-confirmed path does — measurement conditions stay
	// consistent across the kill.
	var restoreFn func()
	var guard *watchdog.Guard
	if disableVendor != "" && strings.ToLower(disableVendor) != "none" {
		logger.Info("Re-disabling vendor for resumed assessment", map[string]interface{}{
			"vendor": disableVendor,
		})
		result, restore := disabler.Disable(disableVendor)
		restoreFn = restore
		maxDuration := time.Duration(days)*24*time.Hour + time.Hour
		g, err := watchdog.Start(disableVendor, 90*time.Second, maxDuration)
		if err != nil {
			logger.Warn("Failed to arm re-enable watchdog", map[string]interface{}{"error": err.Error()})
		} else {
			guard = g
		}
		sender.Send(transport.EventAssessmentReady, map[string]interface{}{
			"vendor_disabled": result.Vendor,
			"disabled":        result.Disabled,
			"notes":           result.Notes,
			"target":          target.Vendor,
			"profile":         profile,
			"detail":          "auto-resume after EDR kill",
		})
	}

	sched := core.NewScheduler(profile, days)
	runner := modes.NewActiveRunner(cfg, logger, sched, target, "all", sender, testType)
	if err := runner.Run(); err != nil {
		logger.Error("Resumed assessment failed", map[string]interface{}{"error": err.Error()})
	}

	// Always re-enable the vendor and disarm the watchdog, mirroring the
	// dashboard-confirmed path.
	if restoreFn != nil {
		restoreFn()
	}
	if guard != nil {
		guard.Stop()
	}
	state.ClearIntent()
}
