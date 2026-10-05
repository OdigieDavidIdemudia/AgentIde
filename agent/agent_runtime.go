// Platform-neutral agent runtime shared by the Windows service and the
// foreground / Linux execution paths.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"agentide/core"
	"agentide/disabler"
	"agentide/discovery"
	"agentide/fingerprint"
	"agentide/modes"
	"agentide/resilience"
	"agentide/transport"
	"agentide/watchdog"
)

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
		"version": version,
		"mode":    mode,
		"profile": profile,
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

	sender.SendFingerprint(fp.ToMap())
	sender.StartHeartbeat()

	vendor := "None Detected"
	if len(agents) > 0 {
		vendor = agents[0].Vendor
	}
	sender.SendDiscovery(map[string]interface{}{"discovered_vendor": vendor})

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

	switch strings.ToLower(mode) {
	case "passive":
		logger.Info("Starting Passive Mode", nil)

		// Listen for start_assessment commands from the dashboard in the background
		go func() {
			// pendingConfirm holds context from a start_assessment while we wait for confirm_assessment
			type pendingAssessment struct {
				profile  string
				testType string
				days     int
			}
			var pending *pendingAssessment

			for cmd := range sender.Commands() {
				cmdType, _ := cmd["type"].(string)

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
						profile:  cmdProfile,
						testType: cmdTestType,
						days:     days,
					}

					logger.Info("Pre-scan complete — waiting for user confirmation", map[string]interface{}{
						"agents_found": len(liveAgents),
					})
					continue
				}

				// ── Phase 2: User confirmed — proceed with optional disable ───────
				if cmdType == "confirm_assessment" && pending != nil {
					disableVendor, _ := cmd["disable_vendor"].(string)

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
					runner := modes.NewActiveRunner(cfg, logger, sched, target, "all", sender, pending.testType)
					if err := runner.Run(); err != nil {
						logger.Error("Assessment failed", map[string]interface{}{"error": err.Error()})
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
