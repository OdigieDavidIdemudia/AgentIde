//go:build windows

// Package guard implements the AgentIde self-protection guardian.
//
// The guardian is a second Windows service that watches the main AgentIde
// service and repairs it: if the service is stopped it is started, if its
// registration is deleted it is recreated, and if the installed binary is
// removed it is restored from a backup. This keeps the assessment agent
// running even against an EDR that tries to stop or uninstall it.
package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"agentide/service"
)

const pollInterval = 15 * time.Second

// standDownThreshold is how many consecutive ticks may observe an in-flight
// self-update before the guardian escalates. The lock is meant to expire after
// 15 minutes, so anything beyond this is a stale or refreshed lock — most often
// an EDR killing the agent mid-swap, which re-triggers the update path and
// re-creates the lock every cycle.
const standDownThreshold = 8 // 8 ticks * 15s = 2 minutes

// escalateStandDownCount is how many consecutive escalations we tolerate before
// clearing a lock that cannot be expiring on its own. Clearing it is the only
// way to break the livelock, and it is safe: the worst case is that the
// guardian restores a binary while an update is genuinely in flight, and the
// updater's SHA-256 verification rejects it on the next attempt.
const escalateStandDownCount = 2

func logPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "AgentIde")
	// The installer normally creates this, but the guardian may be the first
	// thing to run (e.g. when it is started directly by the SCM).
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "guardian.log")
}

// Run is the guardian loop. It repairs the AgentIde install on every tick and
// returns when stop is closed (service stop / shutdown).
func Run(stop <-chan struct{}) {
	logf, _ := os.OpenFile(logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if logf != nil {
		defer logf.Close()
	}
	logLine := func(format string, args ...interface{}) {
		if logf != nil {
			fmt.Fprintf(logf, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
		}
	}

	logLine("guardian started (interval %s)", pollInterval)

	consecutiveStandDowns := 0
	escalations := 0

	repair := func() {
		if service.UpdateInProgress() {
			consecutiveStandDowns++

			// Still inside a plausible update window.
			if consecutiveStandDowns < standDownThreshold {
				logLine("self-update in progress — standing down (%d/%d)",
					consecutiveStandDowns, standDownThreshold)
				return
			}

			// The lock has outlived a normal update. Restoring the binary is
			// still safe — we deliberately do NOT restart the service, because
			// that is what races with an in-flight swap. This is the "degraded
			// mode" that keeps the agent recoverable instead of fully passive.
			if escalations < escalateStandDownCount {
				escalations++
				logLine("⚠️ self-update lock stale (%d ticks) — degraded mode: restoring binary only, not restarting service",
					consecutiveStandDowns)
				service.RestoreBinaryIfMissing()
				return
			}

			// Still locked after escalation. Break the livelock: an EDR killing
			// the agent mid-update refreshes the lock on every cycle, so expiry
			// alone never fires.
			logLine("🚨 self-update lock stuck for %d ticks — forcing clear to break livelock", consecutiveStandDowns)
			service.ClearUpdateInProgress()
			consecutiveStandDowns = 0
			escalations = 0
			return
		}

		// No update in flight — normal repair.
		consecutiveStandDowns = 0
		escalations = 0
		if err := service.EnsureInstalled(); err != nil {
			logLine("repair failed: %v", err)
			return
		}
		logLine("repair ok")
	}

	repair()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			logLine("guardian stopping (service control)")
			return
		case <-ticker.C:
			repair()
		}
	}
}
