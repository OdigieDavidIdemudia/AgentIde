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

	repair := func() {
		if service.UpdateInProgress() {
			logLine("self-update in progress — standing down")
			return
		}
		if err := service.EnsureInstalled(); err != nil {
			logLine("repair failed: %v", err)
		}
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
