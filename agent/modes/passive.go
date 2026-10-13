package modes

import (
	"fmt"
	"time"

	"agentide/core"
	"agentide/discovery"
	"agentide/transport"
)

// PassiveRunner watches the OS for new security agent installations.
type PassiveRunner struct {
	cfg       *core.Config
	logger    *core.Logger
	scheduler *core.Scheduler
	sender    transport.Sender
}

// NewPassiveRunner creates a configured PassiveRunner.
func NewPassiveRunner(cfg *core.Config, logger *core.Logger, scheduler *core.Scheduler, sender transport.Sender) *PassiveRunner {
	return &PassiveRunner{cfg: cfg, logger: logger, scheduler: scheduler, sender: sender}
}

// Run starts the passive installation watcher loop.
// It blocks indefinitely, monitoring for new security agent installations.
func (r *PassiveRunner) Run() error {
	r.logger.Info("Passive Mode started", map[string]interface{}{
		"profile": string(r.scheduler.Profile),
	})

	fmt.Println("[PASSIVE] Monitoring for security agent installations. Press Ctrl+C to stop.")
	fmt.Printf("[PASSIVE] Profile: %s\n\n", r.scheduler.ProfileDescription())

	return watchInstallations(r.cfg, r.logger, r.sender)
}

// watchInstallations polls the OS for new security agent installations.
func watchInstallations(cfg *core.Config, logger *core.Logger, sender transport.Sender) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Track every vendor we have already reported, so each one is announced
	// exactly once. A layered estate (Defender + a third-party sensor) can have
	// several agents running at once and every one of them matters to the
	// assessment — reporting only the first would hide real coverage.
	reported := map[string]bool{}

	for range ticker.C {
		logger.Debug("Passive watch tick", nil)

		agents, err := discovery.Scan()
		if err != nil {
			logger.Warn("Discovery scan failed", map[string]interface{}{"error": err.Error()})
			continue
		}

		var fresh []map[string]interface{}
		for _, a := range agents {
			if reported[a.Vendor] {
				continue
			}
			reported[a.Vendor] = true
			logger.Info("Discovered security agent", map[string]interface{}{
				"vendor": a.Vendor,
				"pid":    a.PID,
			})
			fresh = append(fresh, map[string]interface{}{
				"discovered_vendor": a.Vendor,
				"process_name":      a.ProcessName,
				"service_name":      a.ServiceName,
				"pid":               a.PID,
			})
		}

		if len(fresh) > 0 && sender != nil {
			// Send as an array so every vendor on the host reaches the dashboard.
			// The dashboard's handleDiscovery accepts both this array shape and
			// the single-object shape older agents send.
			sender.SendDiscovery(fresh)
		}
	}
	return nil
}
