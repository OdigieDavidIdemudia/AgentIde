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

	// Keep track of the last discovered agent to avoid spamming events
	var lastDiscoveredVendor string

	for range ticker.C {
		logger.Debug("Passive watch tick", nil)
		
		agents, err := discovery.Scan()
		if err != nil {
			logger.Warn("Discovery scan failed", map[string]interface{}{"error": err.Error()})
			continue
		}

		if len(agents) > 0 {
			vendor := agents[0].Vendor
			if vendor != lastDiscoveredVendor {
				logger.Info("Discovered security agent", map[string]interface{}{
					"vendor": vendor,
					"pid":    agents[0].PID,
				})
				lastDiscoveredVendor = vendor

				if sender != nil {
					sender.SendDiscovery(map[string]interface{}{
						"discovered_vendor": vendor,
						"process_name":      agents[0].ProcessName,
						"service_name":      agents[0].ServiceName,
					})
				}
			}
		}
	}
	return nil
}
