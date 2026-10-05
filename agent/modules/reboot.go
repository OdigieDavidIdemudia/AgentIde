package modules

import (
	"agentide/core"
	"fmt"
	"time"
)

type rebootModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *rebootModule) Name() string { return "reboot" }

func (m *rebootModule) Run() RawResult {
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1547.001",
		Action:     "Boot gap test: plant startup payload and reboot to test agent startup speed",
	}

	if !m.cfg.AllowReboot {
		result.Notes = "Skipped — pass --allow-reboot flag to enable this test"
		m.logger.Info("Reboot module skipped (--allow-reboot not set)", nil)
		return result
	}

	start := time.Now()
	m.logger.Info("Reboot: planting startup payload", nil)

	// Plant the startup payload
	if err := plantStartupPayload(); err != nil {
		result.Notes = fmt.Sprintf("Failed to plant startup payload: %v", err)
		m.logger.Error("Reboot: payload plant failed", map[string]interface{}{"error": err.Error()})
		return result
	}

	// Record in ledger so cleanup removes it if the reboot test is skipped
	globalLedger.Record("startup", "agentide_bootgap_test", nil)

	// Persist state so AgentIde knows on next boot it's in a boot gap test
	if err := persistBootGapState(); err != nil {
		result.Notes = fmt.Sprintf("Failed to persist boot state: %v", err)
		return result
	}

	result.ElapsedMs = time.Since(start).Milliseconds()
	result.Notes = "Startup payload planted. Rebooting system in 5 seconds..."
	m.logger.Info("Reboot: triggering system reboot", nil)

	// Trigger reboot (platform-specific)
	triggerReboot()

	return result
}
