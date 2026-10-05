package modules

import (
	"agentide/core"
	"agentide/discovery"
	"fmt"
	"os"
	"time"
)

type antiTamperModule struct {
	logger *core.Logger
	target discovery.DiscoveredAgent
}

func (m *antiTamperModule) Name() string { return "antitamper" }

func (m *antiTamperModule) Run() RawResult {
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562.001",
		Action:     fmt.Sprintf("Attempt to stop/kill %s agent processes and services", m.target.Vendor),
	}

	start := time.Now()
	notes := []string{}
	anyBlocked := false

	// ── 1. Try to terminate vendor process by PID ─────────────────────────
	if m.target.PID > 0 {
		m.logger.Info("AntiTamper: attempting process termination", map[string]interface{}{
			"vendor": m.target.Vendor, "pid": m.target.PID,
		})
		blocked, note := tryKillProcess(m.target.PID)
		notes = append(notes, note)
		if blocked {
			anyBlocked = true
		}
	}

	// ── 2. Try to stop vendor service ─────────────────────────────────────
	if m.target.ServiceName != "" {
		m.logger.Info("AntiTamper: attempting service stop", map[string]interface{}{
			"service": m.target.ServiceName,
		})
		blocked, note := tryStopService(m.target.ServiceName)
		notes = append(notes, note)
		if blocked {
			anyBlocked = true
		}
	}

	// ── 3. Try to delete vendor process binary ────────────────────────────
	if m.target.ProcessName != "" {
		binPath := findBinary(m.target.ProcessName)
		if binPath != "" {
			m.logger.Info("AntiTamper: attempting binary deletion", map[string]interface{}{"path": binPath})
			err := os.Remove(binPath)
			if err != nil {
				anyBlocked = true
				notes = append(notes, fmt.Sprintf("Binary deletion blocked (%s): %v", binPath, err))
			} else {
				notes = append(notes, fmt.Sprintf("Binary deleted (FAIL — not protected): %s", binPath))
				// Record for cleanup restoration attempt
				globalLedger.Record("file", binPath, nil)
			}
		}
	}

	result.OSFeedback.AccessDenied = anyBlocked
	result.ElapsedMs = time.Since(start).Milliseconds()
	result.Notes = joinNotes(notes)
	return result
}
