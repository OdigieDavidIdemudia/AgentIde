package modules

import (
	"agentide/core"
	"fmt"
	"time"
)

type identityModule struct{ logger *core.Logger }

func (m *identityModule) Name() string { return "identity" }

func (m *identityModule) Run() RawResult {
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1110.003",
		Action:     "Simulate password spray: 10 rapid failed local authentication attempts",
	}

	start := time.Now()
	m.logger.Info("Identity: password spray started", map[string]interface{}{"attempts": 10})

	blocked, note := simulatePasswordSpray(10)

	// AccessDenied drives the verifier's pass/fail. It is only true when the
	// vendor's identity protection demonstrably reacted to THIS spray, which
	// simulatePasswordSpray guarantees by attributing events to a probe
	// account and a time window. Anything else (including an unreadable event
	// log) stays false so an unmeasured host is never scored as protected.
	result.OSFeedback.AccessDenied = blocked
	result.ElapsedMs = time.Since(start).Milliseconds()
	if blocked {
		result.Notes = fmt.Sprintf("%s (elapsed: %dms)", note, result.ElapsedMs)
	} else {
		// Make the inconclusive cases explicit for the report: a silent
		// "not blocked" reads like a clean result rather than a failed probe.
		result.Notes = fmt.Sprintf("%s (elapsed: %dms) — NOT PROTECTED / INCONCLUSIVE, do not read as a pass",
			note, result.ElapsedMs)
	}

	m.logger.Info("Identity: password spray complete", map[string]interface{}{
		"blocked": blocked,
		"note":    note,
	})
	return result
}
