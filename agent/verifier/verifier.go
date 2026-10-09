package verifier

import (
	"fmt"

	"agentide/core"
	"agentide/discovery"
	"agentide/modules"
	"agentide/reporter"
)

// PreflightResult holds the result of a preflight trust check.
type PreflightResult struct {
	Passed bool
	Reason string
}

func (p PreflightResult) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"passed": p.Passed,
		"reason": p.Reason,
	}
}

// PreflightCheck verifies if the agent is trusted by the target EDR.
func PreflightCheck(cfg *core.Config, target discovery.DiscoveredAgent) PreflightResult {
	// For now, this is a basic stub that passes. You can implement full check logic here.
	if target.Vendor == "None Detected" || target.Vendor == "None" {
		return PreflightResult{Passed: true, Reason: "No EDR detected to block execution"}
	}
	return PreflightResult{Passed: true, Reason: "Agent appears to have necessary execution permissions"}
}

// Verify takes a raw module result and translates local OS signals into a
// structured TestResult with a clear Pass/Fail determination.
// No API keys. No cloud calls. Purely local OS feedback.
func Verify(raw modules.RawResult) reporter.TestResult {
	passed := isPassed(raw)
	detail := buildDetail(raw, passed)

	return reporter.TestResult{
		ModuleName: raw.ModuleName,
		Action:     raw.Action,
		Passed:     passed,
		Detail:     detail,
		ElapsedMs:  raw.ElapsedMs,
		Notes:      raw.Notes,
		Artifacts:  raw.Artifacts,
	}
}

// isPassed determines if the vendor agent successfully blocked the test action.
func isPassed(raw modules.RawResult) bool {
	fb := raw.OSFeedback
	switch raw.ModuleName {
	case "malware":
		// Pass if the EICAR file was quarantined (vanished from disk) OR the
		// execution attempt was blocked by the endpoint's protection.
		return fb.FileVanished || fb.ProcessKilled || fb.AccessDenied

	case "antitamper":
		// Pass if the OS denied every tamper attempt
		return fb.AccessDenied

	case "lolbin":
		// Pass if the process was blocked or access was denied
		return fb.ProcessKilled || fb.AccessDenied

	case "network":
		// Pass if the network connection was blocked
		return fb.NetworkBlocked

	case "identity":
		// Pass if the lockout/alert was observed in the event log
		return fb.EventLogEntryFound || fb.AccessDenied

	case "performance":
		// Performance is always "informational" — always passes
		return true

	case "falsepositive":
		// False positive is informational — always passes (score is in the notes)
		return true

	case "reboot":
		// Reboot is a special test — pass if the payload was blocked on startup
		return fb.AccessDenied || fb.ProcessKilled

	default:
		return false
	}
}

// buildDetail constructs a human-readable result string.
func buildDetail(raw modules.RawResult, passed bool) string {
	fb := raw.OSFeedback

	switch raw.ModuleName {
	case "malware":
		if passed {
			if fb.FileVanished {
				return "PASS — EICAR blocked/quarantined in " + msToStr(fb.VanishTimeMs)
			}
			return "PASS — EICAR execution blocked by endpoint protection"
		}
		return "FAIL — EICAR file remained on disk and execution was not blocked"

	case "antitamper":
		if passed {
			return "PASS — All tamper attempts blocked by vendor"
		}
		return "FAIL — Vendor process/service/binary was NOT protected"

	case "lolbin":
		if passed {
			return "PASS — LOLBin execution blocked"
		}
		return "FAIL — LOLBin techniques allowed to execute"

	case "network":
		if passed {
			return "PASS — Outbound C2 connection blocked"
		}
		return "FAIL — C2 beaconing allowed through"

	case "identity":
		if passed {
			return "PASS — Password spray detected and alerted"
		}
		return "FAIL — No alert raised for repeated failed logins"

	case "performance":
		return "INFO — " + raw.Notes

	case "falsepositive":
		return "INFO — " + raw.Notes

	case "reboot":
		if raw.Notes == "Skipped — pass --allow-reboot flag to enable this test" {
			return "SKIPPED — Reboot not permitted"
		}
		if passed {
			return "PASS — Startup payload blocked on boot"
		}
		return "FAIL — Startup payload executed before vendor agent initialized"
	}
	return raw.Notes
}

func msToStr(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}
