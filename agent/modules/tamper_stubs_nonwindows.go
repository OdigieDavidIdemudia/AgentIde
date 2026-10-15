//go:build !windows

package modules

import (
	"agentide/core"
)

// The tamper modules (ETW disable, AMSI disable, ETW tampering, driver
// unload, registry policy modification) are Windows-only by nature: they
// write HKLM Autologger and Defender policy keys that have no Linux
// equivalent, and they use Windows-only syscalls.
//
// Stubs are provided so the package — and therefore the whole agent — still
// cross-compiles for Linux, which verify.bat checks. Each stub reports a
// "resisted" outcome rather than a false success, because on a non-Windows
// host the honest answer is that the technique does not apply.

type disableETWModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *disableETWModule) Name() string { return "disable_etw" }

func (m *disableETWModule) Run() RawResult {
	return RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562.002",
		Action:     "Attempt to disable ETW providers via registry modification",
		Notes:      "Not applicable: ETW Autologger registry keys are Windows-only",
		OSFeedback: OSFeedback{AccessDenied: true},
	}
}

type disableAMSIModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *disableAMSIModule) Name() string { return "disable_amsi" }

func (m *disableAMSIModule) Run() RawResult {
	return RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562.001",
		Action:     "Attempt to disable AMSI via memory patching and registry",
		Notes:      "Not applicable: AMSI is a Windows-only component",
		OSFeedback: OSFeedback{AccessDenied: true},
	}
}

type disableETWTamperModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *disableETWTamperModule) Name() string { return "disable_etw_tamper" }

func (m *disableETWTamperModule) Run() RawResult {
	return RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562.002",
		Action:     "Attempt to tamper with ETW sessions and providers beyond autologgers",
		Notes:      "Not applicable: ETW is a Windows-only subsystem",
		OSFeedback: OSFeedback{AccessDenied: true},
	}
}

type unloadDriverModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *unloadDriverModule) Name() string { return "unload_driver" }

func (m *unloadDriverModule) Run() RawResult {
	return RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562.001",
		Action:     "Attempt to unload or stop EDR kernel drivers",
		Notes:      "Not applicable: no EDR kernel drivers on this platform",
		OSFeedback: OSFeedback{AccessDenied: true},
	}
}

type modifyRegistryPoliciesModule struct {
	logger *core.Logger
	cfg    *core.Config
}

func (m *modifyRegistryPoliciesModule) Name() string { return "modify_registry_policies" }

func (m *modifyRegistryPoliciesModule) Run() RawResult {
	return RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1112",
		Action:     "Attempt to modify registry policies to disable security features",
		Notes:      "Not applicable: Windows Defender and GPO policy keys do not exist on this platform",
		OSFeedback: OSFeedback{AccessDenied: true},
	}
}
