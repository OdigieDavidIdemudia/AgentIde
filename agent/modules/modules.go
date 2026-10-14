package modules

import (
	"agentide/core"
	"agentide/discovery"
)

// Module is the interface every assessment module must implement.
type Module interface {
	// Name returns the unique identifier for this module (used for --module flag).
	Name() string
	// Run executes the module and returns a raw TestResult.
	Run() RawResult
}

// RawResult is the unverified output from a module's execution attempt.
type RawResult struct {
	ModuleName string
	MitreID    string
	Action     string // Human-readable description of what was attempted
	OSFeedback OSFeedback
	ElapsedMs  int64
	Notes      string
	// Artifacts lists every file/registry path the module created or touched,
	// so the report can show exactly what was written to disk.
	Artifacts []string
}

// OSFeedback captures the raw OS-level signals observed after an action.
type OSFeedback struct {
	ProcessKilled      bool   // The launched test process was terminated immediately
	AccessDenied       bool   // OS returned an access-denied error
	FileVanished       bool   // A dropped file was deleted/quarantined by the vendor
	NetworkBlocked     bool   // The outbound connection was refused/reset
	EventLogEntryFound bool   // A block event was found in the local event log
	VanishTimeMs       int64  // How quickly the file disappeared (ms)
	ErrorCode          string // Raw OS error code if relevant
}

// Cleanup reverses all changes made by modules during the assessment.
// It reads the global change ledger and rolls back in reverse order.
func Cleanup(logger *core.Logger) {
	logger.Info("Cleanup started", nil)
	globalLedger.RollbackAll(logger)
	logger.Info("Cleanup complete", nil)
}

// NewAntiTamperModule creates the anti-tampering test module.
func NewAntiTamperModule(logger *core.Logger, target discovery.DiscoveredAgent) Module {
	return &antiTamperModule{logger: logger, target: target}
}

// NewMalwareModule creates the EICAR malware prevention test module.
func NewMalwareModule(logger *core.Logger) Module {
	return &malwareModule{logger: logger}
}

// NewLOLBinModule creates the Living-Off-The-Land binary execution module.
func NewLOLBinModule(logger *core.Logger) Module {
	return &lolbinModule{logger: logger}
}

// NewNetworkModule creates the C2 beaconing and network toggle module.
func NewNetworkModule(logger *core.Logger) Module {
	return &networkModule{logger: logger}
}

// NewIdentityModule creates the password spray simulation module.
func NewIdentityModule(logger *core.Logger) Module {
	return &identityModule{logger: logger}
}

// NewPerformanceModule creates the CPU/RAM monitoring module.
func NewPerformanceModule(logger *core.Logger) Module {
	return &performanceModule{logger: logger}
}

// NewFalsePositiveModule creates the alert fatigue / false-positive module.
func NewFalsePositiveModule(logger *core.Logger) Module {
	return &falsePositiveModule{logger: logger}
}

// NewRebootModule creates the boot gap persistence test module.
func NewRebootModule(logger *core.Logger, cfg *core.Config) Module {
	return &rebootModule{logger: logger, cfg: cfg}
}

// NewDisableETWModule creates the ETW provider disable test module.
func NewDisableETWModule(logger *core.Logger, cfg *core.Config) Module {
	return &disableETWModule{logger: logger, cfg: cfg}
}

// NewDisableAMSIModule creates the AMSI disable test module.
func NewDisableAMSIModule(logger *core.Logger, cfg *core.Config) Module {
	return &disableAMSIModule{logger: logger, cfg: cfg}
}

// NewDisableETWTamperModule creates the ETW tamper test module.
func NewDisableETWTamperModule(logger *core.Logger, cfg *core.Config) Module {
	return &disableETWTamperModule{logger: logger, cfg: cfg}
}

// NewUnloadDriverModule creates the EDR driver unload test module.
func NewUnloadDriverModule(logger *core.Logger, cfg *core.Config) Module {
	return &unloadDriverModule{logger: logger, cfg: cfg}
}

// NewModifyRegistryPoliciesModule creates the registry policy modification test module.
func NewModifyRegistryPoliciesModule(logger *core.Logger, cfg *core.Config) Module {
	return &modifyRegistryPoliciesModule{logger: logger, cfg: cfg}
}
