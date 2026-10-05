package modes

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"agentide/core"
	"agentide/discovery"
	"agentide/modules"
	"agentide/reporter"
	"agentide/state"
	"agentide/transport"
	"agentide/verifier"

	"github.com/google/uuid"
)

// ActiveRunner executes the full assessment matrix against a discovered target agent.
type ActiveRunner struct {
	cfg       *core.Config
	logger    *core.Logger
	scheduler *core.Scheduler
	target    discovery.DiscoveredAgent
	module    string
	sender    transport.Sender
	testType  string // "whitebox" or "blackbox"
}

// NewActiveRunner creates a configured ActiveRunner.
func NewActiveRunner(cfg *core.Config, logger *core.Logger, scheduler *core.Scheduler, target discovery.DiscoveredAgent, module string, sender transport.Sender, testType string) *ActiveRunner {
	if testType == "" {
		testType = "blackbox"
	}
	return &ActiveRunner{cfg: cfg, logger: logger, scheduler: scheduler, target: target, module: module, sender: sender, testType: testType}
}

// runModuleSafely executes a module and catches any panics or hangs to prevent full agent crash.
func (r *ActiveRunner) runModuleSafely(mod modules.Module) (result modules.RawResult, recovered bool) {
	resCh := make(chan modules.RawResult, 1)
	panicCh := make(chan interface{}, 1)

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				panicCh <- rec
			}
		}()
		resCh <- mod.Run()
	}()

	select {
	case res := <-resCh:
		return res, false
	case rec := <-panicCh:
		r.logger.Error("Module panicked", map[string]interface{}{
			"module": mod.Name(), "panic": fmt.Sprintf("%v", rec),
		})
		r.sender.SendModuleResult(map[string]interface{}{
			"module": mod.Name(), "passed": false, "result": "ERROR",
			"detail":    fmt.Sprintf("module panicked: %v", rec),
			"test_type": r.testType,
			"mitre":     "Unknown",
			"timestamp": time.Now().Format(time.RFC3339),
		})
		return modules.RawResult{}, true
	case <-time.After(35 * time.Second):
		r.logger.Warn("Module hung and timed out", map[string]interface{}{"module": mod.Name()})
		r.sender.SendModuleResult(map[string]interface{}{
			"module": mod.Name(), "passed": false, "result": "TIMEOUT",
			"detail":    "module hung for over 35 seconds and was forcefully timed out",
			"test_type": r.testType,
			"mitre":     "Unknown",
			"timestamp": time.Now().Format(time.RFC3339),
		})
		return modules.RawResult{}, true
	}
}

// Run executes the selected assessment modules and generates the final report.
// If a prior state file exists for a crashed assessment, it resumes from where it left off.
func (r *ActiveRunner) Run() error {
	r.logger.Info("Active Mode started", map[string]interface{}{
		"target": r.target.Vendor, "profile": string(r.scheduler.Profile),
		"module": r.module, "test_type": r.testType,
	})
	fmt.Printf("\n[ACTIVE] Target    : %s\n", r.target.Vendor)
	fmt.Printf("[ACTIVE] Profile   : %s\n", r.scheduler.ProfileDescription())
	fmt.Printf("[ACTIVE] Module    : %s\n", r.module)
	fmt.Printf("[ACTIVE] Test Type : %s\n\n", r.testType)

	preflightResult := verifier.PreflightCheck(r.cfg, r.target)
	r.sender.Send(transport.EventPreflightResult, preflightResult.ToMap())
	if !preflightResult.Passed && r.testType != "blackbox_deployment_test" {
		r.logger.Warn("Preflight check failed — aborting technique execution", map[string]interface{}{"reason": preflightResult.Reason})
		fmt.Printf("[ACTIVE] Preflight failed: %s — aborting to avoid false BLOCKED readings\n", preflightResult.Reason)
		return fmt.Errorf("preflight check failed: %s", preflightResult.Reason)
	}

	// ── STATE RESTORE ───────────────────────────────────────────────────────────
	// Check if there is a prior in-progress assessment that was interrupted (e.g., by EDR).
	var assessState *state.AssessmentState
	priorState := state.Load()

	allModules := buildModuleList(r.cfg, r.logger, r.target)
	selectedModules := filterModules(allModules, r.module)

	if priorState != nil &&
		priorState.Status == state.StatusRunning &&
		priorState.TargetVendor == r.target.Vendor &&
		priorState.TestType == r.testType {

		// We were killed mid-assessment. This is itself forensic evidence.
		assessState = priorState
		_ = assessState.IncrementKillCount()

		killMsg := fmt.Sprintf("EDR process kill detected — assessment interrupted %d time(s). Resuming from last checkpoint.", assessState.EDRKillCount)
		r.logger.Warn(killMsg, map[string]interface{}{
			"session_id":        assessState.SessionID,
			"completed_modules": assessState.CompletedModules,
			"edr_kill_count":    assessState.EDRKillCount,
		})
		fmt.Printf("[ACTIVE] *** RESUMED after EDR kill (kill #%d) ***\n", assessState.EDRKillCount)
		fmt.Printf("[ACTIVE] Session: %s\n", assessState.SessionID)
		fmt.Printf("[ACTIVE] Skipping already-completed modules: %v\n\n", assessState.CompletedModules)

		// Notify the dashboard that this is a resume, not a fresh start.
		r.sender.Send(transport.EventAssessmentResumed, map[string]interface{}{
			"session_id":        assessState.SessionID,
			"edr_kill_count":    assessState.EDRKillCount,
			"completed_modules": assessState.CompletedModules,
			"target":            r.target.Vendor,
			"test_type":         r.testType,
			"timestamp":         time.Now().Format(time.RFC3339),
			"detail":            killMsg,
		})

		// The module that was running when we were killed never completed cleanly.
		// Record it as BLOCKED_BY_EDR — this is a PASS for the EDR (it killed us).
		for _, mod := range selectedModules {
			if !assessState.HasCompleted(mod.Name()) {
				// This is the module we were killed on. Record a BLOCKED_BY_EDR pass.
				killedOnModule := mod.Name()
				mitreID := getMitreID(killedOnModule, allModules)
				edrKillRecord := state.ModuleRecord{
					Name:      killedOnModule,
					Passed:    true, // EDR PASSED — it killed the process
					Result:    "BLOCKED_BY_EDR",
					Detail:    fmt.Sprintf("EDR terminated the agent process during this module — technique was successfully blocked (kill #%d)", assessState.EDRKillCount),
					MitreID:   mitreID,
					DurationMs: 0,
					TestType:  r.testType,
					Timestamp: time.Now().Format(time.RFC3339),
				}
				_ = assessState.MarkCompleted(edrKillRecord)

				// Also emit this to the dashboard so Reports page shows it.
				r.sender.SendModuleResult(map[string]interface{}{
					"module":      killedOnModule,
					"passed":      true,
					"result":      "BLOCKED_BY_EDR",
					"detail":      edrKillRecord.Detail,
					"test_type":   r.testType,
					"mitre":       mitreID,
					"duration_ms": 0,
					"timestamp":   edrKillRecord.Timestamp,
				})
				fmt.Printf("[ACTIVE] Logged EDR kill on module '%s' as BLOCKED_BY_EDR\n\n", killedOnModule)
				break // Only the first unfinished module was the one being run.
			}
		}

	} else {
		// ── FRESH START ─────────────────────────────────────────────────────────
		// Clear any stale state from a different assessment session.
		state.Clear()
		sessionID := uuid.New().String()
		var err error
		assessState, err = state.New(sessionID, r.target.Vendor, string(r.scheduler.Profile), r.testType)
		if err != nil {
			r.logger.Warn("Could not create state file — assessment will not be resumable", map[string]interface{}{"error": err.Error()})
		}
	}

	// Use the original start time from the state for accurate elapsed reporting.
	startTime := assessState.StartedAt
	// Restore any previously accumulated results.
	var results []reporter.TestResult
	for _, rec := range assessState.Results {
		results = append(results, reporter.TestResult{
			ModuleName: rec.Name,
			Passed:     rec.Passed,
			Detail:     rec.Detail,
			ElapsedMs:  rec.DurationMs,
		})
	}

	// ── MODULE EXECUTION LOOP ───────────────────────────────────────────────────
	for i, mod := range selectedModules {
		// Skip modules that were already completed in a prior run.
		if assessState.HasCompleted(mod.Name()) {
			fmt.Printf("[ACTIVE] Skipping '%s' (already completed in prior session)\n", mod.Name())
			continue
		}

		if !r.scheduler.ShouldRunNow(i, len(selectedModules)) {
			continue
		}
		r.scheduler.WaitUntilNext(i, len(selectedModules))

		fmt.Printf("[*] Running: %s\n", mod.Name())
		r.logger.Info("Module starting", map[string]interface{}{"module": mod.Name()})

		r.sender.Send(transport.EventModuleStart, map[string]interface{}{
			"module":      mod.Name(),
			"test_type":   r.testType,
			"index":       i + 1,
			"total":       len(selectedModules),
			"session_id":  assessState.SessionID,
		})

		rawResult, recovered := r.runModuleSafely(mod)
		if recovered {
			// A panic occurred. The error was already sent to the dashboard.
			// Record it as an error in the state so we skip it on resume.
			rec := state.ModuleRecord{
				Name: mod.Name(), Passed: false, Result: "ERROR",
				Detail: "module panicked (see logs)", MitreID: rawResult.MitreID,
				TestType: r.testType, Timestamp: time.Now().Format(time.RFC3339),
			}
			_ = assessState.MarkCompleted(rec)
			continue
		}

		verified := verifier.Verify(rawResult)
		results = append(results, verified)

		status := "PASS"
		if !verified.Passed {
			status = "FAIL"
		}
		fmt.Printf("    [%s] %s - %s\n", status, mod.Name(), verified.Detail)
		r.logger.Info("Module completed", map[string]interface{}{
			"module": mod.Name(), "passed": verified.Passed, "detail": verified.Detail,
		})

		// Persist the completed module BEFORE sending to the dashboard.
		// This ensures we have a record even if the network call is intercepted.
		rec := state.ModuleRecord{
			Name:       mod.Name(),
			Passed:     verified.Passed,
			Result:     status,
			Detail:     verified.Detail,
			MitreID:    rawResult.MitreID,
			DurationMs: rawResult.ElapsedMs,
			TestType:   r.testType,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
		_ = assessState.MarkCompleted(rec)

		r.sender.SendModuleResult(map[string]interface{}{
			"module":      mod.Name(),
			"passed":      verified.Passed,
			"result":      status,
			"detail":      verified.Detail,
			"test_type":   r.testType,
			"duration_ms": rawResult.ElapsedMs,
			"mitre":       rawResult.MitreID,
			"timestamp":   rec.Timestamp,
			"session_id":  assessState.SessionID,
		})
	}

	// ── ASSESSMENT COMPLETE ─────────────────────────────────────────────────────
	elapsed := time.Since(startTime)
	fmt.Printf("\n[ACTIVE] Assessment completed in %s\n", elapsed.Round(time.Second))

	passed := 0
	for _, res := range results {
		if res.Passed {
			passed++
		}
	}

	r.sender.SendAssessmentDone(map[string]interface{}{
		"target":         r.target.Vendor,
		"test_type":      r.testType,
		"session_id":     assessState.SessionID,
		"total_modules":  len(results),
		"passed":         passed,
		"failed":         len(results) - passed,
		"edr_kill_count": assessState.EDRKillCount,
		"duration":       elapsed.String(),
		"timestamp":      time.Now().Format(time.RFC3339),
	})

	// Delete the state file — clean completion.
	state.Clear()
	fmt.Println("[ACTIVE] State checkpoint cleared (clean exit).")

	reportDir := reportDirectory()
	rep := reporter.New(r.target.Vendor, results, elapsed)

	if err := rep.WriteHTML(filepath.Join(reportDir, "report.html")); err != nil {
		r.logger.Warn("HTML report generation failed", map[string]interface{}{"error": err.Error()})
		r.sender.Send(transport.EventReportStatus, map[string]interface{}{"format": "html", "success": false, "error": err.Error()})
	} else {
		fmt.Printf("[ACTIVE] Report saved: %s\n", filepath.Join(reportDir, "report.html"))
		r.sender.Send(transport.EventReportStatus, map[string]interface{}{"format": "html", "success": true, "path": filepath.Join(reportDir, "report.html")})
	}

	if err := rep.WriteCSV(filepath.Join(reportDir, "report.csv")); err != nil {
		r.logger.Warn("CSV report generation failed", map[string]interface{}{"error": err.Error()})
		r.sender.Send(transport.EventReportStatus, map[string]interface{}{"format": "csv", "success": false, "error": err.Error()})
	} else {
		fmt.Printf("[ACTIVE] Report saved: %s\n", filepath.Join(reportDir, "report.csv"))
		r.sender.Send(transport.EventReportStatus, map[string]interface{}{"format": "csv", "success": true, "path": filepath.Join(reportDir, "report.csv")})
	}

	fmt.Println("\n[ACTIVE] Running cleanup...")
	modules.Cleanup(r.logger)
	fmt.Println("[ACTIVE] Cleanup complete.")
	return nil
}

// getMitreID looks up the MITRE ID for a module by name by instantiating it briefly.
func getMitreID(moduleName string, allModules []modules.Module) string {
	for _, m := range allModules {
		if m.Name() == moduleName {
			// Return a sensible default without running the module.
			return "Unknown"
		}
	}
	return "Unknown"
}

// reportDirectory returns %PROGRAMDATA%\AgentIde\reports, creating it if needed.
func reportDirectory() string {
	base := os.Getenv("PROGRAMDATA")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "AgentIde", "reports")
	_ = os.MkdirAll(dir, 0755)
	return dir
}

func buildModuleList(cfg *core.Config, logger *core.Logger, target discovery.DiscoveredAgent) []modules.Module {
	return []modules.Module{
		modules.NewPerformanceModule(logger),
		modules.NewMalwareModule(logger),
		modules.NewLOLBinModule(logger),
		modules.NewNetworkModule(logger),
		modules.NewIdentityModule(logger),
		modules.NewAntiTamperModule(logger, target),
		modules.NewFalsePositiveModule(logger),
		modules.NewRebootModule(logger, cfg),
	}
}

func filterModules(all []modules.Module, selector string) []modules.Module {
	if selector == "all" {
		return all
	}
	var filtered []modules.Module
	for _, m := range all {
		if m.Name() == selector {
			filtered = append(filtered, m)
		}
	}
	return filtered
}
