package resilience

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

/**
 * An EDR successfully blocking the agent must be recorded as a kill.
 *
 * The original detector compared the gap since the last heartbeat against a
 * fixed 45-second threshold. That is backwards for the case that matters: the
 * SCM restarts a killed service within *seconds*, so the gap was always under
 * the threshold and no kill was ever reported. In practice a successful Cortex
 * block produced a silent, zero-result run indistinguishable from a crash.
 * These tests pin the clean-exit-marker behaviour that replaced it.
 */

// redirectState points both the live state file and the legacy Temp lookup at
// a temp dir for one test.
//
// Redirecting legacyLookup is essential, not just tidy: without it the first
// CheckAndUpdate falls through to the migration read and picks up the REAL
// C:\Windows\Temp\agentide_state.json written by the agent service on this
// machine, which silently imported a live kill count into the test.
func redirectState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	origDir, origInterval, origLegacy := stateDir, heartbeatInterval, legacyLookup
	stateDir = dir
	heartbeatInterval = 20 * time.Millisecond
	legacyLookup = func() string { return filepath.Join(dir, "legacy-"+legacyStateFileName) }

	t.Cleanup(func() {
		stateDir = origDir
		heartbeatInterval = origInterval
		legacyLookup = origLegacy
	})
	return StateFile()
}

// seed writes a state file describing a previous process, allowing the test to
// set the fields that decide how the next start is classified.
func seed(t *testing.T, s AgentState) {
	t.Helper()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(StateFile(), data, 0644); err != nil {
		t.Fatalf("write seed: %v", err)
	}
}

func TestFirstStartIsNotAKill(t *testing.T) {
	redirectState(t)

	kill, state := CheckAndUpdate("HOST-A")
	if kill != nil {
		t.Fatalf("first start reported a kill: %+v", kill)
	}
	if state.StartCount != 1 || state.KillCount != 0 {
		t.Fatalf("unexpected state: start=%d kill=%d", state.StartCount, state.KillCount)
	}
}

// The regression that motivated the whole change: the process was terminated
// and restarted almost immediately — 3 seconds, far under the old 45s bound.
func TestFastRestartWithoutCleanExitIsAKill(t *testing.T) {
	redirectState(t)

	CheckAndUpdate("HOST-B")
	seed(t, AgentState{
		Hostname:          "HOST-B",
		StartCount:        1,
		Version:           stateVersion,
		CleanExit:         false,
		AssessmentRunning: false,
		LastHeartbeat:     time.Now().Add(-3 * time.Second),
	})

	kill, state := CheckAndUpdate("HOST-B")
	if kill == nil {
		t.Fatal("a restart 3s after an unclean stop was not classified as a kill")
	}
	if state.KillCount != 1 {
		t.Errorf("kill count = %d, want 1", state.KillCount)
	}
	if kill.Downtime > 45*time.Second {
		t.Errorf("downtime %v is long; classification must not depend on it", kill.Downtime)
	}
	if kill.Reason == "" {
		t.Error("kill event must carry a reason for the report")
	}
}

// An orderly restart is NOT a kill. The previous process ran its shutdown path,
// so a new process starting afterwards is expected — a service update, a
// reboot, an operator restart. Reporting it as a kill would be a false positive
// on every legitimate restart.
func TestOrderlyRestartIsNotAKill(t *testing.T) {
	redirectState(t)

	CheckAndUpdate("HOST-C")
	seed(t, AgentState{
		Hostname:      "HOST-C",
		StartCount:    1,
		Version:       stateVersion,
		CleanExit:     true,
		LastHeartbeat: time.Now().Add(-2 * time.Second),
	})

	kill, state := CheckAndUpdate("HOST-C")
	if kill != nil {
		t.Fatalf("orderly restart reported as a kill: %+v", kill)
	}
	if state.KillCount != 0 {
		t.Errorf("kill count = %d, want 0", state.KillCount)
	}
}

// A restart with an assessment in progress names the EDR kill specifically in
// the reason, which is what makes the finding readable in a report.
func TestRestartDuringAssessmentIsAKillWithEDRReason(t *testing.T) {
	redirectState(t)

	CheckAndUpdate("HOST-D")
	seed(t, AgentState{
		Hostname:          "HOST-D",
		StartCount:        1,
		Version:           stateVersion,
		AssessmentRunning: true,
		LastHeartbeat:     time.Now(),
	})

	kill, _ := CheckAndUpdate("HOST-D")
	if kill == nil {
		t.Fatal("restart during an assessment was not classified as a kill")
	}
	if !strings.Contains(kill.Reason, "EDR") {
		t.Errorf("reason %q should identify the EDR kill as the suspected cause", kill.Reason)
	}
}

// Legacy-state fallback must not fire on a short gap.

// A state file from a pre-marker build has no Version. Timing is then the only
// signal — and a short gap must NOT be reported as a kill, or every restart
// after an upgrade becomes a false positive.
func TestLegacyStateFileFallsBackToTheGapHeuristic(t *testing.T) {
	redirectState(t)

	// Short gap, no version marker: nothing to conclude.
	seed(t, AgentState{Hostname: "HOST-I", StartCount: 1, LastHeartbeat: time.Now().Add(-2 * time.Second)})
	if kill, _ := CheckAndUpdate("HOST-I"); kill != nil {
		t.Fatalf("legacy state with a short gap reported as a kill: %+v", kill)
	}

	// Long gap, no version marker: the original signal still applies.
	seed(t, AgentState{Hostname: "HOST-I", StartCount: 2, LastHeartbeat: time.Now().Add(-2 * time.Hour)})
	kill, _ := CheckAndUpdate("HOST-I")
	if kill == nil {
		t.Fatal("legacy state with a two-hour gap was not classified as a kill")
	}
}

func TestMarkCleanExitSetsTheMarker(t *testing.T) {
	redirectState(t)
	CheckAndUpdate("HOST-E")

	MarkCleanExit()

	data, err := os.ReadFile(StateFile())
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var s AgentState
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !s.CleanExit {
		t.Error("MarkCleanExit did not set CleanExit")
	}
}

func TestSetAssessmentRunningPersistsBothWays(t *testing.T) {
	redirectState(t)
	CheckAndUpdate("HOST-F")

	readFlag := func() bool {
		data, _ := os.ReadFile(StateFile())
		var s AgentState
		_ = json.Unmarshal(data, &s)
		return s.AssessmentRunning
	}

	SetAssessmentRunning(true)
	if !readFlag() {
		t.Error("SetAssessmentRunning(true) did not persist")
	}
	SetAssessmentRunning(false)
	if readFlag() {
		t.Error("SetAssessmentRunning(false) did not persist")
	}
}

// The heartbeat writer previously only wrote when a read succeeded. Once an
// EDR deleted the state file the writer stopped silently and permanently, so no
// kill could ever be detected again.
func TestHeartbeatWriterRecreatesAMissingStateFile(t *testing.T) {
	redirectState(t)
	CheckAndUpdate("HOST-G")

	if err := os.Remove(StateFile()); err != nil {
		t.Fatalf("remove state: %v", err)
	}

	stop := make(chan struct{})
	defer close(stop)
	StartHeartbeatWriter("HOST-G", stop)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(StateFile()); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("state file was not recreated after deletion")
}

// A state file at the old Temp location must still be read, so upgrading does
// not silently reset the accumulated kill count to zero.
func TestLegacyTempStateIsAdoptedOnFirstStart(t *testing.T) {
	redirectState(t)

	legacyDir := t.TempDir()
	legacy := filepath.Join(legacyDir, legacyStateFileName)
	data, err := json.Marshal(&AgentState{
		Hostname: "HOST-H", StartCount: 7, KillCount: 4,
		LastHeartbeat: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	if err := os.WriteFile(legacy, data, 0644); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	// The redirect helper already points legacyLookup at an empty file; point
	// it at the seeded one instead.
	legacyLookup = func() string { return legacy }

	_, state := CheckAndUpdate("HOST-H")
	if state.StartCount != 8 {
		t.Errorf("start count = %d, want 8 (legacy state was not adopted)", state.StartCount)
	}
	if state.KillCount != 4 {
		t.Errorf("kill count = %d, want 4 (legacy state was not adopted)", state.KillCount)
	}
}

// The state must live outside the temp directory. Running as SYSTEM, os.TempDir
// resolves to C:\Windows\Temp — which temp-cleaners and EDRs target.
func TestStateFileIsNotInTemp(t *testing.T) {
	dir := StateFile()
	if filepath.Dir(dir) == os.TempDir() {
		t.Fatalf("state file is in the temp directory: %s", dir)
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("state file should be an absolute path: %s", dir)
	}
}
