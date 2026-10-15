// Package resilience tracks agent liveness and detects when the EDR kills the
// process.
//
// # How a kill is detected
//
// The original implementation compared the gap since the last heartbeat
// against a fixed 45-second threshold. That is backwards for the case this
// exists to catch: when an EDR blocks the agent, the Windows Service Control
// Manager restarts it within seconds, so the gap is small and no kill was ever
// recorded. The faster the EDR killed and recovered us, the less likely we
// were to notice — which meant an EDR successfully blocking a tamper module
// produced a silent, zero-result run indistinguishable from a crash.
//
// Detection is now based on an explicit clean-exit marker rather than elapsed
// time:
//
//   - a graceful shutdown writes CleanExit = true
//   - on startup, a previous state that still has CleanExit set means the last
//     process died without running its shutdown path, which is a kill
//
// Timing is still used, but only as a corroborating signal and as a bound
// derived from the service's own configured recovery delay (see
// ServiceRestartDelay) rather than a hardcoded guess.
package resilience

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	stateFileName = "agentide_state.json"

	// legacyStateFileName is the old Temp-directory location. Read once at
	// startup for migration.
	legacyStateFileName = "agentide_state.json"

	// fallbackKillThreshold is used when the service's recovery delay cannot be
	// read. It is a backstop only — the clean-exit marker is the real signal.
	fallbackKillThreshold = 45 * time.Second

	// serviceName is the Windows service this agent runs as; its SCM recovery
	// configuration supplies the restart bound.
	serviceName = "AgentIde"
)

// heartbeatInterval is a var so tests can drive the writer without waiting
// half a minute for a tick.
var heartbeatInterval = 30 * time.Second

// stateDir is ProgramData, where the service config already lives. The previous
// location was os.TempDir(), which for a SYSTEM service resolves to
// C:\Windows\Temp — a directory that temp-cleaners and EDRs target, and
// durability-critical state does not belong there.
//
// It is a var so tests can redirect it away from the real ProgramData.
var stateDir = `C:\ProgramData\AgentIde`

// AgentState is persisted to disk so restarts can be classified.
type AgentState struct {
	Hostname      string    `json:"hostname"`
	StartedAt     time.Time `json:"started_at"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	StartCount    int       `json:"start_count"` // total number of times agent has started
	KillCount     int       `json:"kill_count"`  // detected external kills

	// CleanExit is set by the graceful shutdown path. If it is still false
	// when the next process starts, the previous process never ran its
	// shutdown — it was terminated (EDR kill, crash, power loss). If it is
	// true, the restart was orderly and must NOT be reported as a kill.
	CleanExit bool `json:"clean_exit"`

	// Version distinguishes a state file written by a build that understands
	// CleanExit from an older one where the field is absent. Absent and false
	// are indistinguishable in JSON, so without this every restart after an
	// upgrade would look like an unclean termination.
	Version int `json:"version"`

	// AssessmentRunning records whether an assessment was in progress when this
	// process last wrote state. It does not decide classification on its own —
	// CleanExit does — but it makes the kill reason specific.
	AssessmentRunning bool `json:"assessment_running"`
}

// stateVersion is the current on-disk format version.
const stateVersion = 1

// KillEvent describes a detected kill/recovery cycle.
type KillEvent struct {
	KilledAt    time.Time     // estimated time of kill (last heartbeat)
	RecoveredAt time.Time     // time this startup completed
	Downtime    time.Duration // how long we were offline
	StartCount  int           // which restart this was
	// Reason explains why this was classified as a kill, for the report.
	Reason string
}

// StateFile returns the path to the resilience state file.
func StateFile() string {
	return filepath.Join(stateDir, stateFileName)
}

// LegacyStateFile is the previous Temp-directory location, read once so an
// upgrade does not lose the accumulated kill count.
func LegacyStateFile() string {
	return filepath.Join(os.TempDir(), legacyStateFileName)
}

// legacyLookup is a var so tests can point the migration read at a fixture.
var legacyLookup = LegacyStateFile

// ServiceRestartDelay reports how long the Service Control Manager is
// configured to wait before restarting this service after a failure, or 0 when
// it cannot be determined.
//
// This is a Windows-only convenience; callers on other platforms get 0 and fall
// back to the threshold heuristic. Querying it means the timing bound adapts
// to however the service was installed instead of assuming 45 seconds.
func ServiceRestartDelay() time.Duration { return queryServiceRestartDelay() }

// CheckAndUpdate reads the existing state, classifies this startup, then
// writes the state for this run.
//
// A kill is returned when any of these hold:
//   - the previous process is recorded as NOT having exited cleanly, which
//     means it was terminated (EDR kill, crash, power loss) — this holds
//     regardless of how quickly the service was restarted
//   - for a state file from a build that predates the marker, the heartbeat gap
//     exceeds the expected restart window
//
// An orderly restart (previous CleanExit true) is NOT a kill.
//
// Returns (nil, state) for a clean first start or a previous clean shutdown.
func CheckAndUpdate(hostname string) (*KillEvent, *AgentState) {
	now := time.Now()
	path := StateFile()

	prev := loadState()
	if prev == nil {
		prev = loadLegacyState()
	}

	state := &AgentState{
		Hostname:      hostname,
		StartedAt:     now,
		LastHeartbeat: now,
		StartCount:    1,
		CleanExit:     false,
		Version:       stateVersion,
	}

	var killEvt *KillEvent

	if prev != nil {
		state.StartCount = prev.StartCount + 1
		state.KillCount = prev.KillCount

		gap := now.Sub(prev.LastHeartbeat)
		reason := ""

		switch {
		case prev.Version >= stateVersion && prev.CleanExit:
			// The previous process ran its shutdown path deliberately. A new
			// process starting afterwards is an orderly restart — a service
			// update, a reboot, an operator restart — and reporting it as a kill
			// would be a false positive.

		case prev.Version >= stateVersion:
			// The previous process never reached its shutdown path, so it was
			// terminated. This is the EDR-kills-the-agent case, and it holds
			// however quickly the SCM brought us back — which is exactly the
			// case the old heartbeat-gap threshold missed.
			if prev.AssessmentRunning {
				reason = "process terminated while an assessment was running (EDR kill suspected)"
			} else {
				reason = "process terminated without a clean shutdown"
			}

		case gap > expectedRestartWindow():
			// A state file from a build that predates CleanExit. Timing is the
			// only signal available, so use it — but bound it by the service's
			// configured restart delay rather than a hardcoded guess.
			reason = fmt.Sprintf("no heartbeat for %s", gap.Truncate(time.Second))
		}

		if reason != "" {
			state.KillCount++
			killEvt = &KillEvent{
				KilledAt:    prev.LastHeartbeat,
				RecoveredAt: now,
				Downtime:    gap.Truncate(time.Second),
				StartCount:  state.StartCount,
				Reason:      reason,
			}
		}
	}

	if err := os.MkdirAll(stateDir, 0755); err != nil {
		// Nothing useful to do here; the caller still gets a usable state and
		// the next start will fall back to a clean first start.
		_ = err
	}
	_ = writeState(path, state)

	return killEvt, state
}

// expectedRestartWindow derives the plausible restart bound from the service's
// own recovery configuration, with generous headroom over the heartbeat
// interval so an ordinary slow beat is not mistaken for a kill.
func expectedRestartWindow() time.Duration {
	delay := ServiceRestartDelay()
	if delay <= 0 {
		return fallbackKillThreshold
	}
	// Two full heartbeat intervals either side: a live agent always beats
	// within one, and the SCM may add its own restart delay plus service init.
	window := 2*heartbeatInterval + delay
	if window < fallbackKillThreshold {
		return fallbackKillThreshold
	}
	return window
}

// MarkCleanExit records that this process is shutting down gracefully, so the
// next start can distinguish an orderly restart from a kill.
func MarkCleanExit() {
	path := StateFile()
	if data, err := os.ReadFile(path); err == nil {
		var s AgentState
		if json.Unmarshal(data, &s) == nil {
			s.CleanExit = true
			s.LastHeartbeat = time.Now()
			_ = writeState(path, &s)
		}
	}
}

// SetAssessmentRunning records whether an assessment is currently in progress,
// so a restart can be classified as a kill rather than an idle restart.
func SetAssessmentRunning(running bool) {
	path := StateFile()
	if data, err := os.ReadFile(path); err == nil {
		var s AgentState
		if json.Unmarshal(data, &s) == nil {
			s.AssessmentRunning = running
			s.LastHeartbeat = time.Now()
			_ = writeState(path, &s)
		}
	}
}

func loadState() *AgentState {
	return readStateFile(StateFile())
}

func loadLegacyState() *AgentState {
	return readStateFile(legacyLookup())
}

func readStateFile(path string) *AgentState {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s AgentState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	return &s
}

// StartHeartbeatWriter updates LastHeartbeat periodically.
//
// It recreates the file when it is missing. The previous implementation only
// wrote when a read succeeded, so once the state file was deleted — which is
// exactly what an EDR "prison" policy does to agent files — the writer
// silently stopped forever and no kill could ever be detected again.
func StartHeartbeatWriter(hostname string, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		path := StateFile()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if s := readStateFile(path); s != nil {
					s.LastHeartbeat = time.Now()
					_ = writeState(path, s)
					continue
				}
				// Missing or unreadable: recreate rather than giving up.
				if err := os.MkdirAll(stateDir, 0755); err != nil {
					continue
				}
				_ = writeState(path, &AgentState{
					Hostname:      hostname,
					StartedAt:     time.Now(),
					LastHeartbeat: time.Now(),
					StartCount:    1,
				})
			}
		}
	}()
}

func writeState(path string, s *AgentState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// FormatKillEvent returns a human-readable description of the kill event.
func FormatKillEvent(e *KillEvent) string {
	return fmt.Sprintf(
		"Agent killed at ~%s | Recovered at %s | Downtime: %s | Recovery #%d | %s",
		e.KilledAt.Format("15:04:05"),
		e.RecoveredAt.Format("15:04:05"),
		e.Downtime,
		e.StartCount,
		e.Reason,
	)
}
