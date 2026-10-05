// Package resilience tracks agent liveness by writing a heartbeat file.
// On every startup it checks for an existing heartbeat, computes the downtime
// since the last write, and emits a tamper_event if the gap exceeds the
// normal heartbeat interval — indicating the agent was killed externally.
package resilience

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	heartbeatInterval = 30 * time.Second
	// If the gap between the last heartbeat and now exceeds this, we were killed.
	killThreshold = 45 * time.Second
	stateFileName = "agentide_state.json"
)

// AgentState is persisted to disk so we can detect restarts.
type AgentState struct {
	Hostname     string    `json:"hostname"`
	StartedAt    time.Time `json:"started_at"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	StartCount   int       `json:"start_count"`  // total number of times agent has started
	KillCount    int       `json:"kill_count"`   // detected external kills
}

// KillEvent describes a detected kill/recovery cycle.
type KillEvent struct {
	KilledAt    time.Time     // estimated time of kill (last heartbeat)
	RecoveredAt time.Time     // time this startup completed
	Downtime    time.Duration // how long we were offline
	StartCount  int           // which restart this was
}

// StateFile returns the path to the resilience state file.
// Stored in the system temp directory so it persists even when
// the agent binary location changes.
func StateFile() string {
	return filepath.Join(os.TempDir(), stateFileName)
}

// CheckAndUpdate reads the existing state file, detects if we were killed,
// then writes an updated state for this run. Returns a KillEvent if a kill
// was detected, or nil if this is a clean first start.
func CheckAndUpdate(hostname string) (*KillEvent, *AgentState) {
	now := time.Now()
	path := StateFile()

	var prev *AgentState
	if data, err := os.ReadFile(path); err == nil {
		var s AgentState
		if json.Unmarshal(data, &s) == nil {
			prev = &s
		}
	}

	// Build the new state for this run
	state := &AgentState{
		Hostname:      hostname,
		StartedAt:     now,
		LastHeartbeat: now,
		StartCount:    1,
	}

	var killEvt *KillEvent

	if prev != nil {
		state.StartCount = prev.StartCount + 1
		state.KillCount = prev.KillCount

		// Detect if the agent was killed externally
		gap := now.Sub(prev.LastHeartbeat)
		if gap > killThreshold {
			state.KillCount++
			killEvt = &KillEvent{
				KilledAt:    prev.LastHeartbeat,
				RecoveredAt: now,
				Downtime:    gap.Truncate(time.Second),
				StartCount:  state.StartCount,
			}
		}
	}

	// Write the new state immediately
	_ = writeState(path, state)

	return killEvt, state
}

// StartHeartbeatWriter begins a background goroutine that updates the
// LastHeartbeat field in the state file every 30 seconds.
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
				// Read current state, update heartbeat, write back
				if data, err := os.ReadFile(path); err == nil {
					var s AgentState
					if json.Unmarshal(data, &s) == nil {
						s.LastHeartbeat = time.Now()
						_ = writeState(path, &s)
					}
				}
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
		"Agent killed at ~%s | Recovered at %s | Downtime: %s | Recovery #%d",
		e.KilledAt.Format("15:04:05"),
		e.RecoveredAt.Format("15:04:05"),
		e.Downtime,
		e.StartCount,
	)
}
