// Package state manages persistent assessment state on disk so that
// if the EDR kills the agent process mid-assessment, the agent can
// resume exactly where it left off after the Windows Service restarts it.
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Status represents the lifecycle state of a persisted assessment.
type Status string

const (
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
)

// ModuleRecord captures the outcome of a single completed module.
type ModuleRecord struct {
	Name       string   `json:"name"`
	Passed     bool     `json:"passed"`
	Result     string   `json:"result"`
	Detail     string   `json:"detail"`
	MitreID    string   `json:"mitre"`
	DurationMs int64    `json:"duration_ms"`
	TestType   string   `json:"test_type"`
	Timestamp  string   `json:"timestamp"`
	Artifacts  []string `json:"artifacts,omitempty"`
}

// AssessmentState is the full persistent checkpoint of an in-progress assessment.
type AssessmentState struct {
	SessionID        string         `json:"session_id"`
	Status           Status         `json:"status"`
	TargetVendor     string         `json:"target_vendor"`
	Profile          string         `json:"profile"`
	TestType         string         `json:"test_type"`
	StartedAt        time.Time      `json:"started_at"`
	LastUpdatedAt    time.Time      `json:"last_updated_at"`
	CompletedModules []string       `json:"completed_modules"`
	Results          []ModuleRecord `json:"results"`
	// EDRKillCount tracks how many times the EDR killed this assessment process.
	EDRKillCount int `json:"edr_kill_count"`
}

// stateDir returns the directory holding persisted assessment files,
// creating it if needed. Stored under %PROGRAMDATA% so it survives
// binary moves and is writable by the service account.
func stateDir() string {
	base := os.Getenv("PROGRAMDATA")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "AgentIde")
	_ = os.MkdirAll(dir, 0755)
	return dir
}

// stateFilePath returns the canonical path for the state file.
func stateFilePath() string {
	return filepath.Join(stateDir(), "assessment_state.json")
}

// Load reads the persisted state from disk. Returns nil if no state exists.
func Load() *AssessmentState {
	path := stateFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s AssessmentState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	return &s
}

// Save writes the current assessment state atomically to disk.
func Save(s *AssessmentState) error {
	s.LastUpdatedAt = time.Now()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Write to a temp file first, then rename for atomicity.
	path := stateFilePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Clear removes the state file after a successful assessment completes.
func Clear() {
	_ = os.Remove(stateFilePath())
}

// HasCompleted returns true if the given module name is already done.
func (s *AssessmentState) HasCompleted(moduleName string) bool {
	for _, name := range s.CompletedModules {
		if name == moduleName {
			return true
		}
	}
	return false
}

// MarkCompleted records a module as done and saves to disk immediately.
func (s *AssessmentState) MarkCompleted(record ModuleRecord) error {
	s.CompletedModules = append(s.CompletedModules, record.Name)
	s.Results = append(s.Results, record)
	return Save(s)
}

// IncrementKillCount bumps the EDR kill counter and persists it.
func (s *AssessmentState) IncrementKillCount() error {
	s.EDRKillCount++
	return Save(s)
}

// New creates a fresh AssessmentState and immediately persists it.
func New(sessionID, targetVendor, profile, testType string) (*AssessmentState, error) {
	s := &AssessmentState{
		SessionID:        sessionID,
		Status:           StatusRunning,
		TargetVendor:     targetVendor,
		Profile:          profile,
		TestType:         testType,
		StartedAt:        time.Now(),
		CompletedModules: []string{},
		Results:          []ModuleRecord{},
		EDRKillCount:     0,
	}
	return s, Save(s)
}

// ── Resume intent ───────────────────────────────────────────────────────────
// The state file records *what* has completed; the intent records *how* the
// operator launched the assessment (vendor disable, profile, test type).
// The auto-resume path needs both: the state file alone cannot tell us
// whether the vendor was disabled when the EDR killed us, and resuming
// without re-applying that choice would mix measurement conditions.

// Intent captures the confirm_assessment context needed to replay an
// interrupted assessment exactly as the operator launched it.
type Intent struct {
	DisableVendor string    `json:"disable_vendor"`
	Profile       string    `json:"profile"`
	TestType      string    `json:"test_type"`
	Days          int       `json:"days"`
	CreatedAt     time.Time `json:"created_at"`
}

// intentFilePath returns the path of the resume-intent file.
func intentFilePath() string {
	return filepath.Join(stateDir(), "resume_intent.json")
}

// SaveIntent persists the operator's choices before an assessment starts.
// It survives a process kill alongside the state file.
func SaveIntent(i Intent) error {
	data, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	path := intentFilePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadIntent reads the persisted intent. Returns nil if none exists.
func LoadIntent() *Intent {
	data, err := os.ReadFile(intentFilePath())
	if err != nil {
		return nil
	}
	var i Intent
	if err := json.Unmarshal(data, &i); err != nil {
		return nil
	}
	return &i
}

// ClearIntent removes the intent file. Called once the assessment has
// either completed or definitively given up.
func ClearIntent() {
	_ = os.Remove(intentFilePath())
}
