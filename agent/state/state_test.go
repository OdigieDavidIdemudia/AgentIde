package state

import (
	"testing"
	"time"
)

// useTempStateDir redirects the %PROGRAMDATA% base directory to a throwaway
// temp folder so tests never touch a real assessment checkpoint.
func useTempStateDir(t *testing.T) {
	t.Helper()
	t.Setenv("PROGRAMDATA", t.TempDir())
}

func TestSaveLoadClearRoundTrip(t *testing.T) {
	useTempStateDir(t)

	s, err := New("sess-1", "Cortex XDR", "rapid", "blackbox")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.Status != StatusRunning {
		t.Fatalf("status = %q, want %q", s.Status, StatusRunning)
	}

	loaded := Load()
	if loaded == nil {
		t.Fatal("Load returned nil for a saved state")
	}
	if loaded.SessionID != "sess-1" || loaded.TargetVendor != "Cortex XDR" ||
		loaded.Profile != "rapid" || loaded.TestType != "blackbox" {
		t.Fatalf("loaded state mismatch: %+v", loaded)
	}

	Clear()
	if Load() != nil {
		t.Fatal("Load returned non-nil after Clear")
	}
}

func TestMarkCompletedPersists(t *testing.T) {
	useTempStateDir(t)

	s, err := New("sess-2", "Defender", "apt", "whitebox")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := ModuleRecord{
		Name: "malware", Passed: true, Result: "PASS",
		Detail: "EICAR quarantined in 800ms", MitreID: "T1059",
		TestType: "whitebox", Timestamp: time.Now().Format(time.RFC3339),
	}
	if err := s.MarkCompleted(rec); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}

	loaded := Load()
	if !loaded.HasCompleted("malware") {
		t.Fatal("HasCompleted(malware) = false after MarkCompleted")
	}
	if loaded.HasCompleted("lolbin") {
		t.Fatal("HasCompleted(lolbin) = true, never marked")
	}
	if len(loaded.Results) != 1 || loaded.Results[0].Detail != rec.Detail {
		t.Fatalf("results not persisted: %+v", loaded.Results)
	}
}

func TestIncrementKillCountPersists(t *testing.T) {
	useTempStateDir(t)

	if _, err := New("sess-3", "SentinelOne", "rapid", "blackbox"); err != nil {
		t.Fatalf("New: %v", err)
	}

	s := Load()
	if err := s.IncrementKillCount(); err != nil {
		t.Fatalf("IncrementKillCount: %v", err)
	}
	if err := s.IncrementKillCount(); err != nil {
		t.Fatalf("IncrementKillCount: %v", err)
	}

	if got := Load().EDRKillCount; got != 2 {
		t.Fatalf("EDRKillCount = %d, want 2", got)
	}
}

func TestIntentRoundTrip(t *testing.T) {
	useTempStateDir(t)

	if LoadIntent() != nil {
		t.Fatal("LoadIntent returned non-nil with no intent saved")
	}

	want := Intent{
		DisableVendor: "cortex",
		Profile:       "apt",
		TestType:      "whitebox",
		Days:          3,
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
	}
	if err := SaveIntent(want); err != nil {
		t.Fatalf("SaveIntent: %v", err)
	}

	got := LoadIntent()
	if got == nil {
		t.Fatal("LoadIntent returned nil after SaveIntent")
	}
	if got.DisableVendor != want.DisableVendor || got.Profile != want.Profile ||
		got.TestType != want.TestType || got.Days != want.Days {
		t.Fatalf("intent mismatch: got %+v, want %+v", got, want)
	}

	ClearIntent()
	if LoadIntent() != nil {
		t.Fatal("LoadIntent returned non-nil after ClearIntent")
	}
}

func TestStaleStateSurvivesIntentClear(t *testing.T) {
	useTempStateDir(t)

	if _, err := New("sess-4", "Cortex XDR", "rapid", "blackbox"); err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := SaveIntent(Intent{DisableVendor: "cortex"}); err != nil {
		t.Fatalf("SaveIntent: %v", err)
	}

	// Clearing the intent must not disturb the checkpoint itself: the kill
	// counter and completed modules are still needed if the operator
	// relaunches manually from the dashboard.
	ClearIntent()
	st := Load()
	if st == nil {
		t.Fatal("state lost when clearing intent")
	}
	if LoadIntent() != nil {
		t.Fatal("intent not cleared")
	}
}
