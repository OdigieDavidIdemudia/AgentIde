package watchdog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvaluateMissingMarkerExits(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "missing.flag")
	decision, _ := evaluate(marker, 90*time.Second, time.Now().Add(time.Hour))
	if decision != decisionExit {
		t.Fatalf("expected decisionExit for missing marker, got %v", decision)
	}
}

func TestEvaluateFreshMarkerContinues(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "fresh.flag")
	if err := touch(marker); err != nil {
		t.Fatal(err)
	}
	decision, _ := evaluate(marker, 90*time.Second, time.Now().Add(time.Hour))
	if decision != decisionContinue {
		t.Fatalf("expected decisionContinue for fresh marker, got %v", decision)
	}
}

func TestEvaluateStaleHeartbeatRestores(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "stale.flag")
	if err := touch(marker); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(marker, stale, stale); err != nil {
		t.Fatal(err)
	}
	decision, age := evaluate(marker, 90*time.Second, time.Now().Add(time.Hour))
	if decision != decisionRestore {
		t.Fatalf("expected decisionRestore for stale heartbeat, got %v", decision)
	}
	if age < 5*time.Minute {
		t.Fatalf("expected stale age > 5m, got %v", age)
	}
}

func TestEvaluateDeadlineExceededRestores(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "fresh.flag")
	if err := touch(marker); err != nil {
		t.Fatal(err)
	}
	decision, _ := evaluate(marker, 90*time.Second, time.Now().Add(-time.Minute))
	if decision != decisionRestore {
		t.Fatalf("expected decisionRestore for exceeded deadline, got %v", decision)
	}
}

func TestTouchRefreshesMtime(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "touch.flag")
	if err := touch(marker); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(marker, stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := touch(marker); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(fi.ModTime()) > time.Minute {
		t.Fatalf("mtime was not refreshed: %v", fi.ModTime())
	}
}

func TestMarkerPathSanitizesVendor(t *testing.T) {
	got := filepath.Base(MarkerPath("CrowdStrike Falcon/Test"))
	want := "agentide-watchdog-crowdstrike-falcon-test.flag"
	if got != want {
		t.Fatalf("MarkerPath base = %q, want %q", got, want)
	}
}
