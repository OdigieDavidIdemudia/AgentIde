//go:build windows

package core

import (
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The tray connects to \\.\pipe\agentide and reads a single JSON object. If
// this breaks, the tray silently shows "Disconnected" forever — which is
// exactly what it did before the agent served the pipe at all.
func TestStatusPipeServesCurrentStatus(t *testing.T) {
	InitStatus("9.9.9-test", "TESTHOST", "wss://dash.example:8443")
	SetStatus("assessing", "Running rapid assessment")

	stop := make(chan struct{})
	defer close(stop)
	StartStatusPipe(stop)

	// Give the server goroutine a moment to create the pipe.
	var st Status
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		st, err = readStatusOnce()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if st.State != "assessing" {
		t.Fatalf("state over pipe: got %q, want assessing", st.State)
	}
	if st.Version != "9.9.9-test" {
		t.Errorf("version over pipe: got %q, want 9.9.9-test", st.Version)
	}
	if st.Hostname != "TESTHOST" {
		t.Errorf("hostname over pipe: got %q, want TESTHOST", st.Hostname)
	}
	if st.DashboardURL != "wss://dash.example:8443" {
		t.Errorf("dashboard url over pipe: got %q", st.DashboardURL)
	}
	if !st.AssessmentActive {
		t.Error("assessment_active should be true while assessing")
	}
	if st.PID == 0 {
		t.Error("pid should be populated so the tray can detect a restart")
	}
}

// Leaving "assessing" must clear the flag, otherwise the tray keeps claiming a
// run is in progress after it finished.
func TestSetStatusClearsAssessmentFlagOnReturn(t *testing.T) {
	SetStatus("assessing", "running")
	if !GetStatus().AssessmentActive {
		t.Fatal("expected assessment_active after entering assessing")
	}
	SetStatus("connected", "Monitoring passively")
	if GetStatus().AssessmentActive {
		t.Error("assessment_active still set after returning to connected")
	}
}

// readStatusOnce mirrors what the tray does, so the test exercises the same
// protocol rather than an internal shortcut.
func readStatusOnce() (Status, error) {
	path, err := windows.UTF16PtrFromString(StatusPipeName)
	if err != nil {
		return Status{}, err
	}
	h, err := windows.CreateFile(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		0, 0,
	)
	if err != nil {
		return Status{}, err
	}
	defer windows.CloseHandle(h)

	buf := make([]byte, 4096)
	var n uint32
	var ov windows.Overlapped
	if err := windows.ReadFile(h, buf, &n, &ov); err != nil {
		return Status{}, err
	}
	var st Status
	if err := json.Unmarshal(trimNewline(buf[:n]), &st); err != nil {
		return Status{}, err
	}
	return st, nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
