//go:build windows

package core

import (
	"os"
	"strings"
	"testing"
)

/**
 * The agent registers a Windows Event Log source at install time. Until now
 * nothing was ever written through it, so the entries the product advertises in
 * Applications and Services Logs never appeared — an administrator or SIEM
 * collecting from the Event Log saw a permanently empty source. These tests
 * cover the formatting and the degradation path, which are the parts that can
 * be verified without an installed service.
 */

func TestFormatEventLineIsDeterministic(t *testing.T) {
	fields := map[string]interface{}{
		"zeta":  1,
		"alpha": "two",
		"mid":   true,
	}

	first := formatEventLine("connected", fields)
	for i := 0; i < 20; i++ {
		if got := formatEventLine("connected", fields); got != first {
			t.Fatalf("map iteration order leaked into the output:\n%q\n%q", first, got)
		}
	}

	// Keys must be sorted so the line reads the same on every run.
	if !strings.Contains(first, "alpha=two, mid=true, zeta=1") {
		t.Errorf("fields not sorted: %q", first)
	}
}

func TestFormatEventLineWithoutFields(t *testing.T) {
	if got := formatEventLine("plain message", nil); got != "plain message" {
		t.Errorf("got %q, want the bare message", got)
	}
	if got := formatEventLine("plain message", map[string]interface{}{}); got != "plain message" {
		t.Errorf("empty fields should not append brackets, got %q", got)
	}
}

// A missing or unregistered source must never break logging. The agent runs
// from the CLI during install and in tests, where no source exists.
func TestEventLogAbsentDoesNotPanic(t *testing.T) {
	CloseEventLog()

	// If a source happens to exist on this machine, reopening is still safe;
	// what matters is that neither path panics or blocks.
	if enabled := EventLogEnabled(); enabled {
		t.Log("an AgentIde event source exists on this host; exercising the live path")
	}

	writeEventLog(LevelError, "error while source absent", map[string]interface{}{"k": "v"})
	writeEventLog(LevelWarn, "warn while source absent", nil)
	writeEventLog(LevelInfo, "info is not mirrored", nil)
	writeEventLog(LevelDebug, "debug is not mirrored", nil)
}

// Info and Debug must not reach the shared Event Log: it is a system-wide
// stream read by collectors, and the agent's own chatter would drown it.
func TestOnlyWarnAndErrorAreMirrored(t *testing.T) {
	if levelForEventMirror(LevelInfo) != 0 {
		t.Error("Info should not be mirrored")
	}
	if levelForEventMirror(LevelDebug) != 0 {
		t.Error("Debug should not be mirrored")
	}
	if levelForEventMirror(LevelWarn) == 0 {
		t.Error("Warn should be mirrored")
	}
	if levelForEventMirror(LevelError) == 0 {
		t.Error("Error should be mirrored")
	}
}

// Single-instance enforcement. Two agents per host is what produced the socket
// livelock: each registration evicted the previous one's socket.
func TestAcquireSingleInstanceIsExclusive(t *testing.T) {
	ok, err := AcquireSingleInstance()
	if err != nil {
		t.Skipf("named mutex unavailable in this environment: %v", err)
	}
	if !ok {
		t.Fatal("first acquisition failed; no other instance should hold the mutex")
	}

	// A second acquisition in the same process observes the existing object.
	second, err := AcquireSingleInstance()
	if err != nil {
		t.Fatalf("second acquisition errored: %v", err)
	}
	if second {
		t.Error("a second instance was granted the mutex; instances are not exclusive")
	}
}

func TestEventSourceNameMatchesInstaller(t *testing.T) {
	// The installer's eventlog.InstallAsEventCreate(serviceName, ...) and the
	// mirror here must agree, or every write silently fails.
	if eventSource != "AgentIde" {
		t.Errorf("event source = %q, want AgentIde", eventSource)
	}
}

func TestLoggerStillWritesFile(t *testing.T) {
	// Mirroring must not displace the file log; the file is the agent's own
	// audit trail and the Event Log is a convenience for outside tooling.
	path := t.TempDir() + "/agentide.log"
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	l.Error("boom", map[string]interface{}{"a": 1})
	l.Warn("careful", nil)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "boom") || !strings.Contains(string(data), "careful") {
		t.Errorf("file log missing entries:\n%s", data)
	}
}
