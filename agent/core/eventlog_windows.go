//go:build windows

package core

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/windows/svc/eventlog"
)

// Event Log source name, matching the one InstallAsEventCreate registers.
const eventSource = "AgentIde"

// Windows Event Log mirroring.
//
// The installer registers this source with eventlog.InstallAsEventCreate, and
// previously nothing was ever written through it — so the Event Log entries the
// application advertises in Applications and Services Logs never appeared. An
// administrator checking Event Viewer, or an SIEM collecting from it, saw a
// permanently empty source.
//
// This is how WinCollect, Cortex XDR and CimsTrak agents are monitored: they
// report to the host's own logging pipeline so no vendor-specific log reader is
// needed. Mirroring the structured log into it costs nothing extra and makes
// the agent visible to tooling the endpoint already has.
//
// Only INFO and above are mirrored, and only when the log is usable: the agent
// runs from CLI during install and in tests, where there is no event source and
// writing would just error on every line.

// eventMirror lazily holds the open handle to the Windows Event Log.
var eventMirror struct {
	once sync.Once
	log  *eventlog.Log
}

// EventLogEnabled reports whether the Windows Event Log is actually reachable.
// Used by tests and diagnostics; the mirror itself never fails a write.
func EventLogEnabled() bool {
	eventMirror.once.Do(openEventLog)
	return eventMirror.log != nil
}

func openEventLog() {
	l, err := eventlog.Open(eventSource)
	if err != nil {
		// Not registered, or no source. Expected during CLI runs and in tests.
		return
	}
	eventMirror.log = l
}

// writeEventLog mirrors one entry. Errors are swallowed on purpose: losing a log
// line must never take down the agent or a running assessment.
func writeEventLog(level LogLevel, msg string, fields map[string]interface{}) {
	eventMirror.once.Do(openEventLog)
	if eventMirror.log == nil {
		return
	}

	// Event IDs are in the application-defined range (0x8000+), which keeps
	// them out of the vendor-reserved space.
	const (
		eidError = 0x8000
		eidWarn  = 0x8001
	)

	line := formatEventLine(msg, fields)

	// The log chooses severity by which method is called.
	switch levelForEventMirror(level) {
	case eventlog.Error:
		_ = eventMirror.log.Error(eidError, line)
	case eventlog.Warning:
		_ = eventMirror.log.Warning(eidWarn, line)
	}
}

// levelForEventMirror maps a log level onto the Event Log severity it should be
// written at, returning 0 for levels that are not mirrored at all.
//
// Info and Debug are deliberately excluded: the Windows Event Log is a shared,
// system-wide stream read by SIEM collectors, and an INFO-level write per
// connection flap would fill it with the agent's own chatter. Warnings and
// errors are what an administrator or collector needs.
func levelForEventMirror(level LogLevel) uint16 {
	switch level {
	case LevelError:
		return eventlog.Error
	case LevelWarn:
		return eventlog.Warning
	default:
		return 0
	}
}

// formatEventLine flattens a structured log entry into a single readable line.
// The event log has no structured payload, so fields are appended as sorted
// key=value pairs to keep output stable between runs.
func formatEventLine(msg string, fields map[string]interface{}) string {
	if len(fields) == 0 {
		return msg
	}

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString(msg)
	b.WriteString(" [")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s=%v", k, fields[k])
	}
	b.WriteString("]")
	return b.String()
}

// CloseEventLog releases the handle. Called on shutdown so the SCM sees a clean
// stop rather than a process exiting with an open log.
func CloseEventLog() {
	if eventMirror.log != nil {
		_ = eventMirror.log.Close()
		eventMirror.log = nil
	}
}
