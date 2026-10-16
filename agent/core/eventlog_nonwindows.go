//go:build !windows

package core

// There is no Windows Event Log on other platforms, so the mirror is inert.
// These stubs keep the logger's call sites portable.

// EventLogEnabled reports whether the Windows Event Log is reachable — always
// false off Windows.
func EventLogEnabled() bool { return false }

// CloseEventLog is a no-op off Windows.
func CloseEventLog() {}

// writeEventLog is the no-op sink the logger calls. It exists so logger.go
// needs no build tags and the mirror is a single unconditional call site.
func writeEventLog(LogLevel, string, map[string]interface{}) {}
