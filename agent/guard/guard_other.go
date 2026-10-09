//go:build !windows

// Package guard implements the AgentIde self-protection guardian. On
// non-Windows platforms the service lifecycle is owned by systemd, so the
// guardian is a no-op that simply blocks until asked to stop.
package guard

// Run blocks until stop is closed so callers can use it uniformly across
// platforms.
func Run(stop <-chan struct{}) {
	<-stop
}
