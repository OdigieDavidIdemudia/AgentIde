//go:build !windows

package main

import "agentide/core"

// runAsWindowsService runs the agent in the foreground on non-Windows
// platforms, where systemd (not the SCM) manages the process lifecycle.
func runAsWindowsService(cfg *core.Config, mode, profile string, days int, module string) error {
	runAgent(cfg, mode, profile, days, module)
	return nil
}
