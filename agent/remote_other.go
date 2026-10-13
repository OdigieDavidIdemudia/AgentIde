//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"runtime"

	"agentide/core"
)

// restartSelf restarts the agent on non-Windows platforms. The dashboard's
// management commands are currently implemented for the Windows service; on
// other platforms the agent runs under a supervisor, so a restart is reported
// as unsupported rather than silently doing nothing.
func restartSelf(logger *core.Logger) error {
	return fmt.Errorf("remote restart is not implemented on %s", runtime.GOOS)
}

// uninstallSelf removes the agent on non-Windows platforms.
func uninstallSelf(logger *core.Logger) error {
	cmd := exec.Command("systemctl", "disable", "--now", "agentide")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stop agentide service: %w", err)
	}
	return nil
}
