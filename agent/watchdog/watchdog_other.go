//go:build !windows

package watchdog

import (
	"os"
	"os/exec"
	"syscall"
)

// spawnSelf launches a detached copy of the agent binary in watchdog mode.
// Setsid detaches the child into its own session so it survives the
// death of the parent process.
func spawnSelf(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
