//go:build windows

package watchdog

import (
	"os"
	"os/exec"

	"golang.org/x/sys/windows"
)

// spawnSelf launches a detached copy of the agent binary in watchdog mode.
// The child survives the death of the parent process and runs without a
// console window.
func spawnSelf(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	return cmd.Start()
}
