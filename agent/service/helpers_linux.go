//go:build linux

package service

import "os/exec"

// runCmd is a helper to execute a system command, returning any error.
func runCmd(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
