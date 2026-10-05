//go:build linux

package modules

import (
	"agentide/core"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// tryKillProcess attempts to terminate a process by PID using SIGKILL.
func tryKillProcess(pid int) (blocked bool, note string) {
	err := syscall.Kill(pid, syscall.SIGKILL)
	if err != nil {
		return true, fmt.Sprintf("Kill blocked (pid %d): %v", pid, err)
	}
	return false, fmt.Sprintf("Process %d killed (NOT protected)", pid)
}

// tryStopService attempts to stop a systemd service.
func tryStopService(serviceName string) (blocked bool, note string) {
	err := exec.Command("systemctl", "stop", serviceName).Run()
	if err != nil {
		return true, fmt.Sprintf("systemctl stop blocked (%s): %v", serviceName, err)
	}
	return false, fmt.Sprintf("Service stopped (NOT protected): %s", serviceName)
}

// findBinary returns the full path of a binary using 'which'.
func findBinary(processName string) string {
	out, err := exec.Command("which", processName).Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	return string(out[:len(out)-1])
}

// simulatePasswordSpray rapidly calls 'su' with wrong credentials N times.
func simulatePasswordSpray(attempts int) (blocked bool, note string) {
	for i := 0; i < attempts; i++ {
		// Attempt login with a nonexistent user — always fails, but generates auth log entries
		_ = exec.Command("su", "-c", "true", "agentide_nonexistent_user").Run()
	}
	// Check if auth.log captured the attempts
	out, _ := exec.Command("grep", "-c", "authentication failure", "/var/log/auth.log").Output()
	if len(out) > 0 && string(out) != "0\n" {
		return true, fmt.Sprintf("Password spray logged in auth.log: %d attempts", attempts)
	}
	return false, fmt.Sprintf("%d failed su attempts — no lockout/alert observed", attempts)
}

// zipDirectory compresses src directory to destZip using the zip command.
func zipDirectory(src, destZip string) error {
	return exec.Command("zip", "-r", destZip, src).Run()
}

// scanLocalhost calls the cross-platform helper.
func scanLocalhost(ports []int) []int {
	return scanLocalhostPorts(ports)
}

// plantStartupPayload writes a benign cron entry for @reboot.
func plantStartupPayload() error {
	marker := "/tmp/agentide_bootgap_ran"
	entry := fmt.Sprintf("@reboot touch %s\n", marker)
	tmpFile := "/tmp/agentide_cron_tmp"
	if err := os.WriteFile(tmpFile, []byte(entry), 0644); err != nil {
		return err
	}
	return exec.Command("crontab", tmpFile).Run()
}

// persistBootGapState writes a marker file for state persistence across reboot.
func persistBootGapState() error {
	return os.WriteFile("/tmp/agentide_bootgap.state", []byte("pending"), 0644)
}

// triggerReboot initiates a system restart.
func triggerReboot() {
	_ = exec.Command("reboot").Run()
}

// rollback reverses a single ledger entry on Linux.
func rollback(entry ledgerEntry, logger *core.Logger) error {
	switch entry.Kind {
	case "file":
		return os.RemoveAll(entry.Path)
	case "startup":
		return removeStartupPayload()
	default:
		return fmt.Errorf("unknown ledger kind: %s", entry.Kind)
	}
}

func removeStartupPayload() error {
	// Remove AgentIde entries from crontab
	return exec.Command("crontab", "-r").Run()
}
