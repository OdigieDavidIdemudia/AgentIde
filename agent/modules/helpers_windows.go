//go:build windows

package modules

import (
	"agentide/core"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// tryKillProcess attempts to terminate a process by PID using Windows APIs.
func tryKillProcess(pid int) (blocked bool, note string) {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return true, fmt.Sprintf("OpenProcess blocked (pid %d): %v", pid, err)
	}
	defer windows.CloseHandle(handle)

	if err := windows.TerminateProcess(handle, 1); err != nil {
		return true, fmt.Sprintf("TerminateProcess blocked (pid %d): %v", pid, err)
	}
	return false, fmt.Sprintf("Process %d terminated (NOT protected)", pid)
}

// tryStopService attempts to stop a Windows service by name.
func tryStopService(serviceName string) (blocked bool, note string) {
	err := exec.Command("sc", "stop", serviceName).Run()
	if err != nil {
		return true, fmt.Sprintf("Service stop blocked (%s): %v", serviceName, err)
	}
	return false, fmt.Sprintf("Service stopped (NOT protected): %s", serviceName)
}

// findBinary returns the full path of a known process binary using where.exe.
func findBinary(processName string) string {
	out, err := exec.Command("where", processName).Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	return filepath.Clean(string(out[:len(out)-1]))
}

// simulatePasswordSpray calls LogonUser N times with wrong credentials via syscall.
func simulatePasswordSpray(attempts int) (blocked bool, note string) {
	const domain   = "."
	const username = "agentide_test_user_nonexistent"
	const password = "WrongPassword123!"

	logonUser := syscall.MustLoadDLL("advapi32.dll").MustFindProc("LogonUserW")

	userPtr, _   := syscall.UTF16PtrFromString(username)
	domainPtr, _ := syscall.UTF16PtrFromString(domain)
	passPtr, _   := syscall.UTF16PtrFromString(password)

	const logon32LogonNetwork   = 3
	const logon32ProviderDefault = 0

	for i := 0; i < attempts; i++ {
		var token syscall.Token
		_, _, _ = logonUser.Call(
			uintptr(unsafe.Pointer(userPtr)),
			uintptr(unsafe.Pointer(domainPtr)),
			uintptr(unsafe.Pointer(passPtr)),
			logon32LogonNetwork,
			logon32ProviderDefault,
			uintptr(unsafe.Pointer(&token)),
		)
		if token != 0 {
			_ = token.Close()
		}
	}

	// Check if a failed logon event appeared in the Security event log
	out, err := exec.Command("wevtutil", "qe", "Security",
		"/q:*[System[EventID=4625]]", "/c:1", "/rd:true", "/f:text",
	).Output()
	if err == nil && len(out) > 10 {
		return true, fmt.Sprintf("Password spray detected: %d failed attempts logged in Security event log", attempts)
	}
	return false, fmt.Sprintf("%d failed login attempts — no lockout event detected", attempts)
}

// zipDirectory compresses src directory to destZip using PowerShell Compress-Archive.
func zipDirectory(src, destZip string) error {
	return exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("Compress-Archive -Path '%s' -DestinationPath '%s' -Force", src, destZip),
	).Run()
}

// scanLocalhost calls the cross-platform helper.
func scanLocalhost(ports []int) []int {
	return scanLocalhostPorts(ports)
}

// plantStartupPayload writes a benign value to the HKCU Run registry key.
func plantStartupPayload() error {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf("cannot open Run key: %w", err)
	}
	defer k.Close()
	return k.SetStringValue("AgentIdeBootGap", "echo AgentIde Boot Gap Test")
}

// persistBootGapState writes a marker file for state persistence across reboot.
func persistBootGapState() error {
	return exec.Command("powershell", "-NoProfile", "-Command",
		`Set-Content -Path "$env:TEMP\agentide_bootgap.state" -Value "pending"`,
	).Run()
}

// triggerReboot initiates a system restart in 5 seconds.
func triggerReboot() {
	_ = exec.Command("shutdown", "/r", "/t", "5", "/c", "AgentIde Boot Gap Test").Run()
}

// rollback reverses a single ledger entry on Windows.
func rollback(entry ledgerEntry, logger *core.Logger) error {
	switch entry.Kind {
	case "file":
		return removeIfExists(entry.Path)
	case "startup":
		return removeStartupPayload()
	default:
		return fmt.Errorf("unknown ledger kind: %s", entry.Kind)
	}
}

func removeIfExists(path string) error {
	err := exec.Command("cmd", "/c", "del", "/f", "/q", path).Run()
	if err != nil {
		return exec.Command("cmd", "/c", "rmdir", "/s", "/q", path).Run()
	}
	return nil
}

func removeStartupPayload() error {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.DeleteValue("AgentIdeBootGap")
}
