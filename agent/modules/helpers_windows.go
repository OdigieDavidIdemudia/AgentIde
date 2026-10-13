//go:build windows

package modules

import (
	"agentide/core"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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

// sprayProbeUser is the deliberately non-existent account used for the spray.
// A distinctive name makes it possible to attribute Security log events to
// this test rather than to any pre-existing failed logons on the host.
const sprayProbeUser = "agentide_probe_nonexistent"

// queryFailedLogonsSince returns 4625 events newer than since, and how many
// mention the probe account. Reading the event timestamp (rather than merely
// checking that the log contains any 4625) is what makes the result
// attributable to this test — a machine with years of stale failed logons must
// not be scored as protected.
func queryFailedLogonsSince(since time.Time, account string) (total int, ours int, err error) {
	// Restrict to a window that starts before the spray and extends past it, so
	// every event this test could have caused is included and nothing older.
	windowSec := int(time.Since(since).Seconds()) + 60
	if windowSec < 120 {
		windowSec = 120
	}
	query := fmt.Sprintf(
		`*[System[EventID=4625] and TimeCreated[timediff(@SystemTime) <= %d000]]`,
		windowSec,
	)
	out, runErr := exec.Command("wevtutil", "qe", "Security", "/q:"+query, "/f:text", "/rd:true").Output()
	if runErr != nil {
		return 0, 0, fmt.Errorf("read Security log: %w", runErr)
	}

	text := string(out)
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "Event ID: 4625") {
			total++
			if account != "" && strings.Contains(line, account) {
				ours++
			}
		}
	}
	return total, ours, nil
}

// simulatePasswordSpray calls LogonUser N times with wrong credentials via syscall.
// The returned `blocked` flag means "the vendor's identity protection reacted",
// so it is only set when 4625 events attributable to THIS spray appear after it
// started. Previously any historical 4625 satisfied the check, so an
// unprotected host scored a false PASS.
func simulatePasswordSpray(attempts int) (blocked bool, note string) {
	const domain = "."
	const password = "WrongPassword123!"

	logonUser := syscall.MustLoadDLL("advapi32.dll").MustFindProc("LogonUserW")

	userPtr, _ := syscall.UTF16PtrFromString(sprayProbeUser)
	domainPtr, _ := syscall.UTF16PtrFromString(domain)
	passPtr, _ := syscall.UTF16PtrFromString(password)

	const logon32LogonNetwork = 3
	const logon32ProviderDefault = 0

	// Record the start time so only events caused by this spray are counted.
	started := time.Now()

	successes := 0
	for i := 0; i < attempts; i++ {
		var token syscall.Token
		ret, _, _ := logonUser.Call(
			uintptr(unsafe.Pointer(userPtr)),
			uintptr(unsafe.Pointer(domainPtr)),
			uintptr(unsafe.Pointer(passPtr)),
			logon32LogonNetwork,
			logon32ProviderDefault,
			uintptr(unsafe.Pointer(&token)),
		)
		if ret != 0 && token != 0 {
			// Should be impossible for a non-existent account, but never leak
			// a token if it somehow succeeds.
			_ = token.Close()
			successes++
		}
	}

	// Give the audit pipeline a moment to write the events.
	time.Sleep(2 * time.Second)

	total, ours, err := queryFailedLogonsSince(started, sprayProbeUser)
	if err != nil {
		// Inconclusive must NOT be scored as protected.
		return false, fmt.Sprintf(
			"%d spray attempts issued, but the Security log could not be read (%v) — treat as INCONCLUSIVE, not protected",
			attempts, err)
	}

	if successes > 0 {
		return false, fmt.Sprintf(
			"WARNING: %d of %d logons SUCCEEDED for the probe account — local authentication is not protected",
			successes, attempts)
	}

	if ours > 0 {
		return true, fmt.Sprintf(
			"Identity protection active: %d failed logon events (4625) attributed to this spray (probe account %q) were written to the Security log",
			ours, sprayProbeUser)
	}

	if total > 0 {
		return false, fmt.Sprintf(
			"%d spray attempts issued, %d failed logon events seen in the window but NONE matched the probe account — unable to attribute detection",
			attempts, total)
	}

	return false, fmt.Sprintf(
		"%d spray attempts issued and NO 4625 events were written — identity protection did not record the attempts",
		attempts)
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
