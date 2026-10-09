//go:build windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"agentide/core"
	"agentide/service"
)

// swapAndRestart writes a small helper script that stops the service, waits
// until the locked executable can be replaced, starts the service again, then
// deletes itself. The script is launched detached so it survives the agent
// process being stopped.
func swapAndRestart(exePath, newPath string, logger *core.Logger) error {
	// Tell the guardian (and the scheduled task) to stand down while we
	// replace the binary, then give any in-flight repair a moment to finish.
	service.MarkUpdateInProgress()
	time.Sleep(2 * time.Second)

	scriptPath := filepath.Join(os.TempDir(), fmt.Sprintf("agentide_update_%d.cmd", time.Now().UnixNano()))

	// - `-unprotect` widens the service DACL so SYSTEM may stop it (the
	//   hardened descriptor denies stop/delete to SYSTEM).
	// - The lock file is removed on both success and failure so protection
	//   resumes; it also auto-expires if the script is killed.
	// - The backup binary is refreshed so the guardian restores the new build.
	svc := service.ServiceName
	backup := service.BackupExePath()
	lock := service.UpdateLockPath()

	script := "@echo off\r\n" +
		"setlocal enableextensions\r\n" +
		"\"" + exePath + "\" -unprotect >nul 2>&1\r\n" +
		"sc stop " + svc + " >nul 2>&1\r\n" +
		"set /a tries=0\r\n" +
		":retry\r\n" +
		"move /y \"" + newPath + "\" \"" + exePath + "\" >nul 2>&1\r\n" +
		"if not errorlevel 1 goto ok\r\n" +
		"set /a tries=tries+1\r\n" +
		"if %tries% GEQ 120 goto fail\r\n" +
		"ping -n 2 127.0.0.1 >nul\r\n" +
		"goto retry\r\n" +
		":ok\r\n" +
		"copy /y \"" + exePath + "\" \"" + backup + "\" >nul 2>&1\r\n" +
		"sc start " + svc + " >nul 2>&1\r\n" +
		"del \"" + lock + "\" >nul 2>&1\r\n" +
		"del \"%~f0\"\r\n" +
		"exit /b 0\r\n" +
		":fail\r\n" +
		"sc start " + svc + " >nul 2>&1\r\n" +
		"del \"" + lock + "\" >nul 2>&1\r\n" +
		"del \"%~f0\"\r\n" +
		"exit /b 1\r\n"

	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		service.ClearUpdateInProgress()
		return fmt.Errorf("write updater script: %w", err)
	}

	// CREATE_NO_WINDOW | DETACHED_PROCESS: the script survives the agent
	// process being stopped so it can replace the locked binary.
	const detachedProcess = 0x00000008
	const createNoWindow = 0x08000000
	cmd := exec.Command("cmd", "/c", scriptPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | createNoWindow,
	}
	if err := cmd.Start(); err != nil {
		service.ClearUpdateInProgress()
		return fmt.Errorf("launch updater script: %w", err)
	}
	return nil
}
