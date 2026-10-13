//go:build windows

package main

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

// The main service's DACL deliberately denies SERVICE_STOP / DELETE to
// NT AUTHORITY\SYSTEM. That is what stops a SYSTEM-level EDR from disabling
// the agent — but it also means the agent cannot stop its own service, because
// the SCM checks the caller's rights and SYSTEM is explicitly denied.
//
// AgentIdeGuard re-applies the hardened DACL on every 15s tick, so simply
// widening it (Unprotect) is not enough: the guardian puts the hard
// descriptor back before the stop can be issued.
//
// The supported way to stop the service is therefore the update lock, which
// the guardian already honours and stands down for. We take that lock, widen
// the DACL, and let a detached helper issue the stop/start pair — the same
// mechanism the self-update swap uses, which is already proven to get past
// both the DACL and the guardian.
func restartSelf(logger *core.Logger) error {
	// Tell the guardian to stand down, otherwise it re-hardens the DACL and
	// resurrects the service mid-operation.
	service.MarkUpdateInProgress()
	// Give the in-flight tick time to observe the lock and finish.
	time.Sleep(2 * time.Second)

	// Widen the DACL so the stop is permitted at all.
	if err := service.Unprotect(); err != nil {
		service.ClearUpdateInProgress()
		return fmt.Errorf("widen service DACL for restart: %w", err)
	}

	scriptPath := filepath.Join(os.TempDir(), fmt.Sprintf("agentide_restart_%d.cmd", time.Now().UnixNano()))
	lock := service.UpdateLockPath()
	svc := service.ServiceName

	// The helper must clear the lock even on failure, otherwise self-protection
	// would stay disabled for the lock's expiry window.
	script := "@echo off\r\n" +
		"setlocal enableextensions\r\n" +
		"sc stop " + svc + " >nul 2>&1\r\n" +
		"set /a tries=0\r\n" +
		":retry\r\n" +
		"for /f \"tokens=3\" %%s in ('sc query " + svc + " ^| findstr /c:\"STATE\"') do set ST=%%s\r\n" +
		"if /i \"%ST%\"==\"STOPPED\" goto start\r\n" +
		"set /a tries=tries+1\r\n" +
		"if %tries% GEQ 60 goto cleanup\r\n" +
		"ping -n 2 127.0.0.1 >nul\r\n" +
		"goto retry\r\n" +
		":start\r\n" +
		"sc start " + svc + " >nul 2>&1\r\n" +
		":cleanup\r\n" +
		"del \"" + lock + "\" >nul 2>&1\r\n" +
		"del \"%~f0\"\r\n" +
		"exit /b 0\r\n"

	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		service.ClearUpdateInProgress()
		return fmt.Errorf("write restart script: %w", err)
	}

	cmd := exec.Command("cmd", "/c", scriptPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000008 | 0x08000000, // DETACHED_PROCESS | CREATE_NO_WINDOW
	}
	if err := cmd.Start(); err != nil {
		service.ClearUpdateInProgress()
		return fmt.Errorf("launch restart helper: %w", err)
	}

	logger.Info("Restart helper launched; guardian paused until it completes", nil)
	return nil
}

// uninstallSelf removes the agent service in response to the dashboard's
// "Uninstall Agent" command. It must first stop the guardian, otherwise the
// guardian recreates the service within 15 seconds — which is exactly what we
// saw leave a "removed" agent still running.
//
// The same DACL constraint applies, so the guardian is paused via the update
// lock before anything is torn down.
func uninstallSelf(logger *core.Logger) error {
	// Stop the guardian first: once it is stopped it can no longer resurrect
	// the main service. The guardian honours the update lock, so take it first.
	service.MarkUpdateInProgress()
	time.Sleep(2 * time.Second)

	if err := service.Unprotect(); err != nil {
		logger.Warn("Could not widen DACL before uninstall", map[string]interface{}{"error": err.Error()})
	}

	exe, err := os.Executable()
	if err != nil {
		service.ClearUpdateInProgress()
		return fmt.Errorf("resolve executable path: %w", err)
	}

	// `agentide.exe -uninstall` removes the service, the guardian, and the
	// watchdog tasks through the same code path the MSI uninstaller uses.
	cmd := exec.Command(exe, "-uninstall")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000008 | 0x08000000, // DETACHED_PROCESS | CREATE_NO_WINDOW
	}
	if err := cmd.Start(); err != nil {
		service.ClearUpdateInProgress()
		return fmt.Errorf("launch uninstall helper: %w", err)
	}

	// Do NOT clear the lock here: the guardian must stay stood down while the
	// uninstall runs, otherwise it recreates the service. It expires on its own
	// after 15 minutes, and nothing is left to protect once the agent is gone.
	logger.Info("Uninstall helper launched; guardian stood down", nil)
	return nil
}