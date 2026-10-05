//go:build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	modAdvapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procGetSecurityDescriptorDacl = modAdvapi32.NewProc("GetSecurityDescriptorDacl")
)

const (
	serviceName        = "AgentIde"
	serviceDisplayName = "AgentIde Assessment Agent"
	serviceDescription = "AgentIde EDR/XDR Assessment Framework — POC Evaluation Agent"
	watchdogTaskName   = "AgentIde Watchdog"
)

// Install registers AgentIde as a Windows Service with hardened resilience:
//   - Auto-restart on failure (3 rapid retries, then 60s intervals)
//   - Service DACL locked so only SYSTEM/Admins can stop it
//   - Scheduled Task watchdog reinstalls the service if it disappears at boot
func Install(dashboardURL string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("cannot resolve absolute path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to Windows Service Manager: %w", err)
	}
	defer m.Disconnect()

	// Remove stale install if present
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		fmt.Printf("[INFO] Removing existing service %q before reinstall...\n", serviceName)
		if err := Uninstall(); err != nil {
			return fmt.Errorf("could not remove existing service: %w", err)
		}
		// Re-connect after uninstall
		m, err = mgr.Connect()
		if err != nil {
			return fmt.Errorf("cannot reconnect to service manager: %w", err)
		}
		defer m.Disconnect()
	}

	// Build service arguments
	args := []string{"--mode", "passive"}
	if dashboardURL != "" {
		args = append(args, "--dashboard", dashboardURL)
	}

	// Create the service with AutomaticDelayedStart so it starts after the
	// EDR has fully initialized (reduces early-boot kill risk)
	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName:      serviceDisplayName,
		Description:      serviceDescription,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
	}, args...)
	if err != nil {
		return fmt.Errorf("cannot create service: %w", err)
	}
	defer s.Close()

	// Layer 1: Failure recovery — restart immediately 3 times, then every 60s
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2000},   // 2s after 1st failure
		{Type: mgr.ServiceRestart, Delay: 5000},   // 5s after 2nd failure
		{Type: mgr.ServiceRestart, Delay: 60000},  // 60s after 3rd+ failure
	}
	if err := s.SetRecoveryActions(recoveryActions, 86400); err != nil {
		fmt.Printf("[WARN] Could not set recovery actions: %v\n", err)
	}

	// Layer 2: Harden the service DACL — deny Stop/Delete to non-Admins
	if err := hardenServiceDACL(s); err != nil {
		fmt.Printf("[WARN] Could not harden service DACL: %v\n", err)
	}

	// Register event log source
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	// Layer 3: Watchdog scheduled task — reinstalls + starts service at boot
	// and every 5 minutes if not running
	if err := installWatchdogTask(exePath, dashboardURL); err != nil {
		fmt.Printf("[WARN] Could not install watchdog task: %v\n", err)
	}

	// Start the service immediately so it connects to the dashboard right away.
	// A system restart is still recommended to test ELAM early-boot survival,
	// but the agent should be visible and reporting immediately after install.
	if err := s.Start(); err != nil {
		fmt.Printf("[WARN] Service installed but could not start immediately: %v\n", err)
		fmt.Printf("[!] Try: sc start AgentIde  — or restart the system.\n")
	} else {
		fmt.Printf("\n[OK] Service %q installed and started successfully.\n", serviceName)
		fmt.Printf("[i] The agent is now reporting to the dashboard.\n")
		fmt.Printf("[i] For ELAM boot-survival testing, restart the system when ready.\n\n")
	}

	return nil
}

// hardenServiceDACL sets the service's security descriptor so that only
// NT AUTHORITY\SYSTEM and members of the local Administrators group can
// send Stop or Delete control codes. All other users get Query-only access.
func hardenServiceDACL(s *mgr.Service) error {
	// SDDL: SYSTEM (SY) and Admins (BA) get full control; Everyone (WD) gets query-only.
	sddl := "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;WD)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("invalid SDDL: %w", err)
	}

	// Extract the DACL from the security descriptor via syscall
	var dacl *windows.ACL
	var daclPresent, daclDefaulted uint32
	r1, _, e := syscall.SyscallN(
		procGetSecurityDescriptorDacl.Addr(),
		uintptr(unsafe.Pointer(sd)),
		uintptr(unsafe.Pointer(&daclPresent)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&daclDefaulted)),
	)
	if r1 == 0 {
		return fmt.Errorf("GetSecurityDescriptorDacl: %w", e)
	}

	// Apply the DACL to the service object
	err = windows.SetSecurityInfo(
		windows.Handle(s.Handle),
		windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("SetSecurityInfo: %w", err)
	}
	return nil
}

// installWatchdogTask creates a scheduled task that ensures AgentIde is
// always running. It fires at system boot (once) and then every 5 minutes.
// If the service is missing, it re-installs it. If it's stopped, it starts it.
func installWatchdogTask(exePath, dashboardURL string) error {
	dashArg := ""
	if dashboardURL != "" {
		dashArg = " -dashboard " + dashboardURL
	}

	// Ultra-short command to bypass 261 char limit of schtasks /TR
	shortCmd := fmt.Sprintf(`powershell -w hidden -c "if(!(Get-Service AgentIde -ea 0)){&'%s' -install%s}else{Start-Service AgentIde -ea 0}"`, exePath, dashArg)

	// Remove existing task first (ignore errors)
	_ = exec.Command("schtasks", "/Delete", "/TN", watchdogTaskName, "/F").Run()

	// Create task: runs as SYSTEM, triggers at boot + every 5 minutes
	cmd := exec.Command("schtasks",
		"/Create",
		"/TN", watchdogTaskName,
		"/SC", "MINUTE",
		"/MO", "5",
		"/TR", shortCmd,
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/F", // force overwrite
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks create failed: %v — %s", err, string(out))
	}

	// Also add a boot trigger via a second task
	_ = exec.Command("schtasks",
		"/Create",
		"/TN", watchdogTaskName+" Boot",
		"/SC", "ONSTART",
		"/DELAY", "0001:00", // 1 minute delay after boot (after EDR loads)
		"/TR", shortCmd,
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/F",
	).Run()

	fmt.Println("[OK] Watchdog scheduled task installed.")
	return nil
}

// Uninstall removes the AgentIde Windows Service and watchdog tasks.
func Uninstall() error {
	// Remove watchdog tasks first
	_ = exec.Command("schtasks", "/Delete", "/TN", watchdogTaskName, "/F").Run()
	_ = exec.Command("schtasks", "/Delete", "/TN", watchdogTaskName+" Boot", "/F").Run()

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to Windows Service Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		// Service doesn't exist — that's fine for an uninstall
		_ = eventlog.Remove(serviceName)
		return nil
	}
	defer s.Close()

	// Send stop control and wait up to 10 seconds for the service to reach Stopped.
	// Windows service stop is asynchronous — Delete() on a running service only
	// marks it "pending delete", which blocks re-registration under the same name.
	_, _ = s.Control(windows.SERVICE_CONTROL_STOP)
	for i := 0; i < 20; i++ {
		status, err := s.Query()
		if err != nil || status.State == windows.SERVICE_STOPPED {
			break
		}
		// Sleep 500ms between polls
		exec.Command("ping", "-n", "1", "-w", "500", "127.0.0.1").Run() //nolint
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("cannot delete service: %w", err)
	}

	_ = eventlog.Remove(serviceName)
	fmt.Printf("[OK] Service %q and watchdog tasks uninstalled.\n", serviceName)
	return nil
}

