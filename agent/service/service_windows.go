//go:build windows

package service

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	modAdvapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	procGetSecurityDescriptorDacl = modAdvapi32.NewProc("GetSecurityDescriptorDacl")
)

const (
	// ServiceName is the main assessment service. Exported so the service
	// handlers in package main register with the SCM under the right name.
	ServiceName = "AgentIde"
	// GuardServiceName is the self-protection guardian service.
	GuardServiceName = "AgentIdeGuard"

	serviceName        = ServiceName
	guardServiceName   = GuardServiceName
	serviceDisplayName = "AgentIde Assessment Agent"
	serviceDescription = "AgentIde EDR/XDR Assessment Framework — POC Evaluation Agent"
	guardDisplayName   = "AgentIde Health Monitor"
	guardDescription   = "AgentIde self-protection — keeps the assessment agent installed and running"

	watchdogTaskName  = "AgentIde Watchdog"
	watchdogTaskName2 = "AgentIde Service Guard"
)

// Service security descriptors.
//
// fullServiceSDDL is the "open" descriptor used by our own installer /
// uninstaller: SYSTEM and Administrators get full control.
//
// hardServiceSDDL is applied to the live services. It explicitly DENIES
// NT AUTHORITY\SYSTEM the rights to STOP, CHANGE_CONFIG or DELETE the service,
// so a SYSTEM-level EDR (e.g. Cortex XDR) cannot stop or remove the service
// through the Service Control Manager. SYSTEM keeps WRITE_DAC so our own
// uninstaller can widen the DACL again and clean up cleanly.
const (
	fullServiceSDDL = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
	hardServiceSDDL = "D:" +
		"(D;;WP;;;SY)" + // deny SERVICE_STOP to SYSTEM
		"(D;;DC;;;SY)" + // deny SERVICE_CHANGE_CONFIG to SYSTEM
		"(D;;SD;;;SY)" + // deny DELETE to SYSTEM
		"(A;;CCLCSWRPDTLOCRRCWD;;;SY)" + // SYSTEM: query/start/interrogate + WRITE_DAC
		"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" + // Administrators: full control
		"(A;;CCLCSWLOCRRC;;;WD)" // Everyone: query only
)

// InstallParams are the arguments needed to (re)create the main service. The
// guardian service persists them so the agent can rebuild itself if its service
// registration or binary is removed.
type InstallParams struct {
	DashboardURL string `json:"dashboard_url"`
	AgentToken   string `json:"agent_token"`
	CertPin      string `json:"cert_pin"`
	AllowReboot  bool   `json:"allow_reboot"`
}

// dataDir returns %ProgramData%\AgentIde, creating it if needed.
func dataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "AgentIde")
	_ = os.MkdirAll(dir, 0755)
	return dir
}

func paramsPath() string    { return filepath.Join(dataDir(), "install.json") }
func backupExePath() string { return filepath.Join(dataDir(), "agentide.backup.exe") }

// BackupExePath is the location of the self-repair binary backup. The updater
// refreshes it after a successful swap.
func BackupExePath() string { return backupExePath() }

// UpdateLockPath marks that a self-update is in flight. While this file is
// fresh the guardian stands down so it does not restore the old binary or
// restart the service mid-swap.
func UpdateLockPath() string { return filepath.Join(dataDir(), "update.lock") }

// MarkUpdateInProgress tells the guardian to stand down during a self-update.
func MarkUpdateInProgress() {
	_ = os.WriteFile(UpdateLockPath(), []byte(time.Now().Format(time.RFC3339Nano)), 0644)
}

// ClearUpdateInProgress removes the update lock.
func ClearUpdateInProgress() {
	_ = os.Remove(UpdateLockPath())
}

// UpdateInProgress reports whether a self-update is currently in flight. The
// lock expires after 15 minutes so a crashed updater cannot disable
// self-protection forever.
func UpdateInProgress() bool {
	data, err := os.ReadFile(UpdateLockPath())
	if err != nil {
		return false
	}
	ts, err := time.Parse(time.RFC3339Nano, string(data))
	if err != nil || time.Since(ts) > 15*time.Minute {
		_ = os.Remove(UpdateLockPath())
		return false
	}
	return true
}

// SaveInstallParams persists the service arguments for self-repair.
func SaveInstallParams(p InstallParams) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(paramsPath(), data, 0600)
}

// LoadInstallParams reads the persisted service arguments.
func LoadInstallParams() (InstallParams, error) {
	var p InstallParams
	data, err := os.ReadFile(paramsPath())
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(data, &p)
	return p, err
}

// Install registers AgentIde as a Windows Service with hardened resilience:
//   - Auto-restart on crash AND on non-crash termination (2nd service recovery)
//   - Service DACL locked so a SYSTEM-level EDR cannot stop or delete it
//   - A guardian service + scheduled task that rebuild the service if removed
func Install(dashboardURL, agentToken, certPin string, allowReboot bool) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("cannot resolve absolute path: %w", err)
	}

	params := InstallParams{
		DashboardURL: dashboardURL,
		AgentToken:   agentToken,
		CertPin:      certPin,
		AllowReboot:  allowReboot,
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to Windows Service Manager: %w", err)
	}
	defer m.Disconnect()

	// Remove any stale install if present. Never rely on a plain OpenService:
	// a hardened service rejects SERVICE_ALL_ACCESS.
	if serviceExists(m, serviceName) || serviceExists(m, guardServiceName) {
		fmt.Printf("[INFO] Removing existing AgentIde service(s) before reinstall...\n")
		m.Disconnect()
		if err := Uninstall(); err != nil {
			return fmt.Errorf("could not remove existing service(s): %w", err)
		}
		m, err = mgr.Connect()
		if err != nil {
			return fmt.Errorf("cannot reconnect to service manager: %w", err)
		}
		defer m.Disconnect()
	}

	// Persist repair parameters and keep a backup of the binary so the
	// guardian can restore the agent if the installed copy is removed.
	// Done after Uninstall() so a reinstall does not wipe them again.
	if err := SaveInstallParams(params); err != nil {
		fmt.Printf("[WARN] Could not persist install parameters: %v\n", err)
	}
	if err := copyFile(exePath, backupExePath()); err != nil {
		fmt.Printf("[WARN] Could not write binary backup: %v\n", err)
	}

	// ── Main assessment service ────────────────────────────────────────────
	ms, err := createHardenedService(m, serviceName, serviceDisplayName, serviceDescription, exePath, buildMainArgs(params), true)
	if err != nil {
		return fmt.Errorf("cannot create service: %w", err)
	}
	defer ms.Close()
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	// ── Guardian service (self-healing) ────────────────────────────────────
	gs, guardErr := createHardenedService(m, guardServiceName, guardDisplayName, guardDescription, exePath, []string{"-guard"}, false)
	if guardErr != nil {
		fmt.Printf("[WARN] Could not install guardian service: %v\n", guardErr)
		gs = nil
	} else {
		defer gs.Close()
		_ = eventlog.InstallAsEventCreate(guardServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	}

	// ── Tertiary: scheduled task ───────────────────────────────────────────
	// Survives even if both service registrations are removed.
	if err := installWatchdogTask(exePath); err != nil {
		fmt.Printf("[WARN] Could not install watchdog task: %v\n", err)
	}

	// Start the guardian first so it can repair the main service if needed.
	if gs != nil {
		if err := gs.Start(); err != nil {
			fmt.Printf("[WARN] Guardian installed but could not start: %v\n", err)
		}
	}

	if err := ms.Start(); err != nil && err != windows.ERROR_SERVICE_ALREADY_RUNNING {
		// The guardian may already have started the service between creation
		// and here; that is a success, not a failure.
		fmt.Printf("[WARN] Service installed but could not start immediately: %v\n", err)
		fmt.Printf("[!] Try: sc start %s  — or restart the system.\n", serviceName)
	} else {
		fmt.Printf("\n[OK] Service %q installed and started successfully.\n", serviceName)
		fmt.Printf("[i] Self-protection active: the service resists stop/delete by SYSTEM-level processes and rebuilds itself if removed.\n")
		fmt.Printf("[i] The agent is now reporting to the dashboard.\n\n")
	}

	return nil
}

// createHardenedService creates a service, applies crash recovery, and locks
// its DACL. Shared by the install path and the guardian's self-repair path.
func createHardenedService(m *mgr.Mgr, name, display, description, exePath string, args []string, delayed bool) (*mgr.Service, error) {
	s, err := m.CreateService(name, exePath, mgr.Config{
		DisplayName:      display,
		Description:      description,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: delayed,
	}, args...)
	if err != nil {
		return nil, err
	}

	// Restart quickly on any failure. FailureActionsOnNonCrashFailures makes
	// the SCM restart the service even after a hard kill (not just a crash).
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 1000},
		{Type: mgr.ServiceRestart, Delay: 2000},
		{Type: mgr.ServiceRestart, Delay: 5000},
		{Type: mgr.ServiceRestart, Delay: 15000},
	}
	if err := s.SetRecoveryActions(recoveryActions, 86400); err != nil {
		fmt.Printf("[WARN] Could not set recovery actions for %s: %v\n", name, err)
	}
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)

	// Layer: lock the service DACL so a SYSTEM-level EDR cannot stop/delete it.
	if err := hardenServiceDACL(s); err != nil {
		fmt.Printf("[WARN] Could not harden DACL for %s: %v\n", name, err)
	}

	return s, nil
}

// buildMainArgs builds the command line for the main assessment service.
func buildMainArgs(p InstallParams) []string {
	args := []string{"--mode", "passive"}
	if p.DashboardURL != "" {
		args = append(args, "--dashboard", p.DashboardURL)
	}
	if p.AgentToken != "" {
		args = append(args, "--token", p.AgentToken)
	}
	if p.CertPin != "" {
		args = append(args, "--cert-pin", p.CertPin)
	}
	if p.AllowReboot {
		args = append(args, "--allow-reboot")
	}
	return args
}

// hardenServiceDACL sets the service's security descriptor so that
// NT AUTHORITY\SYSTEM cannot Stop, re-configure, or Delete the service, while
// Administrators retain full control. This prevents a SYSTEM-level EDR service
// (Cortex XDR, etc.) from stopping or uninstalling AgentIde via the SCM.
func hardenServiceDACL(s *mgr.Service) error {
	return setServiceDACL(s.Handle, hardServiceSDDL)
}

// applyServiceSDDL opens a service with DACL-write access and replaces its
// security descriptor. Works against both the hard and full descriptors, since
// SYSTEM always retains WRITE_DAC.
func applyServiceSDDL(name, sddl string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	h, err := windows.OpenService(
		m.Handle,
		windows.StringToUTF16Ptr(name),
		windows.READ_CONTROL|windows.WRITE_DAC,
	)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(h)
	return setServiceDACL(h, sddl)
}

// Harden (re)applies the anti-tamper DACL to the main service. Called on every
// service startup so the protection survives a self-update.
func Harden() error {
	return applyServiceSDDL(serviceName, hardServiceSDDL)
}

// Unprotect temporarily widens the main service DACL so the detached updater
// can stop it during a self-update. The next startup re-applies the hard DACL.
func Unprotect() error {
	return applyServiceSDDL(serviceName, fullServiceSDDL)
}

// setServiceDACL applies the DACL from an SDDL string to a service handle.
func setServiceDACL(handle windows.Handle, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("invalid SDDL: %w", err)
	}

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

	return windows.SetSecurityInfo(
		handle,
		windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

// serviceExists reports whether a service is registered. It opens only with
// READ_CONTROL so it succeeds even against a DACL-hardened service.
func serviceExists(m *mgr.Mgr, name string) bool {
	h, err := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(name), windows.READ_CONTROL)
	if err != nil {
		return false
	}
	_ = windows.CloseServiceHandle(h)
	return true
}

// openServiceForMaintenance opens a service with full access. If the service is
// DACL-hardened, it first opens with only the rights needed to widen the DACL,
// then re-opens with full access. This lets our own (possibly SYSTEM) uninstall
// path clean up even though we denied SYSTEM stop/delete.
func openServiceForMaintenance(m *mgr.Mgr, name string) (windows.Handle, error) {
	namePtr := windows.StringToUTF16Ptr(name)

	if h, err := windows.OpenService(m.Handle, namePtr, windows.SERVICE_ALL_ACCESS); err == nil {
		return h, nil
	}

	h, err := windows.OpenService(m.Handle, namePtr, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return 0, err
	}
	if err := setServiceDACL(h, fullServiceSDDL); err != nil {
		_ = windows.CloseServiceHandle(h)
		return 0, err
	}
	if err := windows.CloseServiceHandle(h); err != nil {
		return 0, err
	}
	return windows.OpenService(m.Handle, namePtr, windows.SERVICE_ALL_ACCESS)
}

// stopAndDeleteService stops and removes a service, widening its DACL first if
// necessary. A missing service is not an error.
func stopAndDeleteService(m *mgr.Mgr, name string, removeEvtLog bool) error {
	h, err := openServiceForMaintenance(m, name)
	if err != nil {
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return nil
		}
		return err
	}
	defer windows.CloseServiceHandle(h)

	var st windows.SERVICE_STATUS
	// Ignore stop errors (already stopped / not stoppable) and proceed to delete.
	_ = windows.ControlService(h, windows.SERVICE_CONTROL_STOP, &st)
	for i := 0; i < 75; i++ {
		if err := windows.QueryServiceStatus(h, &st); err != nil {
			break
		}
		if st.CurrentState == windows.SERVICE_STOPPED {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if removeEvtLog {
		_ = eventlog.Remove(name)
	}
	if err := windows.DeleteService(h); err != nil {
		return fmt.Errorf("DeleteService(%s): %w", name, err)
	}
	return nil
}

// Uninstall removes every layer of the AgentIde install: the guardian service,
// the watchdog task(s), and the main service. It also clears the persisted
// repair data and binary backup so the agent cannot resurrect itself.
func Uninstall() error {
	// Guardian first so it can't rebuild the main service mid-uninstall.
	if err := stopAndDeleteServiceIfPresent(guardServiceName); err != nil {
		fmt.Printf("[WARN] Could not remove guardian service: %v\n", err)
	}

	// Watchdog scheduled tasks.
	_ = exec.Command("schtasks", "/Delete", "/TN", watchdogTaskName, "/F").Run()
	_ = exec.Command("schtasks", "/Delete", "/TN", watchdogTaskName2, "/F").Run()

	if err := stopAndDeleteServiceIfPresent(serviceName); err != nil {
		return fmt.Errorf("could not remove service: %w", err)
	}

	// Remove persisted repair data + binary backup last.
	_ = os.Remove(paramsPath())
	_ = os.Remove(backupExePath())

	return nil
}

func stopAndDeleteServiceIfPresent(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	return stopAndDeleteService(m, name, true)
}

// exePath returns the absolute path of the running executable.
func exePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	p, _ = filepath.Abs(p)
	return p
}

// startServiceEx starts a service using only the rights a hardened service
// grants to SYSTEM (start + query status).
func startServiceEx(m *mgr.Mgr, name string) {
	h, err := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(name), windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return
	}
	defer windows.CloseServiceHandle(h)

	var st windows.SERVICE_STATUS
	if windows.QueryServiceStatus(h, &st) == nil && st.CurrentState == windows.SERVICE_STOPPED {
		_ = windows.StartService(h, 0, nil)
	}
}

// readRegistryStartType reads the SCM start type straight from the registry, so
// it works even while the DACL denies SERVICE_CHANGE_CONFIG to SYSTEM.
func readRegistryStartType(name string) (uint32, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("Start")
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// ensureAutoStart restores a service's start type to Automatic if a
// SYSTEM-level actor disabled it (e.g. `sc config <svc> start= disabled` or a
// registry Start=4 write). It briefly widens the DACL to perform the change,
// then re-applies the hardened DACL. Cheap on the common path: one registry
// read.
func ensureAutoStart(name string) {
	st, ok := readRegistryStartType(name)
	if !ok || st == windows.SERVICE_AUTO_START {
		return
	}

	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()

	namePtr := windows.StringToUTF16Ptr(name)
	if h, werr := windows.OpenService(m.Handle, namePtr, windows.READ_CONTROL|windows.WRITE_DAC); werr == nil {
		_ = setServiceDACL(h, fullServiceSDDL)
		_ = windows.CloseServiceHandle(h)
	}

	if s, oerr := m.OpenService(name); oerr == nil {
		if cfg, cerr := s.Config(); cerr == nil && cfg.StartType != mgr.StartAutomatic {
			cfg.StartType = mgr.StartAutomatic
			cfg.DelayedAutoStart = false
			_ = s.UpdateConfig(cfg)
		}
		s.Close()
	}

	// Re-apply the anti-tamper DACL regardless of the outcome.
	_ = applyServiceSDDL(name, hardServiceSDDL)
}

// EnsureInstalled is called by the running guardian service. It repairs the
// main service, reinstates the guardian registration if it was removed, and
// restores start types and DACLs. It never spawns a second guardian instance,
// because the caller already is the guardian.
func EnsureInstalled() error {
	return ensureInstalled(false)
}

// Repair is called by the scheduled task (`-repair`). It behaves like
// EnsureInstalled and additionally starts the guardian service if it is
// stopped.
func Repair() error {
	return ensureInstalled(true)
}

// ensureInstalled repairs the main and guardian services. When startGuard is
// true it also starts the guardian service (task path); the guardian's own
// path leaves the guardian alone.
func ensureInstalled(startGuard bool) error {
	RestoreBinaryIfMissing()

	exe := exePath()
	if exe == "" {
		return fmt.Errorf("cannot determine executable path")
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// Main assessment service.
	if !serviceExists(m, serviceName) {
		params, perr := LoadInstallParams()
		if perr != nil {
			return fmt.Errorf("main service missing and install params unavailable: %w", perr)
		}
		if _, cerr := createHardenedService(m, serviceName, serviceDisplayName, serviceDescription, exe, buildMainArgs(params), true); cerr != nil {
			return fmt.Errorf("recreate main service: %w", cerr)
		}
		_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	}
	startServiceEx(m, serviceName)

	// Guardian service, so it survives a reboot even if its registration
	// was removed while it was running.
	if !serviceExists(m, guardServiceName) {
		if _, cerr := createHardenedService(m, guardServiceName, guardDisplayName, guardDescription, exe, []string{"-guard"}, false); cerr != nil {
			fmt.Printf("[WARN] Could not recreate guardian service: %v\n", cerr)
		} else {
			_ = eventlog.InstallAsEventCreate(guardServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
		}
	}
	if startGuard {
		startServiceEx(m, guardServiceName)
	}

	// Undo a start-type tamper, then re-apply the anti-tamper DACLs.
	ensureAutoStart(serviceName)
	ensureAutoStart(guardServiceName)
	_ = applyServiceSDDL(serviceName, hardServiceSDDL)
	_ = applyServiceSDDL(guardServiceName, hardServiceSDDL)
	return nil
}

// RestoreBinaryIfMissing copies the backed-up agent binary over the installed
// path if the installed binary has been removed.
func RestoreBinaryIfMissing() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	if _, err := os.Stat(exePath); err == nil {
		return
	}
	bak := backupExePath()
	if _, err := os.Stat(bak); err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(exePath), 0755)
	_ = copyFile(bak, exePath)
}

// installWatchdogTask creates scheduled tasks that keep AgentIde running. They
// fire once per minute as SYSTEM and invoke `agentide.exe -repair`, which
// recreates the services if removed, starts them if stopped, and restores an
// Automatic start type if an EDR disabled them. This is the tertiary safety net
// behind the guardian service. They skip while a self-update is in flight.
func installWatchdogTask(exePath string) error {
	shortCmd := fmt.Sprintf(
		`powershell -w hidden -c "if(Test-Path '%s'){exit}; &'%s' -repair"`,
		UpdateLockPath(), exePath,
	)

	// Remove stale tasks first (ignore errors).
	_ = exec.Command("schtasks", "/Delete", "/TN", watchdogTaskName, "/F").Run()
	_ = exec.Command("schtasks", "/Delete", "/TN", watchdogTaskName2, "/F").Run()

	// Primary task: every minute.
	cmd := exec.Command("schtasks",
		"/Create",
		"/TN", watchdogTaskName,
		"/SC", "MINUTE",
		"/MO", "1",
		"/TR", shortCmd,
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/F",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks create failed: %v (%s)", err, string(out))
	}

	// Redundant task under a different name, every 2 minutes.
	redundant := exec.Command("schtasks",
		"/Create",
		"/TN", watchdogTaskName2,
		"/SC", "MINUTE",
		"/MO", "2",
		"/TR", shortCmd,
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/F",
	)
	_ = redundant.Run()

	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
