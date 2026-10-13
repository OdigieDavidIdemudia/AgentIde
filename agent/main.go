package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"agentide/core"
	"agentide/discovery"
	"agentide/fingerprint"
	"agentide/service"
	"agentide/transport"
	"agentide/watchdog"
)

// version is a variable (not a const) so release builds can override it with
// `-ldflags "-X main.version=0.4.0"` to match the MSI package version.
var version = "0.4.0"

func main() {
	// ── CLI Flags ──────────────────────────────────────────────────────────────
	installFlag := flag.Bool("install", false, "Install AgentIde as a system service")
	uninstallFlag := flag.Bool("uninstall", false, "Uninstall the AgentIde system service")
	modeFlag := flag.String("mode", "passive", "Operating mode: passive | active")
	profileFlag := flag.String("profile", "rapid", "Assessment profile: rapid | apt | baseline")
	daysFlag := flag.Int("days", 1, "Duration in days (used with --profile apt or baseline)")
	moduleFlag := flag.String("module", "all", "Run a specific module: all | antitamper | malware | lolbin | network | identity | reboot | performance | falsepositive")
	dashboardFlag := flag.String("dashboard", "", "Dashboard WebSocket URL, or a comma-separated list to try in order (e.g. wss://192.168.1.168:8443,wss://10.0.0.1:8443)")
	tokenFlag := flag.String("token", "", "Agent auth token (must match AGENT_TOKEN on the dashboard)")
	certPinFlag := flag.String("cert-pin", "", "Optional: hex SHA-256 of dashboard cert SPKI to pin instead of trusting any cert")
	watchdogFlag := flag.String("watchdog", "", "Internal: watchdog child mode (vendor,marker,heartbeatSec,deadlineUnix)")
	guardFlag := flag.Bool("guard", false, "Internal: run the self-protection guardian service")
	unprotectFlag := flag.Bool("unprotect", false, "Internal: temporarily widen the service DACL for a self-update")
	repairFlag := flag.Bool("repair", false, "Internal: ensure the services exist and are running (used by the scheduled task)")
	allowReboot := flag.Bool("allow-reboot", false, "Allow AgentIde to reboot the system during Boot Gap testing")
	checkFlag := flag.Bool("check", false, "Test connectivity to -dashboard and exit (0 = reachable, 1 = unreachable)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("AgentIde v%s\n", version)
		os.Exit(0)
	}

	// ── Connectivity Check Mode ────────────────────────────────────────────────
	// Used by the installer and for manual troubleshooting: connect to the
	// dashboard, confirm it accepts our token, then exit with a clear status.
	if *checkFlag {
		if *dashboardFlag == "" {
			fmt.Println("[ERROR] -check requires -dashboard <url>")
			os.Exit(2)
		}
		logger, _ := core.NewLogger("agentide.log")
		hostname, _ := os.Hostname()
		sender := transport.NewSender(*dashboardFlag, hostname, *tokenFlag, *certPinFlag, logger)
		sender.Connect()
		if transport.WaitForConnection(sender, 10*time.Second) {
			fmt.Printf("[OK] Dashboard reachable and token accepted: %s\n", *dashboardFlag)
			sender.Disconnect()
			os.Exit(0)
		}
		fmt.Printf("[ERROR] Dashboard NOT reachable with the given URL/token: %s\n", *dashboardFlag)
		sender.Disconnect()
		os.Exit(1)
	}

	// ── Watchdog Child Mode ────────────────────────────────────────────
	// Internal entrypoint used by the watchdog package: monitor the marker
	// file and re-enable the vendor if the parent dies or the deadline hits.
	if *watchdogFlag != "" {
		parts := strings.Split(*watchdogFlag, ",")
		if len(parts) == 4 {
			heartbeatSec, _ := strconv.Atoi(parts[2])
			deadlineSec, _ := strconv.ParseInt(parts[3], 10, 64)
			watchdog.RunChild(parts[0], parts[1], time.Duration(heartbeatSec)*time.Second, time.Unix(deadlineSec, 0))
		}
		os.Exit(0)
	}

	// ── Guardian Service Mode ──────────────────────────────────────────────
	// The self-protection guardian is a second service that keeps the main
	// AgentIde service installed and running. It is started by the SCM, not
	// by the user.
	if *guardFlag {
		if err := runGuardService(); err != nil {
			log.Fatalf("[FATAL] Guardian service error: %v", err)
		}
		return
	}

	// ── Update Unprotect Mode ──────────────────────────────────────────────
	// Internal: the detached updater runs the current binary with -unprotect
	// to widen the service DACL just long enough to stop and replace the
	// service. The next startup re-applies the hardened DACL.
	if *unprotectFlag {
		if err := unprotectService(); err != nil {
			log.Fatalf("[FATAL] Could not unprotect service for update: %v", err)
		}
		fmt.Println("[OK] Service DACL widened for update.")
		return
	}

	// ── Service Repair Mode ────────────────────────────────────────────────
	// Internal: the scheduled task runs this once per minute to make sure the
	// services exist, are enabled, and are running.
	if *repairFlag {
		if err := repairInstall(); err != nil {
			log.Printf("[WARN] Service repair failed: %v", err)
		}
		return
	}

	// ── Service Management ─────────────────────────────────────────────────────
	if *installFlag {
		fmt.Println("[*] Attempting to install AgentIde service (Deployment Trust Phase)...")

		if err := service.Install(*dashboardFlag, *tokenFlag, *certPinFlag, *allowReboot); err != nil {
			log.Fatalf("[FATAL] Service installation failed: %v", err)
		}

		// Persist the dashboard URL and token to config.json next to the exe so the service
		// can read them at every reboot without needing CLI flags.
		// Start from any existing config so a reinstall/repair/MSI upgrade
		// without flags doesn't wipe the previously saved values.
		exePath, _ := os.Executable()
		exeDir := filepath.Dir(exePath)
		configPath := filepath.Join(exeDir, "config.json")
		persistCfg, cfgErr := core.LoadConfig(configPath)
		if cfgErr != nil {
			persistCfg = core.DefaultConfig()
		}
		if *dashboardFlag != "" {
			persistCfg.DashboardURL = *dashboardFlag
		}
		if *tokenFlag != "" {
			persistCfg.AgentToken = *tokenFlag
		}
		if *certPinFlag != "" {
			persistCfg.CertPin = *certPinFlag
		}
		persistCfg.LogPath = `C:\ProgramData\AgentIde\agentide.log`
		if *allowReboot {
			persistCfg.AllowReboot = true
		}
		if err := core.SaveConfig(configPath, persistCfg); err != nil {
			fmt.Printf("[WARN] Could not write config.json: %v\n", err)
		} else {
			fmt.Printf("[OK] Dashboard URL persisted to %s\n", configPath)
		}

		// If we reached here, the EDR did not block the installation.
		// Connect, wait for the socket to come up, report the install result,
		// then give it a moment to flush before disconnecting. This turns a
		// silent misconfiguration (wrong URL/token) into a visible message.
		if *dashboardFlag != "" {
			logger, _ := core.NewLogger("agentide.log") // Temporary logger
			hostname, _ := os.Hostname()
			sender := transport.NewSender(*dashboardFlag, hostname, *tokenFlag, *certPinFlag, logger)
			sender.Connect()

			if transport.WaitForConnection(sender, 10*time.Second) {
				// Send install survival result
				sender.SendModuleResult(map[string]interface{}{
					"module":      "install_survival",
					"passed":      true,
					"result":      "PASS",
					"detail":      "Service installed successfully. System restart required to test ELAM boot survival.",
					"test_type":   "blackbox",
					"duration_ms": 0,
					"mitre":       "T1543.003",
				})
				time.Sleep(750 * time.Millisecond) // let the message flush
				fmt.Printf("[OK] Agent connected to dashboard and is reporting: %s\n", *dashboardFlag)
			} else {
				fmt.Printf("[WARN] Agent installed but could NOT reach the dashboard at: %s\n", *dashboardFlag)
				fmt.Println("       Check the URL/token, then verify with: agentide.exe -check -dashboard <url> -token <token>")
			}
			sender.Disconnect()
		}

		os.Exit(0)
	}

	if *uninstallFlag {
		if err := service.Uninstall(); err != nil {
			log.Fatalf("[FATAL] Service uninstall failed: %v", err)
		}
		fmt.Println("[OK] AgentIde service uninstalled.")
		os.Exit(0)
	}

	// ── Load Config ────────────────────────────────────────────────────────────
	// Always resolve config.json relative to the executable's directory,
	// not the current working directory (which is System32 when run as a service).
	exePath, _ := os.Executable()
	configPath := filepath.Join(filepath.Dir(exePath), "config.json")
	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		cfg = core.DefaultConfig()
	}
	if *dashboardFlag != "" {
		cfg.DashboardURL = *dashboardFlag
	}
	// Command-line values are authoritative when present. A Windows service is
	// registered with `--dashboard/--token/--cert-pin` (see service.Install), so
	// applying these here guarantees the agent authenticates even when
	// config.json is missing or was not written next to the executable.
	// Previously only -dashboard was applied, so such agents connected with an
	// empty token and were rejected by the dashboard ("received=MISSING").
	if *tokenFlag != "" {
		cfg.AgentToken = *tokenFlag
	}
	if *certPinFlag != "" {
		cfg.CertPin = *certPinFlag
	}
	// Only ever enable reboots; never clear a value persisted in config.json.
	if *allowReboot {
		cfg.AllowReboot = true
	}

	// ── Windows Service vs Interactive CLI Detection ───────────────────────────
	// If the process was launched by the Windows Service Control Manager (not a user
	// terminal), hand control to the SCM dispatcher immediately to avoid Error 1053.
	isService, err := isWindowsService()
	if err != nil {
		log.Fatalf("[FATAL] Could not determine execution context: %v", err)
	}

	if isService {
		// Running as a background Windows Service — SCM controls the lifecycle
		if err := runAsWindowsService(cfg, *modeFlag, *profileFlag, *daysFlag, *moduleFlag); err != nil {
			log.Fatalf("[FATAL] Service execution error: %v", err)
		}
		return
	}

	// ── Interactive CLI Mode ───────────────────────────────────────────────────
	// Running from PowerShell / CMD — show console output as usual
	logger, err := core.NewLogger(cfg.LogPath)
	if err != nil {
		log.Fatalf("[FATAL] Could not initialize logger: %v", err)
	}
	defer logger.Close()

	logger.Info("AgentIde starting", map[string]interface{}{
		"version": version,
		"mode":    *modeFlag,
		"profile": *profileFlag,
	})

	// Fingerprint
	fp, err := fingerprint.Collect()
	if err != nil {
		logger.Warn("Fingerprinting partially failed", map[string]interface{}{"error": err.Error()})
	} else {
		logger.Info("Endpoint fingerprint collected", fp.ToMap())
		fmt.Printf("\n┌─ Endpoint Fingerprint ────────────────────────\n")
		fmt.Printf("│  Hostname  : %s\n", fp.Hostname)
		fmt.Printf("│  IP        : %s\n", fp.IP)
		fmt.Printf("│  MAC       : %s\n", fp.MAC)
		fmt.Printf("│  OS        : %s %s\n", fp.OS, fp.OSVersion)
		fmt.Printf("│  Kernel    : %s\n", fp.KernelBuild)
		fmt.Printf("│  Arch      : %s\n", fp.Arch)
		fmt.Printf("└───────────────────────────────────────────────\n\n")
	}

	// Discovery
	fmt.Println("[*] Scanning for installed security agents...")
	agents, err := discovery.Scan()
	if err != nil {
		logger.Error("Discovery scan failed", map[string]interface{}{"error": err.Error()})
		fmt.Fprintf(os.Stderr, "[ERROR] Discovery scan failed: %v\n", err)
	}

	if len(agents) == 0 {
		fmt.Println("[!] No known security agents detected on this system.")
	} else {
		fmt.Printf("\n┌─ Discovered Security Agents ──────────────────\n")
		for i, a := range agents {
			fmt.Printf("│  [%d] %s (PID: %d, Service: %s)\n", i+1, a.Vendor, a.PID, a.ServiceName)
		}
		fmt.Printf("└───────────────────────────────────────────────\n\n")
	}

	// Transport
	sender := transport.NewSender(cfg.DashboardURL, fp.Hostname, cfg.AgentToken, cfg.CertPin, logger)
	sender.Connect()
	defer sender.Disconnect()

	sender.SendFingerprint(fingerprintPayload(fp, cfg))
	sender.StartHeartbeat()
	if len(agents) > 0 {
		// Report every vendor found, not just the first — a layered estate has
		// several agents running and each one is part of the assessment scope.
		found := make([]map[string]interface{}, 0, len(agents))
		for _, a := range agents {
			found = append(found, map[string]interface{}{
				"discovered_vendor": a.Vendor,
				"process_name":      a.ProcessName,
				"service_name":      a.ServiceName,
				"pid":               a.PID,
			})
		}
		sender.SendDiscovery(found)
	}

	// Run
	runAgent(cfg, *modeFlag, *profileFlag, *daysFlag, *moduleFlag)
}
