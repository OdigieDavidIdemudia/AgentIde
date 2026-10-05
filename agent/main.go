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

const version = "0.1.0"

func main() {
	// ── CLI Flags ──────────────────────────────────────────────────────────────
	installFlag   := flag.Bool("install", false, "Install AgentIde as a system service")
	uninstallFlag := flag.Bool("uninstall", false, "Uninstall the AgentIde system service")
	modeFlag      := flag.String("mode", "passive", "Operating mode: passive | active")
	profileFlag   := flag.String("profile", "rapid", "Assessment profile: rapid | apt | baseline")
	daysFlag      := flag.Int("days", 1, "Duration in days (used with --profile apt or baseline)")
	moduleFlag    := flag.String("module", "all", "Run a specific module: all | antitamper | malware | lolbin | network | identity | reboot | performance | falsepositive")
	dashboardFlag := flag.String("dashboard", "", "Central dashboard WebSocket URL (e.g. wss://192.168.1.10:8080)")
	tokenFlag    := flag.String("token", "", "Agent auth token (must match AGENT_TOKEN on the dashboard)")
	certPinFlag  := flag.String("cert-pin", "", "Optional: hex SHA-256 of dashboard cert SPKI to pin instead of trusting any cert")
	watchdogFlag := flag.String("watchdog", "", "Internal: watchdog child mode (vendor,marker,heartbeatSec,deadlineUnix)")
	allowReboot   := flag.Bool("allow-reboot", false, "Allow AgentIde to reboot the system during Boot Gap testing")
	versionFlag   := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("AgentIde v%s\n", version)
		os.Exit(0)
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

	// ── Service Management ─────────────────────────────────────────────────────
	if *installFlag {
		fmt.Println("[*] Attempting to install AgentIde service (Deployment Trust Phase)...")

		if err := service.Install(*dashboardFlag); err != nil {
			log.Fatalf("[FATAL] Service installation failed: %v", err)
		}

		// Persist the dashboard URL and token to config.json next to the exe so the service
		// can read them at every reboot without needing CLI flags.
		exePath, _ := os.Executable()
		exeDir := filepath.Dir(exePath)
		configPath := filepath.Join(exeDir, "config.json")
		persistCfg := &core.Config{
			DashboardURL: *dashboardFlag,
			AgentToken:   *tokenFlag,
			CertPin:      *certPinFlag,
			LogPath:      `C:\ProgramData\AgentIde\agentide.log`,
			AllowReboot:  *allowReboot,
		}
		if err := core.SaveConfig(configPath, persistCfg); err != nil {
			fmt.Printf("[WARN] Could not write config.json: %v\n", err)
		} else {
			fmt.Printf("[OK] Dashboard URL persisted to %s\n", configPath)
		}

		// If we reached here, the EDR did not block the installation.
		// Connect briefly to report the installation success to the dashboard.
		if *dashboardFlag != "" {
			logger, _ := core.NewLogger("agentide.log") // Temporary logger
			hostname, _ := os.Hostname()
			sender := transport.NewSender(*dashboardFlag, hostname, *tokenFlag, *certPinFlag, logger)
			sender.Connect()
			
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
	cfg.AllowReboot = *allowReboot

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

	sender.SendFingerprint(fp.ToMap())
	sender.StartHeartbeat()
	if len(agents) > 0 {
		sender.SendDiscovery(map[string]interface{}{"discovered_vendor": agents[0].Vendor})
	}

	// Run
	runAgent(cfg, *modeFlag, *profileFlag, *daysFlag, *moduleFlag)
}

