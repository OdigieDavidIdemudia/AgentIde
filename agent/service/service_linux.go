//go:build linux

package service

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	serviceName = "agentide"
	unitPath    = "/etc/systemd/system/agentide.service"
)

// Install writes a systemd unit file and enables the AgentIde service.
func Install(dashboardURL string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("cannot resolve absolute path: %w", err)
	}

	execArgs := "--mode passive"
	if dashboardURL != "" {
		execArgs += " --dashboard " + dashboardURL
	}

	unit := fmt.Sprintf(`[Unit]
Description=AgentIde EDR/XDR Assessment Framework — POC Evaluation Agent
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=%s %s
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=agentide

[Install]
WantedBy=multi-user.target
`, exePath, execArgs)

	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("cannot write systemd unit to %s: %w", unitPath, err)
	}

	// Reload systemd and enable + start the service
	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", serviceName},
		{"systemctl", "start", serviceName},
	}

	for _, args := range cmds {
		if err := runCmd(args[0], args[1:]...); err != nil {
			return fmt.Errorf("command %v failed: %w", args, err)
		}
	}

	fmt.Printf("[OK] Service %q installed and started via systemd.\n", serviceName)
	return nil
}

// Uninstall stops, disables, and removes the AgentIde systemd unit.
func Uninstall() error {
	cmds := [][]string{
		{"systemctl", "stop", serviceName},
		{"systemctl", "disable", serviceName},
	}
	for _, args := range cmds {
		_ = runCmd(args[0], args[1:]...) // best-effort, don't fail if already stopped
	}

	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove unit file %s: %w", unitPath, err)
	}

	_ = runCmd("systemctl", "daemon-reload")
	fmt.Printf("[OK] Service %q uninstalled.\n", serviceName)
	return nil
}
