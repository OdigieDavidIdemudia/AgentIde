//go:build linux

package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// enumerateProcesses reads /proc to enumerate all running processes.
// Returns a map of process name (lowercase) -> processEntry.
func enumerateProcesses() (map[string]processEntry, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("cannot read /proc: %w", err)
	}

	result := make(map[string]processEntry)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // Not a PID directory
		}

		commPath := filepath.Join("/proc", e.Name(), "comm")
		commData, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		name := strings.TrimSpace(string(commData))
		result[strings.ToLower(name)] = processEntry{Name: name, PID: pid}
	}

	return result, nil
}

// enumerateServices queries systemd via the systemctl command to list all active units.
// Returns a map of service unit name (lowercase, without .service) -> display name.
func enumerateServices() (map[string]string, error) {
	data, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(data)) != "systemd" {
		return listServicesFromProc()
	}
	return listServicesSystemd()
}

// listServicesSystemd reads systemd service state from /run/systemd/units/
func listServicesSystemd() (map[string]string, error) {
	result := make(map[string]string)

	entries, err := os.ReadDir("/run/systemd/units")
	if err != nil {
		return result, nil // Non-fatal
	}

	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".service") {
			key := strings.TrimSuffix(name, ".service")
			result[strings.ToLower(key)] = name
		}
	}
	return result, nil
}

// listServicesFromProc is a fallback that reads /proc to find services by process name.
func listServicesFromProc() (map[string]string, error) {
	// Minimal fallback: just return an empty map — process matching will handle most cases
	return make(map[string]string), nil
}
