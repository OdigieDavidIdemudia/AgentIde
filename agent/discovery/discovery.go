package discovery

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed fingerprints.json
var fingerprintsData []byte

// VendorFingerprint maps a vendor name to its known process and service names.
type VendorFingerprint struct {
	Vendor    string   `json:"vendor"`
	Processes []string `json:"processes"`
	Services  []string `json:"services"`
}

// DiscoveredAgent represents a security agent found running on the system.
type DiscoveredAgent struct {
	Vendor      string
	PID         int
	ServiceName string
	ProcessName string
}

// Scan enumerates running processes and services, matching them against the
// embedded fingerprints.json database. Returns all discovered security agents.
func Scan() ([]DiscoveredAgent, error) {
	fingerprints, err := loadFingerprints()
	if err != nil {
		return nil, fmt.Errorf("cannot load vendor fingerprints: %w", err)
	}

	runningProcesses, err := listProcesses()
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate processes: %w", err)
	}

	runningServices, err := listServices()
	if err != nil {
		// Non-fatal: process matching alone is sufficient
		runningServices = map[string]string{}
	}

	var discovered []DiscoveredAgent
	seen := map[string]bool{}

	for _, fp := range fingerprints {
		var matched *DiscoveredAgent

		// Match by process name
		for _, proc := range fp.Processes {
			if entry, ok := runningProcesses[strings.ToLower(proc)]; ok {
				matched = &DiscoveredAgent{
					Vendor:      fp.Vendor,
					PID:         entry.PID,
					ProcessName: proc,
				}
				break
			}
		}

		// Match by service name (enriches or creates a match)
		for _, svc := range fp.Services {
			if displayName, ok := runningServices[strings.ToLower(svc)]; ok {
				if matched != nil {
					matched.ServiceName = displayName
				} else {
					matched = &DiscoveredAgent{
						Vendor:      fp.Vendor,
						ServiceName: displayName,
					}
				}
				break
			}
		}

		if matched != nil && !seen[fp.Vendor] {
			discovered = append(discovered, *matched)
			seen[fp.Vendor] = true
		}
	}

	return discovered, nil
}

// loadFingerprints parses the embedded fingerprints.json file.
func loadFingerprints() ([]VendorFingerprint, error) {
	var fps []VendorFingerprint
	if err := json.Unmarshal(fingerprintsData, &fps); err != nil {
		return nil, err
	}
	return fps, nil
}

// processEntry holds a running process's name and PID.
type processEntry struct {
	Name string
	PID  int
}
