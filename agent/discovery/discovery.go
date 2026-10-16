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

// listProcesses and listServices are variables rather than functions so the
// matching logic in Scan can be exercised against a simulated endpoint.
//
// The original defect — reporting Defender on a Cortex host — could not be
// regression-tested at all, because Scan could only run against a live machine.
// That is how a two-line fingerprint error survived.
var (
	listProcesses = enumerateProcesses
	listServices  = enumerateServices
)

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

	// Defender's engine (MsMpEng) stays resident on many endpoints that a
	// third-party EDR has taken over from, so a Defender match alongside a
	// third-party agent is a conflict, not a co-equal finding. Reporting both
	// as equals let an operator disable Defender while the real vendor — the
	// one actually enforcing policy — was never stood down. That is exactly
	// what happened on a Cortex XDR endpoint.
	//
	// When a third-party EDR is present, the vendor under assessment is that
	// EDR. Defender is retained but explicitly marked so the dashboard and the
	// pre-scan list can say which is which.
	if len(discovered) > 1 {
		prioritiseThirdPartyEDR(discovered)
	}

	return discovered, nil
}

// knownBuiltInVendors are agents that ship with Windows rather than being the
// product under assessment when a third-party EDR is also installed.
var knownBuiltInVendors = map[string]bool{
	"Microsoft Defender": true,
}

// thirdPartyPriority orders the vendors the dashboard offers for disabling.
// A third-party EDR outranks the built-in one so the confirmation dialog
// presents the vendor that is actually enforcing policy first.
func prioritiseThirdPartyEDR(found []DiscoveredAgent) {
	hasThirdParty := false
	for _, a := range found {
		if !knownBuiltInVendors[a.Vendor] {
			hasThirdParty = true
			break
		}
	}
	if !hasThirdParty {
		return
	}

	third, builtin := 0, 0
	for _, a := range found {
		if knownBuiltInVendors[a.Vendor] {
			builtin++
		} else {
			third++
		}
	}
	// Only reorder when there is exactly one third-party agent and one
	// built-in. With several of either, the picture is ambiguous and guessing
	// an order would be worse than leaving the detection order intact.
	if third != 1 || builtin != 1 {
		return
	}

	ti, bi := -1, -1
	for i, a := range found {
		if knownBuiltInVendors[a.Vendor] {
			bi = i
		} else {
			ti = i
		}
	}
	found[0], found[1] = found[ti], found[bi]
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
