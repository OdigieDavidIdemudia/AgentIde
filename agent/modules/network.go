package modules

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"agentide/core"
)

type networkModule struct{ logger *core.Logger }

func (m *networkModule) Name() string { return "network" }

func (m *networkModule) Run() RawResult {
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1071.001",
		Action:     "DNS test domain lookup + HTTP beaconing simulation",
	}

	start := time.Now()
	notes := []string{}

	// ── 1. DNS lookup to known test domain ──────────────────────────────────
	m.logger.Info("Network: DNS lookup", map[string]interface{}{"domain": "www.eicar.org"})
	_, dnsErr := net.LookupHost("www.eicar.org")
	if dnsErr != nil {
		result.OSFeedback.NetworkBlocked = true
		notes = append(notes, fmt.Sprintf("DNS blocked: %v", dnsErr))
		m.logger.Info("DNS lookup blocked", map[string]interface{}{"error": dnsErr.Error()})
	} else {
		notes = append(notes, "DNS lookup allowed")
		m.logger.Info("DNS lookup allowed", nil)
	}

	// ── 2. HTTP beaconing (3 calls, 10s apart — simulates C2 heartbeat) ─────
	beaconURL := "http://www.eicar.org/download/eicar.com.txt"
	beaconBlocked := false
	m.logger.Info("Network: HTTP beaconing started", map[string]interface{}{"url": beaconURL, "attempts": 3})

	client := &http.Client{Timeout: 5 * time.Second}
	for i := 1; i <= 3; i++ {
		_, err := client.Get(beaconURL)
		if err != nil {
			beaconBlocked = true
			notes = append(notes, fmt.Sprintf("Beacon %d/%d blocked: %v", i, 3, err))
			m.logger.Info("Beacon blocked", map[string]interface{}{"attempt": i, "error": err.Error()})
		} else {
			notes = append(notes, fmt.Sprintf("Beacon %d/%d allowed", i, 3))
			m.logger.Info("Beacon allowed", map[string]interface{}{"attempt": i})
		}
		if i < 3 {
			time.Sleep(10 * time.Second)
		}
	}

	if beaconBlocked {
		result.OSFeedback.NetworkBlocked = true
	}

	result.ElapsedMs = time.Since(start).Milliseconds()
	result.Notes = joinNotes(notes)
	return result
}

func joinNotes(notes []string) string {
	out := ""
	for i, n := range notes {
		if i > 0 {
			out += "; "
		}
		out += n
	}
	return out
}
