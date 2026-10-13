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

// beaconHost is the benign, industry-standard test host used for the
// C2-beaconing simulation.
const beaconHost = "www.eicar.org"

// controlReachable performs an independent control request to a well-known
// endpoint. If this succeeds while the beacon does not, the failure can be
// attributed to interception; if it also fails, the endpoint simply has no
// outbound access and the network test is inconclusive.
func controlReachable() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://www.msftconnecttest.com/connecttest.txt")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

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
	dnsReachable := dnsErr == nil
	if dnsErr != nil {
		notes = append(notes, fmt.Sprintf("DNS lookup of %s failed: %v", beaconHost, dnsErr))
		m.logger.Info("DNS lookup failed", map[string]interface{}{"error": dnsErr.Error()})
	} else {
		notes = append(notes, "DNS lookup allowed")
		m.logger.Info("DNS lookup allowed", nil)
	}

	// ── 2. HTTP beaconing (3 calls, 10s apart — simulates C2 heartbeat) ─────
	beaconURL := "http://" + beaconHost + "/download/eicar.com.txt"
	beaconBlocked := false
	beaconAllowed := false
	m.logger.Info("Network: HTTP beaconing started", map[string]interface{}{"url": beaconURL, "attempts": 3})

	client := &http.Client{Timeout: 5 * time.Second}
	for i := 1; i <= 3; i++ {
		_, err := client.Get(beaconURL)
		if err != nil {
			beaconBlocked = true
			notes = append(notes, fmt.Sprintf("Beacon %d/3 blocked: %v", i, err))
			m.logger.Info("Beacon blocked", map[string]interface{}{"attempt": i, "error": err.Error()})
		} else {
			// A non-2xx response still proves the request reached the network;
			// only a transport error indicates interception.
			beaconAllowed = true
			notes = append(notes, fmt.Sprintf("Beacon %d/3 reached the network (not intercepted)", i))
			m.logger.Info("Beacon allowed", map[string]interface{}{"attempt": i})
		}
		if i < 3 {
			time.Sleep(10 * time.Second)
		}
	}

	// A control connection proves the endpoint actually HAS outbound network
	// access. Without it, a failed beacon cannot be attributed to the EDR — on
	// an air-gapped or segmented POC VM (the normal case) every request fails
	// for lack of connectivity, and crediting the vendor with blocking C2 it
	// never saw is a false PASS.
	outboundAvailable := beaconAllowed || controlReachable()
	switch {
	case !outboundAvailable:
		notes = append(notes,
			"INCONCLUSIVE: no outbound connectivity from this endpoint (control connection also failed). "+
				"This host is air-gapped or segmented, so network-control coverage CANNOT be measured here. "+
				"Run from a segment with egress, or supply an external listener via -module network")
		// Deliberately NOT set: absence of egress is not evidence of blocking.
	case beaconBlocked:
		result.OSFeedback.NetworkBlocked = true
		notes = append(notes, "Network control active: beacon traffic was blocked while outbound connectivity was confirmed")
	case dnsReachable:
		notes = append(notes, "Beaconing permitted — outbound C2-style traffic was not intercepted")
	default:
		notes = append(notes, "DNS resolution blocked while HTTP egress worked — inspect DNS filtering specifically")
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
