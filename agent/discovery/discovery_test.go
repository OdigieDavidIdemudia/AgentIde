package discovery

import (
	"encoding/json"
	"strings"
	"testing"
)

/**
 * On a Cortex XDR endpoint the agent reported "Microsoft Defender" and nothing
 * else. The operator therefore disabled Defender — which Cortex had already
 * displaced — while Cortex stayed fully armed and killed the assessment agent.
 *
 * Two independent faults, both covered here:
 *   1. the Cortex XDR fingerprint listed only the Traps-lineage names and
 *      missed the services Palo Alto's own documentation lists as the agent's
 *   2. Defender matched and was reported as an equal finding, so nothing
 *      indicated it was not the vendor under assessment
 */

func loadTestFingerprints(t *testing.T) []VendorFingerprint {
	t.Helper()
	var fps []VendorFingerprint
	if err := json.Unmarshal(fingerprintsData, &fps); err != nil {
		t.Fatalf("fingerprints.json does not parse: %v", err)
	}
	return fps
}

func vendorByName(t *testing.T, name string) VendorFingerprint {
	t.Helper()
	for _, fp := range loadTestFingerprints(t) {
		if fp.Vendor == name {
			return fp
		}
	}
	t.Fatalf("no fingerprint for %q", name)
	return VendorFingerprint{}
}

// The Cortex XDR agent registers these services. Taken from Palo Alto's own
// agent documentation, which lists them when describing VDI/App-Volumes
// registry exclusions.
func TestCortexFingerprintCoversDocumentedServices(t *testing.T) {
	fp := vendorByName(t, "Cortex XDR")

	// tedrdrv is the Cortex EDR driver and tlaservice the agent service; these
	// two are the most reliable indicators the agent is present.
	for _, svc := range []string{"tedrdrv", "tlaservice"} {
		found := false
		for _, s := range fp.Services {
			if strings.EqualFold(s, svc) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Cortex XDR fingerprint is missing service %q; the agent will not be detected", svc)
		}
	}
}

// Regression guard for the original defect: the Traps-lineage names alone were
// not enough, and the fingerprint must not shrink back to them.
func TestCortexFingerprintIsNotJustTrapsLineageNames(t *testing.T) {
	fp := vendorByName(t, "Cortex XDR")
	if len(fp.Services) < 6 {
		t.Errorf("Cortex XDR lists %d services; expected the full documented set", len(fp.Services))
	}
}

// Names are matched case-insensitively by Scan, but a stray capitalised entry
// suggests the data was hand-edited without checking.
func TestFingerprintNamesHaveNoStrayWhitespace(t *testing.T) {
	for _, fp := range loadTestFingerprints(t) {
		for _, s := range append(append([]string{}, fp.Services...), fp.Processes...) {
			if s != strings.TrimSpace(s) {
				t.Errorf("%s: name %q has surrounding whitespace", fp.Vendor, s)
			}
		}
	}
}

func TestThirdPartyEDROutranksBuiltInDefender(t *testing.T) {
	found := []DiscoveredAgent{
		{Vendor: "Microsoft Defender", ProcessName: "MsMpEng.exe"},
		{Vendor: "Cortex XDR", ProcessName: "cyserver.exe"},
	}

	prioritiseThirdPartyEDR(found)

	if found[0].Vendor != "Cortex XDR" {
		t.Errorf("first vendor = %q, want Cortex XDR", found[0].Vendor)
	}
	if found[1].Vendor != "Microsoft Defender" {
		t.Errorf("second vendor = %q, want Microsoft Defender retained", found[1].Vendor)
	}
}

// Defender alone must keep its position — there is no conflict to resolve.
func TestDefenderAloneIsNotReordered(t *testing.T) {
	found := []DiscoveredAgent{{Vendor: "Microsoft Defender"}}
	prioritiseThirdPartyEDR(found)
	if found[0].Vendor != "Microsoft Defender" {
		t.Errorf("vendor = %q, want Microsoft Defender", found[0].Vendor)
	}
}

// Reordering when the picture is ambiguous would be guessing. With two
// third-party agents there is no single "the vendor under assessment".
func TestAmbiguousSetIsLeftInDetectionOrder(t *testing.T) {
	found := []DiscoveredAgent{
		{Vendor: "CrowdStrike Falcon"},
		{Vendor: "Microsoft Defender"},
		{Vendor: "SentinelOne"},
	}
	before := []string{found[0].Vendor, found[1].Vendor, found[2].Vendor}

	prioritiseThirdPartyEDR(found)

	for i := range before {
		if found[i].Vendor != before[i] {
			t.Errorf("ambiguous set was reordered: %v -> %v", before, found)
			break
		}
	}
}

// Every vendor must remain discoverable; a bad edit to one entry must not drop
// another.
func TestAllVendorsHaveFingerprints(t *testing.T) {
	fps := loadTestFingerprints(t)
	if len(fps) < 10 {
		t.Fatalf("only %d vendors fingerprinted; the database appears truncated", len(fps))
	}

	seen := map[string]bool{}
	for _, fp := range fps {
		if fp.Vendor == "" {
			t.Error("a fingerprint has an empty vendor name")
			continue
		}
		if seen[fp.Vendor] {
			t.Errorf("duplicate fingerprint for %q", fp.Vendor)
		}
		seen[fp.Vendor] = true

		if len(fp.Processes) == 0 && len(fp.Services) == 0 {
			t.Errorf("%s has neither processes nor services; it can never match", fp.Vendor)
		}
	}
}
