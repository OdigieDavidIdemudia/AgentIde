package discovery

import "testing"

// Simulates the exact endpoint that broke: Cortex XDR installed, Defender's
// engine still resident. This is what the agent actually enumerated on the VM
// where "Microsoft Defender" was reported and Cortex killed the run.
//
// listProcesses/listServices are package-level function variables precisely so
// this can be driven without a real Windows host.

func TestScanReportsCortexAndDefenderOnACortexEndpoint(t *testing.T) {
	origProc, origSvc := listProcesses, listServices
	defer func() {
		listProcesses = origProc
		listServices = origSvc
	}()

	listProcesses = func() (map[string]processEntry, error) {
		return map[string]processEntry{
			// Cortex agent user-mode process.
			"cyserver.exe": {Name: "cyserver.exe", PID: 900},
			// Defender's engine stays resident under Cortex's prevention policy,
			// which is what made the misidentification happen.
			"msmpeng.exe": {Name: "MsMpEng.exe", PID: 412},
		}, nil
	}
	listServices = func() (map[string]string, error) {
		return map[string]string{
			// The services Palo Alto documents for the Cortex agent. Under the
			// old fingerprint only "cyveraservice" was present and the others
			// were ignored.
			"tlaservice":  "CortexAgent",
			"tedrdrv":     "tedrdrv",
			"win defend":  "WinDefend",
		}, nil
	}

	found, err := Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("nothing discovered on an endpoint with Cortex installed")
	}

	vendors := make([]string, 0, len(found))
	for _, f := range found {
		vendors = append(vendors, f.Vendor)
	}

	// The regression: Cortex must be reported at all.
	var cortexFound bool
	for _, v := range vendors {
		if v == "Cortex XDR" {
			cortexFound = true
		}
	}
	if !cortexFound {
		t.Fatalf("Cortex XDR not discovered; vendors=%v", vendors)
	}

	// And it must lead, because it is the vendor actually enforcing policy.
	if vendors[0] != "Cortex XDR" {
		t.Errorf("first vendor = %q, want Cortex XDR (vendors=%v)", vendors[0], vendors)
	}
}