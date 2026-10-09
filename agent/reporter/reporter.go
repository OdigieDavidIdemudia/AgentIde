package reporter

import "time"

// TestResult is a verified, final result for a single test module.
type TestResult struct {
	ModuleName string
	Action     string
	Passed     bool
	Detail     string
	ElapsedMs  int64
	Notes      string
	// Artifacts lists the files created/touched by this module.
	Artifacts []string
}

// Report aggregates all test results for final output generation.
type Report struct {
	VendorName  string
	Results     []TestResult
	TotalTime   time.Duration
	GeneratedAt time.Time
	Passed      int
	Failed      int
	Skipped     int
}

// New creates a Report from a slice of TestResults.
func New(vendor string, results []TestResult, elapsed time.Duration) *Report {
	r := &Report{
		VendorName:  vendor,
		Results:     results,
		TotalTime:   elapsed,
		GeneratedAt: time.Now().UTC(),
	}
	for _, res := range results {
		if res.Detail == "SKIPPED" || (len(res.Detail) > 7 && res.Detail[:7] == "SKIPPED") {
			r.Skipped++
		} else if res.Passed {
			r.Passed++
		} else {
			r.Failed++
		}
	}
	return r
}

// Score returns the detection score as a percentage of passed tests.
func (r *Report) Score() float64 {
	total := r.Passed + r.Failed
	if total == 0 {
		return 0
	}
	return float64(r.Passed) / float64(total) * 100
}
