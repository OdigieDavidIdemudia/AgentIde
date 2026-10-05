package reporter

import (
	"encoding/csv"
	"fmt"
	"os"
)

// WriteCSV generates a CSV file matching the column format of the original Excel assessment matrix.
func (r *Report) WriteCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create CSV file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header row — matches original Excel matrix columns
	_ = w.Write([]string{
		"Capability Being Tested",
		"Test Action / Scenario",
		"Expected Outcome",
		"Actual Outcome",
		"Detection Latency (ms)",
		"Result",
		"Notes",
	})

	for _, res := range r.Results {
		expected := "Blocked / Detected"
		if res.ModuleName == "performance" || res.ModuleName == "falsepositive" {
			expected = "Informational"
		}

		result := "PASS"
		if !res.Passed {
			result = "FAIL"
		}
		if len(res.Detail) >= 7 && res.Detail[:7] == "SKIPPED" {
			result = "SKIPPED"
		}

		_ = w.Write([]string{
			res.ModuleName,
			res.Action,
			expected,
			res.Detail,
			fmt.Sprintf("%d", res.ElapsedMs),
			result,
			res.Notes,
		})
	}

	// Summary row
	_ = w.Write([]string{})
	_ = w.Write([]string{
		"SUMMARY",
		fmt.Sprintf("Vendor: %s", r.VendorName),
		fmt.Sprintf("Score: %.0f%%", r.Score()),
		fmt.Sprintf("Passed: %d", r.Passed),
		fmt.Sprintf("Failed: %d", r.Failed),
		fmt.Sprintf("Skipped: %d", r.Skipped),
		fmt.Sprintf("Duration: %s", r.TotalTime.Round(1e9)),
	})

	return nil
}
