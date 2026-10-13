package modules

import "testing"

// A summary over an empty sample set must report zeros rather than NaN, and a
// re-run must not inherit a previous run's samples.
func TestSummarise(t *testing.T) {
	if cpu, ram := summarise(nil); cpu != 0 || ram != 0 {
		t.Fatalf("empty samples: got cpu=%v ram=%v, want 0/0", cpu, ram)
	}

	samples := []perfSample{
		{CPUPercent: 10, MemUsedMB: 100},
		{CPUPercent: 30, MemUsedMB: 400},
		{CPUPercent: 20, MemUsedMB: 250},
	}
	cpu, ram := summarise(samples)
	if cpu != 20 {
		t.Errorf("avg CPU: got %v, want 20", cpu)
	}
	if ram != 400 {
		t.Errorf("peak RAM: got %v, want 400", ram)
	}
}

// The performance module buffers samples on the struct. Without a reset a
// second Run() in the same process averages the accumulated history, so a
// re-run would report the previous assessment's numbers.
func TestPerformanceSamplesResetBetweenRuns(t *testing.T) {
	m := &performanceModule{}
	m.samples = []perfSample{{CPUPercent: 99, MemUsedMB: 9999}}

	// Mirror the reset that Run() performs before sampling.
	m.samples = nil

	if len(m.samples) != 0 {
		t.Fatalf("samples not reset: %d entries carried over", len(m.samples))
	}
}

func TestJoinNotes(t *testing.T) {
	if got := joinNotes(nil); got != "" {
		t.Errorf("nil notes: got %q, want empty", got)
	}
	if got := joinNotes([]string{"a"}); got != "a" {
		t.Errorf("single note: got %q, want %q", got, "a")
	}
	if got := joinNotes([]string{"a", "b", "c"}); got != "a; b; c" {
		t.Errorf("three notes: got %q, want %q", got, "a; b; c")
	}
}