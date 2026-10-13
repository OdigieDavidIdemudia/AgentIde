package modules

import (
	"fmt"
	"runtime"
	"time"

	"agentide/core"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
)

type performanceModule struct {
	logger  *core.Logger
	samples []perfSample
}

type perfSample struct {
	Timestamp  time.Time
	CPUPercent float64
	MemUsedMB  float64
	MemPercent float64
}

func (m *performanceModule) Name() string { return "performance" }

// Sampling budget, in one place so the module and the runner's per-module
// timeout cannot drift apart. Previously the module slept 5x10s plus a 1s
// cpu.Percent call per sample (~56s) while the runner killed any module at
// 35s, so performance could never complete - it always reported TIMEOUT and
// never contributed a measurement.
//
// 4 samples at 5s with a 1s cpu.Percent call is ~24s of work, which fits
// inside the 45s budget with headroom.
const (
	perfSamples      = 4
	perfIntervalSec  = 5
	perfSampleBudget = 45 * time.Second
)

func (m *performanceModule) Run() RawResult {
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1082",
		Action: fmt.Sprintf("Collect CPU and RAM usage over ~%ds (%d samples)",
			perfSamples*perfIntervalSec, perfSamples),
	}

	m.logger.Info("Performance: sampling started", map[string]interface{}{
		"samples": perfSamples, "interval_s": perfIntervalSec,
	})
	start := time.Now()

	// Reset the sample buffer so a second run in the same process measures only
	// this run. Without this, summarise() averaged the accumulated history and
	// a re-run inherited the previous assessment's numbers.
	m.samples = nil

	deadline := start.Add(perfSampleBudget)
	for i := 0; i < perfSamples; i++ {
		// Stop early rather than overrun and get killed by the runner: a partial
		// series is still a usable measurement, whereas TIMEOUT is a total loss.
		if i > 0 && time.Now().After(deadline) {
			m.logger.Warn("Performance sampling hit its budget early", map[string]interface{}{
				"collected": len(m.samples), "of": perfSamples,
			})
			break
		}
		sample, err := collectSample()
		if err != nil {
			m.logger.Warn("Performance sample failed", map[string]interface{}{"error": err.Error()})
		} else {
			m.samples = append(m.samples, sample)
			m.logger.Debug("Performance sample", map[string]interface{}{
				"cpu_pct": sample.CPUPercent,
				"mem_mb":  sample.MemUsedMB,
				"mem_pct": sample.MemPercent,
			})
		}
		if i < perfSamples-1 {
			time.Sleep(perfIntervalSec * time.Second)
		}
	}

	avgCPU, peakRAM := summarise(m.samples)
	result.ElapsedMs = time.Since(start).Milliseconds()
	// Be explicit that these are whole-system figures sampled while the vendor
	// agent is running, not per-process CPU attributed to the vendor. Treating
	// system-wide CPU as "EDR overhead" is a measurement error that inflates
	// the vendor's apparent resource cost.
	result.Notes = fmt.Sprintf(
		"Whole-system CPU avg %.1f%% / peak RAM %.0f MB over %d samples (GOOS: %s). "+
			"These are host-wide totals, NOT attributed to the vendor process — "+
			"use baseline comparison to judge impact",
		avgCPU, peakRAM, len(m.samples), runtime.GOOS)
	m.logger.Info("Performance: sampling complete", map[string]interface{}{
		"avg_cpu_pct": avgCPU,
		"peak_ram_mb": peakRAM,
	})
	return result
}

func collectSample() (perfSample, error) {
	cpuPcts, err := cpu.Percent(time.Second, false)
	if err != nil {
		return perfSample{}, err
	}
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return perfSample{}, err
	}
	cpuPct := 0.0
	if len(cpuPcts) > 0 {
		cpuPct = cpuPcts[0]
	}
	return perfSample{
		Timestamp:  time.Now(),
		CPUPercent: cpuPct,
		MemUsedMB:  float64(vmStat.Used) / 1024 / 1024,
		MemPercent: vmStat.UsedPercent,
	}, nil
}

func summarise(samples []perfSample) (avgCPU, peakRAM float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	total := 0.0
	for _, s := range samples {
		total += s.CPUPercent
		if s.MemUsedMB > peakRAM {
			peakRAM = s.MemUsedMB
		}
	}
	avgCPU = total / float64(len(samples))
	return avgCPU, peakRAM
}
