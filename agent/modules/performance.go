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

func (m *performanceModule) Run() RawResult {
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1082",
		Action:     "Collect CPU and RAM usage over 60 seconds (10s intervals)",
	}

	m.logger.Info("Performance: sampling started", map[string]interface{}{"samples": 6, "interval_s": 10})
	start := time.Now()

	for i := 0; i < 6; i++ {
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
		if i < 5 {
			time.Sleep(10 * time.Second)
		}
	}

	avgCPU, peakRAM := summarise(m.samples)
	result.ElapsedMs = time.Since(start).Milliseconds()
	result.Notes = fmt.Sprintf("Avg CPU: %.1f%% | Peak RAM: %.0f MB | GOOS: %s", avgCPU, peakRAM, runtime.GOOS)
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
