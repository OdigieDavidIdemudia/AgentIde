package modules

import (
	"agentide/core"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type falsePositiveModule struct{ logger *core.Logger }

func (m *falsePositiveModule) Name() string { return "falsepositive" }

func (m *falsePositiveModule) Run() RawResult {
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1562",
		Action:     "Simulate legitimate developer activity to measure false-positive rate",
	}

	start := time.Now()
	notes := []string{}

	// ── 1. Create and compress a large folder of dummy log files ──────────
	m.logger.Info("FalsePositive: creating dummy log archive", nil)
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("agentide_fp_%d", time.Now().UnixNano()))
	_ = os.MkdirAll(tmpDir, 0755)
	globalLedger.Record("file", tmpDir, nil)

	// Write 50 dummy log files
	for i := 0; i < 50; i++ {
		data := []byte(fmt.Sprintf("AgentIde FP test log entry #%d — %s\n", i, time.Now().String()))
		_ = os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("log_%03d.txt", i)), data, 0644)
	}
	notes = append(notes, "Created 50 dummy log files")

	// Compress the directory
	zipPath := tmpDir + ".zip"
	if err := zipDirectory(tmpDir, zipPath); err != nil {
		notes = append(notes, fmt.Sprintf("Compression failed: %v", err))
	} else {
		notes = append(notes, "Directory compressed to zip")
		globalLedger.Record("file", zipPath, nil)
	}

	// ── 2. Local port scan (scan own localhost ports) ─────────────────────
	m.logger.Info("FalsePositive: localhost port scan", nil)
	openPorts := scanLocalhost([]int{22, 80, 135, 443, 445, 3389, 8080})
	notes = append(notes, fmt.Sprintf("Localhost scan: found %d open ports", len(openPorts)))

	result.ElapsedMs = time.Since(start).Milliseconds()
	result.Notes = joinNotes(notes)
	m.logger.Info("FalsePositive: complete", map[string]interface{}{"notes": result.Notes})
	return result
}
