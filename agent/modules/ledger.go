package modules

import "agentide/core"

// changeLedger tracks every reversible change made during an assessment
// so they can be rolled back by the cleanup module.
type changeLedger struct {
	entries []ledgerEntry
}

type ledgerEntry struct {
	Kind    string // "file", "registry", "user", "startup"
	Path    string // The path, key, or name of the changed item
	Payload []byte // The original content (for restoration), if applicable
}

// globalLedger is the singleton change tracker used by all modules.
var globalLedger = &changeLedger{}

// Record adds a change to the ledger.
func (l *changeLedger) Record(kind, path string, original []byte) {
	l.entries = append(l.entries, ledgerEntry{Kind: kind, Path: path, Payload: original})
}

// RollbackAll reverses all recorded changes in LIFO order.
func (l *changeLedger) RollbackAll(logger *core.Logger) {
	for i := len(l.entries) - 1; i >= 0; i-- {
		entry := l.entries[i]
		if err := rollback(entry, logger); err != nil {
			logger.Warn("Rollback failed for entry", map[string]interface{}{
				"kind":  entry.Kind,
				"path":  entry.Path,
				"error": err.Error(),
			})
		} else {
			logger.Info("Rolled back", map[string]interface{}{"kind": entry.Kind, "path": entry.Path})
		}
	}
	l.entries = nil
}
