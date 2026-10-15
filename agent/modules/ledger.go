package modules

import "agentide/core"

// changeLedger tracks every reversible change made during an assessment
// so they can be rolled back by the cleanup module.
type changeLedger struct {
	entries []ledgerEntry
}

type ledgerEntry struct {
	Kind    string // "file", "registry", "regvalue", "user", "startup"
	Path    string // The path, key, or name of the changed item
	Payload []byte // The original content (for restoration), if applicable
	// Registry-value bookkeeping. The tamper modules rewrite individual values
	// inside pre-existing keys, so restoring the key itself is not enough —
	// the original value (or the fact that it did not exist) must be put back.
	RegValueName string
	RegType      uint32
	// HadValue records whether the value existed before the module touched it.
	// A value the module created must be deleted on rollback; one that already
	// existed must be restored to RegValue instead.
	HadValue bool
	RegValue uint64
}

// globalLedger is the singleton change tracker used by all modules.
var globalLedger = &changeLedger{}

// Record adds a change to the ledger.
func (l *changeLedger) Record(kind, path string, original []byte) {
	l.entries = append(l.entries, ledgerEntry{Kind: kind, Path: path, Payload: original})
}

// RecordRegValue records the prior state of a registry DWORD so it can be
// restored. hadValue distinguishes "was set to N" from "did not exist".
func (l *changeLedger) RecordRegValue(path, valueName string, hadValue bool, value uint64, regType uint32) {
	l.entries = append(l.entries, ledgerEntry{
		Kind:         "regdword",
		Path:         path,
		RegValueName: valueName,
		HadValue:     hadValue,
		RegValue:     value,
		RegType:      regType,
	})
}

// RecordRegString records the prior state of a registry string value.
func (l *changeLedger) RecordRegString(path, valueName string, hadValue bool, value string) {
	l.entries = append(l.entries, ledgerEntry{
		Kind:         "regstring",
		Path:         path,
		RegValueName: valueName,
		HadValue:     hadValue,
		Payload:      []byte(value),
	})
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
