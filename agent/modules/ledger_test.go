package modules

import "testing"

// The tamper modules permanently disabled AMSI, ETW autologgers and Defender
// policies on the endpoint, and nothing put them back: the change ledger only
// ever recorded files. These tests pin the registry bookkeeping so a completed
// assessment cannot again leave the host weakened.
//
// A registry change is only reversible if the module records the value's state
// *before* overwriting it, and only correct if it distinguishes "was set to N"
// from "did not exist" — a value the assessment created must be deleted on
// rollback, one that already existed must be restored.

func TestRecordRegValueDistinguishesExistingFromAbsent(t *testing.T) {
	l := &changeLedger{}

	l.RecordRegValue(`HKLM\Software\Test`, "AMSIEnabled", true, 1, 4)
	l.RecordRegValue(`HKLM\Software\Test`, "CreatedByUs", false, 0, 4)

	if len(l.entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(l.entries))
	}

	existing := l.entries[0]
	if existing.Kind != "regdword" {
		t.Errorf("kind: got %q, want regdword", existing.Kind)
	}
	if !existing.HadValue {
		t.Error("existing value recorded as absent — rollback would delete it instead of restoring it")
	}
	if existing.RegValue != 1 {
		t.Errorf("original value: got %d, want 1", existing.RegValue)
	}

	created := l.entries[1]
	if created.HadValue {
		t.Error("absent value recorded as present — rollback would write a 0 that never existed")
	}
}

func TestRecordRegStringCapturesOriginalContent(t *testing.T) {
	l := &changeLedger{}
	l.RecordRegString(`HKLM\System\ETW`, "LogFilePath", true, `%SystemRoot%\System32\WMI\AutoLogger\Rt.etl`)

	if len(l.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(l.entries))
	}
	e := l.entries[0]
	if e.Kind != "regstring" {
		t.Errorf("kind: got %q, want regstring", e.Kind)
	}
	if string(e.Payload) != `%SystemRoot%\System32\WMI\AutoLogger\Rt.etl` {
		t.Errorf("payload: got %q, want the original LogFilePath", e.Payload)
	}
}

// Every entry the tamper modules can produce must map to a rollback kind the
// Windows rollback switch understands. A kind that falls through to
// "unknown ledger kind" is silently skipped at cleanup time — the endpoint
// stays broken and nothing reports it.
func TestTamperModulesOnlyProduceRollbackableKinds(t *testing.T) {
	known := map[string]bool{
		"file":      true,
		"startup":   true,
		"regdword":  true,
		"regstring": true,
	}

	l := &changeLedger{}
	// Exactly the kinds the five tamper modules record.
	l.RecordRegValue(`HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger`, "Start", true, 1, 4)
	l.RecordRegValue(`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiSpyware", false, 0, 4)
	l.RecordRegString(`HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger`, "LogFilePath", true, "x")
	l.Record("file", `C:\Windows\Temp\dropper.exe`, nil)
	l.Record("startup", "agentide_bootgap_test", nil)

	for i, e := range l.entries {
		if !known[e.Kind] {
			t.Errorf("entry %d has kind %q, which rollback cannot reverse", i, e.Kind)
		}
	}
}
