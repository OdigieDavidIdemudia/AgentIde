package modes

import (
	"testing"

	"agentide/modules"
)

// The dashboard's module selection was collected, persisted, and then never
// sent to the agent: the runner was hardcoded to "all", so the report claimed
// modules ran that never did. filterModules is where that selection now
// resolves, so it is worth pinning.

type fakeModule struct{ name string }

func (f fakeModule) Name() string { return f.name }
func (f fakeModule) Run() modules.RawResult {
	return modules.RawResult{ModuleName: f.name}
}

func all() []modules.Module {
	return []modules.Module{
		fakeModule{"malware"},
		fakeModule{"identity"},
		fakeModule{"network"},
		fakeModule{"reboot"},
	}
}

func names(got []modules.Module) []string {
	out := make([]string, 0, len(got))
	for _, m := range got {
		out = append(out, m.Name())
	}
	return out
}

func TestFilterModulesAll(t *testing.T) {
	for _, sel := range []string{"all", "", "  "} {
		if got := len(filterModules(all(), sel)); got != 4 {
			t.Errorf("selector %q: got %d modules, want 4", sel, got)
		}
	}
}

func TestFilterModulesSingleName(t *testing.T) {
	got := names(filterModules(all(), "identity"))
	if len(got) != 1 || got[0] != "identity" {
		t.Errorf("single: got %v, want [identity]", got)
	}
}

// The case that was broken: a comma-separated selection from the dashboard.
func TestFilterModulesCommaSeparatedSelection(t *testing.T) {
	got := names(filterModules(all(), "malware,network"))
	if len(got) != 2 {
		t.Fatalf("comma selection: got %v, want 2 modules", got)
	}
	if got[0] != "malware" || got[1] != "network" {
		t.Errorf("comma selection: got %v, want [malware network]", got)
	}
}

func TestFilterModulesIgnoresWhitespaceAndCase(t *testing.T) {
	got := names(filterModules(all(), " malware , IDENTITY ,"))
	if len(got) != 2 {
		t.Errorf("whitespace/case: got %v, want 2 modules", got)
	}
}

func TestFilterModulesUnknownNameYieldsNothing(t *testing.T) {
	if got := filterModules(all(), "does-not-exist"); len(got) != 0 {
		t.Errorf("unknown: got %v, want empty", names(got))
	}
}

// A selection mixing real and unknown names must still run the real ones
// rather than collapsing the whole run.
func TestFilterModulesPartialMatch(t *testing.T) {
	got := names(filterModules(all(), "malware,does-not-exist"))
	if len(got) != 1 || got[0] != "malware" {
		t.Errorf("partial: got %v, want [malware]", got)
	}
}

// Trailing/leading separators must not produce empty selections that would
// silently run nothing.
func TestFilterModulesEmptySegmentsIgnored(t *testing.T) {
	got := names(filterModules(all(), ",malware,,"))
	if len(got) != 1 || got[0] != "malware" {
		t.Errorf("empty segments: got %v, want [malware]", got)
	}
}