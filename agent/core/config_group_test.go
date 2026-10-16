package core

import (
	"os"
	"path/filepath"
	"testing"
)

// Agents declare their fleet group at enrollment, following the Wazuh model
// where the agent states its group when it registers and the manager uses it to
// scope configuration. Without this every endpoint is an unlabelled singleton
// and module policy cannot be scoped by segment.

func TestGroupRoundTripsThroughConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	cfg.Group = "pilot-fleet"
	if err := SaveConfig(path, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.Group != "pilot-fleet" {
		t.Errorf("group = %q, want pilot-fleet", loaded.Group)
	}
}

func TestGroupIsOptional(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// A config written before the field existed must still load, with an
	// empty group rather than an error.
	legacy := `{"dashboard_url":"wss://x:8443","agent_token":"t"}`
	if err := os.WriteFile(path, []byte(legacy), 0644); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("legacy config should still load: %v", err)
	}
	if cfg.Group != "" {
		t.Errorf("group = %q, want empty for a legacy config", cfg.Group)
	}
}

func TestDefaultConfigHasNoGroup(t *testing.T) {
	if g := DefaultConfig().Group; g != "" {
		t.Errorf("default group = %q, want empty so the caller normalises it", g)
	}
}
