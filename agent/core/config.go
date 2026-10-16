package core

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds all runtime configuration for AgentIde.
type Config struct {
	DashboardURL string `json:"dashboard_url"`
	AgentToken   string `json:"agent_token"`
	CertPin      string `json:"cert_pin"`
	LogPath      string `json:"log_path"`
	AllowReboot  bool   `json:"allow_reboot"`
	// Group is the fleet segment this endpoint declares at enrollment. It
	// follows the Wazuh model, where the agent states its group when it
	// registers and the manager uses it to scope configuration — allowing one
	// dashboard to apply different module policy per segment without
	// reconfiguring endpoints individually.
	Group string `json:"group,omitempty"`
}

// DefaultConfig returns a safe set of defaults used when no config.json is present.
func DefaultConfig() *Config {
	return &Config{
		DashboardURL: "",
		AgentToken:   "",
		CertPin:      "",
		LogPath:      "agentide.log",
		AllowReboot:  false,
	}
}

// LoadConfig reads and parses a JSON config file from the given path.
// Returns DefaultConfig if the file does not exist, and an error for malformed JSON.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // config.json is optional
		}
		return cfg, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// SaveConfig writes the config to the given path as JSON, creating parent dirs as needed.
func SaveConfig(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
