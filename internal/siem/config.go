// Package siem is the single point of egress for structured events (VPN
// sessions, container logs, audit trail) heading to an external SIEM.
// Event sources call Default().Emit(source, payload) and don't need to know
// whether a SIEM is configured, reachable, or how events are batched.
package siem

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config describes where fluent-bit should forward events. Persisted at
// ~/.config/bitswan/siem.json.
type Config struct {
	URL        string `json:"url"`         // destination HTTP endpoint, e.g. https://siem.example/ingest
	AuthHeader string `json:"auth_header"` // raw header line or value; see splitAuthHeader
	Enabled    bool   `json:"enabled"`
}

// Defaults fills in zero-valued fields. Currently a no-op — kept so callers
// can add future fields without churn.
func (c *Config) Defaults() {}

// Redacted returns a copy of the config with the auth header masked. Used
// when returning config over the admin API.
func (c Config) Redacted() Config {
	out := c
	if out.AuthHeader != "" {
		out.AuthHeader = maskAuthHeader(out.AuthHeader)
	}
	return out
}

func maskAuthHeader(h string) string {
	if len(h) <= 8 {
		return "***"
	}
	return h[:4] + "…" + h[len(h)-4:]
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "bitswan", "siem.json"), nil
}

// Load reads the persisted config. Returns a zero Config with defaults if no
// file exists — first run has no SIEM configured.
func Load() (Config, error) {
	var cfg Config
	path, err := configPath()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.Defaults()
			return cfg, nil
		}
		return cfg, fmt.Errorf("read siem config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse siem config: %w", err)
	}
	cfg.Defaults()
	return cfg, nil
}

// Save writes the config atomically (via tmp + rename).
func Save(cfg Config) error {
	cfg.Defaults()
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
