// Package ztna is the bitswan abstraction over Zero-Trust-Network-Access
// providers. The first (and currently only) provider is NetBird; future
// providers (Tailscale, Twingate, ZeroTier, …) plug in behind the same
// Provider interface without the rest of the daemon needing to know.
package ztna

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProviderKind enumerates supported ZTNA back-ends. Stored in Config so the
// daemon can route operations to the right implementation.
type ProviderKind string

const (
	ProviderNetBird ProviderKind = "netbird"
)

// Config is what the admin pastes into the Network Access page, persisted at
// ~/.config/bitswan/ztna.json. Provider-specific fields live in dedicated
// sub-structs so the on-disk format documents itself.
type Config struct {
	Provider ProviderKind   `json:"provider"`
	Enabled  bool           `json:"enabled"`
	NetBird  *NetBirdConfig `json:"netbird,omitempty"`
}

// NetBirdConfig captures the credentials and endpoint URLs needed to drive
// a NetBird tenant — works equally for the hosted service at
// api.netbird.io and a self-hosted control plane.
type NetBirdConfig struct {
	// APIURL is the NetBird management API (where our daemon makes calls).
	// e.g. "https://api.netbird.io" for hosted, or the customer's own URL.
	APIURL string `json:"api_url"`
	// ManagementURL is what the agent on the user's device connects to.
	// Often identical to APIURL but exposed separately because some
	// self-hosted deployments split them.
	ManagementURL string `json:"management_url"`
	// PAT is a Personal Access Token with permission to manage peers,
	// groups, setup keys, and DNS records.
	PAT string `json:"pat"`
}

// Defaults fills NetBird endpoints with the hosted-service defaults if the
// admin only supplied a token — saves them having to look up two URLs that
// they almost always want the same value for.
func (c *Config) Defaults() {
	if c.Provider == "" {
		c.Provider = ProviderNetBird
	}
	if c.Provider == ProviderNetBird {
		if c.NetBird == nil {
			c.NetBird = &NetBirdConfig{}
		}
		if c.NetBird.APIURL == "" {
			c.NetBird.APIURL = "https://api.netbird.io"
		}
		if c.NetBird.ManagementURL == "" {
			c.NetBird.ManagementURL = c.NetBird.APIURL
		}
	}
}

// Redacted returns a copy of the config with secrets masked. Used when
// returning config over the admin API so we don't echo the PAT into the UI.
func (c Config) Redacted() Config {
	out := c
	if out.NetBird != nil && out.NetBird.PAT != "" {
		nb := *out.NetBird
		nb.PAT = maskSecret(nb.PAT)
		out.NetBird = &nb
	}
	return out
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

// Masked reports whether s is the redacted form (contains the mask
// character). The admin UI prefills the input with the redacted value so the
// admin can toggle Enabled without re-typing the secret; on POST we treat
// the masked form as "no change".
func Masked(s string) bool {
	return strings.Contains(s, "…")
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "bitswan", "ztna.json"), nil
}

// Load reads the persisted config; missing file ⇒ zero Config with defaults.
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
		return cfg, fmt.Errorf("read ztna config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse ztna config: %w", err)
	}
	cfg.Defaults()
	return cfg, nil
}

// Save writes the config atomically.
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
