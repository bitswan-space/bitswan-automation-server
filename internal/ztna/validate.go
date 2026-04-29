package ztna

import (
	"context"
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/ztna/netbird"
)

// Status is what the admin UI shows for the current ZTNA configuration.
// Connected==true means we successfully authenticated against the provider
// API at validation time. Blank User/Account when Connected==false.
type Status struct {
	Provider  ProviderKind `json:"provider"`
	Configured bool        `json:"configured"`
	Connected bool         `json:"connected"`
	User      string       `json:"user,omitempty"`
	Role      string       `json:"role,omitempty"`
	Error     string       `json:"error,omitempty"`
}

// Validate makes the smallest possible authenticated API call against the
// configured provider; returns a Status the UI can render as-is. Never
// errors — bad config becomes Status.Error.
func Validate(ctx context.Context, cfg Config) Status {
	s := Status{Provider: cfg.Provider}
	if !cfg.Enabled {
		return s
	}
	switch cfg.Provider {
	case ProviderNetBird:
		if cfg.NetBird == nil || cfg.NetBird.APIURL == "" || cfg.NetBird.PAT == "" {
			s.Error = "NetBird API URL and Personal Access Token are required"
			return s
		}
		s.Configured = true
		c := netbird.New(cfg.NetBird.APIURL, cfg.NetBird.PAT)
		u, err := c.CurrentUser(ctx)
		if err != nil {
			s.Error = err.Error()
			return s
		}
		s.Connected = true
		s.User = u.Email
		s.Role = u.Role
		return s
	default:
		s.Error = fmt.Sprintf("unsupported provider %q", cfg.Provider)
		return s
	}
}
