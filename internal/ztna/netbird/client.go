// Package netbird is the NetBird-specific implementation of the ztna
// Provider interface. Phase 1 covers credential validation only — peer
// provisioning, DNS records, and routing-peer lifecycle land in phase 2.
package netbird

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client wraps NetBird's management API. Construct with New and call
// methods directly; concurrency-safe (the underlying http.Client is).
type Client struct {
	baseURL string
	pat     string
	http    *http.Client
}

// New builds a client. baseURL should be the API root (e.g.
// "https://api.netbird.io"); trailing slashes are tolerated.
func New(baseURL, pat string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		pat:     pat,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// User mirrors NetBird's /api/users/current response. Only the fields we
// surface in the admin UI; full schema has more.
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
	IsAdmin bool `json:"-"`
}

// CurrentUser hits /api/users/current — the cheapest way to confirm the PAT
// works and the API URL is reachable. Returns the user record so the admin
// UI can show "connected as <email>".
func (c *Client) CurrentUser(ctx context.Context) (*User, error) {
	var u User
	if err := c.do(ctx, http.MethodGet, "/api/users/current", nil, &u); err != nil {
		return nil, err
	}
	// NetBird's role enum is "admin" / "user" / "owner"; collapse to bool.
	u.IsAdmin = u.Role == "admin" || u.Role == "owner"
	return &u, nil
}

// Group is NetBird's tag for a set of peers. Used in policies and as the
// auto-group attached to setup keys.
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ListGroups returns every group in the account. Paged in NetBird's API but
// we read in one call — admin accounts rarely have thousands of groups.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var groups []Group
	if err := c.do(ctx, http.MethodGet, "/api/groups", nil, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// EnsureGroup is the get-or-create primitive we use throughout provisioning:
// look the name up first, only POST if it's missing. NetBird doesn't enforce
// name uniqueness, so a duplicate POST would create a second copy — hence
// the explicit list step.
func (c *Client) EnsureGroup(ctx context.Context, name string) (*Group, error) {
	groups, err := c.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for i := range groups {
		if groups[i].Name == name {
			return &groups[i], nil
		}
	}
	body := map[string]any{"name": name}
	var created Group
	if err := c.do(ctx, http.MethodPost, "/api/groups", body, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// SetupKey is what an agent uses on first run to enroll itself. NetBird
// supports one-off and reusable keys, with optional auto-groups so the
// resulting peer lands in known groups.
type SetupKey struct {
	ID         string   `json:"id"`
	Key        string   `json:"key"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Revoked    bool     `json:"revoked"`
	AutoGroups []string `json:"auto_groups"`
	UsedTimes  int      `json:"used_times"`
	UsageLimit int      `json:"usage_limit"`
}

// ListSetupKeys returns all setup keys, including revoked. Caller filters.
func (c *Client) ListSetupKeys(ctx context.Context) ([]SetupKey, error) {
	var keys []SetupKey
	if err := c.do(ctx, http.MethodGet, "/api/setup-keys", nil, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// CreateSetupKey makes a new key. Type is "reusable" or "one-off". autoGroups
// is the list of group IDs new peers join. expiresInDays=0 → no expiry.
func (c *Client) CreateSetupKey(ctx context.Context, name, keyType string, autoGroups []string, expiresInDays int, ephemeral bool) (*SetupKey, error) {
	body := map[string]any{
		"name":         name,
		"type":         keyType,
		"auto_groups":  autoGroups,
		"expires_in":   expiresInDays * 24 * 60 * 60, // NetBird wants seconds
		"usage_limit":  0,
		"ephemeral_peers": ephemeral,
		"revoked":      false,
	}
	var key SetupKey
	if err := c.do(ctx, http.MethodPost, "/api/setup-keys", body, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// EnsureSetupKey returns an existing non-revoked, non-expired key with the
// given name+type if one exists; otherwise creates a fresh one. Useful so
// repeated Provision calls don't spam the account with new keys.
func (c *Client) EnsureSetupKey(ctx context.Context, name, keyType string, autoGroups []string, expiresInDays int, ephemeral bool) (*SetupKey, error) {
	keys, err := c.ListSetupKeys(ctx)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		k := keys[i]
		if k.Name == name && k.Type == keyType && !k.Revoked {
			// NetBird doesn't return the raw key after creation, so a
			// rediscovered key has Key=="". The caller must already have
			// stored it locally on first issue, otherwise we'd need to
			// rotate. We treat empty Key as "reuse without secret" — fine
			// for status display, but Provision will create fresh below.
			if k.Key != "" {
				return &k, nil
			}
		}
	}
	return c.CreateSetupKey(ctx, name, keyType, autoGroups, expiresInDays, ephemeral)
}

// Peer is a registered agent endpoint. Returned during status checks.
type Peer struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	Connected bool    `json:"connected"`
	LastSeen string   `json:"last_seen"`
	Groups   []Group  `json:"groups"`
}

// ListPeers returns every peer in the account.
func (c *Client) ListPeers(ctx context.Context) ([]Peer, error) {
	var peers []Peer
	if err := c.do(ctx, http.MethodGet, "/api/peers", nil, &peers); err != nil {
		return nil, err
	}
	return peers, nil
}

// FindPeerByGroup returns the first peer in the named group, or nil if none
// has registered yet. Used after starting the routing-peer container to
// discover its NetBird-assigned IP.
func (c *Client) FindPeerByGroup(ctx context.Context, groupID string) (*Peer, error) {
	peers, err := c.ListPeers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range peers {
		for _, g := range peers[i].Groups {
			if g.ID == groupID {
				return &peers[i], nil
			}
		}
	}
	return nil, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode body: %w", err)
		}
		rdr = strings.NewReader(string(raw))
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.pat)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Surface NetBird's error envelope when present so the admin UI can
		// display something useful instead of just the HTTP code.
		var apiErr struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(respBody, &apiErr)
		if apiErr.Message != "" {
			return fmt.Errorf("netbird %s %s: %s (HTTP %d)", method, path, apiErr.Message, resp.StatusCode)
		}
		return fmt.Errorf("netbird %s %s: HTTP %d", method, path, resp.StatusCode)
	}

	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
