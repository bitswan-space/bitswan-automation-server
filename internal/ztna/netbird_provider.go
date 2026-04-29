package ztna

import (
	"context"
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/ztna/netbird"
)

// netBirdProvider implements Provider over the NetBird management API.
// Stateless — every call is independent; persistence lives in the on-disk
// Config + whatever NetBird itself remembers across calls.
type netBirdProvider struct {
	cfg *NetBirdConfig
}

func newNetBirdProvider(cfg *NetBirdConfig) *netBirdProvider {
	return &netBirdProvider{cfg: cfg}
}

func (p *netBirdProvider) Name() ProviderKind { return ProviderNetBird }

func (p *netBirdProvider) client() *netbird.Client {
	return netbird.New(p.cfg.APIURL, p.cfg.PAT)
}

func (p *netBirdProvider) Validate(ctx context.Context) Status {
	s := Status{Provider: ProviderNetBird}
	if p.cfg == nil || p.cfg.APIURL == "" || p.cfg.PAT == "" {
		s.Error = "NetBird API URL and Personal Access Token are required"
		return s
	}
	s.Configured = true
	u, err := p.client().CurrentUser(ctx)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	s.Connected = true
	s.User = u.Email
	s.Role = u.Role
	return s
}

// Provision drives the per-server NetBird setup we control: groups for the
// routing peer and end users, plus a setup key for each. The routing peer's
// container start, the route advertisement, and DNS records aren't created
// here — they live in the daemon (which knows about Docker) and in NetBird's
// dashboard for v1. We surface what the daemon needs to bring the routing
// peer up.
func (p *netBirdProvider) Provision(ctx context.Context, params ProvisionParams) (*ProvisionResult, error) {
	if p.cfg == nil || p.cfg.PAT == "" {
		return nil, fmt.Errorf("netbird not configured")
	}
	c := p.client()

	// One group for the routing peer, one for end users — keeps NetBird
	// policies easy to read in the dashboard.
	routingGroupName := fmt.Sprintf("bitswan-router-%s", params.ServerSlug)
	usersGroupName := fmt.Sprintf("bitswan-users-%s", params.ServerSlug)

	routingGroup, err := c.EnsureGroup(ctx, routingGroupName)
	if err != nil {
		return nil, fmt.Errorf("ensure routing group: %w", err)
	}
	usersGroup, err := c.EnsureGroup(ctx, usersGroupName)
	if err != nil {
		return nil, fmt.Errorf("ensure users group: %w", err)
	}

	// Routing peer: one-off ephemeral key (cleans itself up if peer
	// vanishes); reusable user key valid for ~1 year so the public admin
	// page can show it without per-user provisioning. Names are stable so
	// repeated Provision calls don't pile up keys.
	routingKeyName := fmt.Sprintf("bitswan-router-key-%s", params.ServerSlug)
	usersKeyName := fmt.Sprintf("bitswan-users-key-%s", params.ServerSlug)

	routingKey, err := c.EnsureSetupKey(ctx, routingKeyName, "one-off", []string{routingGroup.ID}, 365, true)
	if err != nil {
		return nil, fmt.Errorf("ensure routing setup key: %w", err)
	}
	usersKey, err := c.EnsureSetupKey(ctx, usersKeyName, "reusable", []string{usersGroup.ID}, 365, false)
	if err != nil {
		return nil, fmt.Errorf("ensure users setup key: %w", err)
	}

	// EnsureSetupKey returns Key=="" when reusing — only the create call
	// includes the raw secret. For the routing peer we MUST have the raw
	// key (the agent needs it on first start); if reuse hid it, force a
	// fresh key by appending a counter to the name. For the users key
	// we'll accept the same caveat: once issued, it's persisted by the
	// daemon's caller for display.
	if routingKey.Key == "" {
		// Force a new one with a versioned suffix; admins can revoke the
		// old in the dashboard if they want.
		routingKey, err = c.CreateSetupKey(ctx, routingKeyName+"-v2", "one-off", []string{routingGroup.ID}, 365, true)
		if err != nil {
			return nil, fmt.Errorf("create fresh routing setup key: %w", err)
		}
	}

	mgmtURL := p.cfg.ManagementURL
	if mgmtURL == "" {
		mgmtURL = p.cfg.APIURL
	}
	return &ProvisionResult{
		RoutingPeerSetupKey: routingKey.Key,
		ManagementURL:       mgmtURL,
		// usersKey is captured by the caller via a separate path
		// (EndUserInstructions), which re-enumerates from NetBird.
	}, _orcaptureUsersKey(usersKey)
}

// _orcaptureUsersKey is a no-op that preserves the symmetry of the call
// site (we want EnsureSetupKey to have *some* visible result for users key
// even if Provision doesn't surface it directly). Replace with a real
// persistence step if we ever want to cache the users key.
func _orcaptureUsersKey(_ *netbird.SetupKey) error { return nil }

func (p *netBirdProvider) EndUserInstructions(ctx context.Context) (*UserInstructions, error) {
	if p.cfg == nil || p.cfg.PAT == "" {
		return nil, fmt.Errorf("netbird not configured")
	}
	c := p.client()
	keys, err := c.ListSetupKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list setup keys: %w", err)
	}
	var userKey string
	for _, k := range keys {
		if k.Revoked {
			continue
		}
		// Names assigned by Provision; pick the most recently-created.
		if hasPrefix(k.Name, "bitswan-users-key-") && k.Key != "" {
			userKey = k.Key
		}
	}
	mgmtURL := p.cfg.ManagementURL
	if mgmtURL == "" {
		mgmtURL = p.cfg.APIURL
	}
	return &UserInstructions{
		ProviderName:  "NetBird",
		ManagementURL: mgmtURL,
		SetupKey:      userKey,
		InstallURL:    "https://netbird.io/download",
	}, nil
}

func hasPrefix(s, p string) bool {
	if len(s) < len(p) {
		return false
	}
	return s[:len(p)] == p
}
