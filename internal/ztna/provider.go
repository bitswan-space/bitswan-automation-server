package ztna

import "context"

// Provider abstracts a Zero-Trust-Network-Access vendor (NetBird, Tailscale,
// Twingate, …). Bitswan delegates user device management entirely to the
// provider; what we need from each one is uniform: a way to validate the
// credentials, a way to provision a routing peer that bridges the provider's
// overlay to bitswan_vpn_network, and a way to issue end-user setup
// instructions for the public admin page.
type Provider interface {
	// Name returns the provider's short name, matching ProviderKind.
	Name() ProviderKind

	// Validate makes the smallest possible authenticated API call against
	// the provider. Returns a Status the admin UI can render as-is.
	Validate(ctx context.Context) Status

	// Provision performs (or re-affirms) first-time setup: ensures the
	// per-server group, the routing-peer setup key, and the user setup
	// key all exist, plus any provider-specific routes/DNS that need to
	// be in place. Idempotent — safe to call repeatedly.
	Provision(ctx context.Context, p ProvisionParams) (*ProvisionResult, error)

	// EndUserInstructions returns the data the public admin page needs
	// to render install instructions for a non-admin user.
	EndUserInstructions(ctx context.Context) (*UserInstructions, error)
}

// ProvisionParams is the input the daemon hands to Provision: identity of
// this automation server plus the local resources the routing peer needs
// to expose.
type ProvisionParams struct {
	ServerSlug     string // e.g. "network-test-7"
	ServerName     string // e.g. "Network Test 7"
	ServiceSubnet  string // e.g. "fd00:b175:1::/64" — what the routing peer routes to
	InternalDomain string // e.g. "network-test-7.bswn.internal"
	TraefikVPNIPv6 string // IPv6 of traefik-vpn (target of *.bswn.internal)
}

// ProvisionResult is whatever the provider's Provision produced that the
// daemon needs to bring up the routing-peer container.
type ProvisionResult struct {
	// RoutingPeerSetupKey is the one-shot key the routing-peer container
	// uses to register itself with the provider on first start.
	RoutingPeerSetupKey string
	// ManagementURL is what the agent connects to (NetBird-equivalent).
	ManagementURL string
}

// UserInstructions is rendered into the public admin page so the end user
// can install the agent and connect to this server's VPN.
type UserInstructions struct {
	ProviderName  string
	ManagementURL string
	SetupKey      string
	InstallURL    string // marketing link to the agent installer
}

// Build returns the Provider implementation for the configured kind. Lives
// in this package (and not in each provider's package) so callers don't
// have to import every provider's package.
func Build(cfg Config) (Provider, error) {
	cfg.Defaults()
	switch cfg.Provider {
	case ProviderNetBird:
		return newNetBirdProvider(cfg.NetBird), nil
	default:
		return nil, errUnsupportedProvider(string(cfg.Provider))
	}
}

type errUnsupportedProvider string

func (e errUnsupportedProvider) Error() string {
	return "ztna: unsupported provider " + string(e)
}
