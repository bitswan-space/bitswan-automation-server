// Package vpn used to host bitswan's WireGuard implementation; that's gone
// now that ZTNA providers (NetBird etc.) handle the tunnel. What remains
// here is shared by callers that need either the IPv6 layout of the local
// service network or the per-server CA — both of which live in this server
// regardless of which ZTNA provider is wired in.
package vpn

// IPv6 layout of the bitswan-managed service network.
//
//	ClientSubnet  — historical WG client subnet; retained as a constant so
//	                config that referenced it (e.g. ULAs in old deployments)
//	                still resolves cleanly during transition. Not actively
//	                used by anything bitswan ships today.
//	ServiceSubnet — the bitswan_protected_network Docker bridge — where
//	                traefik-protected, the ZTNA routing peer, and any future
//	                internal services live. Routes through this subnet are
//	                what the ZTNA provider advertises so peers can reach
//	                *.bswn.internal.
const (
	ClientSubnet  = "fd00:b175:0::/64"
	ServiceSubnet = "fd00:b175:1::/64"
)
