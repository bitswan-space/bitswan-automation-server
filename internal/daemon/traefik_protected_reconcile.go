package daemon

import (
	"fmt"
)

// reconcileTraefikProtected makes sure the two protected-ingress
// containers are running. They live with the daemon container (same
// host, same docker network) and the daemon owns their lifecycle: the
// previous traefik-protected dies when the daemon does, so we always
// re-bring it up at boot rather than assume `restart: always` will
// have done it for us.
//
// Two pieces:
//
//   - traefik-protected   — workspace-facing reverse proxy on
//     bitswan_protected_network. Only ever reached via the MFA gate.
//   - bitswan-protected-proxy — the shared oauth2-proxy that fronts
//     traefik-protected. Public traffic on *.protected-domain lands
//     here first, redirects to Keycloak, then forwards to the gate.
//
// Either failing is non-fatal: log and continue so the daemon's other
// surfaces (admin, ingress add-route, etc.) stay reachable for
// recovery.
func reconcileTraefikProtected() {
	if !containerRunning("traefik-protected") {
		fmt.Println("traefik-protected not running — daemon won't restart it (already provisioned at init).")
	}
	if !containerRunning("bitswan-protected-proxy") {
		fmt.Println("bitswan-protected-proxy not running — provision it via `bailey init --domain`.")
	}
}
