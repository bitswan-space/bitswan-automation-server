package daemon

import "fmt"

// reconcileTraefikProtected was the startup check for the legacy
// traefik-protected container. The daemon's MFA gate now resolves
// upstream hostnames itself, so there's no traefik-protected anymore;
// migrateInnerHostRoutes removes any leftover container at startup.
// Kept as a thin wrapper so callers don't need to be updated all at
// once.
func reconcileTraefikProtected() {
	if !containerRunning("bitswan-protected-proxy") {
		fmt.Println("bitswan-protected-proxy not running — provision it via `bailey init --domain`.")
	}
}
