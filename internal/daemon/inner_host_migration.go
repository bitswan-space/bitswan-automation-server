package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
)

// migrateInnerHostRoutes is a one-shot startup pass that:
//
//  (a) Tears down the legacy traefik-protected container if it's
//      still around. The daemon's MFA gate now resolves upstreams by
//      hostname directly, so that container is dead weight.
//  (b) Walks the platform-traefik state to make sure every outer
//      protected hostname has its inner pair registered both in
//      platform-traefik (so public traffic enters the auth chain)
//      and in the workspace's own traefik (so the daemon's forward
//      to <workspace>__traefik:80 can route the inner hostname).
//      Idempotent.
func migrateInnerHostRoutes() {
	removeLegacyTraefikProtected()

	platformRoutes, err := traefikapi.ListRoutesWithTraefik("")
	if err != nil {
		fmt.Printf("inner-host migration: list platform-traefik routes: %v\n", err)
		return
	}

	// Group routes by host so we don't double-process the same hostname.
	seen := map[string]bool{}
	for _, route := range platformRoutes {
		host := routeFirstHost(route)
		if host == "" || isInnerHost(host) || isBaileyHost(host) || seen[host] {
			continue
		}
		seen[host] = true

		inner := toInnerHost(host)

		// (1) Platform-traefik must have BOTH the outer and inner hosts
		//     pointing at bitswan-protected-proxy so both enter the auth
		//     chain on public ingress.
		if err := traefikapi.AddRouteWithTraefikPriority(
			host, "bitswan-protected-proxy:80", "", "letsencrypt", 200,
		); err != nil {
			fmt.Printf("inner-host migration: platform-traefik outer %s: %v\n", host, err)
		}
		if err := traefikapi.AddRouteWithTraefikPriority(
			inner, "bitswan-protected-proxy:80", "", "letsencrypt", 200,
		); err != nil {
			fmt.Printf("inner-host migration: platform-traefik inner %s: %v\n", inner, err)
		}
		// (2) Workspace traefik: copy the outer host's existing route to the
		//     inner host so the daemon's forward to <workspace>__traefik
		//     resolves correctly.
		ws := workspaceFromUpstream(routeFirstUpstream(route))
		if ws != "" {
			workspaceTraefikURL := traefikapi.GetWorkspaceTraefikBaseURL(ws)
			if workspaceRoutes, err := traefikapi.ListRoutesWithTraefik(workspaceTraefikURL); err == nil {
				if ups := lookupUpstreamForHost(workspaceRoutes, host); ups != "" {
					_ = traefikapi.AddRouteWithTraefik(inner, ups, workspaceTraefikURL)
				}
			}
		}
		// (3) Keycloak — both callback URIs.
		if err := registerProtectedRedirectURI(host); err != nil {
			fmt.Printf("inner-host migration: keycloak redirect URIs for %s: %v\n", host, err)
		}
		fmt.Printf("inner-host migration: paired %s ↔ %s\n", host, inner)
	}
}

// removeLegacyTraefikProtected stops + removes the traefik-protected
// container if present, and cleans up its compose project dir. Logs a
// note if it found nothing — safe to run on already-clean servers.
func removeLegacyTraefikProtected() {
	if !containerRunning("traefik-protected") {
		// Could still exist in stopped state; rm -f handles both.
	}
	out, err := exec.Command("docker", "rm", "-f", "traefik-protected").CombinedOutput()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		fmt.Printf("inner-host migration: removed legacy traefik-protected container\n")
	}
	// Drop the compose project dir so a future `docker compose down` doesn't
	// race against the dead config.
	homeDir, _ := os.UserHomeDir()
	stateDir := filepath.Join(homeDir, ".config", "bitswan", "traefik-protected")
	if _, err := os.Stat(stateDir); err == nil {
		_ = os.RemoveAll(stateDir)
		fmt.Printf("inner-host migration: removed %s\n", stateDir)
	}
}

// routeFirstHost returns the first hostname matched by a route.
func routeFirstHost(r traefikapi.Route) string {
	for _, m := range r.Match {
		if len(m.Host) > 0 {
			return strings.ToLower(m.Host[0])
		}
	}
	return ""
}

// routeFirstUpstream returns the first upstream dial address.
func routeFirstUpstream(r traefikapi.Route) string {
	for _, h := range r.Handle {
		for _, u := range h.Upstreams {
			return u.Dial
		}
	}
	return ""
}

// workspaceFromUpstream extracts a workspace name from an upstream URL
// like "http://bailey-e2e__traefik:80" → "bailey-e2e". Returns "" if
// the upstream doesn't look like a workspace traefik.
func workspaceFromUpstream(upstream string) string {
	s := upstream
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	const suffix = "__traefik"
	if !strings.HasSuffix(s, suffix) {
		return ""
	}
	return strings.TrimSuffix(s, suffix)
}

// lookupUpstreamForHost finds the upstream that the given hostname
// resolves to within a set of routes.
func lookupUpstreamForHost(routes []traefikapi.Route, host string) string {
	for _, r := range routes {
		if strings.EqualFold(routeFirstHost(r), host) {
			return routeFirstUpstream(r)
		}
	}
	return ""
}
