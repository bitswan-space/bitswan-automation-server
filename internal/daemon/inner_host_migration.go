package daemon

import (
	"fmt"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
)

// migrateInnerHostRoutes ensures every existing OUTER-host route has
// a paired INNER-host route. Runs at daemon startup. Idempotent.
//
// Existing endpoints were registered before the outer/inner split, so
// their inner subdomains have no traefik routes and the wrap iframe
// would 404 trying to load them. We read the current traefik state
// (platform-traefik + traefik-protected) and clone each outer
// hostname's route to its inner pair.
//
// We also re-register the OUTER hostname in platform-traefik to point
// at bitswan-protected-proxy (the daemon serves the wrap there now —
// the pre-migration upstream was the workspace traefik directly, which
// would bypass auth entirely under the new model).
func migrateInnerHostRoutes() {
	// Re-register paired routes for every outer hostname currently
	// known to traefik-protected. That's the authoritative list of
	// "things behind the wrap".
	protectedRoutes, err := traefikapi.ListRoutesWithTraefik("http://traefik-protected:8080")
	if err != nil {
		fmt.Printf("inner-host migration: list traefik-protected routes: %v\n", err)
		return
	}

	for _, route := range protectedRoutes {
		host := routeFirstHost(route)
		if host == "" || isInnerHost(host) {
			continue
		}
		// Bailey is migrated by setupProtectedRoutes already.
		if isBaileyHost(host) {
			continue
		}

		upstream := routeFirstUpstream(route)
		if upstream == "" {
			continue
		}
		inner := toInnerHost(host)

		// (1) Platform-traefik: inner → bitswan-protected-proxy
		if err := traefikapi.AddRouteWithTraefikPriority(
			inner, "bitswan-protected-proxy:80", "", "letsencrypt", 200,
		); err != nil {
			fmt.Printf("inner-host migration: platform-traefik for %s: %v\n", inner, err)
		}
		// (2) traefik-protected: inner → same upstream as outer
		if err := traefikapi.AddRouteWithTraefik(
			inner, upstream, "http://traefik-protected:8080",
		); err != nil {
			fmt.Printf("inner-host migration: traefik-protected for %s: %v\n", inner, err)
		}
		// (3) Outer in platform-traefik: force point at bitswan-protected-proxy.
		//     Pre-migration this could have been the workspace traefik directly
		//     (bypassing auth). Re-registering with priority 200 wins over any
		//     docker-label HostRegexp catch-all.
		if err := traefikapi.AddRouteWithTraefikPriority(
			host, "bitswan-protected-proxy:80", "", "letsencrypt", 200,
		); err != nil {
			fmt.Printf("inner-host migration: platform-traefik for %s: %v\n", host, err)
		}
		// (4) Workspace's own traefik also needs the inner hostname so it
		//     can route to the actual container. Pull the upstream from
		//     the workspace's traefik (where outer is already registered).
		if ws := workspaceFromUpstream(upstream); ws != "" {
			workspaceTraefikURL := traefikapi.GetWorkspaceTraefikBaseURL(ws)
			workspaceRoutes, err := traefikapi.ListRoutesWithTraefik(workspaceTraefikURL)
			if err == nil {
				if ups := lookupUpstreamForHost(workspaceRoutes, host); ups != "" {
					if err := traefikapi.AddRouteWithTraefik(inner, ups, workspaceTraefikURL); err != nil {
						fmt.Printf("inner-host migration: workspace traefik for %s: %v\n", inner, err)
					}
				}
			}
		}
		// (5) Keycloak — register the inner callback URI.
		if err := registerProtectedRedirectURI(host); err != nil {
			fmt.Printf("inner-host migration: keycloak redirect URIs for %s: %v\n", host, err)
		}
		fmt.Printf("inner-host migration: paired %s ↔ %s\n", host, inner)
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
	// strip scheme
	s := upstream
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// strip port
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	// strip path
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
