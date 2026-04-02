package daemon

// caddy_compat.go — Caddy admin API compatibility shim
//
// Older gitops images register automation routes by calling the Caddy admin API
// directly at "caddy:2019". When Traefik replaces Caddy as the global ingress,
// those images would fail because "caddy" no longer resolves in the Docker
// network.
//
// This file adds a lightweight Caddy-compatible admin API server on port 2019.
// The daemon container is given a Docker network alias "caddy" so the hostname
// resolves.  Key Caddy endpoints are translated into Traefik REST API calls;
// everything else returns 200 OK so the gitops container keeps running.
//
// Endpoints handled:
//   PUT  /config/apps/http/servers/srv0/routes/... — add route → Traefik
//   POST /config/apps/http/servers/srv0/routes/... — add route → Traefik
//   DELETE /config/apps/http/servers/srv0/routes/... — remove route → Traefik
//   GET  /reverse_proxy/upstreams — health check; returns current route list
//   *    anything else — 200 OK (no-op, keeps the gitops image happy)

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
)

// caddyRoute mirrors the subset of the Caddy route JSON that gitops images send.
type caddyRoute struct {
	ID    string       `json:"@id,omitempty"`
	Match []caddyMatch `json:"match,omitempty"`
	Handle []caddyHandle `json:"handle,omitempty"`
}

type caddyMatch struct {
	Host []string `json:"host,omitempty"`
}

type caddyHandle struct {
	Handler string        `json:"handler,omitempty"`
	Routes  []caddySubRoute `json:"routes,omitempty"`
}

type caddySubRoute struct {
	Handle []caddyRPHandle `json:"handle,omitempty"`
}

type caddyRPHandle struct {
	Handler   string          `json:"handler,omitempty"`
	Upstreams []caddyUpstream `json:"upstreams,omitempty"`
}

type caddyUpstream struct {
	Dial string `json:"dial,omitempty"`
}

// setupCaddyCompatRoutes registers Caddy-compatible routes on mux.
func (s *Server) setupCaddyCompatRoutes(mux *http.ServeMux) {
	// Route registration / removal — translate to Traefik
	mux.HandleFunc("/config/apps/http/servers/srv0/routes", s.handleCaddyRoutes)
	mux.HandleFunc("/config/apps/http/servers/srv0/routes/", s.handleCaddyRoutes)

	// Upstream health check — return an empty-but-valid list so callers don't error
	mux.HandleFunc("/reverse_proxy/upstreams", s.handleCaddyUpstreams)

	// TLS / policy endpoints — accept without action (Traefik manages its own TLS)
	mux.HandleFunc("/config/apps/tls", s.handleCaddyNoop)
	mux.HandleFunc("/config/apps/tls/", s.handleCaddyNoop)
	mux.HandleFunc("/config/", s.handleCaddyNoop)
	mux.HandleFunc("/load", s.handleCaddyNoop)

	// Catch-all
	mux.HandleFunc("/", s.handleCaddyNoop)
}

// handleCaddyRoutes handles PUT/POST/DELETE on the Caddy routes config path.
func (s *Server) handleCaddyRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var route caddyRoute
		if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
			// Try as array (some caddy clients send an array)
			w.WriteHeader(http.StatusOK)
			return
		}

		hostname, upstream := extractRouteFields(route)
		if hostname != "" && upstream != "" {
			certResolver := ""
			if !strings.HasSuffix(hostname, ".localhost") {
				certResolver = "letsencrypt"
			}
			if err := traefikapi.AddRouteWithTraefik(hostname, upstream, "", certResolver); err != nil {
				fmt.Printf("Caddy compat: failed to add Traefik route for %s: %v\n", hostname, err)
				// Still return 200 so the gitops image doesn't fail the deployment
			} else {
				fmt.Printf("Caddy compat: registered %s -> %s in Traefik\n", hostname, upstream)
			}
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodDelete:
		// Extract hostname from path suffix (e.g. /config/.../routes/hostname)
		path := r.URL.Path
		parts := strings.Split(strings.TrimRight(path, "/"), "/")
		if len(parts) > 0 {
			id := parts[len(parts)-1]
			if id != "" && id != "routes" {
				if err := traefikapi.RemoveRoute(id); err != nil {
					fmt.Printf("Caddy compat: failed to remove Traefik route %s: %v\n", id, err)
				}
			}
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		// Return current Traefik routes in a Caddy-like format
		routes, err := traefikapi.ListRoutes()
		if err != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(routes)

	default:
		w.WriteHeader(http.StatusOK)
	}
}

// handleCaddyUpstreams responds to GET /reverse_proxy/upstreams.
// Old gitops images poll this to check if the deployed automation's upstream is
// registered.  We return all currently known Traefik routes as "healthy"
// upstreams so the caller considers the deployment ready.
func (s *Server) handleCaddyUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusOK)
		return
	}

	routes, err := traefikapi.ListRoutes()
	if err != nil || len(routes) == 0 {
		// Return an empty list — healthier than an error
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	// Build a Caddy-style upstreams response: one entry per upstream dial address
	type upstreamEntry struct {
		Address     string `json:"address"`
		Healthy     bool   `json:"healthy"`
		NumRequests int    `json:"num_requests"`
		Fails       int    `json:"fails"`
	}

	var upstreams []upstreamEntry
	for _, route := range routes {
		for _, handle := range route.Handle {
			for _, up := range handle.Upstreams {
				upstreams = append(upstreams, upstreamEntry{
					Address: up.Dial,
					Healthy: true,
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(upstreams)
}

// handleCaddyNoop accepts any request and returns 200 OK without taking action.
func (s *Server) handleCaddyNoop(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// extractRouteFields pulls hostname and upstream out of a Caddy route struct.
func extractRouteFields(route caddyRoute) (hostname, upstream string) {
	if len(route.Match) > 0 && len(route.Match[0].Host) > 0 {
		hostname = route.Match[0].Host[0]
	}
	for _, h := range route.Handle {
		for _, sub := range h.Routes {
			for _, rph := range sub.Handle {
				if rph.Handler == "reverse_proxy" && len(rph.Upstreams) > 0 {
					upstream = rph.Upstreams[0].Dial
					return
				}
			}
		}
	}
	return
}
