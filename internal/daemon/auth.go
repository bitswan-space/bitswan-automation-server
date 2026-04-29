package daemon

import (
	"net/http"
	"strings"
)

// adminGroup is the suffix of any Keycloak group path that grants admin
// privileges in the VPN admin page. AOC's convention is one child group
// named "admin" under each org (e.g. "/Example Org/admin"); the filtered
// group-membership mapper that AOC attaches to per-server oauth clients
// emits these paths in the OIDC `group_membership` claim, which oauth2-proxy
// forwards as X-Forwarded-Groups (or X-Auth-Request-Groups). Matching by
// suffix means we don't have to know the org's display name.
const adminGroup = "/admin"

// isAdmin reports whether the request's authenticated user is in their
// org's admin group. Absent or empty group headers mean "not admin" — fail
// closed.
func isAdmin(r *http.Request) bool {
	groups := r.Header.Get("X-Forwarded-Groups")
	if groups == "" {
		groups = r.Header.Get("X-Auth-Request-Groups")
	}
	for _, g := range strings.Split(groups, ",") {
		g = strings.TrimSpace(g)
		// Tolerate the bare "admin" too — older configs that emitted the
		// group name without the path-prefix mapper, or test harnesses,
		// shouldn't lock admins out.
		if g == "admin" || strings.HasSuffix(strings.ToLower(g), adminGroup) {
			return true
		}
	}
	return false
}

// requireAdmin writes a 403 response and returns false if the caller isn't an
// admin. Callers should early-return on false.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if isAdmin(r) {
		return true
	}
	http.Error(w, `{"error":"admin access required"}`, http.StatusForbidden)
	return false
}
