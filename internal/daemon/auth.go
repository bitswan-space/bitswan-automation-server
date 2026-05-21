package daemon

import (
	"net/http"
	"strings"
)

// adminGroup is the suffix of any Keycloak group path that grants admin
// privileges in the Bailey admin page. AOC's convention is one child group
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

// identityFromHeaders extracts the authenticated user from the
// oauth2-proxy-forwarded headers. Returns ("", nil) when there is no
// signed identity on the request (e.g. before the OIDC handshake has
// run, or in unit tests).
func identityFromHeaders(r *http.Request) (string, []string) {
	email := r.Header.Get("X-Forwarded-Email")
	if email == "" {
		email = r.Header.Get("X-Auth-Request-Email")
	}
	groupsHeader := r.Header.Get("X-Forwarded-Groups")
	if groupsHeader == "" {
		groupsHeader = r.Header.Get("X-Auth-Request-Groups")
	}
	var groups []string
	for _, g := range strings.Split(groupsHeader, ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	return email, groups
}
