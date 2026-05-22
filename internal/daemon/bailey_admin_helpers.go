package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
)

// signoutRedirect ends the oauth2-proxy session and bounces the user
// to the Keycloak end-session endpoint so the IdP-level session is
// also gone (otherwise hitting any protected page would silently
// re-issue a code from the lingering IdP session).
func signoutRedirect(w http.ResponseWriter, r *http.Request, postLogoutPath string) {
	cfg, _ := oauth.GetOauthConfig(baileyConfigName)
	if cfg == nil || cfg.IssuerUrl == "" {
		http.Redirect(w, r, "/oauth2/sign_out", http.StatusFound)
		return
	}
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	postLogout := scheme + "://" + r.Host + postLogoutPath
	keycloakEnd := strings.TrimRight(cfg.IssuerUrl, "/") +
		"/protocol/openid-connect/logout?post_logout_redirect_uri=" + url.QueryEscape(postLogout) +
		"&client_id=" + url.QueryEscape(cfg.ClientId)
	http.Redirect(w, r, "/oauth2/sign_out?rd="+url.QueryEscape(keycloakEnd), http.StatusFound)
}

// handleWhoami is the auth-debug endpoint. Dumps the auth-related headers
// the daemon sees so an operator can confirm what oauth2-proxy is
// forwarding (mostly useful when an admin login is landing on the
// 'not an admin' page).
func handleWhoami(w http.ResponseWriter, r *http.Request) {
	hs := map[string]string{}
	for _, h := range []string{
		"X-Forwarded-Email", "X-Forwarded-User", "X-Forwarded-Groups",
		"X-Auth-Request-Email", "X-Auth-Request-User", "X-Auth-Request-Groups",
		"X-Forwarded-Preferred-Username", "X-Forwarded-Access-Token",
	} {
		if v := r.Header.Get(h); v != "" {
			if h == "X-Forwarded-Access-Token" {
				v = fmt.Sprintf("<present, len=%d>", len(v))
			}
			hs[h] = v
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"headers":              hs,
		"admin_group_constant": adminGroup,
		"is_admin":             isAdmin(r),
	})
}
