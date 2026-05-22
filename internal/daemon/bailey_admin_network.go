package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
)

// Bailey / Network Access page. After the NetBird-specific UI
// was ripped out, this page describes the protected-ingress flow
// agnostically: the operator can expose the gateway via any external
// tunnel (NetBird, Cloudflare Tunnel, Tailscale, ssh tunnel, …) and
// the page just renders an info card with the hostname pattern, the
// host-loopback port the gateway listens on, and a CA cert link.

const networkAccessHTML = `
<div id="protected-ingress-box"><p class="note">Loading…</p></div>
`

const networkAccessScript = `
fetch('/bailey/api/protected-ingress').then(r => r.json()).then(d => {
  document.getElementById('protected-ingress-box').innerHTML = d.html || '';
});
`

// handleProtectedIngressInfo serves a JSON envelope holding a chunk of
// pre-rendered HTML the page polls in. Server-built so the link/style
// stays consistent with the rest of bailey.
func handleProtectedIngressInfo(w http.ResponseWriter, r *http.Request) {
	sc, _ := config.NewAutomationServerConfig().LoadConfig()
	if sc == nil {
		http.Error(w, "server config not loaded", http.StatusInternalServerError)
		return
	}
	hostnamePattern := "*." + sc.ProtectedHostnameDomain()

	html := fmt.Sprintf(`
<div class="card">
  <h2>Protected ingress</h2>
  <p>The bailey gateway listens on host loopback ports — <code>127.0.0.1:18443</code> (HTTPS) and <code>127.0.0.1:18080</code> (HTTP). Front it with any tunnel that can reach those ports (NetBird, Cloudflare Tunnel, Tailscale, an ssh tunnel, etc.) and admins on your team will reach protected workspace services through the bailey chrome.</p>
  <p><b>Hostname pattern:</b> <code>%s</code></p>
  <p><b>OAuth2 default:</b> requests on the public domain route through the shared <code>bitswan-protected-proxy</code> oauth2-proxy with Keycloak as the IdP. No extra setup needed.</p>
</div>
`, hostnamePattern)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"html": html})
}

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
