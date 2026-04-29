package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/ztna"
)

// networkAccessHTML is the body of the /vpn-admin-internal/network page.
// Phase 1: a single card for entering NetBird credentials and showing
// connection status. Phase 2 will add routing-peer status and DNS records.
const networkAccessHTML = `
<div class="card" style="margin-top:0;">
<h2>NetBird</h2>
<p class="note">Bitswan delegates VPN access to a ZTNA provider. Configure the connection here; user enrollment happens in the provider's dashboard.</p>
<form id="ztna-form" onsubmit="saveConfig(event)">
  <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;">API URL</label>
  <input type="text" id="nb-api" placeholder="https://api.netbird.io">
  <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;">Management URL <span class="note">(agent connects here — usually same as API URL)</span></label>
  <input type="text" id="nb-mgmt" placeholder="https://api.netbird.io">
  <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;">Personal Access Token</label>
  <input type="text" id="nb-pat" placeholder="nb_personal_access_token_…">
  <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;"><input type="checkbox" id="nb-enabled"> Enable NetBird integration</label>
  <div style="margin-top:16px;display:flex;gap:8px;">
    <button type="submit">Save</button>
    <button type="button" class="btn-secondary" onclick="testConnection()">Test connection</button>
  </div>
  <div id="save-result" class="note" style="margin-top:8px;"></div>
</form>
</div>

<div class="card">
<h2>Status</h2>
<div id="status-box"><p class="note">Loading…</p></div>
</div>`

// networkAccessScript powers the Network Access form. Loads existing config,
// renders status (connected as <user>, errors), and POSTs updates back. The
// auth-token field is prefilled with the redacted form so an admin can flip
// "Enabled" without re-typing the secret.
const networkAccessScript = `
function loadConfig() {
  fetch('/vpn-admin-internal/api/ztna-config').then(r=>r.json()).then(d => {
    const nb = (d.config && d.config.netbird) || {};
    document.getElementById('nb-api').value = nb.api_url || '';
    document.getElementById('nb-mgmt').value = nb.management_url || '';
    document.getElementById('nb-pat').value = nb.pat || '';
    document.getElementById('nb-enabled').checked = !!(d.config && d.config.enabled);
    renderStatus(d.status);
  });
}
function renderStatus(s) {
  if (!s) { document.getElementById('status-box').innerHTML = '<p class="note">No status.</p>'; return; }
  let dot, label;
  if (s.connected) { dot = '<span style="color:#22C55E;">&bull;</span>'; label = 'Connected'; }
  else if (s.configured) { dot = '<span style="color:#EF4444;">&bull;</span>'; label = 'Not connected'; }
  else { dot = '<span style="color:#D1D5DB;">&bull;</span>'; label = 'Not configured'; }
  let html = '<table style="width:auto;">';
  html += '<tr><td><b>Provider</b></td><td>' + (s.provider || '-') + '</td></tr>';
  html += '<tr><td><b>Status</b></td><td>' + dot + ' ' + label + '</td></tr>';
  if (s.user) html += '<tr><td><b>User</b></td><td>' + s.user + '</td></tr>';
  if (s.role) html += '<tr><td><b>Role</b></td><td>' + s.role + '</td></tr>';
  if (s.error) html += '<tr><td><b>Error</b></td><td><code>' + s.error + '</code></td></tr>';
  html += '</table>';
  document.getElementById('status-box').innerHTML = html;
}
function saveConfig(e) {
  e.preventDefault();
  const body = {
    provider: 'netbird',
    enabled: document.getElementById('nb-enabled').checked,
    netbird: {
      api_url: document.getElementById('nb-api').value.trim(),
      management_url: document.getElementById('nb-mgmt').value.trim(),
      pat: document.getElementById('nb-pat').value
    }
  };
  fetch('/vpn-admin-internal/api/ztna-config', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  }).then(r => r.json()).then(d => {
    document.getElementById('save-result').textContent = d.error ? d.error : 'Saved.';
    loadConfig();
  });
}
function testConnection() {
  fetch('/vpn-admin-internal/api/ztna-validate', {method:'POST'})
    .then(r => r.json()).then(s => renderStatus(s));
}
loadConfig();`

// handleZTNAConfig is the GET/POST endpoint for the persisted ZTNA config.
// GET returns the redacted config + a freshly-validated status so the UI can
// render "connected as …" without a separate round-trip on first load. POST
// merges the submitted body into the on-disk config and re-validates.
func handleZTNAConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := ztna.Load()
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		status := ztna.Validate(ctx, cfg)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"config": cfg.Redacted(),
			"status": status,
		})
		return

	case http.MethodPost:
		var body struct {
			Provider ztna.ProviderKind `json:"provider"`
			Enabled  bool              `json:"enabled"`
			NetBird  *ztna.NetBirdConfig `json:"netbird"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return
		}
		cur, err := ztna.Load()
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		if body.Provider != "" {
			cur.Provider = body.Provider
		}
		cur.Enabled = body.Enabled
		if body.NetBird != nil {
			if cur.NetBird == nil {
				cur.NetBird = &ztna.NetBirdConfig{}
			}
			if body.NetBird.APIURL != "" {
				cur.NetBird.APIURL = body.NetBird.APIURL
			}
			if body.NetBird.ManagementURL != "" {
				cur.NetBird.ManagementURL = body.NetBird.ManagementURL
			}
			// Preserve secret if the submitted form still contains the mask
			// character — the UI prefills with the redacted form so an admin
			// can toggle Enabled without retyping. Empty input clears.
			if !ztna.Masked(body.NetBird.PAT) {
				cur.NetBird.PAT = body.NetBird.PAT
			}
		}
		if err := ztna.Save(cur); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		// Bring routing peer up (or tear it down) to match new config.
		// Provisioning failures are surfaced to the admin so they can
		// fix permissions on the PAT etc., but we still consider the
		// config "saved" — the on-disk state is canonical.
		var routerErr error
		if cur.Enabled {
			routerErr = ensureZTNARouter(r.Context())
		} else {
			routerErr = teardownZTNARouter()
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"status": "saved"}
		if routerErr != nil {
			resp["router_error"] = routerErr.Error()
		}
		json.NewEncoder(w).Encode(resp)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// handleZTNAValidate runs the cheapest authenticated API call against the
// configured provider so the admin can verify credentials with one click.
// Returns the same Status shape as handleZTNAConfig's "status" field.
func handleZTNAValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := ztna.Load()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ztna.Validate(ctx, cfg))
}

// signoutRedirect is the target of every "Sign out" link in the admin UI.
// It builds the OIDC RP-initiated logout URL for the configured Keycloak
// realm, points oauth2-proxy at it via /oauth2/sign_out?rd=…, and 302s
// the browser there. The result: oauth2-proxy clears its session cookie,
// the browser hits Keycloak's end-session endpoint (which clears the SSO
// session), Keycloak redirects back to postLogoutPath. The whole loop is
// a single click for the user.
func signoutRedirect(w http.ResponseWriter, r *http.Request, postLogoutPath string) {
	cfg := config.NewAutomationServerConfig()
	sc, _ := cfg.LoadConfig()
	if sc == nil || sc.Domain == "" {
		http.Error(w, "server not registered", http.StatusServiceUnavailable)
		return
	}
	oauthCfg, err := getVPNAdminOAuthConfig(sc.Domain)
	if err != nil {
		http.Error(w, "oauth config unavailable", http.StatusServiceUnavailable)
		return
	}

	// Build absolute post-logout URL on the same host the user is on, so
	// the loop ends back where they started (not on a hard-coded host).
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	postLogout := scheme + "://" + host + postLogoutPath

	logoutURL := keycloakLogoutURL(oauthCfg, postLogout)
	target := "/oauth2/sign_out?rd=" + url.QueryEscape(logoutURL)
	http.Redirect(w, r, target, http.StatusFound)
}

// handleWhoami is the auth-debug endpoint. Dumps the auth-related headers
// oauth2-proxy forwards and decodes the access token so admins can confirm
// what claims Keycloak emits — useful while role/group setups are settling.
// Available to any authenticated user; only sees their own session.
func handleWhoami(w http.ResponseWriter, r *http.Request) {
	headers := map[string]string{}
	for _, h := range []string{
		"X-Forwarded-Email", "X-Forwarded-User", "X-Forwarded-Groups",
		"X-Forwarded-Preferred-Username", "X-Forwarded-Access-Token",
		"X-Auth-Request-Email", "X-Auth-Request-User", "X-Auth-Request-Groups",
		"X-Auth-Request-Preferred-Username", "X-Auth-Request-Access-Token",
		"Authorization", "Gap-Auth",
	} {
		if v := r.Header.Get(h); v != "" {
			if h == "Authorization" || strings.Contains(h, "Access-Token") {
				headers[h] = "<present, len=" + fmt.Sprint(len(v)) + ">"
			} else {
				headers[h] = v
			}
		}
	}
	var tokenClaims map[string]any
	token := r.Header.Get("X-Forwarded-Access-Token")
	if token == "" {
		token = r.Header.Get("X-Auth-Request-Access-Token")
	}
	if token == "" {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if token != "" {
		parts := strings.Split(token, ".")
		if len(parts) >= 2 {
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				_ = json.Unmarshal(payload, &tokenClaims)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"headers":              headers,
		"is_admin":             isAdmin(r),
		"admin_group_constant": adminGroup,
		"access_token_claims":  tokenClaims,
	})
}
