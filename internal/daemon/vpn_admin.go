package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/vpn"
)

func magicLinkStore() *vpn.MagicLinkStore {
	homeDir, _ := os.UserHomeDir()
	return vpn.NewMagicLinkStore(filepath.Join(homeDir, ".config", "bitswan"))
}

// handleVPNAdminExternal serves the external VPN admin page.
// This page is exposed on the internet (via external Traefik) and is OAuth-protected.
// It allows: first-admin bootstrap download, magic link claim + credential download.
func (s *Server) handleVPNAdminExternal(w http.ResponseWriter, r *http.Request) {
	// The external VPN admin page is internet-facing. It only serves:
	// - Magic link claim (token-validated, created by admins on the internal page)
	// - CA certificate download (public, needed to trust internal HTTPS)
	// Bootstrap is NOT available externally — use the VPN-internal page or CLI.

	switch {
	case r.URL.Path == "/vpn-admin" || r.URL.Path == "/vpn-admin/":
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, vpnAdminExternalHTML())

	case r.URL.Path == "/vpn-admin/bootstrap":
		// Bootstrap is only available from the VPN-internal page or CLI.
		// On the external page, require OAuth (X-Forwarded-Email must be set
		// by an upstream OAuth proxy like oauth2-proxy).
		email := r.Header.Get("X-Forwarded-Email")
		if email == "" {
			http.Error(w, "Bootstrap requires authentication. Use the VPN-internal admin page, the CLI (bitswan vpn bootstrap), or configure OAuth.", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mgr := vpnManager()
		users, _ := mgr.ListDevices()
		if len(users) > 0 {
			http.Error(w, "bootstrap already completed — use a magic link instead", http.StatusForbidden)
			return
		}
		conf, err := mgr.GenerateClient(email, "web")
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to generate credentials: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=wireguard.conf")
		w.Write(conf)

	case r.URL.Path == "/vpn-admin/ca.crt":
		// Download the VPN CA certificate for trusting internal HTTPS
		homeDir, _ := os.UserHomeDir()
		caMgr := vpn.NewCAManager(filepath.Join(homeDir, ".config", "bitswan", "vpn"))
		caCert, err := caMgr.CACertPEM()
		if err != nil || len(caCert) == 0 {
			http.Error(w, "VPN CA certificate not available", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=bitswan-vpn-ca.crt")
		w.Write(caCert)

	case strings.HasPrefix(r.URL.Path, "/vpn-admin/claim/"):
		// Magic link claim: validate token, generate credentials
		token := strings.TrimPrefix(r.URL.Path, "/vpn-admin/claim/")
		if token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		store := magicLinkStore()
		if err := store.Validate(token); err != nil {
			http.Error(w, fmt.Sprintf("invalid token: %v", err), http.StatusForbidden)
			return
		}

		if r.Method == http.MethodGet {
			// Show confirmation page
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnAdminClaimHTML(token))
			return
		}

		// POST: actually claim and generate credentials
		email := r.Header.Get("X-Forwarded-Email")
		if email == "" {
			email = "user-" + token[:8]
		}
		if err := store.Claim(token, email); err != nil {
			http.Error(w, fmt.Sprintf("failed to claim token: %v", err), http.StatusForbidden)
			return
		}
		mgr := vpnManager()
		conf, err := mgr.GenerateClient(email, "web")
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to generate credentials: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=wireguard.conf")
		w.Write(conf)

	default:
		http.NotFound(w, r)
	}
}

// handleVPNAdminInternal serves the internal VPN admin page (behind VPN).
// Allows: generating magic links, listing users, revoking users.
func (s *Server) handleVPNAdminInternal(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/vpn-admin-internal" || r.URL.Path == "/vpn-admin-internal/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnAdminInternalHTML())
			return
		}

	case r.URL.Path == "/vpn-admin-internal/api/magic-link":
		if r.Method == http.MethodPost {
			var body struct {
				CreatedBy string `json:"created_by"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.CreatedBy == "" {
				body.CreatedBy = "admin"
			}
			store := magicLinkStore()
			token, err := store.Create(body.CreatedBy)
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to create magic link: %v", err), http.StatusInternalServerError)
				return
			}
			// Build the claim URL using the external admin hostname
			domain := os.Getenv("BITSWAN_GITOPS_DOMAIN")
			claimURL := fmt.Sprintf("https://vpn-admin.%s/vpn-admin/claim/%s", domain, token)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"token":     token,
				"claim_url": claimURL,
				"expires":   "1 hour",
			})
			return
		}
		if r.Method == http.MethodGet {
			store := magicLinkStore()
			links, _ := store.List()
			if links == nil {
				links = []vpn.MagicLink{}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(links)
			return
		}

	case r.URL.Path == "/vpn-admin-internal/ca.crt":
		// Download the VPN CA certificate
		homeDir, _ := os.UserHomeDir()
		caMgr := vpn.NewCAManager(filepath.Join(homeDir, ".config", "bitswan", "vpn"))
		caCert, err := caMgr.CACertPEM()
		if err != nil || len(caCert) == 0 {
			http.Error(w, "VPN CA certificate not available", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=bitswan-vpn-ca.crt")
		w.Write(caCert)
		return

	case r.URL.Path == "/vpn-admin-internal/api/users":
		mgr := vpnManager()
		users, _ := mgr.ListDevices()
		if users == nil {
			users = []vpn.VPNDevice{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
		return

	case strings.HasPrefix(r.URL.Path, "/vpn-admin-internal/api/revoke/"):
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		userID := strings.TrimPrefix(r.URL.Path, "/vpn-admin-internal/api/revoke/")
		mgr := vpnManager()
		if err := mgr.RevokeDevice(userID); err != nil {
			http.Error(w, fmt.Sprintf("failed to revoke: %v", err), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
		return
	}

	http.NotFound(w, r)
}

// --- HTML templates ---

func vpnAdminExternalHTML() string {
	return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BitSwan VPN</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; color: #333; }
h1 { color: #1a73e8; }
.card { background: #f8f9fa; border-radius: 8px; padding: 24px; margin: 20px 0; }
button { background: #1a73e8; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px; }
button:hover { background: #1557b0; }
.note { color: #666; font-size: 14px; }
</style></head><body>
<h1>BitSwan VPN Access</h1>
<div class="card">
<h2>Have a Magic Link?</h2>
<p>If someone shared a magic link with you, paste the token below.</p>
<input type="text" id="token-input" placeholder="Paste your token here" style="width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px;">
<button onclick="claimToken()">Get VPN Config</button>
</div>
<div class="card">
<h2>Trust Internal HTTPS</h2>
<p>To avoid browser certificate warnings for internal services, install the BitSwan VPN CA certificate.</p>
<button onclick="downloadCA()" style="background:#34a853;">Download CA Certificate</button>
<details style="margin-top:12px;">
<summary class="note" style="cursor:pointer;">Installation instructions</summary>
<div style="margin-top:8px;font-size:13px;">
<p><b>macOS:</b> Double-click the .crt file, add to Keychain, then trust it (Always Trust).</p>
<p><b>Windows:</b> Double-click the .crt, Install Certificate → Local Machine → Trusted Root Certification Authorities.</p>
<p><b>Linux:</b> <code>sudo cp bitswan-vpn-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates</code></p>
<p><b>Firefox:</b> Settings → Privacy & Security → View Certificates → Import.</p>
<p><b>Corporate CA:</b> If your organization uses its own CA, upload it via the cert authority API.</p>
</div>
</details>
</div>
<p class="note">First-time setup: use the CLI (<code>bitswan vpn bootstrap</code>) or the VPN-internal admin page.</p>
<script>
function claimToken() {
  const token = document.getElementById('token-input').value.trim();
  if (!token) { alert('Please enter a token'); return; }
  fetch('/vpn-admin/claim/' + token, {method:'POST'})
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t) }); return r.blob(); })
    .then(b => { const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = 'wireguard.conf'; a.click(); })
    .catch(e => alert(e.message));
}
function downloadCA() {
  const a = document.createElement('a'); a.href = '/vpn-admin/ca.crt'; a.download = 'bitswan-vpn-ca.crt'; a.click();
}
</script></body></html>`
}

func vpnAdminClaimHTML(token string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Claim VPN Access</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; }
h1 { color: #1a73e8; }
.card { background: #f8f9fa; border-radius: 8px; padding: 24px; margin: 20px 0; }
button { background: #1a73e8; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px; }
</style></head><body>
<h1>Claim VPN Access</h1>
<div class="card">
<p>Click below to download your WireGuard VPN configuration.</p>
<form method="POST" action="/vpn-admin/claim/%s">
<button type="submit">Download VPN Config</button>
</form>
</div></body></html>`, token)
}

func vpnAdminInternalHTML() string {
	return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VPN Admin</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #333; }
h1 { color: #1a73e8; }
.card { background: #f8f9fa; border-radius: 8px; padding: 24px; margin: 20px 0; }
button { background: #1a73e8; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; }
button:hover { background: #1557b0; }
button.danger { background: #dc3545; }
button.danger:hover { background: #c82333; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #dee2e6; }
th { background: #e9ecef; }
.link-box { background: #fff; border: 1px solid #1a73e8; border-radius: 4px; padding: 12px; margin: 12px 0; word-break: break-all; font-family: monospace; }
#status { margin: 10px 0; color: #28a745; }
</style></head><body>
<h1>VPN Administration</h1>

<div class="card">
<h2>Generate Magic Link</h2>
<p>Create a one-time link (valid 1 hour) for a new user to download VPN credentials.</p>
<button onclick="generateLink()">Generate Magic Link</button>
<div id="link-result"></div>
</div>

<div class="card">
<h2>VPN Users</h2>
<div id="users-table">Loading...</div>
</div>

<div class="card">
<h2>Active Magic Links</h2>
<div id="links-table">Loading...</div>
</div>

<script>
function generateLink() {
  fetch('/vpn-admin-internal/api/magic-link', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({created_by:'admin'})})
    .then(r => r.json())
    .then(d => {
      document.getElementById('link-result').innerHTML =
        '<div class="link-box">' + d.claim_url + '</div>' +
        '<button onclick="navigator.clipboard.writeText(\'' + d.claim_url + '\').then(()=>alert(\'Copied!\'))">Copy to Clipboard</button>' +
        '<p style="color:#666">Expires in ' + d.expires + '</p>';
      loadLinks();
    });
}
function loadUsers() {
  fetch('/vpn-admin-internal/api/users').then(r=>r.json()).then(users => {
    if (!users.length) { document.getElementById('users-table').innerHTML = '<p>No users yet.</p>'; return; }
    let html = '<table><tr><th>User</th><th>IP</th><th>Public Key</th><th></th></tr>';
    users.forEach(u => {
      html += '<tr><td>'+u.id+'</td><td>'+u.ip+'</td><td style="font-family:monospace;font-size:12px">'+u.public_key+'</td>';
      html += '<td><button class="danger" onclick="revokeUser(\''+u.id+'\')">Revoke</button></td></tr>';
    });
    html += '</table>';
    document.getElementById('users-table').innerHTML = html;
  });
}
function loadLinks() {
  fetch('/vpn-admin-internal/api/magic-link').then(r=>r.json()).then(links => {
    if (!links.length) { document.getElementById('links-table').innerHTML = '<p>No active links.</p>'; return; }
    let html = '<table><tr><th>Created By</th><th>Expires</th><th>Token (first 8)</th></tr>';
    links.forEach(l => {
      html += '<tr><td>'+l.created_by+'</td><td>'+new Date(l.expires_at).toLocaleString()+'</td><td style="font-family:monospace">'+l.token.substring(0,8)+'...</td></tr>';
    });
    html += '</table>';
    document.getElementById('links-table').innerHTML = html;
  });
}
function revokeUser(id) {
  if (!confirm('Revoke VPN access for ' + id + '?')) return;
  fetch('/vpn-admin-internal/api/revoke/' + id, {method:'POST'}).then(() => loadUsers());
}
loadUsers();
loadLinks();
</script></body></html>`
}
