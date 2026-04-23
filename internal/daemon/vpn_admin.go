package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
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
	// The external VPN admin page is internet-facing and MUST be behind OAuth
	// (Keycloak via oauth2-proxy). The OAuth proxy sets X-Forwarded-Email.
	// If it's missing, the user hasn't authenticated — reject the request.
	//
	// Exception: /vpn-admin/ca.crt is public (CA cert needed before VPN setup).
	email := r.Header.Get("X-Forwarded-Email")
	if email == "" && r.URL.Path != "/vpn-admin/ca.crt" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BitSwan VPN</title>
<style>`+bitswanPageCSS+`</style></head><body>
<div class="header">`+bitswanLogoSVG+`<h1>Sign In Required</h1></div>
<div class="card">
<p>This page requires sign-in via your organization's identity provider.</p>
<p>To enable sign-in, register this automation server with the <a href="https://aoc.bitswan.ai" style="color:#093DF5">Automation Operation Center (AOC)</a>:</p>
<pre><code>bitswan register --aoc-api https://api.bitswan.ai --otp &lt;your-otp&gt;</code></pre>
</div>
<div class="card">
<h2>Already an admin?</h2>
<p>Get your VPN config via CLI:</p>
<pre><code>bitswan vpn bootstrap --device my-laptop</code></pre>
<p>Once connected to the VPN, the admin page is available without sign-in.</p>
</div></body></html>`)
		return
	}

	switch {
	case r.URL.Path == "/vpn-admin" || r.URL.Path == "/vpn-admin/":
		mgr := vpnManager()
		users, _ := mgr.ListDevices()
		cfgPage := config.NewAutomationServerConfig()
		scPage, _ := cfgPage.LoadConfig()
		internalDomain := ""
		srvName := ""
		if scPage != nil {
			internalDomain = scPage.InternalDomain()
			srvName = scPage.Name
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, vpnAdminExternalHTML(email, len(users) == 0, internalDomain, srvName))

	case r.URL.Path == "/vpn-admin/bootstrap":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mgr := vpnManager()
		users, _ := mgr.ListDevices()
		if len(users) > 0 {
			http.Error(w, "VPN bootstrap already completed — ask an admin for a magic link.", http.StatusForbidden)
			return
		}
		conf, err := mgr.GenerateClient(email, "web")
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to generate credentials: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		cfgName := config.NewAutomationServerConfig()
		scName, _ := cfgName.LoadConfig()
		wgFilename := "wireguard.conf"
		if scName != nil && scName.Name != "" {
			wgFilename = scName.Name + ".conf"
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", wgFilename))
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
		// Name the cert file after the automation server
		cfgLoader := config.NewAutomationServerConfig()
		sc, _ := cfgLoader.LoadConfig()
		certFilename := "bitswan-vpn-ca.crt"
		if sc != nil && sc.Name != "" {
			certFilename = sc.Name + "-ca.crt"
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", certFilename))
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
		cfgName := config.NewAutomationServerConfig()
		scName, _ := cfgName.LoadConfig()
		wgFilename := "wireguard.conf"
		if scName != nil && scName.Name != "" {
			wgFilename = scName.Name + ".conf"
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", wgFilename))
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
			email := r.Header.Get("X-Forwarded-Email")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnAdminInternalHTML(email))
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
			cfgMagic := config.NewAutomationServerConfig()
			scMagic, _ := cfgMagic.LoadConfig()
			magicDomain := ""
			if scMagic != nil {
				magicDomain = scMagic.Domain
			}
			claimURL := fmt.Sprintf("https://vpn-admin.%s/vpn-admin/claim/%s", magicDomain, token)
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
		cfgInt := config.NewAutomationServerConfig()
		scInt, _ := cfgInt.LoadConfig()
		certFilename := "bitswan-vpn-ca.crt"
		if scInt != nil && scInt.Name != "" {
			certFilename = scInt.Name + "-ca.crt"
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", certFilename))
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
		deviceID := strings.TrimPrefix(r.URL.Path, "/vpn-admin-internal/api/revoke/")
		mgr := vpnManager()
		if err := mgr.RevokeDevice(deviceID); err != nil {
			http.Error(w, fmt.Sprintf("failed to revoke: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
		return

	case r.URL.Path == "/vpn-admin-internal/api/add-device":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			UserID     string `json:"user_id"`
			DeviceName string `json:"device_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID == "" || body.DeviceName == "" {
			http.Error(w, `{"error":"user_id and device_name are required"}`, http.StatusBadRequest)
			return
		}
		mgr := vpnManager()
		conf, err := mgr.GenerateClient(body.UserID, body.DeviceName)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "created",
			"config": string(conf),
		})
		return
	}

	http.NotFound(w, r)
}

// --- HTML templates ---

// bitswanLogo returns the BitSwan logo SVG sized for page headers.
const bitswanLogoSVG = `<svg width="140" height="33" viewBox="0 0 663.4 154.8" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M612.6,77.7c5.8-5.8,12.4-8.7,19.8-8.7c6.1,0,10.8,1,14,3s4.3,3.7,4.3,7.3v38h12.6V78.6c0-5.6-1.8-9.8-5.4-12.9c-5.6-4.7-13.2-7.1-22.7-7.1c-8.6,0-16.2,3.3-22.7,9.9v-8.6H600v57.5h12.6V77.7z M583.2,117.3V59.8h-12.6V68c-7-6-15.8-9.4-25-9.5c-9,0-16.7,2.6-23,7.9c-3.5,3.1-5.4,7.3-5.4,12.9v18.5c0,5.6,1.8,9.8,5.4,12.9c6.1,5.2,13.8,7.8,23,7.8c9.2,0.2,18.2-3.2,25-9.4v8.1L583.2,117.3z M570.6,98.4c-2.7,3.2-6.2,5.6-10.1,7c-3.8,1.8-8,2.8-12.2,2.9c-4.8,0-9.6-1.3-13.8-3.7c-3.5-2-4.7-3.8-4.7-7.4V80.1c0-3.8,1.1-5.5,4.7-7.4c4.2-2.4,8.9-3.6,13.8-3.6c4.2,0.1,8.4,1,12.2,2.7c4.5,1.8,7.8,4.1,10.1,7V98.4z M491.7,117.3l18.1-57.5h-13.1l-14.2,47.3h-3l-15-47.3h-13.4l-16.3,47.3H432l-13.9-47.3h-13.6l18.2,57.5H443l14.5-42.9l14,42.9H491.7z M360.5,118.4c12.2,0,21.1-1.2,26.5-3.6c6.4-3,9.6-7.6,9.6-13.6v-6.1c0.2-3.8-1.4-7.5-4.2-10c-2.6-2.4-7.2-4.6-14-6.3l-20.1-5.4c-5.6-1.4-9.2-2.8-10.6-4s-2.4-3.3-2.4-6c0-2.9,1-4.9,3-6.2c2.6-1.7,8.4-2.6,17.1-2.6c9.1-0.1,18.1,0.8,27,2.7V46.8c-8.5-1.6-17-2.4-25.6-2.3c-12.7,0-21.8,1.7-27.1,5.3c-4.7,3.1-7,7.1-7,12v5.3c-0.1,3.6,1.3,7,3.9,9.5c3.1,2.9,8.4,5.4,16,7.3l19.2,5.2c9.3,2.3,12.1,4.5,12.1,9.5c0,3.6-1.1,6-3.3,7.2c-3.3,1.7-9.8,2.6-19.4,2.6c-9.5,0.1-18.9-0.9-28.2-2.7v10.7C341.9,117.8,351.1,118.5,360.5,118.4 M323.3,106.7c-4.6,1.3-9.3,1.9-14.1,1.8c-4.7,0-8.4-0.9-11-2.9c-2.4-1.8-3.1-4-3.1-8.6V69.6h28.2v-9.9h-28.1V45.1h-12.6v52.8c0,7.8,1.4,12,5.8,15.7c4.2,3.3,10.6,4.9,19.4,4.9c6.8,0,11.9-0.7,15.6-2.2L323.3,106.7z M266,59.7h-12.6v57.5H266V59.7z M266,36.5h-12.6v13.1H266V36.5z M213,117.3c11.8,0,18-1.3,22.7-5.3c4.5-3.8,6.1-6.5,6.1-12.4v-5c0-6-2.9-10.3-8.7-12.9c-0.9-0.5-1.6-0.8-1.9-0.9l0.4-0.2c5.4-2.2,8-6.3,8-12.4V63c0-5.5-1.4-8.5-5.1-11.8c-4.4-3.7-11.8-5.5-22.4-5.5h-36.3v71.6H213z M215.2,85.9c5,0,8.6,0.8,10.8,2.5s3.3,4.5,3.3,8.4s-1.3,6.5-3.7,8.2c-2.2,1.6-6.3,2.4-12.3,2.4h-25.1V85.9H215.2z M211.2,55.7c6.8,0,11.1,0.9,13.3,2.9c1.7,1.7,2.6,4.2,2.6,7.7c0,3.7-0.9,6.2-2.8,7.7c-2.1,1.5-5,2.3-8.9,2.3h-27.2V55.7H211.2z" fill="#0D1326"/><path d="M0,104.5V5l59.9,50L10.3,92.8C6,96,2.5,100,0,104.5z M90.7,80.6l-21.3,18c-7.1,6.2-10.9,14.5-10.9,24c0,8.6,3.4,16.7,9.4,22.8c6.1,6.1,14.2,9.5,22.8,9.5s16.7-3.4,22.8-9.5c6.1-6.1,9.4-14.2,9.4-22.8s-3.3-16.7-9.4-22.7L90.7,80.6z M118.5,15.8l-25,19.5l0,0L13.1,96.6C4.9,102.6,0,112.3,0,122.5c0,8.6,3.4,16.7,9.4,22.8c6.1,6.1,14.2,9.5,22.8,9.5h40.4c-2.9-1.6-5.6-3.7-8.1-6.1c-7-7-10.8-16.3-10.8-26.1c0-10.7,4.4-20.5,12.5-27.6l46-38.7c6.8-5.8,10.8-14.9,10.8-24C123,26.4,121.5,20.8,118.5,15.8z M57.5,0l36.1,29.3L115.7,12c-0.5-0.6-1.3-1.5-2.3-2.7C107,1.6,97.5,0,90.8,0H57.5z" fill="#093DF5"/></svg>`

// bitswanPageCSS returns the shared CSS for all VPN admin pages, matching the AOC theme.
const bitswanPageCSS = `
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 40px 20px; color: #18181B; background: #FAFAFA; }
.header { display: flex; align-items: center; gap: 16px; margin-bottom: 32px; padding-bottom: 20px; border-bottom: 1px solid #E4E4E7; }
.header h1 { font-size: 20px; font-weight: 600; color: #18181B; margin: 0; flex: 1; }
.sign-out { font-size: 13px; color: #71717A; text-decoration: none; padding: 6px 12px; border: 1px solid #E4E4E7; border-radius: 6px; }
.sign-out:hover { background: #F5F5F6; color: #18181B; }
.card { background: #fff; border: 1px solid #E4E4E7; border-radius: 8px; padding: 24px; margin: 16px 0; }
.card h2 { font-size: 16px; font-weight: 600; margin: 0 0 8px 0; color: #18181B; }
.card p { margin: 8px 0; color: #3F3F46; font-size: 14px; line-height: 1.5; }
.card.highlight { border-color: #093DF5; border-width: 2px; }
button, .btn { background: #093DF5; color: #FAFAFA; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; display: inline-block; text-decoration: none; }
button:hover, .btn:hover { background: #0731C4; }
.tab, .tab:hover { background: none; color: #71717A; border-radius: 0; padding: 10px 18px; }
.tab:hover { color: #18181B; background: none; }
.tab.active, .tab.active:hover { color: #093DF5; background: none; }
.btn-secondary { background: #F5F5F6; color: #093DF5; border: 1px solid #E4E4E7; }
.btn-secondary:hover { background: #E4E4E7; }
input[type=text] { width: 100%%; padding: 10px 12px; margin: 8px 0; border: 1px solid #D1D5DB; border-radius: 6px; font-size: 14px; box-sizing: border-box; }
input[type=text]:focus { outline: none; border-color: #093DF5; box-shadow: 0 0 0 2px rgba(9,61,245,0.15); }
.note { color: #71717A; font-size: 13px; }
.user-info { font-size: 13px; color: #71717A; text-align: right; }
table { width: 100%%; border-collapse: collapse; margin: 12px 0; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #E4E4E7; font-size: 14px; }
th { background: #F5F5F6; font-weight: 600; color: #18181B; }
.link-box { background: #F5F5F6; border: 1px solid #E4E4E7; border-radius: 6px; padding: 12px; margin: 12px 0; word-break: break-all; font-family: monospace; font-size: 13px; }
button.danger { background: #DC2626; }
button.danger:hover { background: #B91C1C; }
code { background: #F5F5F6; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
details { margin-top: 12px; }
details[open] > summary { margin-bottom: 4px; }
summary { cursor: pointer; color: #71717A; font-size: 14px; }
summary b { color: #18181B; }
pre { background: #F5F5F6; border-radius: 6px; padding: 12px; overflow-x: auto; margin: 8px 0; }
pre code { background: none; padding: 0; }
ol { padding-left: 20px; margin: 12px 0; }
ol li { margin: 8px 0; font-size: 14px; color: #3F3F46; line-height: 1.6; }
.tabs { display: flex; gap: 0; border-bottom: 2px solid #E4E4E7; margin-bottom: 20px; }
.tab { padding: 10px 18px; font-size: 14px; font-weight: 500; color: #71717A; cursor: pointer; border: none; background: none; border-bottom: 2px solid transparent; margin-bottom: -2px; transition: all 0.15s; }
.tab:hover { color: #18181B; }
.tab.active { color: #093DF5; border-bottom-color: #093DF5; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.step-num { display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; border-radius: 50%%; background: #093DF5; color: #fff; font-size: 12px; font-weight: 600; margin-right: 8px; flex-shrink: 0; }
.step { display: flex; align-items: flex-start; margin: 14px 0; }
.step-text { font-size: 14px; color: #3F3F46; line-height: 1.6; }
.step-text a { color: #093DF5; }
.install-link { display: inline-flex; align-items: center; gap: 6px; background: #F5F5F6; border: 1px solid #E4E4E7; border-radius: 6px; padding: 8px 14px; text-decoration: none; color: #18181B; font-size: 13px; font-weight: 500; margin: 8px 0; }
.install-link:hover { background: #E4E4E7; }
.tip { background: #EFF6FF; border: 1px solid #BFDBFE; border-radius: 6px; padding: 12px 16px; margin: 12px 0; font-size: 13px; color: #1E40AF; }
`

func vpnAdminExternalHTML(email string, isFirstUser bool, internalDomain string, serverName string) string {
	if serverName == "" {
		serverName = "bitswan-vpn"
	}
	caFilename := serverName + "-ca.crt"
	wgFilename := serverName + ".conf"
	bootstrapSection := ""
	if isFirstUser {
		bootstrapSection = `<div class="card highlight">
<h2>Welcome &mdash; First-Time VPN Setup</h2>
<p>You are the first user. Click below to download your WireGuard VPN configuration.</p>
<button onclick="bootstrap()">Download VPN Config</button>
<p class="note">This option is available only once. After downloading, use the VPN-internal admin page to invite others.</p>
</div>`
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BitSwan VPN</title>
<style>`+bitswanPageCSS+`</style></head><body>
<div class="header">`+bitswanLogoSVG+`<h1>VPN Access</h1><a href="/oauth2/sign_out" class="sign-out">Sign out</a></div>
<div id="vpn-banner" class="card highlight" style="display:none;text-align:center;">
<h2>You're connected to the VPN</h2>
<p>Manage users, create magic links, and add devices from the internal admin.</p>
<a href="" id="vpn-internal-link" class="btn" style="text-decoration:none;">Open Internal Admin &rarr;</a>
</div>
<p class="user-info">Signed in as <b>%s</b></p>
%s
<div class="card">
<h2>Have a Magic Link?</h2>
<p>If someone shared a magic link with you, paste the token below.</p>
<input type="text" id="token-input" placeholder="Paste your token here">
<button onclick="claimToken()">Get VPN Config</button>
</div>
<div class="card">
<h2>VPN Setup Guide</h2>
<p>After downloading your configuration file, follow these steps to connect.</p>
<div class="tabs" id="vpn-tabs">
  <button class="tab active" onclick="showTab('vpn-tabs','vpn-macos')">macOS</button>
  <button class="tab" onclick="showTab('vpn-tabs','vpn-windows')">Windows</button>
  <button class="tab" onclick="showTab('vpn-tabs','vpn-linux')">Linux</button>
</div>

<div id="vpn-macos" class="tab-content active">
  <div class="step"><span class="step-num">1</span><div class="step-text">Install the WireGuard client<br><a href="https://apps.apple.com/app/wireguard/id1451685025" class="install-link">Download from Mac App Store &rarr;</a></div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Open WireGuard and select <b>Import Tunnel(s) from File</b> (or drag the file onto the app icon)</div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Select the downloaded configuration file</div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Click <b>Activate</b> to connect to the VPN</div></div>
</div>

<div id="vpn-windows" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Install the WireGuard client<br><a href="https://www.wireguard.com/install/" class="install-link">Download from wireguard.com &rarr;</a></div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Open WireGuard and click <b>Import tunnel(s) from file</b></div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Select the downloaded configuration file</div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Click <b>Activate</b> to connect to the VPN</div></div>
</div>

<div id="vpn-linux" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Install WireGuard<pre><code>sudo apt install wireguard      # Debian / Ubuntu
sudo dnf install wireguard-tools  # Fedora / RHEL
sudo pacman -S wireguard-tools    # Arch</code></pre></div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Copy the configuration file<pre><code>sudo cp ~/Downloads/wireguard.conf /etc/wireguard/bitswan.conf</code></pre></div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Connect to the VPN<pre><code>sudo wg-quick up bitswan</code></pre></div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Optional: enable auto-connect on boot<pre><code>sudo systemctl enable wg-quick@bitswan</code></pre></div></div>
  <div class="tip">To disconnect: <code>sudo wg-quick down bitswan</code><br><br>
<b>DNS note:</b> If you use a custom DNS resolver (dnsmasq, Unbound, etc.) instead of systemd-resolved, add a forwarding rule for <code>.bswn.internal</code>:<br>
<b>dnsmasq:</b> add <code>server=/bswn.internal/10.8.0.1</code> to your config<br>
<b>Unbound:</b> add a <code>forward-zone</code> for <code>bswn.internal</code> pointing to <code>10.8.0.1</code></div>
</div>
</div>

<div class="card">
<h2>Certificate Trust Setup</h2>
<p>Internal services use HTTPS with a private certificate authority. Install the CA certificate so your browser trusts these connections.</p>
<div style="margin-bottom:16px;">
  <button onclick="downloadCA()">Download CA Certificate</button>
</div>
<div class="tabs" id="cert-tabs">
  <button class="tab active" onclick="showTab('cert-tabs','cert-macos')">macOS</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-windows')">Windows</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-linux')">Linux</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-chrome')">Chrome</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-firefox')">Firefox</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-ios')">iOS</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-android')">Android</button>
</div>

<div id="cert-macos" class="tab-content active">
  <div class="step"><span class="step-num">1</span><div class="step-text">Double-click the downloaded <code>.crt</code> file to open Keychain Access</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">The certificate will be added to your login keychain. Find it by searching for the server name.</div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Double-click the certificate, expand <b>Trust</b>, and set <b>When using this certificate</b> to <b>Always Trust</b></div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Close the dialog and enter your password to confirm</div></div>
  <div class="tip">This trusts the certificate for Safari and Chrome. Firefox uses its own certificate store &mdash; see the Firefox tab.</div>
</div>

<div id="cert-windows" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Double-click the downloaded <code>.crt</code> file</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Click <b>Install Certificate</b></div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Select <b>Local Machine</b> (requires administrator), click Next</div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Select <b>Place all certificates in the following store</b>, click Browse, choose <b>Trusted Root Certification Authorities</b></div></div>
  <div class="step"><span class="step-num">5</span><div class="step-text">Click Next, then Finish. Confirm the security warning.</div></div>
  <div class="tip">This trusts the certificate for Edge and Chrome. Firefox uses its own store &mdash; see the Firefox tab.</div>
</div>

<div id="cert-linux" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Copy the certificate to the system trust store<pre><code>sudo cp ~/Downloads/*-ca.crt /usr/local/share/ca-certificates/</code></pre></div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Update the certificate store<pre><code>sudo update-ca-certificates</code></pre></div></div>
  <div class="tip">This trusts the certificate for <code>curl</code>, <code>wget</code>, and Chromium-based browsers. Firefox uses its own store &mdash; see the Firefox tab.<br><br>
On Fedora/RHEL, use instead:<pre><code>sudo cp ~/Downloads/*-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust</code></pre></div>
</div>

<div id="cert-chrome" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Open Chrome and go to <code>chrome://settings/certificates</code> (or Settings &rarr; Privacy and security &rarr; Security &rarr; Manage certificates)</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Click the <b>Authorities</b> tab</div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Click <b>Import</b> and select the downloaded <code>.crt</code> file</div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Check <b>Trust this certificate for identifying websites</b> and click OK</div></div>
  <div class="tip">On macOS and Windows, Chrome uses the system certificate store, so installing via the OS-level instructions above is usually sufficient. The Chrome import is mainly needed on Linux.</div>
</div>

<div id="cert-firefox" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Open Firefox and go to <code>about:preferences#privacy</code> (or Settings &rarr; Privacy &amp; Security)</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Scroll down to <b>Certificates</b> and click <b>View Certificates</b></div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">In the <b>Authorities</b> tab, click <b>Import</b></div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Select the downloaded <code>.crt</code> file</div></div>
  <div class="step"><span class="step-num">5</span><div class="step-text">Check <b>Trust this CA to identify websites</b> and click OK</div></div>
  <div class="tip">Firefox uses its own certificate store on all platforms. Even if the certificate is trusted at the OS level, you still need to import it into Firefox separately.</div>
</div>

<div id="cert-ios" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Download the CA certificate on your iPhone or iPad (tap the download button above in Safari)</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">A prompt will appear: <b>This website is trying to download a configuration profile.</b> Tap <b>Allow</b>.</div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Open <b>Settings</b> &rarr; <b>General</b> &rarr; <b>VPN &amp; Device Management</b> (or <b>Profiles</b> on older iOS)</div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Tap the downloaded profile and tap <b>Install</b>. Enter your passcode when prompted.</div></div>
  <div class="step"><span class="step-num">5</span><div class="step-text">Go to <b>Settings</b> &rarr; <b>General</b> &rarr; <b>About</b> &rarr; <b>Certificate Trust Settings</b></div></div>
  <div class="step"><span class="step-num">6</span><div class="step-text">Enable full trust for the certificate by toggling it on. Confirm when prompted.</div></div>
  <div class="tip">Both steps are required on iOS: installing the profile (step 4) and enabling trust (step 6). Without step 6, Safari will still show certificate warnings.</div>
</div>

<div id="cert-android" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Download the CA certificate on your Android device (tap the download button above in Chrome)</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Open <b>Settings</b> &rarr; <b>Security</b> (or <b>Security &amp; Privacy</b>) &rarr; <b>Encryption &amp; credentials</b></div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Tap <b>Install a certificate</b> &rarr; <b>CA certificate</b></div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">You may see a warning about network monitoring. Tap <b>Install anyway</b>.</div></div>
  <div class="step"><span class="step-num">5</span><div class="step-text">Select the downloaded <code>.crt</code> file and confirm</div></div>
  <div class="tip">The exact menu path varies by Android version and manufacturer. On Samsung devices: Settings &rarr; Biometrics and Security &rarr; Other security settings &rarr; Install from device storage. On Pixel: Settings &rarr; Security &rarr; More security settings &rarr; Encryption &amp; credentials.</div>
</div>
</div>
<script>
function bootstrap() {
  fetch('/vpn-admin/bootstrap', {method:'POST'})
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t) }); return r.blob(); })
    .then(b => { const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = '%s'; a.click(); location.reload(); })
    .catch(e => alert(e.message));
}
function claimToken() {
  const token = document.getElementById('token-input').value.trim();
  if (!token) { alert('Please enter a token'); return; }
  fetch('/vpn-admin/claim/' + token, {method:'POST'})
    .then(r => { if (!r.ok) return r.text().then(t => { throw new Error(t) }); return r.blob(); })
    .then(b => { const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = '%s'; a.click(); })
    .catch(e => alert(e.message));
}
function downloadCA() {
  const a = document.createElement('a'); a.href = '/vpn-admin/ca.crt'; a.download = '%s'; a.click();
}
// VPN detection: try to reach the internal admin via a hidden image load.
// Images bypass CORS, so if the VPN Traefik responds at all we know VPN is up.
(function() {
  const internalUrl = 'https://vpn-admin.%s/vpn-admin-internal/';
  const banner = document.getElementById('vpn-banner');
  const link = document.getElementById('vpn-internal-link');
  link.href = internalUrl;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3000);
  fetch(internalUrl, {mode:'no-cors', signal:controller.signal})
    .then(() => { clearTimeout(timeout); banner.style.display = ''; })
    .catch(() => { clearTimeout(timeout); });
})();

function showTab(groupId, tabId) {
  const group = document.getElementById(groupId);
  const card = group.closest('.card');
  card.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  group.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  event.target.classList.add('active');
}
</script>
</body></html>`, email, bootstrapSection, wgFilename, wgFilename, caFilename, internalDomain)
}

func vpnAdminClaimHTML(token string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BitSwan VPN</title>
<style>`+bitswanPageCSS+`</style></head><body>
<div class="header">`+bitswanLogoSVG+`<h1>Claim VPN Access</h1></div>
<div class="card">
<p>Click below to download your WireGuard VPN configuration.</p>
<form method="POST" action="/vpn-admin/claim/%s">
<button type="submit">Download VPN Config</button>
</form>
</div></body></html>`, token)
}

func vpnAdminInternalHTML(email string) string {
	signOutLink := ""
	if email != "" {
		signOutLink = `<a href="/oauth2/sign_out" class="sign-out">Sign out</a>`
	}
	userInfo := ""
	if email != "" {
		userInfo = fmt.Sprintf(`<p class="user-info">Signed in as <b>%s</b></p>`, email)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BitSwan VPN Admin</title>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<style>` + bitswanPageCSS + `
body { max-width: 800px; }
.device-row { display: flex; align-items: center; gap: 12px; padding: 12px 0; border-bottom: 1px solid #E4E4E7; }
.device-row:last-child { border-bottom: none; }
.device-info { flex: 1; }
.device-name { font-weight: 600; color: #18181B; }
.device-meta { font-size: 13px; color: #71717A; margin-top: 2px; }
.device-meta code { font-size: 12px; }
.user-group { margin-bottom: 20px; }
.user-group-header { font-weight: 600; color: #093DF5; font-size: 15px; margin-bottom: 8px; padding-bottom: 6px; border-bottom: 2px solid #093DF5; }
.add-device-form { display: flex; gap: 8px; margin-top: 12px; align-items: center; }
.add-device-form input { flex: 1; margin: 0; }
.qr-modal { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.qr-modal-content { background: #fff; border-radius: 12px; padding: 32px; max-width: 400px; width: 90%%; text-align: center; }
.qr-modal-content h3 { margin: 0 0 8px; }
.qr-modal-content p { color: #71717A; font-size: 14px; margin: 8px 0 16px; }
.qr-canvas { margin: 16px auto; }
.qr-instructions { text-align: left; margin: 16px 0; font-size: 13px; color: #3F3F46; }
.qr-instructions ol { padding-left: 20px; margin: 8px 0; }
.qr-instructions li { margin: 4px 0; }
</style></head><body>
<div class="header">` + bitswanLogoSVG + `<h1>VPN Administration</h1>%s</div>
%s

<div class="card">
<h2>My Devices</h2>
<p>Add a new VPN device for your account.</p>
<div class="add-device-form">
  <input type="text" id="add-device" placeholder="Device name (e.g. laptop, phone)">
  <button onclick="addDevice()">Add Device</button>
</div>
<div id="add-result"></div>
</div>

<div class="card">
<h2>Invite User</h2>
<p>Create a one-time magic link (valid 1 hour) for a new user to join the VPN.</p>
<button onclick="generateLink()">Generate Magic Link</button>
<div id="link-result"></div>
</div>

<div class="card">
<h2>VPN Users &amp; Devices</h2>
<div id="users-table">Loading...</div>
</div>

<div class="card">
<h2>Pending Invitations</h2>
<div id="links-table">Loading...</div>
</div>

<div id="qr-overlay" class="qr-modal" style="display:none" onclick="if(event.target===this)closeQR()">
<div class="qr-modal-content">
  <h3 id="qr-title">Scan with WireGuard</h3>
  <p id="qr-subtitle">Open the WireGuard app on your phone and scan this QR code.</p>
  <div id="qr-code" class="qr-canvas"></div>
  <div class="qr-instructions">
    <details><summary><b>iOS</b></summary>
    <ol><li>Open WireGuard app</li><li>Tap <b>+</b> &rarr; <b>Create from QR code</b></li><li>Point camera at QR code</li><li>Name the tunnel and tap <b>Save</b></li></ol></details>
    <details><summary><b>Android</b></summary>
    <ol><li>Open WireGuard app</li><li>Tap <b>+</b> &rarr; <b>Scan from QR code</b></li><li>Point camera at QR code</li><li>Name the tunnel and tap <b>Create Tunnel</b></li></ol></details>
  </div>
  <button onclick="closeQR()">Close</button>
</div>
</div>

<script>
function generateLink() {
  fetch('/vpn-admin-internal/api/magic-link', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({created_by:'admin'})})
    .then(r => r.json())
    .then(d => {
      document.getElementById('link-result').innerHTML =
        '<div class="link-box">' + d.claim_url + '</div>' +
        '<button class="btn-secondary" onclick="navigator.clipboard.writeText(\'' + d.claim_url + '\').then(()=>this.textContent=\'Copied!\')">Copy Link</button>' +
        '<span class="note" style="margin-left:8px;">Expires in ' + d.expires + '</span>';
      loadLinks();
    });
}

const currentUserEmail = '%s';
function addDevice() {
  const userId = currentUserEmail;
  const deviceName = document.getElementById('add-device').value.trim();
  if (!userId) { alert('Not signed in'); return; }
  if (!deviceName) { alert('Enter a device name (e.g. laptop, phone)'); return; }
  fetch('/vpn-admin-internal/api/add-device', {method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({user_id: userId, device_name: deviceName})})
    .then(r => r.json())
    .then(d => {
      if (d.error) { alert(d.error); return; }
      document.getElementById('add-result').innerHTML =
        '<div class="tip" style="margin-top:12px;">Device <b>' + deviceName + '</b> created for <b>' + userId + '</b></div>';
      // Show QR code
      showQR(d.config, userId + ' / ' + deviceName);
      loadUsers();
      document.getElementById('add-user').value = '';
      document.getElementById('add-device').value = '';
    })
    .catch(e => alert(e.message));
}

function showQR(config, title) {
  const qr = qrcode(0, 'M');
  qr.addData(config);
  qr.make();
  document.getElementById('qr-code').innerHTML = qr.createSvgTag(6, 0);
  document.getElementById('qr-title').textContent = 'Scan with WireGuard';
  document.getElementById('qr-subtitle').textContent = title;
  document.getElementById('qr-overlay').style.display = 'flex';
}
function closeQR() { document.getElementById('qr-overlay').style.display = 'none'; }

function loadUsers() {
  fetch('/vpn-admin-internal/api/users').then(r=>r.json()).then(users => {
    if (!users.length) { document.getElementById('users-table').innerHTML = '<p class="note">No users yet.</p>'; return; }
    // Group by user_id
    const grouped = {};
    users.forEach(u => {
      if (!grouped[u.user_id]) grouped[u.user_id] = [];
      grouped[u.user_id].push(u);
    });
    let html = '';
    Object.keys(grouped).sort().forEach(userId => {
      html += '<div class="user-group"><div class="user-group-header">' + userId + '</div>';
      grouped[userId].forEach(d => {
        const issued = d.issued_at ? new Date(d.issued_at).toLocaleDateString() : '';
        html += '<div class="device-row">';
        html += '<div class="device-info"><div class="device-name">' + d.device_name + '</div>';
        html += '<div class="device-meta">IP: <code>' + d.ip + '</code> &middot; Added: ' + issued + '</div></div>';
        html += '<button class="danger" style="padding:6px 12px;font-size:13px;" onclick="revokeDevice(\'' + d.device_id + '\')">Revoke</button>';
        html += '</div>';
      });
      html += '</div>';
    });
    document.getElementById('users-table').innerHTML = html;
  });
}

function loadLinks() {
  fetch('/vpn-admin-internal/api/magic-link').then(r=>r.json()).then(links => {
    if (!links.length) { document.getElementById('links-table').innerHTML = '<p class="note">No pending invitations.</p>'; return; }
    let html = '<table><tr><th>Created By</th><th>Expires</th><th>Token</th></tr>';
    links.forEach(l => {
      html += '<tr><td>'+l.created_by+'</td><td>'+new Date(l.expires_at).toLocaleString()+'</td>';
      html += '<td style="font-family:monospace;font-size:12px">'+l.token.substring(0,12)+'&hellip;</td></tr>';
    });
    html += '</table>';
    document.getElementById('links-table').innerHTML = html;
  });
}

function revokeDevice(deviceId) {
  if (!confirm('Revoke device ' + deviceId + '?')) return;
  fetch('/vpn-admin-internal/api/revoke/' + encodeURIComponent(deviceId), {method:'POST'})
    .then(() => loadUsers());
}

loadUsers();
loadLinks();
</script></body></html>`, signOutLink, userInfo, email)
}
