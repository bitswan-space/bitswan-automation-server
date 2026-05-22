package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/siem"
	"github.com/bitswan-space/bitswan-workspaces/internal/vpn"
)


// handleBailey serves the internal Bailey (behind the VPN/ZTNA
// tunnel). Used by admins to configure NetBird, the SIEM forwarder, and
// trust-store certificates. Device-level access lives in the ZTNA
// provider's own dashboard, not here.
//
// The whole page is admin-only with two intentional exceptions:
//   - /favicon.svg: served unauthenticated so browsers don't 403 in the
//     network panel.
//   - /ca.crt: any authenticated user can pull the CA cert so they can
//     trust internal HTTPS — useful as a fallback to the public admin's
//     download (which is the primary path for the un-tunnelled).
func (s *Server) handleBailey(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/bailey/favicon.svg" {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fmt.Fprint(w, bitswanFaviconSVG)
		return
	}

	email := r.Header.Get("X-Forwarded-Email")

	// CA cert is the only data path callable by non-admins.
	if r.URL.Path == "/bailey/ca.crt" {
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
	}

	// Whoami stays available to any authenticated user as a diagnostic so
	// they can confirm their identity headers without admin privileges.
	if r.URL.Path == "/bailey/api/whoami" {
		handleWhoami(w, r)
		return
	}

	// Run the MFA gate (TOTP + device cookie) on the admin pages too —
	// otherwise the admin landing would be reachable with just the OIDC
	// session. Two bypasses:
	//
	//   /bailey/api/* — JSON callers; a 303 from the gate is
	//     useless to a fetch(). Admin-status is still enforced below.
	//   /bailey/signout — sign-out must always work even if the
	//     user's TOTP or device cookie is missing. Refusing to log them
	//     out because they failed the gate would be backwards.
	if !strings.HasPrefix(r.URL.Path, "/bailey/api/") &&
		r.URL.Path != "/bailey/signout" &&
		!enforceMFAGate(w, r) {
		return
	}

	// Chrome wrap is now applied by chromeWrapMiddleware at server
	// entry — every response from this handler flows back through
	// the middleware, which handles wrap / marker-propagation /
	// iframe-escape uniformly. No per-handler wrap call needed.

	admin := isAdmin(r)

	// /bailey/ landing:
	//   - admin → 303 redirect to /workspaces (keeps URL stable)
	//   - non-admin → 200 render of their devices page directly
	// Either way the user is past the MFA gate before landing here.
	if r.URL.Path == "/bailey" || r.URL.Path == "/bailey/" {
		if admin {
			http.Redirect(w, r, "/bailey/workspaces", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "devices", false))
		return
	}

	// Sign-out works for any authenticated identity. Done up here so we
	// don't gate the user out of their own log-out path.
	if r.URL.Path == "/bailey/signout" {
		signoutRedirect(w, r, "/")
		return
	}

	// /devices and /recovery are self-service for the signed-in user.
	// Non-admins can see them; the underlying /2fa-gate/account/* pages
	// only ever read/write the caller's own records.
	switch r.URL.Path {
	case "/bailey/devices", "/bailey/devices/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "devices", admin))
			return
		}
	case "/bailey/recovery", "/bailey/recovery/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "recovery", admin))
			return
		}
	case "/bailey/endpoints", "/bailey/endpoints/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "endpoints", admin))
			return
		}
	case "/bailey/approvals", "/bailey/approvals/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "approvals", admin))
			return
		}
	case "/bailey/notifications", "/bailey/notifications/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "notifications", admin))
			return
		}
	case "/bailey/api/notifications-count":
		if r.Method == http.MethodGet {
			handleNotificationsCount(w, r)
			return
		}
	case "/bailey/api/endpoints":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, callerGroups := identityFromHeaders(r)
		listing, err := buildEndpointListing(email, callerGroups, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listing)
		return

	// Workspaces page + API: any authenticated user can see/create
	// workspaces. Listing is filtered per caller (only workspaces
	// the caller has any ACL grant on). POST creates a new workspace
	// with the caller as owner of its editor + gitops endpoints.
	case "/bailey/workspaces", "/bailey/workspaces/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "workspaces", admin))
			return
		}
	case "/bailey/api/workspaces":
		switch r.Method {
		case http.MethodGet:
			handleListAccessibleWorkspaces(w, r, email)
			return
		case http.MethodPost:
			s.handleCreateWorkspaceFromBaileyAdmin(w, r, email)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	// Everything below this point is admin-only.
	if !requireAdmin(w, r) {
		return
	}

	switch {
	case r.URL.Path == "/bailey/siem" || r.URL.Path == "/bailey/siem/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "siem", true))
			return
		}

	case r.URL.Path == "/bailey/certs" || r.URL.Path == "/bailey/certs/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "certs", true))
			return
		}

	case r.URL.Path == "/bailey/signout":
		// See the external /bailey/signout case — we use "/" because
		// that's what AOC registers as the post-logout URI on the
		// Keycloak client. The docs catch-all redirects from "/" to
		// /bailey/ when the request is on the internal host.
		signoutRedirect(w, r, "/")
		return

		// (api/workspaces handler is above — open to any signed-in user.)

	case r.URL.Path == "/bailey/api/siem-config":
		if !requireAdmin(w, r) {
			return
		}
		if r.Method == http.MethodGet {
			cfg := siem.Default().Config()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"config": cfg.Redacted(),
				"stats":  siem.Default().Stats(),
			})
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				URL        string `json:"url"`
				AuthHeader string `json:"auth_header"`
				Enabled    bool   `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
				return
			}
			cur := siem.Default().Config()
			cur.URL = body.URL
			cur.Enabled = body.Enabled
			// The UI prefills the auth header with the redacted form so the
			// admin can toggle Enabled without re-entering the secret. If the
			// submitted value still contains the mask character, treat it as
			// "no change". Anything else (including empty) overrides.
			if !strings.Contains(body.AuthHeader, "…") {
				cur.AuthHeader = body.AuthHeader
			}
			if err := siem.Default().Configure(cur); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
			if err := ensureFluentBit(); err != nil {
				// Config saved, but the reload failed — surface it so the
				// admin doesn't think it's live.
				http.Error(w, fmt.Sprintf(`{"error":"config saved; fluent-bit reload failed: %s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
			return
		}

	case r.URL.Path == "/bailey/api/siem-test":
		if !requireAdmin(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		siem.Default().EmitTest()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
		return

	case r.URL.Path == "/bailey/api/cert-authorities":
		if !requireAdmin(w, r) {
			return
		}
		if r.Method == http.MethodGet {
			cas, err := listCertAuthorities()
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(cas)
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				Name        string `json:"name"`
				PEMContents string `json:"pem"` // raw PEM, not base64
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.PEMContents == "" {
				http.Error(w, `{"error":"name and pem are required"}`, http.StatusBadRequest)
				return
			}
			if err := addCertAuthorityPEM(body.Name, []byte(body.PEMContents)); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "added"})
			return
		}

	case strings.HasPrefix(r.URL.Path, "/bailey/api/cert-authorities/"):
		if !requireAdmin(w, r) {
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/bailey/api/cert-authorities/")
		if err := removeCertAuthorityFile(name); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
		return

	case r.URL.Path == "/bailey/api/hostname-certs":
		if !requireAdmin(w, r) {
			return
		}
		if r.Method == http.MethodGet {
			entries, err := listHostnameCerts()
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(entries)
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				Hostname string `json:"hostname"`
				CertPEM  string `json:"cert_pem"`
				KeyPEM   string `json:"key_pem"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Hostname == "" || body.CertPEM == "" || body.KeyPEM == "" {
				http.Error(w, `{"error":"hostname, cert_pem and key_pem are required"}`, http.StatusBadRequest)
				return
			}
			if err := installHostnameCert(body.Hostname, []byte(body.CertPEM), []byte(body.KeyPEM)); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "installed"})
			return
		}

	case strings.HasPrefix(r.URL.Path, "/bailey/api/hostname-certs/"):
		if !requireAdmin(w, r) {
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		host := strings.TrimPrefix(r.URL.Path, "/bailey/api/hostname-certs/")
		if err := removeHostnameCert(host); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
		return
	}

	http.NotFound(w, r)
}

// --- HTML templates ---

// bitswanLogo returns the BitSwan logo SVG sized for page headers.
const bitswanLogoSVG = `<svg width="140" height="33" viewBox="0 0 663.4 154.8" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M612.6,77.7c5.8-5.8,12.4-8.7,19.8-8.7c6.1,0,10.8,1,14,3s4.3,3.7,4.3,7.3v38h12.6V78.6c0-5.6-1.8-9.8-5.4-12.9c-5.6-4.7-13.2-7.1-22.7-7.1c-8.6,0-16.2,3.3-22.7,9.9v-8.6H600v57.5h12.6V77.7z M583.2,117.3V59.8h-12.6V68c-7-6-15.8-9.4-25-9.5c-9,0-16.7,2.6-23,7.9c-3.5,3.1-5.4,7.3-5.4,12.9v18.5c0,5.6,1.8,9.8,5.4,12.9c6.1,5.2,13.8,7.8,23,7.8c9.2,0.2,18.2-3.2,25-9.4v8.1L583.2,117.3z M570.6,98.4c-2.7,3.2-6.2,5.6-10.1,7c-3.8,1.8-8,2.8-12.2,2.9c-4.8,0-9.6-1.3-13.8-3.7c-3.5-2-4.7-3.8-4.7-7.4V80.1c0-3.8,1.1-5.5,4.7-7.4c4.2-2.4,8.9-3.6,13.8-3.6c4.2,0.1,8.4,1,12.2,2.7c4.5,1.8,7.8,4.1,10.1,7V98.4z M491.7,117.3l18.1-57.5h-13.1l-14.2,47.3h-3l-15-47.3h-13.4l-16.3,47.3H432l-13.9-47.3h-13.6l18.2,57.5H443l14.5-42.9l14,42.9H491.7z M360.5,118.4c12.2,0,21.1-1.2,26.5-3.6c6.4-3,9.6-7.6,9.6-13.6v-6.1c0.2-3.8-1.4-7.5-4.2-10c-2.6-2.4-7.2-4.6-14-6.3l-20.1-5.4c-5.6-1.4-9.2-2.8-10.6-4s-2.4-3.3-2.4-6c0-2.9,1-4.9,3-6.2c2.6-1.7,8.4-2.6,17.1-2.6c9.1-0.1,18.1,0.8,27,2.7V46.8c-8.5-1.6-17-2.4-25.6-2.3c-12.7,0-21.8,1.7-27.1,5.3c-4.7,3.1-7,7.1-7,12v5.3c-0.1,3.6,1.3,7,3.9,9.5c3.1,2.9,8.4,5.4,16,7.3l19.2,5.2c9.3,2.3,12.1,4.5,12.1,9.5c0,3.6-1.1,6-3.3,7.2c-3.3,1.7-9.8,2.6-19.4,2.6c-9.5,0.1-18.9-0.9-28.2-2.7v10.7C341.9,117.8,351.1,118.5,360.5,118.4 M323.3,106.7c-4.6,1.3-9.3,1.9-14.1,1.8c-4.7,0-8.4-0.9-11-2.9c-2.4-1.8-3.1-4-3.1-8.6V69.6h28.2v-9.9h-28.1V45.1h-12.6v52.8c0,7.8,1.4,12,5.8,15.7c4.2,3.3,10.6,4.9,19.4,4.9c6.8,0,11.9-0.7,15.6-2.2L323.3,106.7z M266,59.7h-12.6v57.5H266V59.7z M266,36.5h-12.6v13.1H266V36.5z M213,117.3c11.8,0,18-1.3,22.7-5.3c4.5-3.8,6.1-6.5,6.1-12.4v-5c0-6-2.9-10.3-8.7-12.9c-0.9-0.5-1.6-0.8-1.9-0.9l0.4-0.2c5.4-2.2,8-6.3,8-12.4V63c0-5.5-1.4-8.5-5.1-11.8c-4.4-3.7-11.8-5.5-22.4-5.5h-36.3v71.6H213z M215.2,85.9c5,0,8.6,0.8,10.8,2.5s3.3,4.5,3.3,8.4s-1.3,6.5-3.7,8.2c-2.2,1.6-6.3,2.4-12.3,2.4h-25.1V85.9H215.2z M211.2,55.7c6.8,0,11.1,0.9,13.3,2.9c1.7,1.7,2.6,4.2,2.6,7.7c0,3.7-0.9,6.2-2.8,7.7c-2.1,1.5-5,2.3-8.9,2.3h-27.2V55.7H211.2z" fill="#0D1326"/><path d="M0,104.5V5l59.9,50L10.3,92.8C6,96,2.5,100,0,104.5z M90.7,80.6l-21.3,18c-7.1,6.2-10.9,14.5-10.9,24c0,8.6,3.4,16.7,9.4,22.8c6.1,6.1,14.2,9.5,22.8,9.5s16.7-3.4,22.8-9.5c6.1-6.1,9.4-14.2,9.4-22.8s-3.3-16.7-9.4-22.7L90.7,80.6z M118.5,15.8l-25,19.5l0,0L13.1,96.6C4.9,102.6,0,112.3,0,122.5c0,8.6,3.4,16.7,9.4,22.8c6.1,6.1,14.2,9.5,22.8,9.5h40.4c-2.9-1.6-5.6-3.7-8.1-6.1c-7-7-10.8-16.3-10.8-26.1c0-10.7,4.4-20.5,12.5-27.6l46-38.7c6.8-5.8,10.8-14.9,10.8-24C123,26.4,121.5,20.8,118.5,15.8z M57.5,0l36.1,29.3L115.7,12c-0.5-0.6-1.3-1.5-2.3-2.7C107,1.6,97.5,0,90.8,0H57.5z" fill="#0D1326"/></svg>`

// bitswanFavicon is an SVG data URI of the BitSwan logo mark used as favicon on all pages.
// bitswanFavicon links to /bailey/favicon.svg served by the handler.
const bitswanFavicon = `<link rel="icon" type="image/svg+xml" href="/bailey/favicon.svg">`

// bitswanFaviconSVG is the raw SVG content for the favicon.
const bitswanFaviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 124 155"><path d="M0,104.5V5l59.9,50L10.3,92.8C6,96,2.5,100,0,104.5z M90.7,80.6l-21.3,18c-7.1,6.2-10.9,14.5-10.9,24c0,8.6,3.4,16.7,9.4,22.8c6.1,6.1,14.2,9.5,22.8,9.5s16.7-3.4,22.8-9.5c6.1-6.1,9.4-14.2,9.4-22.8s-3.3-16.7-9.4-22.7L90.7,80.6z M118.5,15.8l-25,19.5l0,0L13.1,96.6C4.9,102.6,0,112.3,0,122.5c0,8.6,3.4,16.7,9.4,22.8c6.1,6.1,14.2,9.5,22.8,9.5h40.4c-2.9-1.6-5.6-3.7-8.1-6.1c-7-7-10.8-16.3-10.8-26.1c0-10.7,4.4-20.5,12.5-27.6l46-38.7c6.8-5.8,10.8-14.9,10.8-24C123,26.4,121.5,20.8,118.5,15.8z M57.5,0l36.1,29.3L115.7,12c-0.5-0.6-1.3-1.5-2.3-2.7C107,1.6,97.5,0,90.8,0H57.5z" fill="#0D1326"/></svg>`

// bitswanPageCSS returns the shared CSS for all Bailey pages, matching the AOC theme.
const bitswanPageCSS = `
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 700px; margin: 0 auto; padding: 40px 20px; color: #18181B; background: #FAFAFA; }
.header { display: flex; align-items: center; gap: 16px; margin-bottom: 32px; padding-bottom: 20px; border-bottom: 1px solid #E4E4E7; }
.header h1 { font-size: 20px; font-weight: 600; color: #18181B; margin: 0; flex: 1; }
.sign-out { font-size: 13px; color: #71717A; text-decoration: none; padding: 6px 12px; border: 1px solid #E4E4E7; border-radius: 6px; }
.sign-out:hover { background: #F5F5F6; color: #18181B; }
.breadcrumb { font-size: 13px; color: #71717A; margin-bottom: 16px; }
.breadcrumb a { color: #093DF5; text-decoration: none; }
.breadcrumb a:hover { text-decoration: underline; }
.breadcrumb span { margin: 0 6px; }
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


// sidebarCSS is extra CSS for the sidebar layout used by internal pages.
const sidebarCSS = `
body { max-width: none; padding: 0; display: flex; min-height: 100vh; }
.sidebar { width: 240px; background: #fff; border-right: 1px solid #E4E4E7; padding: 24px 0; flex-shrink: 0; display: flex; flex-direction: column; }
.sidebar-logo { padding: 0 20px 20px; border-bottom: 1px solid #E4E4E7; margin-bottom: 8px; }
.sidebar-nav { flex: 1; }
.sidebar-nav a { display: flex; align-items: center; gap: 10px; padding: 10px 20px; color: #3F3F46; text-decoration: none; font-size: 14px; font-weight: 500; border-left: 3px solid transparent; }
.sidebar-nav a:hover { background: #F5F5F6; color: #18181B; }
.sidebar-nav a.active { background: #EFF6FF; color: #093DF5; border-left-color: #093DF5; }
.sidebar-section { padding: 20px 20px 6px; font-size: 11px; font-weight: 600; color: #A1A1AA; text-transform: uppercase; letter-spacing: 0.5px; border-top: 1px solid #F4F4F5; margin-top: 8px; }
.sidebar-footer { padding: 16px 20px; border-top: 1px solid #E4E4E7; font-size: 13px; color: #71717A; }
.sidebar-footer a { color: #71717A; text-decoration: none; }
.sidebar-footer a:hover { color: #18181B; }
.main { flex: 1; padding: 32px 40px; overflow-y: auto; }
.main h1 { font-size: 22px; font-weight: 600; margin: 0 0 24px; color: #18181B; }
.main table { white-space: nowrap; }
`

func vpnInternalPage(email string, groups []string, page string, admin bool) string {
	cfgSlug := config.NewAutomationServerConfig()
	scSlug, _ := cfgSlug.LoadConfig()
	serverName := "BitSwan"
	if scSlug != nil && scSlug.Name != "" {
		serverName = scSlug.Name
	}

	active := func(p string) string {
		if p == page {
			return " active"
		}
		return ""
	}

	// Page content per section
	var pageContent, pageTitle, pageScript string

	switch page {
	case "workspaces":
		pageTitle = "Workspaces"
		pageContent = `
<div class="card" id="workspaces-box" style="margin-top:0;">
  <h2>Your workspaces</h2>
  <p class="note">Workspaces you own or have been granted access to. Click the editor link to open it.</p>
  <div id="workspaces-list"><p class="note">Loading…</p></div>
</div>

<div class="card">
  <h2>Create a new workspace</h2>
  <p class="note">You'll be the owner of the editor and gitops endpoints. You can share access from those endpoints' share pages later.</p>
  <form id="create-form" onsubmit="return createWorkspace(event)" style="display:flex;gap:8px;align-items:center;">
    <input type="text" id="new-name" placeholder="my-workspace" pattern="[a-z][a-z0-9-]{1,32}"
      title="lowercase, alphanumeric + hyphens, starts with a letter, 2-33 chars"
      style="padding:6px 8px;font-family:ui-monospace,monospace;" required>
    <button type="submit" style="background:#093DF5;color:white;border:0;padding:8px 16px;border-radius:4px;cursor:pointer;font-size:14px;">Create</button>
  </form>
  <p id="create-status" class="note" style="margin-top:10px;"></p>
</div>`
		pageScript = `
function loadList() {
  fetch('/bailey/api/workspaces', {credentials:'same-origin'}).then(r => r.ok ? r.json() : {workspaces:[]}).then(d => {
    const box = document.getElementById('workspaces-list');
    if (!d.workspaces || !d.workspaces.length) {
      box.innerHTML = '<p class="note">You don\'t have access to any workspaces yet. Create one below, or wait for someone to share one with you.</p>';
      return;
    }
    let html = '<table style="width:100%;border-collapse:collapse;">';
    html += '<thead><tr style="text-align:left;border-bottom:1px solid #E4E4E7;"><th style="padding:8px 0;">Name</th><th>Your role</th><th>Links</th></tr></thead><tbody>';
    for (const w of d.workspaces) {
      const role = w.is_owner ? 'owner' : (w.editor_role || w.gitops_role || 'access');
      html += '<tr style="border-top:1px solid #F4F4F5;">'
        + '<td style="padding:8px 0;"><b>' + w.name + '</b></td>'
        + '<td>' + role + '</td>'
        + '<td><a href="' + w.editor_url + '" target="_blank" style="color:#093DF5;text-decoration:none;margin-right:12px;">Editor →</a>'
        + '<a href="' + w.gitops_url + '" target="_blank" style="color:#093DF5;text-decoration:none;">GitOps →</a></td>'
        + '</tr>';
    }
    html += '</tbody></table>';
    box.innerHTML = html;
  }).catch(e => {
    document.getElementById('workspaces-list').innerHTML = '<p class="note" style="color:#b00020;">Couldn\'t load workspaces: ' + e + '</p>';
  });
}
function createWorkspace(e) {
  e.preventDefault();
  const name = document.getElementById('new-name').value.trim();
  const statusEl = document.getElementById('create-status');
  statusEl.textContent = 'Creating ' + name + '… (this can take 30-60s while the editor + gitops images come up)';
  statusEl.style.color = '#71717A';
  fetch('/bailey/api/workspaces', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name: name})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      statusEl.textContent = 'Created. Editor: ' + d.editor_url;
      statusEl.style.color = '#0a7d24';
      document.getElementById('new-name').value = '';
      loadList();
    } else {
      statusEl.textContent = 'Failed: ' + (d.error || 'unknown error');
      statusEl.style.color = '#b00020';
    }
  }).catch(e => {
    statusEl.textContent = 'Failed: ' + e;
    statusEl.style.color = '#b00020';
  });
  return false;
}
loadList();`

	case "devices":
		pageTitle = "Devices"
		pageContent = `
<div class="card" style="margin-top:0;">
  <h2>Paired devices</h2>
  <p class="note">Browsers you've trusted to access this server. Removing a device immediately invalidates its session.</p>
  <iframe src="/2fa-gate/account/devices" style="width:100%;min-height:480px;border:0;"></iframe>
</div>`

	case "approvals":
		pageTitle = "Device approvals"
		pageContent = `
<div class="card" style="margin-top:0;">
  <h2>Pending device approvals</h2>
  <p class="note">Someone signing in from a new browser sees a 6-digit code. Ask them to read it to you, type it here, and approve.</p>
  <iframe id="approvals-iframe" src="/2fa-gate/approve" style="width:100%;min-height:600px;border:0;"></iframe>
</div>`

	case "notifications":
		pageTitle = "Notifications"
		pageContent = notificationsPageHTML(email, groups, admin)

	case "endpoints":
		pageTitle = "Endpoints"
		pageContent = `
<div class="card" style="margin-top:0;">
  <h2>Protected endpoints on this server</h2>
  <p class="note">Every endpoint that's been registered shows up here. If you own one you can manage its sharing. If you're an access grantee you see the endpoint but not who else has access. Server owners see everything in read-only audit mode.</p>
  <div id="ep-list"><p class="note">Loading…</p></div>
</div>`
		pageScript = `
fetch('/bailey/api/endpoints', {credentials:'same-origin'}).then(r => r.json()).then(d => {
  const box = document.getElementById('ep-list');
  if (d.is_server_owner) {
    box.insertAdjacentHTML('beforebegin', '<p class="note"><b>Server-owner audit view</b> — you see every endpoint registered on this server, read-only.</p>');
  }
  if (!d.endpoints || !d.endpoints.length) {
    box.innerHTML = '<p class="note">No endpoints visible to you. Create a workspace or wait for someone to share one.</p>';
    return;
  }
  let html = '<table style="width:100%;border-collapse:collapse;">';
  html += '<thead><tr style="text-align:left;border-bottom:1px solid #E4E4E7;"><th style="padding:8px 0;">Endpoint</th><th>Owner</th><th>Your role</th><th>Grants</th><th></th></tr></thead><tbody>';
  for (const e of d.endpoints) {
    let grantsHtml = '<span class="note">—</span>';
    if (e.grants && e.grants.length) {
      grantsHtml = e.grants.map(g =>
        '<div style="font-size:13px;color:#3F3F46;"><code>' + g.principal_value + '</code> <span class="note">(' + g.principal_type + ', ' + g.role + ')</span></div>'
      ).join('');
    } else if (e.caller_role === 'access') {
      grantsHtml = '<span class="note">visible to owners only</span>';
    }
    const manageBtn = (e.caller_role === 'owner')
      ? '<a href="/2fa-gate/share/' + encodeURIComponent(e.hostname) + '" style="color:#093DF5;text-decoration:none;">Manage →</a>'
      : '';
    html += '<tr style="border-bottom:1px solid #F4F4F5;">'
      + '<td style="padding:8px 4px;"><b>' + e.hostname + '</b><br><span class="note">' + (e.display_name || '') + '</span></td>'
      + '<td><code>' + e.owner_email + '</code></td>'
      + '<td>' + e.caller_role + '</td>'
      + '<td>' + grantsHtml + '</td>'
      + '<td style="text-align:right;">' + manageBtn + '</td>'
      + '</tr>';
  }
  html += '</tbody></table>';
  box.innerHTML = html;
}).catch(e => {
  document.getElementById('ep-list').innerHTML = '<p class="note" style="color:#b00020;">Couldn\'t load endpoints: ' + e + '</p>';
});`

	case "recovery":
		pageTitle = "Recovery (TOTP)"
		pageContent = `
<div class="card" style="margin-top:0;">
  <h2>Authenticator-based recovery</h2>
  <p class="note">TOTP is required for admins. Optional (but recommended) for regular users — lets you re-pair a fresh browser without bothering an admin.</p>
  <iframe src="/2fa-gate/account/2fa?_bailey_iframe=1" style="width:100%;min-height:380px;border:0;"></iframe>
</div>`

	case "siem":
		pageTitle = "SIEM Integration"
		pageContent = `
<div class="card" style="margin-top:0;">
<h2>Forward events to a SIEM</h2>
<p class="note">All VPN session events (and, soon, container logs) are streamed to the configured endpoint as newline-delimited JSON over HTTPS. Events are batched for efficiency and retried on transient failures.</p>
<form id="siem-form" onsubmit="saveConfig(event)">
  <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;">Endpoint URL</label>
  <input type="text" id="siem-url" placeholder="https://siem.example.com/collector">
  <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;">Auth header (optional)</label>
  <input type="text" id="siem-auth" placeholder="Authorization: Bearer &lt;token&gt;  — or just the token">
  <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;"><input type="checkbox" id="siem-enabled"> Enable forwarding</label>
  <div style="margin-top:16px;display:flex;gap:8px;">
    <button type="submit">Save</button>
    <button type="button" class="btn-secondary" onclick="sendTest()">Send test event</button>
  </div>
  <div id="save-result" class="note" style="margin-top:8px;"></div>
</form>
</div>

<div class="card">
<h2>Status</h2>
<div id="stats"></div>
</div>`
		pageScript = `
function loadConfig() {
  fetch('/bailey/api/siem-config').then(r=>r.json()).then(d => {
    document.getElementById('siem-url').value = d.config.url || '';
    document.getElementById('siem-auth').value = d.config.auth_header || '';
    document.getElementById('siem-enabled').checked = !!d.config.enabled;
    renderStats(d.stats);
  });
}
function renderStats(s) {
  if (!s) { document.getElementById('stats').innerHTML = ''; return; }
  const dot = s.configured ? '<span style="color:#22C55E;">&bull;</span> configured' : '<span style="color:#D1D5DB;">&bull;</span> not configured';
  let html = '<table style="width:auto;">';
  html += '<tr><td><b>Status</b></td><td>' + dot + '</td></tr>';
  html += '<tr><td><b>Queued</b></td><td>' + (s.queued||0) + '</td></tr>';
  html += '<tr><td><b>Sent</b></td><td>' + (s.sent||0) + '</td></tr>';
  html += '<tr><td><b>Dropped</b></td><td>' + (s.dropped||0) + '</td></tr>';
  html += '<tr><td><b>Failed</b></td><td>' + (s.failed||0) + '</td></tr>';
  if (s.last_error) html += '<tr><td><b>Last error</b></td><td><code>' + s.last_error + '</code></td></tr>';
  html += '</table>';
  document.getElementById('stats').innerHTML = html;
}
function saveConfig(e) {
  e.preventDefault();
  const body = {
    url: document.getElementById('siem-url').value.trim(),
    auth_header: document.getElementById('siem-auth').value,
    enabled: document.getElementById('siem-enabled').checked
  };
  fetch('/bailey/api/siem-config', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)})
    .then(r => r.json())
    .then(d => {
      document.getElementById('save-result').textContent = d.status === 'saved' ? 'Saved.' : (d.error || 'Error');
      loadConfig();
    });
}
function sendTest() {
  fetch('/bailey/api/siem-test', {method:'POST'}).then(() => {
    document.getElementById('save-result').textContent = 'Test event queued. Watch stats.';
    setTimeout(loadConfig, 1500);
  });
}
loadConfig();
setInterval(() => fetch('/bailey/api/siem-config').then(r=>r.json()).then(d => renderStats(d.stats)), 5000);`

	case "certs":
		pageTitle = "Certificates"
		// Build cert-trust instructions block (same tabs as the external admin).
		caFilename := "bitswan-vpn-ca.crt"
		if scSlug != nil && scSlug.Name != "" {
			caFilename = scSlug.Name + "-ca.crt"
		}
		trustBlock := fmt.Sprintf(certTrustInstructionsHTML, caFilename, caFilename, caFilename, caFilename)

		adminBlock := ""
		if admin {
			adminBlock = certsAdminBlockHTML
		}
		pageContent = trustBlock + adminBlock

		pageScript = fmt.Sprintf(`
const caFilename = '%s';
function downloadCA() {
  const a = document.createElement('a');
  a.href = '/bailey/ca.crt';
  a.download = caFilename;
  a.click();
}
function showTab(groupId, tabId) {
  const group = document.getElementById(groupId);
  const card = group.closest('.card') || group.parentElement;
  card.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  group.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  group.querySelectorAll('.tab').forEach(el => {
    if (el.getAttribute('onclick') && el.getAttribute('onclick').includes(tabId)) el.classList.add('active');
  });
}
%s
`, caFilename, certsAdminScript(admin))
	}

	// admin is always true for the internal admin (handler gates non-admins),
	// but we keep the parameter so future shared layouts can vary the nav.
	_ = admin

	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8">`+bitswanFavicon+`<title>%s — %s VPN</title>
<style>`+bitswanPageCSS+sidebarCSS+`
</style></head><body>
<div class="sidebar">
  <div class="sidebar-logo">`+bitswanLogoSVG+`</div>
  <nav class="sidebar-nav">
    <a href="/bailey/workspaces" class="%s">Workspaces</a>
    <a href="/bailey/endpoints" class="%s">Endpoints</a>
    <a href="/bailey/notifications" class="%s" id="nav-notifications">Notifications<span id="nav-notifications-badge" style="display:none;background:#DC2626;color:#fff;border-radius:10px;padding:1px 7px;font-size:11px;margin-left:6px;"></span></a>
    <a href="/bailey/devices" class="%s">Devices</a>
    <a href="/bailey/recovery" class="%s">Recovery (TOTP)</a>
    <div class="sidebar-section">Admin</div>
    <a href="/bailey/approvals" class="%s">Approvals</a>
    <a href="/bailey/certs" class="%s">Certificates</a>
    <a href="/bailey/siem" class="%s">SIEM</a>
  </nav>
  <script>
    (function(){
      function poll(){
        fetch('/bailey/api/notifications-count',{credentials:'same-origin'})
          .then(r=>r.ok?r.json():{count:0})
          .then(d=>{
            var b=document.getElementById('nav-notifications-badge');
            if(d&&d.count>0){ b.textContent=d.count; b.style.display='inline-block'; }
            else{ b.style.display='none'; }
          }).catch(function(){});
      }
      poll(); setInterval(poll, 4000);
    })();
  </script>
  <div class="sidebar-footer">
    <div style="margin-bottom:4px;">%s</div>
    <a href="/bailey/signout">Sign out</a>
  </div>
</div>
<div class="main">
  <h1>%s</h1>
  %s
</div>
<script>%s</script>
</body></html>`,
		pageTitle, serverName,
		active("workspaces"), active("endpoints"), active("notifications"),
		active("devices"), active("recovery"),
		active("approvals"), active("certs"), active("siem"),
		email, pageTitle, pageContent, pageScript)
}
