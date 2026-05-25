package daemon

import (
	"encoding/json"
	"fmt"
	"html"
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
		!strings.HasPrefix(r.URL.Path, "/bailey/static/") &&
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

	// Static assets (vendored JS/CSS) are public to any authenticated
	// caller — the bundles aren't sensitive and admin pages depend on
	// them. Done before the per-path switch so it covers any path
	// prefix under /bailey/static/.
	if strings.HasPrefix(r.URL.Path, "/bailey/static/") {
		handleBaileyStatic(w, r)
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
		// Legacy URL — kept as a redirect to the merged workspaces page
		// for anyone with a bookmark. Plain 301 so browsers update.
		http.Redirect(w, r, "/bailey/workspaces", http.StatusMovedPermanently)
		return
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
	case "/bailey/api/devices":
		if r.Method == http.MethodGet {
			handleBaileyDevicesAPI(w, r, email)
			return
		}
	case "/bailey/api/devices/remove":
		if r.Method == http.MethodPost {
			handleBaileyDevicesRemoveAPI(w, r, email)
			return
		}
	case "/bailey/api/approvals":
		if r.Method == http.MethodGet {
			_, groups := identityFromHeaders(r)
			handleBaileyApprovalsAPI(w, r, email, isAdminGroups(groups))
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
	case "/bailey/api/workspaces/empty-trash":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleEmptyTrash(w, r, email)
		return
	}
	// Per-workspace trash + restore — path: /bailey/api/workspaces/{name}/{action}.
	// Handled outside the switch because Go's net/http switch is exact-match;
	// rather than introducing a router for two endpoints, just prefix-match here.
	if strings.HasPrefix(r.URL.Path, "/bailey/api/workspaces/") && r.Method == http.MethodPost {
		rest := strings.TrimPrefix(r.URL.Path, "/bailey/api/workspaces/")
		parts := strings.Split(rest, "/")
		if len(parts) == 2 {
			workspaceName, action := parts[0], parts[1]
			switch action {
			case "trash":
				s.handleTrashWorkspace(w, r, email, workspaceName)
				return
			case "restore":
				s.handleRestoreWorkspace(w, r, email, workspaceName)
				return
			case "update":
				s.handleUpdateWorkspace(w, r, email, workspaceName)
				return
			}
		}
	}

	// Everything below this point is admin-only.
	if !requireAdmin(w, r) {
		return
	}

	switch {
	case r.URL.Path == "/bailey/api/admin/devices":
		if r.Method == http.MethodGet {
			handleAdminDevicesAPI(w, r)
			return
		}
	case r.URL.Path == "/bailey/api/admin/devices/remove":
		if r.Method == http.MethodPost {
			handleAdminDeviceRemoveAPI(w, r)
			return
		}
	case r.URL.Path == "/bailey/api/admin/network-map":
		if r.Method == http.MethodGet {
			handleNetworkMapAPI(w, r)
			return
		}
	case r.URL.Path == "/bailey/map" || r.URL.Path == "/bailey/map/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "map", true))
			return
		}
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

	case r.URL.Path == "/bailey/updates" || r.URL.Path == "/bailey/updates/":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, vpnInternalPage(email, identityGroups(r), "updates", true))
			return
		}

	case r.URL.Path == "/bailey/api/admin/default-images":
		switch r.Method {
		case http.MethodGet:
			s.handleAdminDefaultImagesGet(w, r)
			return
		case http.MethodPost:
			s.handleAdminDefaultImagesPost(w, r, email)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
<style>
  .ws-toolbar {
    display:flex; align-items:center; gap:12px; margin:0 0 18px;
  }
  .ws-toolbar h1 { margin:0; flex:1; }
  .ws-new-btn {
    background:#093DF5; color:#fff; border:0; padding:9px 16px;
    border-radius:8px; cursor:pointer; font-size:14px; font-weight:500;
  }
  .ws-new-btn:hover { background:#0731C4; }

  .ws-card {
    background:#fff; border:1px solid #E4E4E7; border-radius:10px;
    padding:18px 20px; margin-bottom:18px;
  }
  .ws-card-head {
    display:flex; align-items:center; gap:14px; margin-bottom:14px;
    border-bottom:1px solid #F4F4F5; padding-bottom:12px;
  }
  .ws-card-head h2 {
    margin:0; font-size:16px; font-weight:600; color:#18181B; flex:1;
  }
  .ws-card-head .role {
    font-size:11px; padding:2px 8px; border-radius:999px;
    background:#F4F4F5; color:#52525B; text-transform:uppercase;
    letter-spacing:0.4px; font-weight:600;
  }
  .ws-card-head .role.owner { background:#DBEAFE; color:#1E40AF; }
  .ws-editor-btn {
    display:inline-flex; align-items:center; gap:8px;
    background:#18181B; color:#fff; border:0;
    padding:8px 14px; border-radius:8px; cursor:pointer; font-size:13px;
    text-decoration:none; font-weight:500;
  }
  .ws-editor-btn:hover { background:#27272A; }

  .ws-apps {
    display:grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap:12px;
  }
  .ws-app-card {
    display:block; padding:14px; border:1px solid #E4E4E7; border-radius:8px;
    text-decoration:none; color:inherit; background:#fff;
    transition: border-color 0.12s, box-shadow 0.12s;
  }
  .ws-app-card:hover {
    border-color:#93C5FD; box-shadow: 0 1px 3px rgba(9,61,245,0.08);
  }
  .ws-app-card .name {
    font-size:14px; font-weight:600; color:#18181B; margin-bottom:4px;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  }
  .ws-app-card .host {
    font-size:12px; color:#71717A; font-family:ui-monospace,monospace;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  }
  .ws-app-empty { font-size:13px; color:#A1A1AA; padding:8px 4px; }
  .ws-trash-btn {
    background:transparent; border:1px solid #E4E4E7; color:#71717A;
    padding:6px 10px; border-radius:6px; cursor:pointer; font-size:12px;
    margin-left:8px;
  }
  .ws-trash-btn:hover { border-color:#FCA5A5; color:#B91C1C; background:#FEF2F2; }
  .ws-card.trashed { opacity:0.65; background:#FAFAFA; border-style:dashed; }
  .ws-card.trashed .ws-card-head h2::after {
    content:' (trashed)'; color:#A1A1AA; font-weight:normal; font-size:13px;
  }
  .trash-section { margin-top:32px; }
  .trash-section h2 {
    font-size:14px; color:#71717A; text-transform:uppercase;
    letter-spacing:0.04em; margin:0 0 12px;
  }
  .trash-empty-btn {
    margin-top:12px; padding:8px 14px; border:1px solid #FCA5A5;
    background:#fff; color:#B91C1C; border-radius:6px; cursor:pointer;
    font-size:13px; font-weight:500;
  }
  .trash-empty-btn:hover { background:#FEF2F2; }

  .ws-modal-backdrop {
    position:fixed; inset:0; background:rgba(15,23,42,0.55);
    display:none; align-items:center; justify-content:center; z-index:1000;
  }
  .ws-modal-backdrop.open { display:flex; }
  .ws-modal-card {
    background:#fff; border-radius:12px; padding:22px;
    width:min(420px, 92vw); box-shadow:0 24px 60px rgba(0,0,0,0.25);
  }
  .ws-modal-card h2 { margin:0 0 6px; font-size:17px; font-weight:600; }
  .ws-modal-card .note { color:#71717A; font-size:13px; margin-bottom:14px; }
  .ws-modal-card input {
    width:100%; padding:9px 12px; border:1px solid #E4E4E7; border-radius:8px;
    font-size:14px; box-sizing:border-box; font-family:ui-monospace,monospace;
  }
  .ws-modal-card .actions {
    display:flex; justify-content:flex-end; gap:8px; margin-top:14px;
  }
  .ws-modal-card button {
    padding:9px 16px; border-radius:8px; border:0; cursor:pointer;
    font-size:13px; font-weight:500;
  }
  .ws-modal-card .cancel { background:#F4F4F5; color:#3F3F46; }
  .ws-modal-card .create { background:#093DF5; color:#fff; }
  .ws-modal-card .create:hover { background:#0731C4; }
  .ws-modal-card .status { font-size:12px; color:#71717A; margin-top:10px; min-height:14px; }
</style>

<div class="ws-toolbar">
  <h1>Your workspaces</h1>
  <button class="ws-new-btn" onclick="document.getElementById('ws-modal').classList.add('open');document.getElementById('ws-modal-input').focus();">+ New workspace</button>
</div>

<div id="workspaces-list"><p class="note">Loading…</p></div>

<div class="trash-section" id="trash-section" style="display:none;">
  <h2>Trash</h2>
  <div id="trash-list"></div>
  <div id="trash-empty-wrap" style="display:none;">
    <button class="trash-empty-btn" onclick="document.getElementById('empty-trash-modal').classList.add('open');document.getElementById('empty-trash-input').focus();">Empty trash…</button>
  </div>
</div>

<div class="ws-modal-backdrop" id="empty-trash-modal" onclick="if(event.target===this){this.classList.remove('open')}">
  <div class="ws-modal-card">
    <h2>Empty trash</h2>
    <p class="note">This permanently deletes every trashed workspace you own — containers, volumes, gitops folders, AOC registrations. There is no undo.</p>
    <p class="note">Type <code>empty trash</code> to confirm:</p>
    <form id="empty-trash-form">
      <input type="text" id="empty-trash-input" placeholder="empty trash" autocomplete="off">
      <div class="actions">
        <button type="button" class="cancel" onclick="document.getElementById('empty-trash-modal').classList.remove('open');document.getElementById('empty-trash-input').value='';">Cancel</button>
        <button type="submit" class="create" style="background:#B91C1C;" id="empty-trash-confirm" disabled>Empty trash</button>
      </div>
      <pre id="empty-trash-log" style="display:none;margin-top:10px;padding:8px;background:#f6f7f9;border:1px solid #e4e4e7;border-radius:6px;font-size:11px;max-height:200px;overflow:auto;font-family:ui-monospace,monospace;"></pre>
    </form>
  </div>
</div>

<div class="ws-modal-backdrop" id="ws-modal" onclick="if(event.target===this){this.classList.remove('open')}">
  <div class="ws-modal-card">
    <h2>New workspace</h2>
    <p class="note">You'll be the owner of every endpoint this workspace creates (dashboard, automations).</p>
    <form id="ws-create-form">
      <input type="text" id="ws-modal-input" placeholder="my-workspace" pattern="[a-z][a-z0-9-]{1,32}"
        title="lowercase, alphanumeric + hyphens, starts with a letter, 2-33 chars" required autocomplete="off">
      <div class="actions">
        <button type="button" class="cancel" onclick="document.getElementById('ws-modal').classList.remove('open')">Cancel</button>
        <button type="submit" class="create">Create</button>
      </div>
      <p class="status" id="ws-modal-status"></p>
    </form>
  </div>
</div>`
		pageScript = `
function escapeHTML(s){ return String(s||'').replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]); }
// Friendly app-card name: prefix-stripped, capitalised.
function appName(host, workspace) {
  var label = host.split('.')[0];
  var tail = label.replace(workspace + '-', '');
  return tail.charAt(0).toUpperCase() + tail.slice(1);
}
function loadList() {
  // Pull workspaces + endpoints in parallel. Workspaces tells us
  // which names exist (and our role); endpoints gives us the per-app
  // hostnames we can render as cards.
  Promise.all([
    fetch('/bailey/api/workspaces', {credentials:'same-origin'}).then(r => r.ok ? r.json() : {workspaces:[]}),
    fetch('/bailey/api/endpoints', {credentials:'same-origin'}).then(r => r.ok ? r.json() : {endpoints:[]})
  ]).then(function(arr){
    var wsResp = arr[0], epResp = arr[1];
    var workspaces = (wsResp.workspaces || []).slice();
    var endpoints = (epResp.endpoints || []).filter(function(e){
      return e.caller_role && e.caller_role !== 'none' && e.caller_role !== '';
    });
    // Map workspace name → { editor: ep, apps: [ep, ...] }.
    // Workspace name matches the longest known-workspace prefix of the hostname label.
    var wsNames = workspaces.map(function(w){ return w.name; });
    wsNames.sort(function(a,b){ return b.length - a.length; }); // longest first so we match greedily

    var byWs = {};
    workspaces.forEach(function(w){ byWs[w.name] = { ws: w, dashboard: null, apps: [] }; });

    endpoints.forEach(function(ep){
      var label = ep.hostname.split('.')[0];
      var match = null;
      for (var i = 0; i < wsNames.length; i++) {
        var name = wsNames[i];
        if (label === name || label.indexOf(name + '-') === 0) { match = name; break; }
      }
      if (!match) return;
      var tail = label === match ? '' : label.slice(match.length + 1);
      if (tail === 'gitops') return;                     // no gitops links — per UX policy
      if (tail === 'editor') return;                     // editor is gone; ignore stale entries
      if (tail === 'dashboard') { byWs[match].dashboard = ep; return; }
      byWs[match].apps.push(ep);
    });

    var box = document.getElementById('workspaces-list');
    var trashBox = document.getElementById('trash-list');
    var trashSection = document.getElementById('trash-section');
    if (!workspaces.length) {
      box.innerHTML = '<div class="ws-card"><p class="note">No workspaces visible to you. Create one with the button above, or wait for someone to share one with you.</p></div>';
      trashSection.style.display = 'none';
      return;
    }
    function renderCard(w, opts){
      var bucket = byWs[w.name];
      var role = w.is_owner ? 'owner' : (w.editor_role || w.gitops_role || 'access');
      var appsHTML;
      // Trashed workspaces: containers are down, so the apps + dashboard
      // links would 502. Skip rendering them and show a restore hint
      // instead — keeps the trash row visually quieter and avoids
      // dead-end clicks.
      if (opts.trashed) {
        appsHTML = '<p class="ws-app-empty">Containers are stopped. Restore to bring them back up, or empty the trash to delete everything permanently.</p>';
      } else if (bucket.apps.length) {
        appsHTML = '<div class="ws-apps">' + bucket.apps.map(function(ep){
          var url = 'https://' + ep.hostname + '/';
          return '<a class="ws-app-card" href="' + escapeHTML(url) + '" target="_blank" rel="noopener">' +
            '<div class="name">' + escapeHTML(appName(ep.hostname, w.name)) + '</div>' +
            '<div class="host">' + escapeHTML(ep.hostname) + '</div>' +
          '</a>';
        }).join('') + '</div>';
      } else {
        appsHTML = '<p class="ws-app-empty">No deployed automations yet.</p>';
      }
      var actionBtn;
      if (opts.trashed) {
        actionBtn = w.is_owner
          ? '<button class="ws-editor-btn" data-action="restore" data-ws="' + escapeHTML(w.name) + '">Restore</button>'
          : '<span class="note">Trashed by owner.</span>';
      } else {
        actionBtn = bucket.dashboard
          ? '<a class="ws-editor-btn" href="https://' + escapeHTML(bucket.dashboard.hostname) + '/" target="_blank" rel="noopener">Open ↗</a>'
          : '<span class="note">Dashboard not deployed.</span>';
      }
      var trashBtn = (w.is_owner && !opts.trashed)
        ? '<button class="ws-trash-btn" data-action="trash" data-ws="' + escapeHTML(w.name) + '" title="Move to trash (stops all containers, keeps data)">🗑 Trash</button>'
        : '';
      var updateBtn = (w.is_owner && !opts.trashed)
        ? '<button class="ws-trash-btn" data-action="update" data-ws="' + escapeHTML(w.name) + '" title="Pull current default images and recreate containers">↻ Update</button>'
        : '';
      return '<div class="ws-card ' + (opts.trashed ? 'trashed' : '') + '" data-ws="' + escapeHTML(w.name) + '">' +
        '<div class="ws-card-head">' +
          '<h2>' + escapeHTML(w.name) + '</h2>' +
          '<span class="role ' + (role === 'owner' ? 'owner' : '') + '">' + escapeHTML(role) + '</span>' +
          actionBtn +
          updateBtn +
          trashBtn +
        '</div>' +
        appsHTML +
        '</div>';
    }

    var active = workspaces.filter(function(w){ return !w.is_trashed; });
    var trashed = workspaces.filter(function(w){ return w.is_trashed; });

    box.innerHTML = active.length
      ? active.map(function(w){ return renderCard(w, {trashed:false}); }).join('')
      : '<div class="ws-card"><p class="note">All your workspaces are in the trash. Restore one or empty the trash to start fresh.</p></div>';

    if (trashed.length) {
      trashBox.innerHTML = trashed.map(function(w){ return renderCard(w, {trashed:true}); }).join('');
      // Empty-trash button is shown when the caller owns at least one trashed
      // workspace — otherwise they have nothing to empty.
      var ownsAnyTrashed = trashed.some(function(w){ return w.is_owner; });
      document.getElementById('trash-empty-wrap').style.display = ownsAnyTrashed ? '' : 'none';
      trashSection.style.display = '';
    } else {
      trashSection.style.display = 'none';
    }

    // Wire up update buttons. POST streams NDJSON progress events
    // (pull + recreate); render them in a small log row below the
    // card so the operator can see what's happening without blocking
    // the whole page.
    document.querySelectorAll('[data-action="update"]').forEach(function(btn){
      btn.addEventListener('click', function(){
        var ws = btn.getAttribute('data-ws');
        if (!confirm('Update "' + ws + '"? This pulls the current default images and recreates containers — workspace will briefly be unavailable.')) return;
        var card = btn.closest('.ws-card');
        var logRow = document.createElement('pre');
        logRow.style.cssText = 'margin:10px 0 0;padding:8px;background:#f6f7f9;border:1px solid #e4e4e7;border-radius:6px;font-size:11px;max-height:180px;overflow:auto;font-family:ui-monospace,monospace;';
        logRow.textContent = 'Updating…\n';
        card.appendChild(logRow);
        btn.disabled = true;
        btn.textContent = 'Updating…';
        fetch('/bailey/api/workspaces/' + encodeURIComponent(ws) + '/update', {
          method:'POST', credentials:'same-origin'
        }).then(function(r){
          if (!r.ok && r.status !== 200) throw new Error('HTTP ' + r.status);
          var reader = r.body.getReader();
          var decoder = new TextDecoder();
          var partial = '';
          function readLoop(){
            return reader.read().then(function(chunk){
              if (chunk.done) {
                if (partial.trim()) handleLine(partial);
                return;
              }
              partial += decoder.decode(chunk.value, {stream:true});
              var lines = partial.split('\n');
              partial = lines.pop();
              lines.forEach(handleLine);
              return readLoop();
            });
          }
          function handleLine(line){
            if (!line.trim()) return;
            var ev;
            try { ev = JSON.parse(line); } catch(e){
              logRow.textContent += line + '\n';
              logRow.scrollTop = logRow.scrollHeight;
              return;
            }
            if (ev.event === 'log' || ev.event === 'start') {
              logRow.textContent += (ev.message || '') + '\n';
              logRow.scrollTop = logRow.scrollHeight;
            } else if (ev.event === 'done') {
              logRow.textContent += '\n✓ Updated.\n';
              btn.textContent = '↻ Update';
              btn.disabled = false;
              setTimeout(function(){ loadList(); }, 800);
            } else if (ev.event === 'error') {
              logRow.textContent += '\n✗ ' + (ev.error || 'unknown error') + '\n';
              btn.textContent = '↻ Update';
              btn.disabled = false;
            }
          }
          return readLoop();
        }).catch(function(e){
          logRow.textContent += '\n✗ Failed: ' + e.message + '\n';
          btn.textContent = '↻ Update';
          btn.disabled = false;
        });
      });
    });

    // Wire up trash / restore buttons. Trash is optimistic — the card
    // moves to the trash section the moment the button is clicked,
    // before the POST returns. The backend writes the .trashed marker
    // synchronously and spawns "docker compose down" in a goroutine,
    // so the next loadList() (fired when the POST settles) sees the
    // workspace already trashed and the user perceives no wait.
    document.querySelectorAll('[data-action="trash"], [data-action="restore"]').forEach(function(btn){
      btn.addEventListener('click', function(){
        var action = btn.getAttribute('data-action');
        var ws = btn.getAttribute('data-ws');
        if (!confirm(action === 'trash'
          ? 'Move "' + ws + '" to trash? Containers will stop but data is preserved.'
          : 'Restore "' + ws + '"? Containers will start back up.')) return;

        if (action === 'trash') {
          // Optimistic update: re-render this single card as trashed and
          // move it into the trash section right away. If the POST
          // ultimately fails, loadList() in the catch handler snaps the
          // UI back to truth.
          var card = btn.closest('.ws-card');
          if (card) {
            card.classList.add('trashed');
            // Disable links / buttons on the card so the user doesn't
            // click into a 502 (containers are shutting down).
            card.querySelectorAll('a, button').forEach(function(el){
              el.style.pointerEvents = 'none';
              el.style.opacity = '0.5';
            });
            // Move into the trash section if it's already visible,
            // otherwise reveal the section first.
            trashSection.style.display = '';
            trashBox.appendChild(card);
            document.getElementById('trash-empty-wrap').style.display = '';
          }
        } else {
          btn.disabled = true;
          btn.textContent = 'Restoring…';
        }

        fetch('/bailey/api/workspaces/' + encodeURIComponent(ws) + '/' + action, {
          method:'POST', credentials:'same-origin'
        }).then(function(r){ return r.json().catch(function(){ return {ok:r.ok}; }); }).then(function(d){
          if (d.ok === false) {
            alert('Failed: ' + (d.error || 'unknown error'));
          }
          loadList();
        }).catch(function(e){
          alert('Failed: ' + e.message);
          loadList();
        });
      });
    });
  }).catch(function(e){
    document.getElementById('workspaces-list').innerHTML = '<div class="ws-card"><p class="note" style="color:#b00020;">Couldn\'t load: ' + escapeHTML(String(e)) + '</p></div>';
  });
}
document.getElementById('ws-create-form').addEventListener('submit', function(e){
  e.preventDefault();
  var name = document.getElementById('ws-modal-input').value.trim();
  var status = document.getElementById('ws-modal-status');
  var form   = document.getElementById('ws-create-form');
  // Stage names are derived from server log lines — we don't depend on
  // a structured progress event, so this stays robust if the daemon
  // rewords a message. Mapping is best-effort.
  var stageRules = [
    {re: /Init bitswan network|EnsureDocker(IPv6)?Network|Creating per-workspace stage networks/i, label: 'Preparing docker networks…'},
    {re: /Workspace sub-Traefik started|sub-Traefik/i,                 label: 'Starting workspace sub-traefik…'},
    {re: /Initializing git in workspace|Git initialized in workspace/i,label: 'Initialising git workspace…'},
    {re: /Setting up GitOps worktree|GitOps worktree set up/i,         label: 'Setting up gitops worktree…'},
    {re: /Generating SSH key pair|SSH key pair generated/i,            label: 'Generating SSH keys…'},
    {re: /Registering workspace|Workspace registered/i,                label: 'Registering workspace with AOC…'},
    {re: /Getting automation server token|automation server token/i,   label: 'Getting AOC token…'},
    {re: /Getting EMQX JWT|EMQX JWT/i,                                 label: 'Getting MQTT credentials…'},
    {re: /Setting up GitOps deployment|GitOps deployment set up/i,     label: 'Wiring gitops ingress routes…'},
    {re: /Installing certs from|Certs copied successfully/i,           label: 'Installing TLS certs…'},
    {re: /Launching BitSwan Workspace services|docker compose .* up/i, label: 'Starting workspace containers…'},
    {re: /Container .* (Started|Created)/i,                            label: 'Bringing up containers…'},
    {re: /Setting up workspace-dashboard|Dashboard service enabled/i,  label: 'Starting dashboard…'},
    {re: /Starting Dashboard container/i,                              label: 'Starting dashboard container…'},
    {re: /Internal routing ready/i,                                    label: 'Finalising routes…'},
    {re: /BitSwan GitOps initialized successfully|GITOPS INFO/i,       label: 'Almost done — finishing up…'},
  ];
  function classify(line){
    for (var i = 0; i < stageRules.length; i++) {
      if (stageRules[i].re.test(line)) return stageRules[i].label;
    }
    return null;
  }

  // Swap the form for a streaming progress view inside the same modal.
  // The log is expanded by default so the user can see the stream tick
  // along even when stage-classification regexes don't match a line.
  form.style.display = 'none';
  var progressBox = document.createElement('div');
  progressBox.id = 'ws-progress';
  progressBox.innerHTML = ''
    + '<h2 style="margin:0 0 6px;">Creating <code>' + escapeHTML(name) + '</code></h2>'
    + '<p id="ws-stage" style="margin:0 0 8px;font-size:14px;color:#3F3F46;">Starting…</p>'
    + '<pre id="ws-log" style="margin:6px 0 0;padding:8px;background:#f6f7f9;border:1px solid #e4e4e7;border-radius:6px;font-size:11px;max-height:280px;overflow:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;"></pre>';
  form.parentNode.appendChild(progressBox);
  var stageEl = document.getElementById('ws-stage');
  var logEl   = document.getElementById('ws-log');

  fetch('/bailey/api/workspaces', {
    method:'POST', credentials:'same-origin',
    headers:{'Content-Type':'application/json', 'Accept': 'application/x-ndjson'},
    body: JSON.stringify({name: name})
  }).then(function(r){
    if (!r.ok && r.status !== 200) {
      throw new Error('HTTP ' + r.status);
    }
    var reader = r.body.getReader();
    var decoder = new TextDecoder();
    var partial = '';
    function readLoop(){
      return reader.read().then(function(chunk){
        if (chunk.done) {
          if (partial.trim()) handleLine(partial);
          return;
        }
        partial += decoder.decode(chunk.value, {stream:true});
        var lines = partial.split('\n');
        partial = lines.pop();  // last is incomplete
        lines.forEach(handleLine);
        return readLoop();
      });
    }
    function handleLine(line){
      if (!line.trim()) return;
      var ev;
      try { ev = JSON.parse(line); } catch (e) {
        // Non-JSON line — show it raw in the log, don't fail.
        logEl.textContent += line + '\n';
        logEl.scrollTop = logEl.scrollHeight;
        return;
      }
      if (ev.event === 'log') {
        logEl.textContent += (ev.stream === 'stderr' ? '! ' : '') + (ev.message || '') + '\n';
        logEl.scrollTop = logEl.scrollHeight;
        var stage = classify(ev.message || '');
        if (stage) stageEl.textContent = stage;
      } else if (ev.event === 'start') {
        stageEl.textContent = ev.message || 'Starting…';
      } else if (ev.event === 'done') {
        stageEl.textContent = 'Workspace created.';
        stageEl.style.color = '#0a7d24';
        document.getElementById('ws-modal-input').value = '';
        // Show the dashboard link prominently with a Close button. The
        // user dismisses the modal themselves — auto-closing in 800ms
        // before they can read it (and miss the dashboard URL entirely)
        // is what made the previous flow feel broken.
        var done = document.createElement('div');
        done.style.marginTop = '10px';
        done.innerHTML = ''
          + (ev.dashboard_url
              ? '<p style="margin:0 0 8px;font-size:13px;">Dashboard: <a href="' + escapeHTML(ev.dashboard_url) + '" target="_blank" rel="noopener">' + escapeHTML(ev.dashboard_url) + ' ↗</a></p>'
              : '')
          + '<button type="button" id="ws-progress-close" style="padding:6px 14px;border:none;background:#093DF5;color:#fff;border-radius:6px;cursor:pointer;">Close</button>';
        progressBox.appendChild(done);
        document.getElementById('ws-progress-close').onclick = function(){
          document.getElementById('ws-modal').classList.remove('open');
          form.style.display = '';
          progressBox.remove();
          loadList();
        };
        // Reload list in background so when they hit Close it's fresh.
        loadList();
      } else if (ev.event === 'error') {
        stageEl.textContent = 'Failed: ' + (ev.error || 'unknown error');
        stageEl.style.color = '#b00020';
        // Leave the modal open so the user can read the log + close manually.
        progressBox.innerHTML += '<p style="margin-top:8px;"><button type="button" onclick="this.closest(\'.ws-modal-backdrop\').classList.remove(\'open\');document.getElementById(\'ws-create-form\').style.display=\'\';document.getElementById(\'ws-progress\').remove();" style="padding:6px 12px;border:1px solid #d4d4d8;background:#F4F4F5;color:#3F3F46;border-radius:6px;cursor:pointer;">Close</button></p>';
      }
    }
    return readLoop();
  }).catch(function(e){
    stageEl.textContent = 'Failed: ' + e.message;
    stageEl.style.color = '#b00020';
  });
});
// Empty-trash modal: confirm button only enables when the user types
// the exact phrase. Submit streams NDJSON the same way create does.
document.getElementById('empty-trash-input').addEventListener('input', function(e){
  document.getElementById('empty-trash-confirm').disabled = e.target.value.trim() !== 'empty trash';
});
document.getElementById('empty-trash-form').addEventListener('submit', function(e){
  e.preventDefault();
  var input = document.getElementById('empty-trash-input');
  var confirmBtn = document.getElementById('empty-trash-confirm');
  var logEl = document.getElementById('empty-trash-log');
  logEl.style.display = '';
  logEl.textContent = '';
  confirmBtn.disabled = true;
  confirmBtn.textContent = 'Emptying…';
  fetch('/bailey/api/workspaces/empty-trash', {
    method:'POST', credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({confirmation: input.value.trim()})
  }).then(function(r){
    if (!r.ok && r.status !== 200) throw new Error('HTTP ' + r.status);
    var reader = r.body.getReader();
    var decoder = new TextDecoder();
    var partial = '';
    function readLoop(){
      return reader.read().then(function(chunk){
        if (chunk.done) {
          if (partial.trim()) handleLine(partial);
          return;
        }
        partial += decoder.decode(chunk.value, {stream:true});
        var lines = partial.split('\n');
        partial = lines.pop();
        lines.forEach(handleLine);
        return readLoop();
      });
    }
    function handleLine(line){
      if (!line.trim()) return;
      var ev;
      try { ev = JSON.parse(line); } catch(e){
        logEl.textContent += line + '\n';
        logEl.scrollTop = logEl.scrollHeight;
        return;
      }
      if (ev.event === 'log' || ev.event === 'start') {
        logEl.textContent += (ev.message || '') + '\n';
        logEl.scrollTop = logEl.scrollHeight;
      } else if (ev.event === 'done') {
        logEl.textContent += '\n✓ Trash emptied.\n';
        confirmBtn.textContent = 'Done';
        setTimeout(function(){
          document.getElementById('empty-trash-modal').classList.remove('open');
          input.value = '';
          confirmBtn.textContent = 'Empty trash';
          logEl.style.display = 'none';
          loadList();
        }, 1200);
      } else if (ev.event === 'error') {
        logEl.textContent += '\n✗ Failed: ' + (ev.error || 'unknown') + '\n';
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Empty trash';
      }
    }
    return readLoop();
  }).catch(function(e){
    logEl.textContent += '\n✗ Failed: ' + e.message + '\n';
    confirmBtn.disabled = false;
    confirmBtn.textContent = 'Empty trash';
  });
});

loadList();`

	case "devices":
		pageTitle = "Devices"
		pageContent = fmt.Sprintf(`
<div class="card" style="margin-top:0;">
  <h2>Pair a new browser</h2>
  <p class="note">Opened bailey on another browser and saw a 6-digit code? Enter it here to approve that device for <code>%s</code>.</p>
  <form id="self-approve-form" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px;">
    <input type="text" id="self-approve-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="off" required placeholder="000000" style="font-size:20px;letter-spacing:6px;padding:8px 10px;width:140px;font-family:ui-monospace,monospace;">
    <button type="submit" style="background:#093DF5;color:white;border:0;padding:10px 18px;border-radius:6px;cursor:pointer;font-size:14px;">Approve</button>
    <span id="self-approve-status" class="note" style="margin-left:8px;"></span>
  </form>
</div>

<div class="card">
  <h2>Paired devices</h2>
  <p class="note">Browsers you've trusted to access this server. Removing a device immediately invalidates its session.</p>
  <div id="device-list"><p class="note">Loading…</p></div>
</div>`, html.EscapeString(email))
		pageScript = `
function loadDevices() {
  fetch('/bailey/api/devices', {credentials:'same-origin'}).then(r => r.json()).then(d => {
    var box = document.getElementById('device-list');
    if (!d.devices || !d.devices.length) {
      box.innerHTML = '<p class="note">No devices paired yet.</p>'; return;
    }
    var rows = d.devices.map(function(dv){
      var label = dv.name + (dv.is_current ? ' <span style="color:#093DF5;font-weight:600;">(this device)</span>' : '');
      return '<tr style="border-bottom:1px solid #F4F4F5;">' +
        '<td style="padding:8px 4px;">' + label + '</td>' +
        '<td style="color:#71717A;">' + (dv.paired_at||'') + '</td>' +
        '<td style="color:#71717A;">' + (dv.last_seen||'') + '</td>' +
        '<td style="text-align:right;"><button class="rm-btn" data-id="' + dv.id + '" style="color:#b00020;background:none;border:0;cursor:pointer;font-size:13px;">Remove</button></td></tr>';
    }).join('');
    box.innerHTML =
      '<table style="width:100%;border-collapse:collapse;margin:8px 0;">' +
      '<thead><tr style="text-align:left;border-bottom:1px solid #E4E4E7;"><th style="padding:8px 0;">Device</th><th>Paired</th><th>Last seen</th><th></th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>';
    box.querySelectorAll('.rm-btn').forEach(function(btn){
      btn.addEventListener('click', function(){
        if (!confirm('Remove this device?')) return;
        var id = btn.getAttribute('data-id');
        var body = new URLSearchParams(); body.append('id', id);
        fetch('/bailey/api/devices/remove', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: body.toString()})
          .then(function(r){ if (!r.ok) throw new Error('HTTP '+r.status); loadDevices(); })
          .catch(function(e){ alert('Failed to remove: '+e); });
      });
    });
  }).catch(function(e){
    document.getElementById('device-list').innerHTML = '<p class="note" style="color:#b00020;">Couldn\'t load: '+e+'</p>';
  });
}
loadDevices();
document.getElementById('self-approve-form').addEventListener('submit', function(e){
  e.preventDefault();
  var codeEl = document.getElementById('self-approve-code');
  var status = document.getElementById('self-approve-status');
  var code = codeEl.value.trim();
  if (!/^[0-9]{6}$/.test(code)) {
    status.textContent = 'Code must be 6 digits.'; status.style.color = '#b00020'; return;
  }
  status.textContent = 'Approving…'; status.style.color = '#71717A';
  var body = new URLSearchParams();
  body.append('email', ` + fmt.Sprintf("%q", email) + `);
  body.append('code', code);
  fetch('/2fa-gate/api/approve', {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: body.toString()
  }).then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
    .then(function(res){
      if (res.ok) {
        status.textContent = 'Approved. The new browser will redirect on its own.';
        status.style.color = '#0a7d24';
        codeEl.value = '';
        loadDevices();
      } else {
        status.textContent = (res.d && res.d.error) || 'Approval failed.';
        status.style.color = '#b00020';
      }
    }).catch(function(e){ status.textContent = 'Network error: '+e; status.style.color='#b00020'; });
});`

	case "approvals":
		pageTitle = "Users & devices"
		pageContent = `
<div class="card" style="margin-top:0;">
  <p class="note">Every user that's ever paired a browser with this server. Expand a user to see their devices and last-active times. Pending pair requests show up inline next to their owner; revoking a device immediately invalidates its session.</p>
  <div id="ud-tree"><p class="note">Loading…</p></div>
</div>
<style>
  .ud-user { border:1px solid #E4E4E7; border-radius:10px; margin:14px 0; background:#fff; overflow:hidden; }
  .ud-user-head { display:flex; align-items:center; gap:12px; padding:14px 16px; cursor:pointer; user-select:none; }
  .ud-user-head:hover { background:#FAFAFA; }
  .ud-caret { color:#71717A; font-size:12px; width:14px; flex-shrink:0; transition:transform 0.12s; }
  .ud-user.open .ud-caret { transform: rotate(90deg); }
  .ud-avatar { width:32px; height:32px; border-radius:50%; background:#093DF5; color:#fff; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:600; flex-shrink:0; }
  .ud-meta { flex:1; min-width:0; }
  .ud-meta .email { font-size:14px; font-weight:500; color:#18181B; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .ud-meta .sub { font-size:12px; color:#71717A; margin-top:2px; }
  .ud-chip { font-size:11px; padding:2px 8px; border-radius:999px; background:#F4F4F5; color:#3F3F46; flex-shrink:0; }
  .ud-chip.alert { background:#FEE2E2; color:#991B1B; }
  .ud-chip.totp  { background:#DBEAFE; color:#1E40AF; }
  .ud-body { border-top:1px solid #F4F4F5; padding:8px 16px 14px; display:none; }
  .ud-user.open .ud-body { display:block; }
  .ud-dev { display:flex; align-items:center; gap:12px; padding:8px 4px; border-bottom:1px solid #F4F4F5; }
  .ud-dev:last-child { border-bottom:none; }
  .ud-dev-name { flex:1; min-width:0; font-size:13px; color:#18181B; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .ud-dev-name .cur { color:#093DF5; font-weight:600; margin-left:6px; }
  .ud-dev-when { font-size:12px; color:#71717A; flex-shrink:0; min-width:160px; text-align:right; }
  .ud-rm-btn { color:#b00020; background:none; border:1px solid transparent; padding:4px 10px; border-radius:6px; cursor:pointer; font-size:12px; }
  .ud-rm-btn:hover { background:#FEE2E2; border-color:#FECACA; }
  .ud-pp-row { background:#FFFBEB; border:1px solid #FDE68A; border-radius:8px; padding:10px 12px; margin-top:10px; display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
  .ud-pp-code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:18px; letter-spacing:3px; background:#fff; padding:4px 10px; border-radius:6px; border:1px solid #FDE68A; }
  .ud-pp-form { display:flex; gap:6px; align-items:center; flex:1; min-width:240px; }
  .ud-pp-form input { font-size:16px; letter-spacing:3px; padding:6px 8px; width:110px; font-family:ui-monospace,monospace; }
  .ud-pp-form button { background:#093DF5; color:#fff; border:0; padding:7px 14px; border-radius:6px; cursor:pointer; font-size:13px; }
  .ud-pp-status { font-size:12px; color:#71717A; }
</style>`
		pageScript = `
function escapeHTML(s){ return String(s).replace(/[&<>"]/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
function initials(s){ s=String(s||'').replace(/[^a-zA-Z0-9]/g,' ').trim(); if(!s) return '?'; var p=s.split(/\s+/); return (p.length===1 ? p[0].slice(0,2) : p[0][0]+p[1][0]).toUpperCase(); }
function ago(sec){ if(sec<60) return sec+'s ago'; if(sec<3600) return Math.floor(sec/60)+'m ago'; if(sec<86400) return Math.floor(sec/3600)+'h ago'; return Math.floor(sec/86400)+'d ago'; }
function fmtTs(ts){
  if(!ts) return '—';
  var d = new Date(ts);
  if(isNaN(d)) return ts;
  var diff = Math.floor((Date.now()-d.getTime())/1000);
  if(diff>=0 && diff<86400*30) return ago(diff);
  return d.toISOString().slice(0,16).replace('T',' ');
}
function renderTree(){
  fetch('/bailey/api/admin/devices', {credentials:'same-origin'})
    .then(function(r){ return r.ok ? r.json() : Promise.reject(new Error('HTTP '+r.status)); })
    .then(function(d){
      var box = document.getElementById('ud-tree');
      var users = (d.users||[]).concat(d.pending_pairs_orphan||[]);
      if (!users.length) { box.innerHTML = '<p class="note">No users have paired a browser with this server yet.</p>'; return; }
      box.innerHTML = users.map(function(u){
        var pp = u.pending_pair;
        var chips = '';
        if (pp) chips += '<span class="ud-chip alert">Pending pair</span>';
        if (u.totp_enrolled) chips += '<span class="ud-chip totp">TOTP</span>';
        chips += '<span class="ud-chip">'+(u.devices ? u.devices.length : 0)+' device'+((u.devices||[]).length===1?'':'s')+'</span>';
        var devices = (u.devices||[]).map(function(dv){
          var cur = dv.is_current ? '<span class="cur">(this browser)</span>' : '';
          return '<div class="ud-dev">' +
            '<div class="ud-dev-name">'+escapeHTML(dv.name)+cur+'</div>' +
            '<div class="ud-dev-when">paired '+fmtTs(dv.paired_at)+' · seen '+fmtTs(dv.last_seen)+'</div>' +
            '<button class="ud-rm-btn" data-email="'+escapeHTML(u.email)+'" data-id="'+escapeHTML(dv.id)+'">Revoke</button>' +
          '</div>';
        }).join('') || '<p class="note" style="margin:8px 4px;">No paired devices.</p>';
        var ppHtml = '';
        if (pp) {
          ppHtml = '<div class="ud-pp-row">' +
            '<div>Expected code: <span class="ud-pp-code">'+escapeHTML(pp.code)+'</span></div>' +
            '<form class="ud-pp-form" data-email="'+escapeHTML(u.email)+'">' +
              '<input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="off" required placeholder="000000">' +
              '<button type="submit">Approve</button>' +
              '<span class="ud-pp-status"></span>' +
            '</form></div>';
        }
        return '<div class="ud-user'+(pp?' open':'')+'">' +
          '<div class="ud-user-head" onclick="this.parentNode.classList.toggle(\'open\')">' +
            '<span class="ud-caret">▸</span>' +
            '<span class="ud-avatar">'+initials(u.email)+'</span>' +
            '<div class="ud-meta"><div class="email">'+escapeHTML(u.email)+'</div></div>' +
            chips +
          '</div>' +
          '<div class="ud-body">'+devices+ppHtml+'</div>' +
        '</div>';
      }).join('');
      bindRowActions();
    })
    .catch(function(e){
      document.getElementById('ud-tree').innerHTML = '<p class="note" style="color:#b00020;">Couldn\'t load: '+e+'</p>';
    });
}
function bindRowActions(){
  document.querySelectorAll('.ud-rm-btn').forEach(function(btn){
    btn.addEventListener('click', function(e){
      e.stopPropagation();
      if (!confirm('Revoke '+btn.getAttribute('data-email')+'\'s device? This invalidates its session immediately.')) return;
      var body = new URLSearchParams();
      body.append('email', btn.getAttribute('data-email'));
      body.append('id', btn.getAttribute('data-id'));
      fetch('/bailey/api/admin/devices/remove', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: body.toString()})
        .then(function(r){ if(!r.ok) return r.json().then(function(d){throw new Error(d.error||'HTTP '+r.status);}); renderTree(); })
        .catch(function(e){ alert('Failed: '+e); });
    });
  });
  document.querySelectorAll('.ud-pp-form').forEach(function(f){
    f.addEventListener('click', function(e){ e.stopPropagation(); });
    f.addEventListener('submit', function(e){
      e.preventDefault();
      var email = f.getAttribute('data-email');
      var code = f.querySelector('input[name=code]').value.trim();
      var status = f.querySelector('.ud-pp-status');
      status.textContent = 'Approving…'; status.style.color = '#71717A';
      var body = new URLSearchParams(); body.append('email', email); body.append('code', code);
      fetch('/2fa-gate/api/approve', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: body.toString()})
        .then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
        .then(function(res){
          if (res.ok) { status.textContent = 'Approved.'; status.style.color = '#0a7d24'; setTimeout(renderTree, 600); }
          else { status.textContent = (res.d && res.d.error) || 'Failed.'; status.style.color='#b00020'; }
        }).catch(function(e){ status.textContent = 'Network error: '+e; status.style.color='#b00020'; });
    });
  });
}
renderTree();
setInterval(renderTree, 8000);`

	case "notifications":
		pageTitle = "Notifications"
		pageContent = notificationsPageHTML(email, groups, admin)

	case "recovery":
		pageTitle = "Recovery (TOTP)"
		pageContent = `
<div class="card" style="margin-top:0;">
  <h2>Authenticator-based recovery</h2>
  <p class="note">TOTP is required for admins. Optional (but recommended) for regular users — lets you re-pair a fresh browser without bothering an admin.</p>
  <iframe src="/2fa-gate/account/2fa?_bailey_iframe=1" style="width:100%;min-height:380px;border:0;"></iframe>
</div>`

	case "map":
		pageTitle = "Network map"
		pageContent = fmt.Sprintf(`
<link rel="stylesheet" href="/bailey/static/network-map.css?v=%s">
<div id="network-map-root" style="min-height:520px;"></div>
<script src="/bailey/static/network-map.js?v=%s" defer></script>`,
			staticAssetVersion("network-map.css"),
			staticAssetVersion("network-map.js"))
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

	case "updates":
		pageTitle = "Updates"
		pageContent = updatesPageHTML
		pageScript = updatesPageJS
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
    <a href="/bailey/notifications" class="%s" id="nav-notifications">Notifications<span id="nav-notifications-badge" style="display:none;background:#DC2626;color:#fff;border-radius:10px;padding:1px 7px;font-size:11px;margin-left:6px;"></span></a>
    <a href="/bailey/devices" class="%s">Devices</a>
    <a href="/bailey/recovery" class="%s">Recovery (TOTP)</a>
    <div class="sidebar-section">Admin</div>
    <a href="/bailey/approvals" class="%s">Users &amp; devices</a>
    <a href="/bailey/updates" class="%s">Updates</a>
    <a href="/bailey/map" class="%s">Network map</a>
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
		active("workspaces"), active("notifications"),
		active("devices"), active("recovery"),
		active("approvals"), active("updates"), active("map"), active("certs"), active("siem"),
		email, pageTitle, pageContent, pageScript)
}
