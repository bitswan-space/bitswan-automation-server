package daemon

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// MFA gate — sits between bitswan-protected-proxy and traefik-protected,
// enforces a second factor before forwarding to workspace services.
//
// Admins: must have a valid TOTP cookie.
// Normal users: must have a valid device cookie (paired device).
// First admin on a fresh server: trust-on-first-use bootstrap.
// Everyone else without a device: pending-pair flow.

const (
	mfaGateListenAddr  = ":9080"
	mfaGateUpstream    = "http://traefik-protected:80"
	mfaGatePathPrefix  = "/2fa-gate"
	gateOriginCookie   = "_bailey_origin"
)

func startMFAGate() error {
	upstream, err := url.Parse(mfaGateUpstream)
	if err != nil {
		return fmt.Errorf("parse upstream: %w", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	orig := proxy.Director
	proxy.Director = func(r *http.Request) {
		orig(r)
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			r.Host = h
		}
	}
	// Two responsibilities on the inner content:
	//   1. Strip iframe-blocking headers so the wrap can embed it.
	//   2. Inject a strict CSP that pins the inner content to the
	//      bailey domain — the app inside the iframe cannot fetch
	//      resources from arbitrary third-party origins, and cannot
	//      be framed by anything except the paired outer wrap.
	// The CSP applies only to HTML docs (it's a per-document policy);
	// for JS/CSS/images we just strip frame headers and leave the
	// payload alone.
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("X-Frame-Options")
		host := requestEndpointHost(resp.Request)
		if !isInnerHost(host) {
			// Not inner content — leave headers as the upstream sent.
			return nil
		}
		ct := resp.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "text/html") {
			resp.Header.Set("Content-Security-Policy", strictInnerCSP(host))
		} else if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
			// Non-HTML with its own CSP: at least drop frame-ancestors
			// so the wrap stays able to embed (chrome ignores CSP on
			// non-docs but Firefox/Safari are pickier).
			resp.Header.Set("Content-Security-Policy", stripCSPFrameAncestors(csp))
		}
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mfaGateHandler(w, r, proxy)
	})
	// Chrome wrap is applied here as a single middleware so every
	// request to the MFA gate inherits it. The handler itself no
	// longer needs to call serveBaileyChrome.
	srv := &http.Server{
		Addr:              mfaGateListenAddr,
		Handler:           chromeWrapMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("MFA gate listener error: %v\n", err)
		}
	}()
	fmt.Printf("MFA gate listening on %s, proxying %s\n", mfaGateListenAddr, mfaGateUpstream)
	return nil
}

func mfaGateHandler(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy) {
	if strings.HasPrefix(r.URL.Path, mfaGatePathPrefix) {
		handleGatePath(w, r)
		return
	}
	if !enforceMFAGate(w, r) {
		return
	}
	// Chrome wrap is now applied by chromeWrapMiddleware at server
	// entry — every response from here flows back through that
	// middleware, which decides whether to wrap, propagate the
	// iframe marker, or escape the iframe.
	proxy.ServeHTTP(w, r)
}

// enforceMFAGate runs the second-factor + ACL check. Returns true if
// the caller should continue serving; returns false (and writes a
// redirect or page) when the gate handled the request.
//
// Two-phase enforcement:
//   - Phase 1: MFA. Admin needs valid TOTP cookie; everyone needs a
//     device cookie. First admin on a fresh server bootstrap-TOFUs.
//   - Phase 2: ACL. Once MFA is satisfied, look up the request's
//     Host against the endpoints table. Original owner / matching
//     grant ⇒ through. Nothing matches ⇒ deny with a "request
//     access" page (the caller can ping the endpoint owner).
//
// ACL is bypassed when:
//   - The hostname isn't yet registered (treat as "bootstrap window"
//     — the next eligible user effectively becomes its owner via the
//     normal init path)
//   - The Host is bailey.<domain> AND no endpoint exists yet
//     (bootstrap: first user to sign in claims server ownership)
func enforceMFAGate(w http.ResponseWriter, r *http.Request) bool {
	if os.Getenv("BAILEY_MFA_GATE_DISABLE") == "1" {
		return true
	}
	email, groups := identityFromHeaders(r)
	if email == "" {
		return true // no identity → upstream OIDC failed; let it through
	}
	admin := isAdminGroups(groups)
	if admin {
		if !hasValidSession(r, email) {
			rememberOrigin(w, r)
			http.Redirect(w, r, mfaGatePathPrefix+"/admin/challenge", http.StatusSeeOther)
			return false
		}
	}
	dev := currentDeviceForRequest(r, email)
	if dev == nil {
		// Bootstrap: first admin on an empty server gets TOFU'd.
		if admin && !anyDevicesExist() {
			rec, err := addDevice(email, deviceNameFromRequest(r))
			if err != nil {
				http.Error(w, "bootstrap pair: "+err.Error(), http.StatusInternalServerError)
				return false
			}
			_ = setDeviceCookie(w, r, email, rec.ID)
			dev = rec
		} else {
			rememberOrigin(w, r)
			http.Redirect(w, r, mfaGatePathPrefix+"/pending-pair", http.StatusSeeOther)
			return false
		}
	}
	if dev != nil {
		touchDevice(email, dev.ID)
	}

	// Phase 2: ACL check against the host.
	return enforceEndpointACL(w, r, email, groups)
}

// enforceEndpointACL looks up the request's Host in the endpoints
// table and decides whether the caller can proceed. Returns true if
// the request should be served; false if it was handled (denied page
// rendered, request-access form, or auto-claimed bootstrap).
//
// bailey.<domain> gets a free pass — it's the management
// surface where per-page logic applies. The bailey-admin handler
// runs its own per-page authorization (devices/recovery for any
// signed-in user, server-admin pages for the server owner). We
// still register the bailey-admin endpoint on first sign-in so the
// share/audit UI works for it, but the gate doesn't 403 it.
func enforceEndpointACL(w http.ResponseWriter, r *http.Request, email string, groups []string) bool {
	host := requestEndpointHost(r)
	if host == "" {
		return true
	}
	// ACL state is keyed by the OUTER hostname. Inner-subdomain
	// requests look up against the same row.
	host = toOuterHost(host)
	if isBaileyHost(host) {
		// Register endpoint row on first sign-in so audit / share
		// pages have an owner to attribute to, but don't gate.
		if ep, _ := getEndpoint(host); ep == nil {
			_, _ = registerEndpoint(host, email, "Bailey ("+host+")")
		}
		return true
	}
	ep, err := getEndpoint(host)
	if err != nil {
		http.Error(w, "ACL lookup: "+err.Error(), http.StatusInternalServerError)
		return false
	}
	if ep == nil {
		// Unknown host — workspace init / automation deploy hasn't
		// registered it yet. Leave open until the register call sets
		// an owner.
		return true
	}
	role, err := roleFor(host, email, groups)
	if err != nil {
		http.Error(w, "ACL check: "+err.Error(), http.StatusInternalServerError)
		return false
	}
	if role == roleNone {
		_ = addAccessRequest(host, email)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, accessDeniedHTML(host, ep, email))
		return false
	}
	return true
}

// isBaileyHost matches both the outer (bailey.<domain>) and inner
// (bailey--inner.<domain>) subdomains of the bailey itself.
func isBaileyHost(host string) bool {
	h := strings.ToLower(host)
	return strings.HasPrefix(h, "bailey.") || strings.HasPrefix(h, "bailey"+innerHostSuffix+".")
}

// requestEndpointHost returns the canonical hostname for ACL lookup.
// Prefers X-Forwarded-Host (set by the upstream proxy), falls back to
// r.Host. Strips any port suffix.
func requestEndpointHost(r *http.Request) string {
	h := r.Header.Get("X-Forwarded-Host")
	if h == "" {
		h = r.Host
	}
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

func isAdminGroups(groups []string) bool {
	for _, g := range groups {
		if g == "admin" || strings.HasSuffix(strings.ToLower(g), adminGroup) {
			return true
		}
	}
	return false
}

func rememberOrigin(w http.ResponseWriter, r *http.Request) {
	origin := r.URL.Path
	if r.URL.RawQuery != "" {
		origin += "?" + r.URL.RawQuery
	}
	http.SetCookie(w, &http.Cookie{
		Name: gateOriginCookie, Value: origin, Path: "/",
		MaxAge: 600, HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

func originRedirect(w http.ResponseWriter, r *http.Request) {
	target := "/"
	if c, err := r.Cookie(gateOriginCookie); err == nil && c.Value != "" {
		target = c.Value
	}
	http.SetCookie(w, &http.Cookie{Name: gateOriginCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// handleGatePathRoot is the bare http.HandlerFunc for mounting on any
// mux. Just unwraps to handleGatePath.
func handleGatePathRoot(w http.ResponseWriter, r *http.Request) {
	handleGatePath(w, r)
}

func handleGatePath(w http.ResponseWriter, r *http.Request) {
	email, groups := identityFromHeaders(r)
	if email == "" {
		http.Error(w, "no identity on request", http.StatusForbidden)
		return
	}
	admin := isAdminGroups(groups)

	switch {
	case r.URL.Path == mfaGatePathPrefix+"/admin/enroll" || r.URL.Path == mfaGatePathPrefix+"/admin/challenge":
		if !admin {
			http.Error(w, "admin enrol/challenge is for admin-group users", http.StatusForbidden)
			return
		}
		handleTOTPGate(w, r, mfaGatePathPrefix+"/admin", email)

	case r.URL.Path == mfaGatePathPrefix+"/pending-pair":
		handlePendingPair(w, r, email)
	case r.URL.Path == mfaGatePathPrefix+"/pending-pair/poll":
		handlePendingPairPoll(w, r, email)
	case r.URL.Path == mfaGatePathPrefix+"/approve":
		handleApprovePair(w, r, email)
	case r.URL.Path == mfaGatePathPrefix+"/recovery":
		handleRecovery(w, r, email)
	case r.URL.Path == mfaGatePathPrefix+"/account/devices":
		handleAccountDevices(w, r, email)
	case r.URL.Path == mfaGatePathPrefix+"/account/2fa":
		handleAccountTOTP(w, r, email)
	case r.URL.Path == mfaGatePathPrefix+"/whoami":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "email=%s\ngroups=%s\nadmin=%v\n", email, strings.Join(groups, ","), admin)

	case strings.HasPrefix(r.URL.Path, mfaGatePathPrefix+"/api/share/"):
		handleShareAPI(w, r, email, groups)

	case r.URL.Path == mfaGatePathPrefix+"/share" ||
		r.URL.Path == mfaGatePathPrefix+"/share/" ||
		strings.HasPrefix(r.URL.Path, mfaGatePathPrefix+"/share/"):
		handleShareEndpoint(w, r, email, groups)

	case strings.HasPrefix(r.URL.Path, mfaGatePathPrefix+"/request-access/"):
		handleRequestAccess(w, r, email)

	default:
		http.NotFound(w, r)
	}
}

// Stub vars filled in by mfa_pair.go and mfa_account.go's init().
var (
	handlePendingPair     = func(w http.ResponseWriter, r *http.Request, email string) {}
	handlePendingPairPoll = func(w http.ResponseWriter, r *http.Request, email string) {}
	handleApprovePair     = func(w http.ResponseWriter, r *http.Request, email string) {}
	handleRecovery        = func(w http.ResponseWriter, r *http.Request, email string) {}
	handleAccountDevices  = func(w http.ResponseWriter, r *http.Request, email string) {}
	handleAccountTOTP     = func(w http.ResponseWriter, r *http.Request, email string) {}
)

// stripCSPFrameAncestors keeps the CSP intact except for its
// frame-ancestors directive, which would otherwise block the chrome
// wrap from embedding the response.
func stripCSPFrameAncestors(csp string) string {
	parts := strings.Split(csp, ";")
	keep := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.HasPrefix(strings.TrimSpace(strings.ToLower(p)), "frame-ancestors") {
			continue
		}
		keep = append(keep, p)
	}
	return strings.Join(keep, ";")
}
