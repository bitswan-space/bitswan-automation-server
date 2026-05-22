package daemon

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// Bailey chrome — a thin footer pinned to the bottom of every
// protected app's tab. Tells the user they're inside a bailey and
// gives them a sign-out button. Tab origin stays per-app for browser
// storage isolation; the chrome is just a thin wrapper.

const (
	chromeFooterPx       = 22
	chromeFooterBg       = "#0D1326"
	chromeFooterFg       = "#FAFAFA"
	iframeMarkerQueryKey = "_bailey_iframe"
)

// shouldWrapWithChrome returns true for browser-style HTML fetches
// that the chrome wrap should render. The wrap fires on top-level
// navigations and is suppressed in two situations:
//
//  1. The URL carries the `_bailey_iframe=1` marker — we're inside
//     the wrap's own iframe, the inner content is the upstream
//     service and must not be wrapped again.
//
//  2. The Referer carries that marker — the request originates from
//     within the wrap iframe. This catches the upstream service's
//     own internal iframes (e.g. code-server's webviews) which would
//     otherwise come in with `Sec-Fetch-Dest: iframe` and no marker,
//     visually indistinguishable from a fresh top-level navigation.
//     If the request was provoked by a page we already wrapped, we
//     don't wrap again.
//
// We deliberately do NOT use Sec-Fetch-Dest alone as a discriminator:
// browsers send `iframe` even for the top-level URL when the user
// navigated to it from a tab where that hostname was previously
// embedded somewhere — which would otherwise leave the user staring
// at the upstream service with no wrap.
//
// Non-HTML accept (CSS/JS/images) and non-GET requests are excluded
// so subresources and form posts pass through.
func shouldWrapWithChrome(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		return false
	}
	if r.URL.Query().Get(iframeMarkerQueryKey) != "" {
		return false
	}
	if ref := r.Header.Get("Referer"); ref != "" && strings.Contains(ref, iframeMarkerQueryKey+"=1") {
		return false
	}
	return true
}

func serveBaileyChrome(w http.ResponseWriter, r *http.Request) {
	email, groups := identityFromHeaders(r)
	host := requestEndpointHost(r)

	q := r.URL.Query()
	q.Set(iframeMarkerQueryKey, "1")
	iframePath := r.URL.Path
	if rq := q.Encode(); rq != "" {
		iframePath += "?" + rq
	}
	if r.URL.Fragment != "" {
		iframePath += "#" + r.URL.Fragment
	}

	// The Share button is only shown to owners — non-owners have no
	// authority to change sharing rules, so the button would be a
	// dead end. roleFor returns "" if the endpoint isn't registered
	// (which can happen for bailey-admin pre-bootstrap); treat that
	// as "no Share button" to be safe.
	isOwner := false
	if role, _ := roleFor(host, email, groups); role == roleOwner {
		isOwner = true
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	fmt.Fprint(w, baileyChromeHTML(email, host, iframePath, isOwner))
}

// serverDisplayName returns the friendly name of the bailey
// automation server for the chrome footer. Falls back to slug or
// "Bailey" if no name is configured.
func serverDisplayName() string {
	sc, err := config.NewAutomationServerConfig().LoadConfig()
	if err != nil || sc == nil {
		return "Bailey"
	}
	if sc.Name != "" {
		return sc.Name
	}
	if sc.Slug != "" {
		return sc.Slug
	}
	return "Bailey"
}

// baileyCourtyardHost returns the bailey-admin hostname (the
// "courtyard" — the central page from which the user manages all
// their endpoints). Currently bailey-admin.<protected-domain>.
//
// Returns empty if no domain is configured (e.g. during init).
func baileyCourtyardHost() string {
	sc, err := config.NewAutomationServerConfig().LoadConfig()
	if err != nil || sc == nil {
		return ""
	}
	d := sc.ProtectedHostnameDomain()
	if d == "" {
		return ""
	}
	return "bailey-admin." + d
}

func baileyChromeHTML(email, host, iframeSrc string, isOwner bool) string {
	emailDisp := "anonymous"
	if email != "" {
		emailDisp = email
	}
	server := serverDisplayName()
	fence := strings.Repeat("▲", 400)
	apiURL := mfaGatePathPrefix + "/api/share/" + url.PathEscape(host)

	// Only owners see the Share button. Non-owners have no authority
	// to change sharing rules; presenting the button to them would
	// either invite confusion or expose grants they shouldn't see.
	shareBtn := ""
	shareModal := ""
	shareScript := ""
	if isOwner {
		shareBtn = `<a class="btn" href="#" onclick="window.__baileyShareOpen();return false;">Share</a>`
		shareModal = shareModalHTML()
		shareScript = shareModalJS(host, emailDisp, apiURL)
	}

	// "Back to bailey" link — the courtyard from which the user
	// manages all their endpoints. Suppressed when we ARE on the
	// bailey host (showing a self-link would be pointless).
	courtyardBtn := ""
	if cy := baileyCourtyardHost(); cy != "" && !strings.EqualFold(cy, host) {
		courtyardBtn = fmt.Sprintf(
			`<a class="btn courtyard" href="https://%[1]s/" target="_top" title="Back to the bailey">↩ %[1]s</a>`,
			html.EscapeString(cy))
	}

	return fmt.Sprintf(`<!doctype html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bailey</title>
<style>
  html, body { margin: 0; padding: 0; height: 100%%; overflow: hidden; background: %[1]s; }
  iframe.bailey-content { position: fixed; inset: 0 0 %[2]dpx 0; width: 100vw; height: calc(100vh - %[2]dpx); border: 0; display: block; background: white; }
  footer.bailey-footer {
    position: fixed; left: 0; right: 0; bottom: 0; height: %[2]dpx;
    background: %[1]s; color: %[3]s;
    font: 12px/%[2]dpx -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    display: flex; align-items: center; overflow: hidden; white-space: nowrap; z-index: 2147483647;
  }
  footer.bailey-footer .label   { padding: 0 10px; flex-shrink: 0; }
  footer.bailey-footer .label b { font-weight: 600; }
  footer.bailey-footer .sep     { padding: 0 6px; opacity: 0.55; flex-shrink: 0; }
  footer.bailey-footer .fence   { flex: 1; opacity: 0.45; letter-spacing: 1px; overflow: hidden; }
  footer.bailey-footer a.btn    { padding: 0 12px; color: %[3]s; text-decoration: none; flex-shrink: 0; border-left: 1px solid rgba(255,255,255,0.18); cursor: pointer; }
  footer.bailey-footer a.btn:hover { background: rgba(255,255,255,0.06); }
  footer.bailey-footer a.btn.courtyard { font-family: ui-monospace,SFMono-Regular,Menlo,monospace; opacity: 0.9; }
%[9]s
</style>
</head><body>
<iframe class="bailey-content" src="%[4]s" allow="clipboard-read; clipboard-write; fullscreen; camera; microphone; geolocation"></iframe>
<footer class="bailey-footer">
  <span class="label">🛡 Protected by Bitswan Bailey <b>%[5]s</b></span>
  <span class="sep">·</span>
  <span class="label">Logged in as <b>%[6]s</b></span>
  <span class="fence">%[7]s</span>
  %[12]s
  %[8]s
  <a class="btn" href="/oauth2/sign_out" target="_top">Logout</a>
</footer>
%[10]s
<script>%[11]s</script>
</body></html>`,
		chromeFooterBg, chromeFooterPx, chromeFooterFg,
		html.EscapeString(iframeSrc),
		html.EscapeString(server), html.EscapeString(emailDisp),
		fence,
		shareBtn,
		shareModalCSS,
		shareModal,
		shareScript,
		courtyardBtn)
}
