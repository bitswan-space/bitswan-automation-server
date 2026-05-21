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

// shouldWrapWithChrome returns true on top-level browser navigations
// that should get the chrome wrap. iframe loads (Sec-Fetch-Dest:
// iframe or marker query present), subresources (non-HTML Accept),
// and non-GET requests are never wrapped.
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
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "iframe", "frame":
		return false
	case "document", "":
		return true
	}
	return false
}

func serveBaileyChrome(w http.ResponseWriter, r *http.Request) {
	email, _ := identityFromHeaders(r)
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	fmt.Fprint(w, baileyChromeHTML(email, host, iframePath))
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

func baileyChromeHTML(email, host, iframeSrc string) string {
	emailDisp := "anonymous"
	if email != "" {
		emailDisp = email
	}
	server := serverDisplayName()
	fence := strings.Repeat("▲", 400)
	shareHref := mfaGatePathPrefix + "/share/" + url.PathEscape(host)
	return fmt.Sprintf(`<!doctype html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bailey</title>
<style>
  html, body { margin: 0; padding: 0; height: 100%%; overflow: hidden; background: %[1]s; }
  iframe { position: fixed; inset: 0 0 %[2]dpx 0; width: 100vw; height: calc(100vh - %[2]dpx); border: 0; display: block; background: white; }
  footer {
    position: fixed; left: 0; right: 0; bottom: 0; height: %[2]dpx;
    background: %[1]s; color: %[3]s;
    font: 12px/%[2]dpx -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    display: flex; align-items: center; overflow: hidden; white-space: nowrap; z-index: 2147483647;
  }
  footer .label   { padding: 0 10px; flex-shrink: 0; }
  footer .label b { font-weight: 600; }
  footer .sep     { padding: 0 6px; opacity: 0.55; flex-shrink: 0; }
  footer .fence   { flex: 1; opacity: 0.45; letter-spacing: 1px; overflow: hidden; }
  footer a.btn    { padding: 0 12px; color: %[3]s; text-decoration: none; flex-shrink: 0; border-left: 1px solid rgba(255,255,255,0.18); }
  footer a.btn:hover { background: rgba(255,255,255,0.06); }
</style>
</head><body>
<iframe src="%[4]s" allow="clipboard-read; clipboard-write; fullscreen; camera; microphone; geolocation"></iframe>
<footer>
  <span class="label">🛡 Protected by Bitswan Bailey <b>%[5]s</b></span>
  <span class="sep">·</span>
  <span class="label">Logged in as <b>%[6]s</b></span>
  <span class="fence">%[7]s</span>
  <a class="btn" href="%[8]s" target="_top">Share</a>
  <a class="btn" href="/oauth2/sign_out" target="_top">Logout</a>
</footer>
</body></html>`,
		chromeFooterBg, chromeFooterPx, chromeFooterFg,
		html.EscapeString(iframeSrc),
		html.EscapeString(server), html.EscapeString(emailDisp),
		fence, html.EscapeString(shareHref))
}
