package daemon

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// chromeWrapMiddleware is the single point where the "Protected by
// Bitswan Bailey" iframe wrap is applied. Apply it once at the
// outermost http.Server.Handler and every endpoint that passes
// through inherits the wrap — no per-handler opt-in.
//
// The middleware does two related things:
//
//  1. On top-level GET text/html navigations (no `_bailey_iframe=1`
//     query marker), serve the chrome-wrap HTML. Inside that HTML
//     is an iframe with the marker appended; the next request loads
//     the actual content inside that iframe.
//
//  2. On any request that DOES carry the marker (i.e., it's being
//     loaded inside the wrap's iframe), watch for 30x responses and
//     append the marker to the Location. Without this, an MFA gate
//     redirect inside the iframe would land at a marker-less URL,
//     which the middleware would re-wrap — nesting wraps and
//     eventually escaping the user's tab.
//
// Exempt paths (escape-the-iframe): /oauth2/* and /bailey-admin/signout
// must redirect to external IdP URLs (Keycloak end_session, etc.).
// Those targets reject iframe embedding via X-Frame-Options or CSP,
// so the wrap would leave the user looking at a blank iframe. We
// serve a tiny HTML body that uses `window.top.location` to break
// out of the iframe and continue the redirect at the top level.
func chromeWrapMiddleware(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marker := r.URL.Query().Get(iframeMarkerQueryKey)
		email := r.Header.Get("X-Forwarded-Email")
		wrap := marker == "" && email != "" && shouldWrapWithChrome(r)
		fmt.Printf("[wrap-mw] host=%s path=%q method=%s email=%q marker=%q acc=%q sfd=%q wrap=%v\n",
			r.Host, r.URL.Path, r.Method, email, marker,
			r.Header.Get("Accept"), r.Header.Get("Sec-Fetch-Dest"), wrap)

		// Top-level navigation (no marker) → wrap. We only wrap
		// AUTHENTICATED requests (X-Forwarded-Email set by
		// oauth2-proxy) — wrapping a pre-auth request would put
		// oauth2-proxy's redirect-to-Keycloak inside an iframe, and
		// Keycloak refuses iframe embedding (X-Frame-Options: DENY),
		// breaking the login flow.
		if wrap {
			serveBaileyChrome(w, r)
			return
		}

		// Inside the iframe — wrap any 30x Location with the marker
		// so subsequent navigations stay in the iframe. Special case
		// for /oauth2/* and /signout: those need top-level redirects
		// to reach Keycloak / break the iframe.
		if marker != "" {
			needsTopLevelEscape := isIframeEscapePath(r.URL.Path)
			rw := &chromeFlowWriter{
				ResponseWriter: w,
				propagate:      !needsTopLevelEscape,
				escapeIframe:   needsTopLevelEscape,
				req:            r,
			}
			inner.ServeHTTP(rw, r)
			return
		}

		// Non-wrapped, non-iframe (subresources, POSTs, JSON callers).
		inner.ServeHTTP(w, r)
	})
}

// isIframeEscapePath returns true for URLs whose redirect targets
// are external auth/logout endpoints that won't embed in an iframe.
// When the iframe lands on these, we serve an HTML escape page that
// uses window.top.location to perform the redirect at top level.
func isIframeEscapePath(path string) bool {
	return strings.HasPrefix(path, "/oauth2/") ||
		path == "/bailey-admin/signout"
}

// chromeFlowWriter intercepts the response from a handler running
// inside the chrome iframe. Two transformations:
//
//   - propagate=true: if the handler issues a 30x with a Location,
//     append `_bailey_iframe=1` to the Location URL so the next hop
//     stays inside the iframe.
//   - escapeIframe=true: instead of forwarding a 30x to the iframe,
//     serve an HTML page that uses window.top.location to navigate
//     the parent frame to the target. Used for /oauth2 redirects
//     to Keycloak.
type chromeFlowWriter struct {
	http.ResponseWriter
	propagate    bool
	escapeIframe bool
	req          *http.Request
	wroteHeader  bool
}

func (w *chromeFlowWriter) WriteHeader(status int) {
	if w.wroteHeader {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.wroteHeader = true

	loc := w.Header().Get("Location")
	if loc == "" || status < 300 || status >= 400 {
		w.ResponseWriter.WriteHeader(status)
		return
	}

	if w.escapeIframe {
		// Replace the redirect with an HTML escape page.
		w.Header().Del("Location")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.ResponseWriter.WriteHeader(http.StatusOK)
		_, _ = w.ResponseWriter.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>Continuing…</title></head><body><script>
try { window.top.location = ` + jsString(loc) + `; }
catch (e) { window.location = ` + jsString(loc) + `; }
</script><p>If you are not redirected, <a href="` + htmlEscape(loc) + `" target="_top">click here</a>.</p></body></html>`))
		return
	}

	if w.propagate {
		if propagated, ok := appendIframeMarker(loc); ok {
			w.Header().Set("Location", propagated)
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *chromeFlowWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

// appendIframeMarker adds ?_bailey_iframe=1 to a Location URL. Only
// rewrites same-origin (i.e. relative / origin-rooted) URLs — for
// absolute external URLs (Keycloak end_session etc.) we deliberately
// don't rewrite so the user lands externally. Returns the new URL
// and true if a rewrite happened, original + false otherwise.
func appendIframeMarker(loc string) (string, bool) {
	if loc == "" {
		return loc, false
	}
	// Absolute URL with a scheme → external; don't touch.
	if strings.Contains(loc, "://") {
		return loc, false
	}
	u, err := url.Parse(loc)
	if err != nil {
		return loc, false
	}
	q := u.Query()
	if q.Get(iframeMarkerQueryKey) != "" {
		return loc, false // already marked
	}
	q.Set(iframeMarkerQueryKey, "1")
	u.RawQuery = q.Encode()
	return u.String(), true
}

func jsString(s string) string {
	// Tiny JS-string serialiser. Good enough for absolute/relative
	// URLs (no embedded quotes / newlines in practice). Falls back
	// to JSON-ish escaping.
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case ' ':
			b.WriteString(` `)
		case ' ':
			b.WriteString(` `)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				const hex = "0123456789abcdef"
				b.WriteByte(hex[(r>>4)&0xf])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		`'`, "&#39;",
	)
	return r.Replace(s)
}
