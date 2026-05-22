package daemon

import (
	"fmt"
	"net/http"
	"strings"
)

// chromeWrapMiddleware decides per-request whether to render the
// "Protected by Bitswan Bailey" wrap HTML or pass through to the
// inner handler. The decision is made purely on the request hostname:
//
//   - OUTER hostname (e.g. foo.<domain>): authenticated GET text/html
//     → serve the wrap. The wrap's iframe src is the paired INNER
//     hostname; CSP on the response pins the iframe to that origin.
//     Anything else on the outer hostname (subresources, POSTs, JSON)
//     is rejected with 404 — the outer host has no app surface.
//
//   - INNER hostname (e.g. foo--inner.<domain>): always pass through
//     to the inner handler. The inner handler proxies to the actual
//     workspace/service.
//
// There is no marker, no Referer chain, no Sec-Fetch-Dest. Hostname
// decides everything, so a `<a href="/foo">` inside an upstream app
// can't trigger a double-wrap (the hostname doesn't change) and a
// link to a third-party origin can't end up under the wrap bar
// (CSP frame-src blocks it).
func chromeWrapMiddleware(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := requestEndpointHost(r)
		email := r.Header.Get("X-Forwarded-Email")
		isInner := isInnerHost(host)
		fmt.Printf("[wrap-mw] host=%s path=%q method=%s email=%q inner=%v\n",
			host, r.URL.Path, r.Method, email, isInner)

		if isInner {
			inner.ServeHTTP(w, r)
			return
		}

		// Outer hostname. The wrap is meaningful only on a top-level
		// browser GET for HTML — everything else (favicon, oauth
		// callbacks served by oauth2-proxy upstream, etc.) we either
		// let through or 404.
		if strings.HasPrefix(r.URL.Path, "/oauth2/") {
			// oauth2-proxy is the layer above us — it handles these
			// directly, so they should never reach the daemon. If one
			// somehow does, pass it through unchanged.
			inner.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.NotFound(w, r)
			return
		}
		if email == "" {
			// Should be impossible — oauth2-proxy upstream sets the
			// header. If we get here without it, oauth failed; fall
			// through and let the inner handler 401.
			inner.ServeHTTP(w, r)
			return
		}
		serveBaileyChrome(w, r)
	})
}
