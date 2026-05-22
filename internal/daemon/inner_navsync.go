package daemon

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// injectNavSyncMiddleware buffers responses, and if they're text/html
// on an inner-host request, appends the nav-sync script before
// returning. Used to cover handler paths that bypass the reverse
// proxy's ModifyResponse — handleGatePath in particular renders its
// own HTML pages and writes them straight to the ResponseWriter.
func injectNavSyncMiddleware(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isInnerHost(requestEndpointHost(r)) {
			inner.ServeHTTP(w, r)
			return
		}
		rec := &capturingWriter{
			real:    w,
			headers: http.Header{},
			status:  200,
			buf:     &bytes.Buffer{},
		}
		inner.ServeHTTP(rec, r)

		ct := rec.headers.Get("Content-Type")
		body := rec.buf.Bytes()
		if strings.HasPrefix(ct, "text/html") && len(body) > 0 {
			body = appendNavSyncToHTML(body)
			rec.headers.Set("Content-Length", strconv.Itoa(len(body)))
		}
		// Flush the recorded headers ONCE to the real writer. Earlier
		// we double-emitted because rec.Header() and w.Header() were
		// the same map (we embedded ResponseWriter), so iterating and
		// Add()-ing duplicated every entry.
		dst := w.Header()
		for k, vv := range rec.headers {
			dst[k] = append(dst[k][:0:0], vv...)
		}
		w.WriteHeader(rec.status)
		_, _ = w.Write(body)
	})
}

func appendNavSyncToHTML(body []byte) []byte {
	insertion := []byte(navSyncScript)
	if idx := bytes.LastIndex(bytes.ToLower(body), []byte("</body>")); idx >= 0 {
		out := make([]byte, 0, len(body)+len(insertion))
		out = append(out, body[:idx]...)
		out = append(out, insertion...)
		out = append(out, body[idx:]...)
		return out
	}
	return append(body, insertion...)
}

// capturingWriter buffers everything an inner handler writes so the
// middleware can rewrite text/html bodies before flushing them.
// Does NOT embed http.ResponseWriter — that would make Header()
// return the real writer's headers, causing the flush-back loop to
// duplicate every entry. Keep a private header map instead.
type capturingWriter struct {
	real        http.ResponseWriter
	headers     http.Header
	status      int
	wroteHeader bool
	buf         *bytes.Buffer
}

func (c *capturingWriter) Header() http.Header { return c.headers }

func (c *capturingWriter) WriteHeader(status int) {
	if !c.wroteHeader {
		c.status = status
		c.wroteHeader = true
	}
}
func (c *capturingWriter) Write(p []byte) (int, error) {
	if !c.wroteHeader {
		c.wroteHeader = true
		c.status = 200
	}
	return c.buf.Write(p)
}

// inner-content URL sync. The wrap's outer URL (the one the user sees
// in their address bar) needs to mirror the path of whatever the
// iframe is currently showing — otherwise reloading the page ends up
// back at "/" instead of, say, /bailey/map.
//
// Outer and inner are different origins (the whole point of the
// outer/inner split), so the parent can't peek into the iframe's
// location. Workaround: every HTML doc served on the inner subdomain
// gets a small inline script appended that postMessages the current
// path to window.parent — on initial load and on every pushState /
// replaceState / popstate. The wrap listens for those messages and
// history.replaceStates its own URL.
//
// injectNavSync rewrites resp.Body in place when the response is
// text/html on an inner-subdomain request. Handles plain and gzipped
// bodies (Content-Encoding: gzip).

const navSyncScript = `<script>(function(){
  function post(){
    if (window.parent && window.parent !== window) {
      try {
        window.parent.postMessage({type:'bailey-nav', path: location.pathname + location.search + location.hash}, '*');
      } catch (e) {}
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', post);
  } else { post(); }
  var _push = history.pushState;
  history.pushState = function(){ var r = _push.apply(this, arguments); post(); return r; };
  var _replace = history.replaceState;
  history.replaceState = function(){ var r = _replace.apply(this, arguments); post(); return r; };
  window.addEventListener('popstate', post);
  window.addEventListener('hashchange', post);
})();</script>`

// injectNavSync mutates resp to append the script before </body> (or
// at end-of-body if no </body> tag exists). Returns silently for
// responses we shouldn't touch.
func injectNavSync(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		return
	}
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))

	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		// Leave a closed body; the proxy will surface an error to the
		// caller. Restoring the original bytes would require buffering
		// earlier, which we don't.
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return
	}

	body := raw
	if enc == "gzip" {
		if gr, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
			if decompressed, err := io.ReadAll(gr); err == nil {
				body = decompressed
			}
			_ = gr.Close()
		}
	}

	body = appendNavSyncToHTML(body)

	if enc == "gzip" {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, _ = gw.Write(body)
		_ = gw.Close()
		body = buf.Bytes()
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.ContentLength = int64(len(body))
}
