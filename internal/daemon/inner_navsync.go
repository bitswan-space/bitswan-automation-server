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
		// capturingWriter only buffers when the upstream sets
		// Content-Type: text/html (the only case where we need to
		// rewrite the body to append the nav-sync script). Anything
		// else — JSON, NDJSON streams, JS, CSS, images — falls through
		// to the real writer immediately, preserving Flush() for
		// streaming endpoints like POST /bailey/api/workspaces.
		rec := &capturingWriter{
			real:    w,
			headers: http.Header{},
			status:  200,
			buf:     &bytes.Buffer{},
		}
		inner.ServeHTTP(rec, r)

		// Pass-through path already wrote headers + body straight to
		// `real`; nothing left to flush here.
		if rec.passthrough {
			return
		}

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

// capturingWriter routes writes one of two ways depending on the
// handler's Content-Type:
//
//   - text/html: buffer the whole body so the middleware can append
//     the nav-sync script before flushing.
//   - everything else: pass through to the real writer, preserving
//     Flush() semantics. Critical for streaming endpoints like
//     POST /bailey/api/workspaces (NDJSON) — buffering those would
//     hold the entire response until the upstream closes, defeating
//     the whole point of incremental events.
//
// The text/html vs. other split is decided lazily on the first Write
// (or WriteHeader) because the handler typically calls Header().Set
// before WriteHeader. Once `passthrough` is set, subsequent writes
// bypass the buffer entirely.
//
// Does NOT embed http.ResponseWriter — that would make Header()
// return the real writer's headers, causing the flush-back loop to
// duplicate every entry. Keep a private header map instead.
type capturingWriter struct {
	real        http.ResponseWriter
	headers     http.Header
	status      int
	wroteHeader bool
	buf         *bytes.Buffer
	passthrough bool // once true, Write goes straight to `real`
}

func (c *capturingWriter) Header() http.Header { return c.headers }

func (c *capturingWriter) WriteHeader(status int) {
	if c.wroteHeader {
		return
	}
	c.wroteHeader = true
	c.status = status
	// Decide here whether we need to rewrite the body. If not, copy
	// the headers + status straight to the real writer now so
	// subsequent Write()s pass through unbuffered (preserves Flush
	// for streaming responses).
	ct := c.headers.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		c.passthrough = true
		dst := c.real.Header()
		for k, vv := range c.headers {
			dst[k] = append(dst[k][:0:0], vv...)
		}
		c.real.WriteHeader(status)
	}
}
func (c *capturingWriter) Write(p []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(200)
	}
	if c.passthrough {
		return c.real.Write(p)
	}
	return c.buf.Write(p)
}

// Flush makes capturingWriter satisfy http.Flusher so handler-side
// w.(http.Flusher).Flush() calls actually reach the real writer when
// we're in passthrough mode. In buffering mode the call is a no-op
// (we can't partially flush text/html before the rewrite anyway).
func (c *capturingWriter) Flush() {
	if c.passthrough {
		if f, ok := c.real.(http.Flusher); ok {
			f.Flush()
		}
	}
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
