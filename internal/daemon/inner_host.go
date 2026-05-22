package daemon

import (
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// protectedHostnameDomain returns the suffix used for protected
// endpoint hostnames (e.g. "sandbox.bitswan.ai"). Empty if the
// daemon hasn't been initialised with a domain yet.
func protectedHostnameDomain() string {
	sc, err := config.NewAutomationServerConfig().LoadConfig()
	if err != nil || sc == nil {
		return ""
	}
	return sc.ProtectedHostnameDomain()
}

// Two-subdomain model for protected endpoints. Every endpoint has:
//
//   - An OUTER hostname (e.g. "foo.<domain>") — what the user types
//     into the address bar. The daemon serves the chrome-wrap HTML
//     here. Nothing else.
//   - An INNER hostname (e.g. "foo--inner.<domain>") — what the wrap
//     iframe loads. Routes to the actual workspace/service via
//     traefik-protected. Direct visits work too (CSP on the wrap is
//     the only thing that pins the iframe to this subdomain).
//
// The hostname decides the role — no Sec-Fetch-Dest, no URL marker,
// no Referer chain. A third-party app inside the iframe can have any
// `<a href>` it likes and the wrap can't get nested or double-applied,
// because the wrap subdomain physically serves only the wrap HTML.

const innerHostSuffix = "--inner"

// isInnerHost returns true if the hostname is the inner-subdomain
// half of a paired endpoint (e.g. "foo--inner.example.com").
func isInnerHost(host string) bool {
	if host == "" {
		return false
	}
	label, _, ok := strings.Cut(host, ".")
	if !ok {
		return false
	}
	return strings.HasSuffix(label, innerHostSuffix)
}

// toInnerHost maps an outer hostname to its inner pair.
// "foo.example.com" → "foo--inner.example.com". If the input already
// has the suffix it's returned unchanged.
func toInnerHost(outer string) string {
	if outer == "" || isInnerHost(outer) {
		return outer
	}
	label, rest, ok := strings.Cut(outer, ".")
	if !ok {
		return outer + innerHostSuffix
	}
	return label + innerHostSuffix + "." + rest
}

// toOuterHost is the inverse of toInnerHost: strips the inner suffix
// from the leftmost label. "foo--inner.example.com" → "foo.example.com".
// If the input has no suffix it's returned unchanged.
func toOuterHost(inner string) string {
	if inner == "" {
		return inner
	}
	label, rest, ok := strings.Cut(inner, ".")
	if !ok {
		return strings.TrimSuffix(label, innerHostSuffix)
	}
	if !strings.HasSuffix(label, innerHostSuffix) {
		return inner
	}
	return strings.TrimSuffix(label, innerHostSuffix) + "." + rest
}

// baileyDomainWildcard returns a CSP source-list entry for the
// bailey's hostname domain, e.g. "https://*.sandbox.bitswan.ai".
// Empty string if the domain isn't configured yet (bootstrap window).
func baileyDomainWildcard() string {
	d := protectedHostnameDomain()
	if d == "" {
		return ""
	}
	return "https://*." + d
}

// baileyDomainWildcardWS is the wss:// variant for connect-src.
func baileyDomainWildcardWS() string {
	d := protectedHostnameDomain()
	if d == "" {
		return ""
	}
	return "wss://*." + d
}

// strictInnerCSP returns the Content-Security-Policy header value for
// content served on an inner-subdomain. It restricts the inner app
// to fetching resources from the bailey's own hostname family —
// nothing on the open internet — and pins frame-ancestors to the
// outer-subdomain so only the paired wrap can embed it.
//
// 'unsafe-inline' and 'unsafe-eval' are included for script-src and
// style-src because most editor/IDE apps (Monaco, CodeMirror, etc.)
// don't function without them. The cross-origin restriction is the
// security primitive; XSS-within-the-app is the app's own problem.
func strictInnerCSP(innerHost string) string {
	outer := toOuterHost(innerHost)
	wild := baileyDomainWildcard()
	wildWS := baileyDomainWildcardWS()
	if wild == "" {
		// Domain unconfigured (bootstrap window). Fall back to a
		// CSP that at least pins frame-ancestors so the bare app
		// can't be embedded by arbitrary origins.
		return "frame-ancestors https://" + outer
	}
	src := "'self' " + wild
	return strings.Join([]string{
		"default-src " + src,
		"img-src " + src + " data: blob:",
		"font-src " + src + " data:",
		"connect-src " + src + " " + wildWS + " wss://" + innerHost + " ws://" + innerHost,
		"frame-src " + src,
		"script-src " + src + " 'unsafe-inline' 'unsafe-eval' blob:",
		"style-src " + src + " 'unsafe-inline'",
		"media-src " + src + " data: blob:",
		"worker-src " + src + " blob:",
		"form-action " + src,
		"frame-ancestors https://" + outer,
	}, "; ")
}
