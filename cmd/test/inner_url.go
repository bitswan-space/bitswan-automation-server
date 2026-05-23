package test

import (
	"net/url"
	"strings"
)

// innerGitopsURL rewrites the workspace's outer gitops URL (the
// bailey-fronted hostname that browsers hit) into the matching inner
// hostname that traefik routes straight to the gitops container.
//
// Outer:  https://<ws>-gitops.<domain>          → bailey-protected-proxy → OAuth
// Inner:  https://<ws>-gitops--inner.<domain>   → gitops:8079 directly
//
// Integration tests carry a gitops-issued bearer token, not a bailey
// session cookie, so they have to bypass the wrap. Hitting the inner
// hostname does that without needing to be in the docker network.
func innerGitopsURL(outer string) string {
	parsed, err := url.Parse(outer)
	if err != nil {
		return outer
	}
	host := parsed.Host
	if host == "" {
		return outer
	}
	// Split off the optional :port suffix so we only rewrite the label.
	port := ""
	if idx := strings.LastIndex(host, ":"); idx > 0 && strings.LastIndex(host, "]") < idx {
		port = host[idx:]
		host = host[:idx]
	}
	label, rest, ok := strings.Cut(host, ".")
	if !ok {
		// No dot — single-label host. Just append the suffix.
		parsed.Host = host + "--inner" + port
		return parsed.String()
	}
	if strings.HasSuffix(label, "--inner") {
		// Already inner — no change.
		return outer
	}
	parsed.Host = label + "--inner." + rest + port
	return parsed.String()
}
