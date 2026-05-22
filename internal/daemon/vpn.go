package daemon

import (
	"archive/tar"
	"compress/gzip"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
)

// dockerComposeUp writes the compose content to a file and runs docker
// compose up -d. Generic helper used by the SIEM, ZTNA, and traefik-protected
// lifecycles — kept here because the daemon's other compose helpers are
// here too.
func dockerComposeUp(projectName, composeContent, workDir string) error {
	composePath := filepath.Join(workDir, "docker-compose.yaml")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create dir %s: %w", workDir, err)
	}
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		return fmt.Errorf("failed to write compose file: %w", err)
	}
	cmd := exec.Command("docker", "compose", "-p", projectName, "-f", composePath, "up", "-d")
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

// dockerComposeDown is the symmetric tear-down helper.
func dockerComposeDown(projectName, workDir string) error {
	composePath := filepath.Join(workDir, "docker-compose.yaml")
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		return nil
	}
	cmd := exec.Command("docker", "compose", "-p", projectName, "-f", composePath, "down", "--remove-orphans")
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

// containerIPv6 returns a container's GlobalIPv6Address on the named Docker
// network, or the empty string if unavailable.
func containerIPv6(container, network string) string {
	format := fmt.Sprintf(`{{(index .NetworkSettings.Networks %q).GlobalIPv6Address}}`, network)
	out, err := exec.Command("docker", "inspect", container, "--format", format).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// baileyConfigName is the workspace identity bitswan registers with AOC for
// the OIDC client that protects the Bailey pages.
const baileyConfigName = "bailey"

// getBaileyOAuthConfig fetches a cached OAuth config for the Bailey
// pages, or provisions one via AOC on first call.
func getBaileyOAuthConfig(domain string) (*oauth.Config, error) {
	if cfg, err := oauth.GetOauthConfig(baileyConfigName); err == nil {
		return cfg, nil
	}

	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		return nil, fmt.Errorf("AOC not configured: %w", err)
	}
	redirectURI := fmt.Sprintf("https://bailey.%s/oauth2/callback", domain)
	resp, err := aocClient.GetOrCreateOAuthClient("bailey", redirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create OAuth client from AOC: %w", err)
	}

	cfg := &oauth.Config{
		ClientId:     resp.ClientID,
		ClientSecret: resp.ClientSecret,
		IssuerUrl:    resp.IssuerURL,
		CookieSecret: genRandomString(32),
		EmailDomains: []string{"*"},
	}

	homeDir := os.Getenv("HOME")
	os.MkdirAll(filepath.Join(homeDir, ".config", "bitswan", "workspaces", baileyConfigName), 0755)
	oauth.SaveOauthConfig(baileyConfigName, cfg)
	return cfg, nil
}

// startOAuth2Proxy launches an oauth2-proxy subprocess in front of the daemon
// for the given hostname/port. Configured exactly the way the editor's
// oauth2-proxy is — same env vars CreateOAuthEnvVars produces — so any
// Keycloak setup that works for the editor works here too. We override
// only the redirect URL (different hostname pattern) and HTTP address
// (different per-instance port).
func startOAuth2Proxy(domain, hostname string, port int) error {
	oauthCfg, err := getBaileyOAuthConfig(domain)
	if err != nil {
		return err
	}

	// Idempotently register this hostname's callback with Keycloak.
	redirectURL := fmt.Sprintf("https://%s/oauth2/callback", hostname)
	if aocClient, err := aoc.NewAOCClient(); err == nil {
		aocClient.GetOrCreateOAuthClient("bailey", redirectURL)
	}

	// Lean on CreateOAuthEnvVars for the canonical bitswan oauth2-proxy
	// env shape (provider, scope, groups claim, optional discovery
	// overrides, allowed groups). It builds REDIRECT_URL and HTTP_ADDRESS
	// from the workspace/service convention used by the editor and
	// gitops; we replace those two with our values below since the VPN
	// admin doesn't follow the {workspace}-{service} hostname pattern.
	envVars := oauth.CreateOAuthEnvVars(oauthCfg, "bailey", "", domain)
	envVars = setEnvVar(envVars, "OAUTH2_PROXY_REDIRECT_URL", redirectURL)
	envVars = setEnvVar(envVars, "OAUTH2_PROXY_HTTP_ADDRESS", fmt.Sprintf("0.0.0.0:%d", port))

	cookieName := fmt.Sprintf("_bitswan_vpn_%d", port)
	envVars = append(envVars,
		"OAUTH2_PROXY_UPSTREAMS=http://127.0.0.1:8080",
		"OAUTH2_PROXY_COOKIE_NAME="+cookieName,
		// Forward identity to our backend so /bailey-internal handlers
		// can read X-Forwarded-Email / Groups for the admin check.
		"OAUTH2_PROXY_PASS_USER_HEADERS=true",
		"OAUTH2_PROXY_SET_XAUTHREQUEST=true",
		"OAUTH2_PROXY_PASS_ACCESS_TOKEN=true",
		"OAUTH2_PROXY_SET_AUTHORIZATION_HEADER=true",
		// Allow ?rd= in /oauth2/sign_out to redirect to Keycloak's
		// end-session endpoint so we can do RP-initiated logout.
		"OAUTH2_PROXY_WHITELIST_DOMAINS="+keycloakHostFromIssuer(oauthCfg.IssuerUrl),
	)

	// Bitswan-branded error template. The "Not authorized" hint
	// names the actual organisation (server name) the user needs to
	// be a member of, so the error is actionable — saying "Keycloak"
	// in the message is jargon that confuses users who only know it
	// as the org/IdP.
	homeDir := os.Getenv("HOME")
	templateDir := filepath.Join(homeDir, ".config", "bitswan", "oauth2-proxy-templates")
	os.MkdirAll(templateDir, 0755)
	orgName := serverDisplayName() // e.g. "Sandbox" or "BitSwan"
	errorTemplate := `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>` + html.EscapeString(orgName) + ` — Authentication Error</title>
<style>` + bitswanPageCSS + `</style></head><body>
<div class="header">` + bitswanLogoSVG + `<h1>Authentication Error</h1></div>
<div class="card">
<h2>{{.Title}}</h2>
<p>{{.Message}}</p>
</div>
<div class="card">
<h2>Common causes</h2>
<div class="step"><span class="step-num">1</span><div class="step-text"><b>Email not verified</b> — please verify your email on your identity provider, then try again.</div></div>
<div class="step"><span class="step-num">2</span><div class="step-text"><b>Session expired</b> — try signing in again by visiting the <a href="/bailey/" style="color:#093DF5">Bailey page</a>.</div></div>
<div class="step"><span class="step-num">3</span><div class="step-text"><b>Not authorized</b> — you may not be a member of the <b>` + html.EscapeString(orgName) + `</b> organisation.</div></div>
</div></body></html>`
	os.WriteFile(filepath.Join(templateDir, "error.html"), []byte(errorTemplate), 0644)
	envVars = append(envVars, "OAUTH2_PROXY_CUSTOM_TEMPLATES_DIR="+templateDir)

	binPath, err := ensureOAuth2ProxyBinary()
	if err != nil {
		return fmt.Errorf("oauth2-proxy binary unavailable: %w", err)
	}

	cmd := exec.Command(binPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), envVars...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start oauth2-proxy: %w", err)
	}
	fmt.Printf("oauth2-proxy started for %s (PID %d, listening on :%d)\n", hostname, cmd.Process.Pid, port)
	go func() {
		if err := cmd.Wait(); err != nil {
			fmt.Printf("Warning: oauth2-proxy (%s) exited: %v\n", hostname, err)
		}
	}()
	return nil
}

// setEnvVar replaces the value of an OAUTH2_PROXY_* env var in a slice of
// "KEY=value" strings, appending if not present. Used so we can override
// individual settings produced by CreateOAuthEnvVars without rewriting it.
func setEnvVar(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// keycloakHostFromIssuer returns the host portion of a Keycloak issuer URL
// like "https://keycloak.example.com/realms/master" → "keycloak.example.com".
// Used for oauth2-proxy's --whitelist-domain so sign-out can redirect to
// the issuer's end-session endpoint.
func keycloakHostFromIssuer(issuer string) string {
	s := strings.TrimPrefix(issuer, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// keycloakLogoutURL builds an OIDC RP-initiated logout URL for the issuer in
// oauthCfg. Used as the ?rd= target for oauth2-proxy's /oauth2/sign_out so
// the user's cookie is cleared *and* their Keycloak SSO session ends.
func keycloakLogoutURL(oauthCfg *oauth.Config, postLogoutRedirect string) string {
	base := strings.TrimRight(oauthCfg.IssuerUrl, "/") + "/protocol/openid-connect/logout"
	q := url.Values{}
	q.Set("client_id", oauthCfg.ClientId)
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	return base + "?" + q.Encode()
}

func genRandomString(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		var rb [1]byte
		crand.Read(rb[:])
		b[i] = alphabet[int(rb[0])%len(alphabet)]
	}
	return string(b)
}

// oauth2ProxyPath is the on-disk location of the oauth2-proxy binary. We
// keep it under ~/.config/bitswan (a host-mounted volume) so it survives
// daemon container recreation — the daemon image itself doesn't ship
// oauth2-proxy.
func oauth2ProxyPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".config", "bitswan", "oauth2-proxy")
}

// ensureOAuth2ProxyBinary returns the path to oauth2-proxy, downloading the
// latest linux-amd64 release from GitHub if it isn't already present.
func ensureOAuth2ProxyBinary() (string, error) {
	path := oauth2ProxyPath()
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return path, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", fmt.Errorf("create target dir: %w", err)
	}

	fmt.Println("Downloading oauth2-proxy...")
	resp, err := http.Get("https://api.github.com/repos/oauth2-proxy/oauth2-proxy/releases/latest")
	if err != nil {
		return "", fmt.Errorf("fetch release info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("release info status %d", resp.StatusCode)
	}
	var releaseInfo struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releaseInfo); err != nil {
		return "", fmt.Errorf("parse release info: %w", err)
	}

	var downloadURL string
	for _, a := range releaseInfo.Assets {
		if strings.Contains(a.Name, "linux-amd64.tar.gz") && !strings.Contains(a.Name, ".sha256sum") {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return "", fmt.Errorf("no linux-amd64 tarball in release")
	}

	tarResp, err := http.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer tarResp.Body.Close()
	if tarResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download status %d", tarResp.StatusCode)
	}
	gz, err := gzip.NewReader(tarResp.Body)
	if err != nil {
		return "", fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("tar: %w", err)
		}
		if strings.HasSuffix(hdr.Name, "/oauth2-proxy") || hdr.Name == "oauth2-proxy" {
			tmp := path + ".tmp"
			out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return "", fmt.Errorf("create output: %w", err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				os.Remove(tmp)
				return "", fmt.Errorf("write binary: %w", err)
			}
			out.Close()
			if err := os.Rename(tmp, path); err != nil {
				return "", fmt.Errorf("install: %w", err)
			}
			fmt.Printf("oauth2-proxy downloaded to %s\n", path)
			return path, nil
		}
	}
	return "", fmt.Errorf("oauth2-proxy binary not in tarball")
}

// setupProtectedRoutes wires bailey.<domain> into the shared
// two-subdomain protected-ingress chain. The outer bailey hostname
// gets the chrome wrap; the inner bailey--inner hostname routes
// through to the daemon's docs server which renders the actual
// bailey admin UI.
//
// One Keycloak client for everything (bitswan-protected-client); no
// separate per-bailey oauth2-proxy. Both subdomains' callback URIs
// are registered idempotently via AOC.
func setupProtectedRoutes(domain, internalDomain string) {
	outer := "bailey." + domain
	inner := toInnerHost(outer)

	if err := registerProtectedRedirectURI(outer); err != nil {
		fmt.Printf("Warning: AOC didn't accept protected-client redirect URIs for %s/%s: %v\n", outer, inner, err)
	}
	// OUTER → bitswan-protected-proxy (auth) → daemon (wrap HTML).
	if err := traefikapi.AddRouteWithTraefikPriority(
		outer, "bitswan-protected-proxy:80", "", "letsencrypt", 200,
	); err != nil {
		fmt.Printf("Warning: register platform route for %s: %v\n", outer, err)
	}
	// INNER → bitswan-protected-proxy (auth) → daemon (MFA gate + ACL)
	//       → daemon docs server (8080, in-process). The daemon's MFA
	// gate resolves the upstream by hostname now; no traefik-protected
	// hop needed.
	if err := traefikapi.AddRouteWithTraefikPriority(
		inner, "bitswan-protected-proxy:80", "", "letsencrypt", 200,
	); err != nil {
		fmt.Printf("Warning: register platform route for %s: %v\n", inner, err)
	}
}
