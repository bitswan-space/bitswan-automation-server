package traefikapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ============================================================
// Public types (kept API-compatible with caddyapi)
// ============================================================

type Route struct {
	ID       string   `json:"@id,omitempty"`
	Match    []Match  `json:"match"`
	Handle   []Handle `json:"handle"`
	Terminal bool     `json:"terminal"`
}

type Match struct {
	Host []string `json:"host"`
}

type Handle struct {
	Handler   string     `json:"handler"`
	Routes    []Route    `json:"routes,omitempty"`
	Upstreams []Upstream `json:"upstreams,omitempty"`
}

type Upstream struct {
	Dial string `json:"dial"`
}

type TLSPolicy struct {
	ID                   string                  `json:"@id,omitempty"`
	Match                TLSMatch                `json:"match"`
	CertificateSelection TLSCertificateSelection `json:"certificate_selection"`
}

type TLSMatch struct {
	SNI []string `json:"sni"`
}

type TLSCertificateSelection struct {
	AnyTag []string `json:"any_tag"`
}

type TLSFileLoad struct {
	ID          string   `json:"@id,omitempty"`
	Certificate string   `json:"certificate"`
	Key         string   `json:"key"`
	Tags        []string `json:"tags"`
}

// ============================================================
// Internal Traefik dynamic config types
// ============================================================

type traefikDynConfig struct {
	HTTP *traefikHTTPConfig `json:"http,omitempty"`
	TLS  *traefikTLSConfig  `json:"tls,omitempty"`
}

type traefikHTTPConfig struct {
	Routers  map[string]*traefikRouter  `json:"routers,omitempty"`
	Services map[string]*traefikService `json:"services,omitempty"`
}

type traefikRouter struct {
	EntryPoints []string          `json:"entryPoints,omitempty"`
	Rule        string            `json:"rule"`
	Service     string            `json:"service"`
	TLS         *traefikRouterTLS `json:"tls,omitempty"`
}

// traefikRouterTLS, when non-nil, enables TLS termination on a router.
type traefikRouterTLS struct {
	CertResolver string `json:"certResolver,omitempty"`
}

type traefikService struct {
	LoadBalancer *traefikLoadBalancer `json:"loadBalancer"`
}

type traefikLoadBalancer struct {
	Servers []traefikServer `json:"servers"`
}

type traefikServer struct {
	URL string `json:"url"`
}

type traefikTLSConfig struct {
	Certificates []traefikTLSCert `json:"certificates,omitempty"`
}

type traefikTLSCert struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// ============================================================
// State management
// ============================================================

var stateMu sync.Mutex

// getTraefikBaseURL returns the Traefik management API base URL.
// If workspaceName is provided and non-empty, it returns http://{workspaceName}__traefik:8080.
// Otherwise it checks BITSWAN_TRAEFIK_HOST, defaulting to http://localhost:8080.
func getTraefikBaseURL(workspaceName ...string) string {
	if len(workspaceName) > 0 && workspaceName[0] != "" {
		return fmt.Sprintf("http://%s__traefik:8080", workspaceName[0])
	}

	host := strings.TrimSpace(os.Getenv("BITSWAN_TRAEFIK_HOST"))
	if host == "" {
		return "http://localhost:8080"
	}

	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "http://" + host
	}
	host = strings.TrimRight(host, "/")
	return host
}

func getWorkspaceTraefikBaseURL(workspaceName string) string {
	return getTraefikBaseURL(workspaceName)
}

// GetWorkspaceTraefikBaseURL is the public version of getWorkspaceTraefikBaseURL.
func GetWorkspaceTraefikBaseURL(workspaceName string) string {
	return getWorkspaceTraefikBaseURL(workspaceName)
}

// isWorkspaceURL reports whether the base URL targets a workspace sub-traefik.
func isWorkspaceURL(traefikBaseURL string) bool {
	return strings.Contains(traefikBaseURL, "__traefik")
}

// extractWorkspaceName extracts the workspace name from a workspace traefik URL
// (format: http://{workspace}__traefik:8080).
func extractWorkspaceName(traefikBaseURL string) string {
	urlWithoutScheme := strings.TrimPrefix(traefikBaseURL, "http://")
	urlWithoutScheme = strings.TrimPrefix(urlWithoutScheme, "https://")
	hostPart := strings.Split(urlWithoutScheme, ":")[0]
	return strings.TrimSuffix(hostPart, "__traefik")
}

// getStateFilePath returns the path of the REST provider state file for the given base URL.
// Global traefik:    ~/.config/bitswan/traefik/rest-state.json
// Workspace traefik: ~/.config/bitswan/workspaces/{ws}/traefik/rest-state.json
func getStateFilePath(traefikBaseURL string) string {
	homeDir := os.Getenv("HOME")
	if isWorkspaceURL(traefikBaseURL) {
		workspaceName := extractWorkspaceName(traefikBaseURL)
		return filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName, "traefik", "rest-state.json")
	}
	return filepath.Join(homeDir, ".config", "bitswan", "traefik", "rest-state.json")
}

func loadState(path string) (*traefikDynConfig, error) {
	state := &traefikDynConfig{
		HTTP: &traefikHTTPConfig{
			Routers:  make(map[string]*traefikRouter),
			Services: make(map[string]*traefikService),
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	// Ensure maps are initialised after unmarshalling.
	if state.HTTP == nil {
		state.HTTP = &traefikHTTPConfig{}
	}
	if state.HTTP.Routers == nil {
		state.HTTP.Routers = make(map[string]*traefikRouter)
	}
	if state.HTTP.Services == nil {
		state.HTTP.Services = make(map[string]*traefikService)
	}

	return state, nil
}

func saveState(path string, state *traefikDynConfig) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}
	return nil
}

// pushState PUTs the full dynamic config to Traefik's REST provider endpoint.
func pushState(traefikBaseURL string, state *traefikDynConfig) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal state for push: %w", err)
	}
	url := traefikBaseURL + "/api/providers/rest"
	_, err = sendRequest("PUT", url, data)
	if err != nil {
		return fmt.Errorf("failed to push state to Traefik: %w", err)
	}
	return nil
}

// modifyState serialises load → fn → save → push under stateMu.
func modifyState(traefikBaseURL string, fn func(*traefikDynConfig) error) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	stateFilePath := getStateFilePath(traefikBaseURL)
	if err := os.MkdirAll(filepath.Dir(stateFilePath), 0755); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	state, err := loadState(stateFilePath)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	if err := fn(state); err != nil {
		return err
	}

	if err := saveState(stateFilePath, state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	if err := pushState(traefikBaseURL, state); err != nil {
		return fmt.Errorf("failed to push state: %w", err)
	}

	return nil
}

// ============================================================
// Internal helpers
// ============================================================

// sanitizeHostname converts a hostname to a safe route ID by replacing dots
// and hyphens with underscores.
func sanitizeHostname(hostname string) string {
	return strings.ReplaceAll(strings.ReplaceAll(hostname, ".", "_"), "-", "_")
}

// ensureUpstreamURL ensures the upstream is a full URL for Traefik's loadBalancer.
// Unlike Caddy, Traefik requires "http://host:port" (not just "host:port").
// Also remaps WSS port 8084 → WS port 8083 since TLS termination happens at Traefik.
func ensureUpstreamURL(upstream string) string {
	upstream = strings.TrimPrefix(upstream, "/")

	// Remap WSS port.
	if strings.Contains(upstream, ":8084") {
		upstream = strings.Replace(upstream, ":8084", ":8083", 1)
	}

	// Return as-is if already has a scheme.
	if strings.HasPrefix(upstream, "http://") || strings.HasPrefix(upstream, "https://") {
		return upstream
	}

	// Strip other scheme prefixes, then add http://.
	upstream = strings.TrimPrefix(upstream, "ws://")
	upstream = strings.TrimPrefix(upstream, "wss://")
	return "http://" + upstream
}

// extractHostFromRule extracts the literal hostname from a Host(`hostname`) rule.
// Returns the raw rule string for any other rule format (e.g. HostRegexp).
func extractHostFromRule(rule string) string {
	if start := strings.Index(rule, "Host(`"); start != -1 {
		start += 6
		if end := strings.Index(rule[start:], "`)"); end != -1 {
			return rule[start : start+end]
		}
	}
	return rule
}

func sendRequest(method, url string, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Traefik API: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Traefik API returned status code %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// ============================================================
// Public functions
// ============================================================

// InitSet is a no-op stub kept for API compatibility with caddyapi.
// Traefik state is managed via the state file; there is no incremental init path.
func InitSet(url string, payload []byte) error {
	return nil
}

// InitTraefik ensures the global Traefik REST provider state file exists and
// pushes an empty (or existing) configuration to Traefik.
func InitTraefik() error {
	traefikBaseURL := getTraefikBaseURL()
	return modifyState(traefikBaseURL, func(_ *traefikDynConfig) error {
		return nil
	})
}

// InitWorkspaceTraefik initialises a workspace Traefik (HTTP-only).
// Callers must set BITSWAN_TRAEFIK_HOST to target the correct workspace instance.
func InitWorkspaceTraefik() error {
	traefikBaseURL := getTraefikBaseURL()
	return modifyState(traefikBaseURL, func(_ *traefikDynConfig) error {
		return nil
	})
}

// RegisterServiceWithTraefik registers a service hostname in Traefik.
// It constructs {workspaceName}-{serviceName}.{domain} and delegates to AddRoute.
func RegisterServiceWithTraefik(serviceName, workspaceName, domain, upstream string) error {
	hostname := fmt.Sprintf("%s-%s.%s", workspaceName, serviceName, domain)
	return AddRoute(hostname, upstream)
}

// UnregisterTraefikService removes a service route from Traefik.
func UnregisterTraefikService(serviceName, workspaceName, domain string) error {
	if domain != "" {
		hostname := fmt.Sprintf("%s-%s.%s", workspaceName, serviceName, domain)
		err := RemoveRoute(hostname)
		if err == nil {
			return nil
		}
		fmt.Printf("Warning: failed to remove route using hostname %s, trying legacy format: %v\n", hostname, err)
	}

	// Fall back to legacy ID (workspaceName_serviceName).
	legacyID := fmt.Sprintf("%s_%s", workspaceName, serviceName)
	traefikBaseURL := getTraefikBaseURL()
	return modifyState(traefikBaseURL, func(state *traefikDynConfig) error {
		delete(state.HTTP.Routers, legacyID)
		delete(state.HTTP.Services, legacyID)
		return nil
	})
}

// AddRoute adds a route for hostname → upstream using the default Traefik base URL.
func AddRoute(hostname, upstream string) error {
	return AddRouteWithTraefik(hostname, upstream, "")
}

// AddRouteWithTraefik adds a route for hostname → upstream.
// If traefikBaseURL is empty, uses the default from getTraefikBaseURL().
// Routes targeting a workspace sub-traefik are HTTP-only (no TLS).
// Routes targeting the global traefik include TLS and both entrypoints.
// An optional certResolver string can be provided to use ACME (e.g. "letsencrypt").
func AddRouteWithTraefik(hostname, upstream, traefikBaseURL string, certResolver ...string) error {
	if traefikBaseURL == "" {
		traefikBaseURL = getTraefikBaseURL()
	}

	routeID := sanitizeHostname(hostname)
	processedUpstream := ensureUpstreamURL(upstream)
	fmt.Printf("AddRoute: original upstream='%s', processed upstream='%s'\n", upstream, processedUpstream)

	workspaceTarget := isWorkspaceURL(traefikBaseURL)

	resolver := ""
	if len(certResolver) > 0 {
		resolver = certResolver[0]
	}

	return modifyState(traefikBaseURL, func(state *traefikDynConfig) error {
		router := &traefikRouter{
			Rule:    fmt.Sprintf("Host(`%s`)", hostname),
			Service: routeID,
		}
		if workspaceTarget {
			router.EntryPoints = []string{"web"}
		} else {
			router.EntryPoints = []string{"web", "websecure"}
			router.TLS = &traefikRouterTLS{CertResolver: resolver}
		}

		state.HTTP.Routers[routeID] = router
		state.HTTP.Services[routeID] = &traefikService{
			LoadBalancer: &traefikLoadBalancer{
				Servers: []traefikServer{{URL: processedUpstream}},
			},
		}

		fmt.Printf("AddRoute: added route %s -> %s (ID: %s)\n", hostname, processedUpstream, routeID)
		return nil
	})
}

// RemoveRoute removes a route by hostname using the default Traefik base URL.
func RemoveRoute(hostname string) error {
	return RemoveRouteWithTraefik(hostname, "")
}

// RemoveRouteWithTraefik removes a route by hostname.
// If traefikBaseURL is empty, uses the default from getTraefikBaseURL().
// Connection errors are treated as success (Traefik unreachable → route already gone).
func RemoveRouteWithTraefik(hostname, traefikBaseURL string) error {
	if traefikBaseURL == "" {
		traefikBaseURL = getTraefikBaseURL()
	}

	routeID := sanitizeHostname(hostname)

	err := modifyState(traefikBaseURL, func(state *traefikDynConfig) error {
		delete(state.HTTP.Routers, routeID)
		delete(state.HTTP.Services, routeID)
		return nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "timeout") {
			return nil // Traefik unreachable — assume route is gone.
		}
		return fmt.Errorf("failed to remove route for hostname '%s': %w", hostname, err)
	}

	return nil
}

// ListRoutes retrieves all current routes from the default Traefik state file.
func ListRoutes() ([]Route, error) {
	return ListRoutesWithTraefik("")
}

// ListRoutesWithTraefik retrieves all current routes from the Traefik state file.
// If traefikBaseURL is empty, uses the default from getTraefikBaseURL().
// The returned []Route is in the caddyapi-compatible format.
func ListRoutesWithTraefik(traefikBaseURL string) ([]Route, error) {
	if traefikBaseURL == "" {
		traefikBaseURL = getTraefikBaseURL()
	}

	stateMu.Lock()
	stateFilePath := getStateFilePath(traefikBaseURL)
	state, err := loadState(stateFilePath)
	stateMu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}

	var routes []Route
	for routeID, router := range state.HTTP.Routers {
		hostname := extractHostFromRule(router.Rule)

		var upstreams []Upstream
		if svc, ok := state.HTTP.Services[routeID]; ok && svc.LoadBalancer != nil {
			for _, srv := range svc.LoadBalancer.Servers {
				upstreams = append(upstreams, Upstream{Dial: srv.URL})
			}
		}

		routes = append(routes, Route{
			ID:    routeID,
			Match: []Match{{Host: []string{hostname}}},
			Handle: []Handle{{
				Handler:   "reverse_proxy",
				Upstreams: upstreams,
			}},
			Terminal: true,
		})
	}

	return routes, nil
}

// InstallTLSCerts installs TLS certificates for Traefik and registers them in
// the global Traefik state.
//
// Parameters:
//   - hostname: the hostname for the certificate (required)
//   - local: if true, generate certs with mkcert
//   - domain_dir: directory containing pre-existing certs to install (optional)
func InstallTLSCerts(hostname string, local bool, domain_dir string) error {
	var targetHostname string

	if domain_dir != "" {
		if hostname == "" {
			return fmt.Errorf("hostname is required when installing from directory")
		}
		targetHostname = hostname
		traefikConfig := os.Getenv("HOME") + "/.config/bitswan/traefik"
		if err := InstallCertsFromDir(domain_dir, targetHostname, traefikConfig); err != nil {
			return fmt.Errorf("failed to install certificates from directory: %w", err)
		}
	} else if local {
		if hostname == "" {
			return fmt.Errorf("hostname is required for local certificate generation")
		}
		if !strings.Contains(hostname, ".") {
			return fmt.Errorf("invalid hostname format: must contain at least one dot")
		}

		certDir, err := generateCertsForHostname(hostname)
		if err != nil {
			return fmt.Errorf("failed to generate certificates for hostname: %w", err)
		}
		defer os.RemoveAll(certDir)

		targetHostname = hostname
		traefikConfig := os.Getenv("HOME") + "/.config/bitswan/traefik"
		if err := InstallCertsFromDir(certDir, targetHostname, traefikConfig); err != nil {
			return fmt.Errorf("failed to install certificates: %w", err)
		}
	} else {
		return fmt.Errorf("cannot use mkcert to generate non-local certificates")
	}

	// Register cert paths in global Traefik state.
	traefikBaseURL := getTraefikBaseURL()
	sanitized := sanitizeHostname(targetHostname)
	certFile := fmt.Sprintf("/tls/%s/full-chain.pem", sanitized)
	keyFile := fmt.Sprintf("/tls/%s/private-key.pem", sanitized)

	return modifyState(traefikBaseURL, func(state *traefikDynConfig) error {
		if state.TLS == nil {
			state.TLS = &traefikTLSConfig{}
		}
		// Deduplicate: remove any existing entry for the same cert path.
		var newCerts []traefikTLSCert
		for _, cert := range state.TLS.Certificates {
			if cert.CertFile != certFile {
				newCerts = append(newCerts, cert)
			}
		}
		state.TLS.Certificates = append(newCerts, traefikTLSCert{
			CertFile: certFile,
			KeyFile:  keyFile,
		})
		return nil
	})
}

// DeleteTraefikRecords removes all Traefik routing entries for a workspace.
func DeleteTraefikRecords(workspaceName string) error {
	return DeleteTraefikRecordsWithWriter(workspaceName, nil)
}

// DeleteTraefikRecordsWithWriter removes all Traefik routing entries for a workspace,
// writing progress messages to writer (stdout if nil).
func DeleteTraefikRecordsWithWriter(workspaceName string, writer io.Writer) error {
	log := func(format string, args ...interface{}) {
		if writer != nil {
			fmt.Fprintf(writer, format+"\n", args...)
		} else {
			fmt.Printf(format+"\n", args...)
		}
	}

	// Read domain from workspace metadata.
	metadataPath := os.Getenv("HOME") + "/.config/bitswan/workspaces/" + workspaceName + "/metadata.yaml"
	log("Reading workspace metadata from %s...", metadataPath)

	var domain string
	if data, err := os.ReadFile(metadataPath); err == nil {
		var md struct {
			Domain string `yaml:"domain"`
		}
		if err := yaml.Unmarshal(data, &md); err == nil {
			domain = md.Domain
			log("Found domain: %s", domain)
		} else {
			log("Warning: failed to parse %s: %v", metadataPath, err)
		}
	} else {
		log("Warning: failed to read metadata file %s: %v (workspace may already be partially removed)", metadataPath, err)
	}

	traefikBaseURL := getTraefikBaseURL()

	// Remove per-service routes.
	if domain != "" {
		log("Deleting service routes for domain %s...", domain)
		for _, service := range []string{"gitops", "editor"} {
			hostname := fmt.Sprintf("%s-%s.%s", workspaceName, service, domain)
			log("Removing route for %s...", hostname)
			if err := RemoveRoute(hostname); err != nil {
				log("Warning: failed to remove route for %s: %v", hostname, err)
			} else {
				log("Successfully removed route for %s", hostname)
			}
		}
	} else {
		log("No domain found, skipping service route deletion")
	}

	// Remove TLS cert entries that belong to this workspace.
	log("Removing TLS cert entries for workspace %s...", workspaceName)
	if err := modifyState(traefikBaseURL, func(state *traefikDynConfig) error {
		if state.TLS == nil {
			return nil
		}
		var keep []traefikTLSCert
		for _, cert := range state.TLS.Certificates {
			if !strings.Contains(cert.CertFile, workspaceName) {
				keep = append(keep, cert)
			}
		}
		state.TLS.Certificates = keep
		return nil
	}); err != nil {
		log("Warning: failed to remove TLS cert entries: %v", err)
	}

	log("Traefik cleanup completed")
	return nil
}

// InstallCertsFromDir copies certificates from inputCertsDir into the Traefik
// cert directory structure at {traefikConfig}/certs/{sanitizedHostname}/.
func InstallCertsFromDir(inputCertsDir, hostname, traefikConfig string) error {
	if inputCertsDir == "" {
		return nil
	}

	fmt.Println("Installing certs from", inputCertsDir)

	traefikCertsDir := traefikConfig + "/certs"
	if _, err := os.Stat(traefikCertsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(traefikCertsDir, 0755); err != nil {
			return fmt.Errorf("failed to create Traefik certs directory: %w", err)
		}
	}

	sanitizedHostname := sanitizeHostname(hostname)
	certsDir := traefikCertsDir + "/" + sanitizedHostname
	if _, err := os.Stat(certsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(certsDir, 0755); err != nil {
			return fmt.Errorf("failed to create certs directory: %w", err)
		}
	}

	entries, err := os.ReadDir(inputCertsDir)
	if err != nil {
		return fmt.Errorf("failed to read certs directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(inputCertsDir + "/" + entry.Name())
		if err != nil {
			return fmt.Errorf("failed to read cert file: %w", err)
		}
		if err := os.WriteFile(certsDir+"/"+entry.Name(), data, 0755); err != nil {
			return fmt.Errorf("failed to copy cert file: %w", err)
		}
	}

	fmt.Println("Certs copied successfully!")
	return nil
}

// ============================================================
// Certificate generation helpers (mkcert)
// ============================================================

func generateWildcardCerts(domain string) (string, error) {
	tempDir, err := os.MkdirTemp("", "certs-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		originalDir = "/tmp"
	}

	if err := os.Chdir(tempDir); err != nil {
		return "", fmt.Errorf("failed to change to temp directory: %w", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			os.Chdir("/tmp") //nolint:errcheck
		}
	}()

	if err := exec.Command("mkcert", "*."+domain).Run(); err != nil {
		return "", fmt.Errorf("failed to generate certificate: %w", err)
	}

	keyFile := fmt.Sprintf("_wildcard.%s-key.pem", domain)
	certFile := fmt.Sprintf("_wildcard.%s.pem", domain)

	if err := os.Rename(keyFile, "private-key.pem"); err != nil {
		return "", fmt.Errorf("failed to rename key file: %w", err)
	}
	if err := os.Rename(certFile, "full-chain.pem"); err != nil {
		return "", fmt.Errorf("failed to rename cert file: %w", err)
	}

	return tempDir, nil
}

func generateCertsForHostname(hostname string) (string, error) {
	tempDir, err := os.MkdirTemp("", "certs-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		originalDir = "/tmp"
	}

	if err := os.Chdir(tempDir); err != nil {
		return "", fmt.Errorf("failed to change to temp directory: %w", err)
	}
	defer os.Chdir(originalDir) //nolint:errcheck

	if err := exec.Command("mkcert", hostname).Run(); err != nil {
		return "", fmt.Errorf("failed to generate certificate: %w", err)
	}

	keyFile := fmt.Sprintf("%s-key.pem", hostname)
	certFile := fmt.Sprintf("%s.pem", hostname)

	if err := os.Rename(keyFile, "private-key.pem"); err != nil {
		return "", fmt.Errorf("failed to rename key file: %w", err)
	}
	if err := os.Rename(certFile, "full-chain.pem"); err != nil {
		return "", fmt.Errorf("failed to rename cert file: %w", err)
	}

	return tempDir, nil
}
