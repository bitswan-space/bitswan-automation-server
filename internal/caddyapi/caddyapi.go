package caddyapi

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
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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

// getWorkspaceCaddyBaseURL returns the base URL for a workspace sub-caddy API
func getWorkspaceCaddyBaseURL(workspaceName string) string {
	containerName := fmt.Sprintf("%s__caddy", workspaceName)
	return fmt.Sprintf("http://%s:2019", containerName)
}

// getCaddyBaseURL returns the base URL for the Caddy API, preferring
// the BITSWAN_CADDY_HOST environment variable if set, otherwise defaulting
// to http://localhost:2019. It also normalizes the value by ensuring a scheme
// and stripping any trailing slash.
func getCaddyBaseURL() string {
    host := strings.TrimSpace(os.Getenv("BITSWAN_CADDY_HOST"))
    if host == "" {
        return "http://localhost:2019"
    }

    // Prepend default scheme if missing
    if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
        host = "http://" + host
    }

    // Strip trailing slash if present
    if strings.HasSuffix(host, "/") {
        host = strings.TrimRight(host, "/")
    }

    return host
}

func RegisterServiceWithCaddy(serviceName, workspaceName, domain, upstream string) error {
	// Construct the hostname using the existing pattern
	hostname := fmt.Sprintf("%s-%s.%s", workspaceName, serviceName, domain)

	// Use the new AddRoute function
	return AddRoute(hostname, upstream)
}

func UnregisterCaddyService(serviceName, workspaceName, domain string) error {
	// First try the new approach using hostname if domain is provided
	if domain != "" {
		hostname := fmt.Sprintf("%s-%s.%s", workspaceName, serviceName, domain)
		err := RemoveRoute(hostname)
		if err == nil {
			return nil
		}
		// If new approach fails, print warning and try old approach
		fmt.Printf("Warning: failed to remove route using hostname %s, trying legacy format: %v\n", hostname, err)
	}

	// Fall back to old approach using the legacy ID format
	legacyID := fmt.Sprintf("%s_%s", workspaceName, serviceName)
	url := fmt.Sprintf(getCaddyBaseURL()+"/id/%s", legacyID)

	if _, err := sendRequest("DELETE", url, nil); err != nil {
		return fmt.Errorf("failed to unregister service '%s' using both new and legacy formats: %w", serviceName, err)
	}

	fmt.Printf("Successfully unregistered service using legacy format: %s\n", serviceName)
	return nil
}

func InstallTLSCerts(workspaceName, domain string) error {
	// Initialize TLS app structure first
	tlsAppSet := getCaddyBaseURL() + "/config/apps/tls"
	if err := InitSet(tlsAppSet, []byte(`{}`)); err != nil {
		return fmt.Errorf("failed to initialize TLS app: %w", err)
	}

	// Initialize certificates structure
	certsSet := getCaddyBaseURL() + "/config/apps/tls/certificates"
	if err := InitSet(certsSet, []byte(`{}`)); err != nil {
		return fmt.Errorf("failed to initialize TLS certificates: %w", err)
	}

	// Initialize load_files array
	loadFilesSet := getCaddyBaseURL() + "/config/apps/tls/certificates/load_files"
	caddyAPITLSBaseUrl := loadFilesSet + "/..."
	if err := InitSet(loadFilesSet, []byte(`[]`)); err != nil {
		return fmt.Errorf("failed to initialize TLS load_files: %w", err)
	}

	// Initialize TLS connection policies
	policiesSet := getCaddyBaseURL() + "/config/apps/http/servers/srv0/tls_connection_policies"
	caddyAPITLSPoliciesBaseUrl := policiesSet + "/..."
	if err := InitSet(policiesSet, []byte(`[]`)); err != nil {
		return fmt.Errorf("failed to initialize TLS connection policies: %w", err)
	}

	// Define TLS policies and certificates
	tlsPolicy := []TLSPolicy{
		{
			ID: fmt.Sprintf("%s_tlspolicy", workspaceName),
			Match: TLSMatch{
				SNI: []string{
					fmt.Sprintf("*.%s", domain),
				},
			},
			CertificateSelection: TLSCertificateSelection{
				AnyTag: []string{workspaceName},
			},
		},
	}

	tlsLoad := []TLSFileLoad{
		{
			ID:          fmt.Sprintf("%s_tlscerts", workspaceName),
			Certificate: fmt.Sprintf("/tls/%s/full-chain.pem", sanitizeHostname(domain)),
			Key:         fmt.Sprintf("/tls/%s/private-key.pem", sanitizeHostname(domain)),
			Tags:        []string{workspaceName},
		},
	}

	// Send TLS certificates to Caddy
	jsonPayload, err := json.Marshal(tlsLoad)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS certificates payload: %w", err)
	}

	_, err = sendRequest("POST", caddyAPITLSBaseUrl, jsonPayload)
	if err != nil {
		return fmt.Errorf("failed to add TLS certificates to Caddy: %w", err)
	}

	// Send TLS policies to Caddy
	jsonPayload, err = json.Marshal(tlsPolicy)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS policies payload: %w", err)
	}

	_, err = sendRequest("POST", caddyAPITLSPoliciesBaseUrl, jsonPayload)
	if err != nil {
		return fmt.Errorf("failed to add TLS policies to Caddy: %w", err)
	}

	fmt.Println("TLS certificates and policies installed successfully!")
	return nil
}

func InitSet(url string, payload []byte) error {
	_, err := sendRequest("PUT", url, payload)
	if err != nil {
		if strings.Contains(err.Error(), "status code 409") {
			fmt.Println("Set already initialized!")
			return nil
		}
		return fmt.Errorf("failed to initialize set: %w", err)
	}
	return nil
}

func InitCaddy() error {
	urls := []string{
		getCaddyBaseURL() + "/config/apps/http/servers/srv0/routes",
		getCaddyBaseURL() + "/config/apps/http/servers/srv0/listen",
	}

	for idx, url := range urls {
		var payload []byte
		if idx == 1 {
			payload = []byte(`[":80", ":443"]`)
		} else {
			payload = []byte(`[]`)
		}

		err := InitSet(url, payload)
		if err != nil {
			return fmt.Errorf("failed to initialize Caddy: %w", err)
		}
	}

	fmt.Println("Caddy initialized successfully!")
	return nil
}

func DeleteCaddyRecords(workspaceName string) error {
	return DeleteCaddyRecordsWithWriter(workspaceName, nil)
}

func DeleteCaddyRecordsWithWriter(workspaceName string, writer io.Writer) error {
	// Helper to write log messages
	log := func(format string, args ...interface{}) {
		if writer != nil {
			fmt.Fprintf(writer, format+"\n", args...)
		} else {
			fmt.Printf(format+"\n", args...)
		}
	}

	// First, try to get the domain from workspace metadata
	// We need to import the config package for this to work
	// For now, we'll handle this differently by checking if we can delete by service routes first

	// Try to delete service routes (gitops, editor) by constructing likely hostnames
	// We'll use a more robust approach by deleting directly by the old ID format for TLS items

	// Delete service routes that follow hostname pattern
	serviceRoutes := []string{"gitops", "editor"}

	// For service routes, we need the domain. Let's try to get it from metadata
	metadataPath := os.Getenv("HOME") + "/.config/bitswan/workspaces/" + workspaceName + "/metadata.yaml"

	log("Reading workspace metadata from %s...", metadataPath)
	// Read domain from metadata if available
	var domain string
	if data, err := os.ReadFile(metadataPath); err == nil {
		// Parse YAML to extract domain using yaml.v3
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

	// Delete service routes if we have a domain
	if domain != "" {
		log("Deleting service routes for domain %s...", domain)
		for _, service := range serviceRoutes {
			hostname := fmt.Sprintf("%s-%s.%s", workspaceName, service, domain)
			log("Removing route for %s...", hostname)
			if err := RemoveRoute(hostname); err != nil {
				// Don't fail completely if one service route fails - it might not exist
				log("Warning: failed to remove route for %s: %v", hostname, err)
			} else {
				log("Successfully removed route for %s", hostname)
			}
		}
	} else {
		log("No domain found, skipping service route deletion")
	}

	// Delete TLS-related items using the old direct ID approach
	log("Deleting TLS-related items...")
	tlsItems := []string{"tlspolicy", "tlscerts"}
	for _, item := range tlsItems {
		url := fmt.Sprintf(getCaddyBaseURL()+"/id/%s_%s", workspaceName, item)
		log("Deleting TLS item %s...", item)
		if _, err := sendRequest("DELETE", url, nil); err != nil {
			// Don't fail completely if TLS items fail - they might not exist
			if strings.Contains(err.Error(), "status code 404") {
				log("TLS item %s already removed or doesn't exist", item)
			} else {
				log("Warning: failed to delete %s: %v", item, err)
			}
		} else {
			log("Successfully deleted TLS item %s", item)
		}
	}

	log("Caddy cleanup completed")
	return nil
}

// sanitizeHostname converts a hostname to a safe ID by replacing dots and special chars with underscores
func sanitizeHostname(hostname string) string {
	return strings.ReplaceAll(strings.ReplaceAll(hostname, ".", "_"), "-", "_")
}

// ensureUpstreamScheme ensures the upstream is in the correct format for Caddy
// For Caddy's reverse_proxy, the dial field should be "host:port" (no scheme)
// For WebSocket connections, if the backend port is WSS (8084), use WS port (8083) instead
// because Caddy handles TLS termination and connects to the backend via plain WebSocket
func ensureUpstreamScheme(upstream string) string {
	// Remove any leading slashes that might have been accidentally added
	upstream = strings.TrimPrefix(upstream, "/")

	// Remove any scheme prefix (http://, https://, ws://, wss://)
	// Caddy's dial field should be just "host:port"
	upstream = strings.TrimPrefix(upstream, "http://")
	upstream = strings.TrimPrefix(upstream, "https://")
	upstream = strings.TrimPrefix(upstream, "ws://")
	upstream = strings.TrimPrefix(upstream, "wss://")

	// Check if this is the WSS port (8084) - if so, use WS port (8083) instead
	// because Caddy will handle TLS termination and connect via plain WebSocket
	if strings.Contains(upstream, ":8084") {
		upstream = strings.Replace(upstream, ":8084", ":8083", 1)
	}

	// Return just "host:port" format (no scheme)
	return upstream
}

// RegisterWorkspaceRouting registers routing patterns in global caddy to proxy to workspace sub-caddy
// This should be called with global caddy context (BITSWAN_WORKSPACE_CADDY should not be set)
func RegisterWorkspaceRouting(workspaceName, domain string) error {
	workspaceCaddyUpstream := fmt.Sprintf("%s__caddy:80", workspaceName)

	// Create route patterns that match workspace hostnames
	// Pattern 1: {workspaceName}-*.{domain} (e.g., myworkspace-automation-staging.example.com)
	pattern1 := fmt.Sprintf("%s-*.%s", workspaceName, domain)
	// Pattern 2: *.{workspaceName}-*.{domain} (e.g., *.myworkspace-automation-staging.example.com)
	pattern2 := fmt.Sprintf("*.%s-*.%s", workspaceName, domain)

	routeID := fmt.Sprintf("workspace_%s_routing", sanitizeHostname(workspaceName))

	// Create the route with hostname pattern matching
	route := Route{
		ID: routeID,
		Match: []Match{
			{
				Host: []string{pattern1, pattern2},
			},
		},
		Handle: []Handle{
			{
				Handler: "reverse_proxy",
				Upstreams: []Upstream{
					{
						Dial: workspaceCaddyUpstream,
					},
				},
				// Add headers to preserve original hostname for sub-caddy route matching
				// This is done via the reverse_proxy handler's headers option
			},
		},
		Terminal: true,
	}

	// First, remove any existing workspace routing route
	removeURL := getCaddyBaseURL() + "/id/" + routeID
	sendRequest("DELETE", removeURL, nil) // Ignore errors

	// Marshal the route into JSON
	jsonPayload, err := json.Marshal([]Route{route})
	if err != nil {
		return fmt.Errorf("failed to marshal workspace routing payload: %w", err)
	}

	// Send to global caddy (ensure we're using global caddy, not workspace caddy)
	originalWorkspaceCaddy := os.Getenv("BITSWAN_WORKSPACE_CADDY")
	os.Unsetenv("BITSWAN_WORKSPACE_CADDY")
	defer func() {
		if originalWorkspaceCaddy != "" {
			os.Setenv("BITSWAN_WORKSPACE_CADDY", originalWorkspaceCaddy)
		}
	}()

	caddyAPIRoutesBaseUrl := getCaddyBaseURL() + "/config/apps/http/servers/srv0/routes/..."
	_, err = sendRequest("POST", caddyAPIRoutesBaseUrl, jsonPayload)
	if err != nil {
		return fmt.Errorf("failed to register workspace routing for %s: %w", workspaceName, err)
	}

	fmt.Printf("Registered workspace routing: %s, %s -> %s\n", pattern1, pattern2, workspaceCaddyUpstream)
	return nil
}

// AddRoute adds a generic route for any hostname to upstream mapping
func AddRoute(hostname, upstream string) error {
	caddyAPIRoutesBaseUrl := getCaddyBaseURL() + "/config/apps/http/servers/srv0/routes/..."

	// First, remove any existing routes with the same ID to avoid duplicates
	if err := RemoveRoute(hostname); err != nil {
		return fmt.Errorf("failed to remove existing route before adding new one for %s: %w", hostname, err)
	}

	// Create a sanitized ID for the route based on hostname
	routeID := sanitizeHostname(hostname)

	// Process the upstream to ensure correct format
	processedUpstream := ensureUpstreamScheme(upstream)
	fmt.Printf("AddRoute: original upstream='%s', processed upstream='%s'\n", upstream, processedUpstream)

	// Create the route for the hostname
	route := Route{
		ID: routeID,
		Match: []Match{
			{
				Host: []string{hostname},
			},
		},
		Handle: []Handle{
			{
				Handler: "reverse_proxy",
				Upstreams: []Upstream{
					{
						// For WebSocket connections, use http:// scheme
						// Caddy will automatically handle WebSocket upgrade
						// If upstream doesn't have a scheme, add http://
						Dial: processedUpstream,
					},
				},
			},
		},
		Terminal: true,
	}

	// Marshal the route into JSON
	jsonPayload, err := json.Marshal([]Route{route})
	if err != nil {
		return fmt.Errorf("failed to marshal route payload: %w", err)
	}

	// Debug: Print the JSON payload being sent
	fmt.Printf("AddRoute: Sending JSON payload to Caddy:\n%s\n", string(jsonPayload))

	// Send the payload to the Caddy API
	_, err = sendRequest("POST", caddyAPIRoutesBaseUrl, jsonPayload)
	if err != nil {
		return fmt.Errorf("failed to add route for %s to Caddy: %w", hostname, err)
	}

	// Verify the route was added correctly by fetching it back
	verifyRoutes, err := ListRoutes()
	if err == nil {
		for _, r := range verifyRoutes {
			if r.ID == routeID {
				for _, handle := range r.Handle {
					if handle.Handler == "reverse_proxy" {
						for _, up := range handle.Upstreams {
							fmt.Printf("AddRoute: Verified route in Caddy - Dial field: '%s'\n", up.Dial)
						}
					}
				}
			}
		}
	}

	fmt.Printf("Successfully added route: %s -> %s\n", hostname, upstream)
	return nil
}

// RemoveRoute removes a route by hostname, retrying until 404 is returned
func RemoveRoute(hostname string) error {
	// Create a sanitized ID for the route based on hostname
	routeID := sanitizeHostname(hostname)

	// Construct the URL for the specific route
	url := fmt.Sprintf(getCaddyBaseURL()+"/id/%s", routeID)

	// Try to delete once - if it fails with 404, the route doesn't exist (success)
	// If it fails with other errors, return the error immediately
	// Don't retry to avoid hanging on unreachable Caddy
	_, err := sendRequest("DELETE", url, nil)
	if err != nil {
		// Check if this is a 404 error (route doesn't exist) - this is success
		if strings.Contains(err.Error(), "status code 404") {
			return nil // Route already removed or doesn't exist - success
		}
		// For timeout or connection errors, assume the route is gone or Caddy is unreachable
		// Don't fail - just log and continue
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
			return nil // Assume route is gone or Caddy is unreachable
		}
		// For other errors, return the error
		return fmt.Errorf("failed to remove route for hostname '%s': %w", hostname, err)
	}

	// If we get here, the deletion was successful
	return nil
}

// ListRoutes retrieves and lists all current routes from Caddy
func ListRoutes() ([]Route, error) {
	url := getCaddyBaseURL() + "/config/apps/http/servers/srv0/routes"

	responseBody, err := sendRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get routes from Caddy API: %w", err)
	}

	var routes []Route
	if err := json.Unmarshal(responseBody, &routes); err != nil {
		return nil, fmt.Errorf("failed to parse routes response: %w", err)
	}

	return routes, nil
}

func sendRequest(method, url string, payload []byte) ([]byte, error) {
	// Create context with timeout to ensure request doesn't hang
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to call Caddy API: %w", err)
	}
	defer resp.Body.Close()

	if method == http.MethodDelete && (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != 404 {
		// Read the response body to get detailed error information
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Caddy API returned status code %d for DELETE request (failed to read response body: %w)", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("Caddy API returned status code %d for DELETE request: %s", resp.StatusCode, string(body))
	}

	// For PUT requests, 409 (Conflict) means the resource already exists, which is acceptable for initialization
	if method == http.MethodPut && resp.StatusCode == 409 {
		// Read the response body to avoid connection issues
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		return body, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read the response body to get detailed error information
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Caddy API returned status code %d (failed to read response body: %w)", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("Caddy API returned status code %d: %s", resp.StatusCode, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// generateWildcardCerts generates wildcard certificates using mkcert
func generateWildcardCerts(domain string) (string, error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "certs-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Store current working directory
	originalDir, err := os.Getwd()
	if err != nil {
		// If we can't get the current directory, use /tmp as fallback
		originalDir = "/tmp"
	}

	// Change to temp directory
	if err := os.Chdir(tempDir); err != nil {
		return "", fmt.Errorf("failed to change to temp directory: %w", err)
	}

	// Ensure we change back to original directory when function returns
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			// If we can't change back, try /tmp as fallback
			os.Chdir("/tmp")
		}
	}()

	// Generate wildcard certificate
	wildcardDomain := "*." + domain
	cmd := exec.Command("mkcert", wildcardDomain)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Generate file names
	keyFile := fmt.Sprintf("_wildcard.%s-key.pem", domain)
	certFile := fmt.Sprintf("_wildcard.%s.pem", domain)

	// Rename files
	if err := os.Rename(keyFile, "private-key.pem"); err != nil {
		return "", fmt.Errorf("failed to rename key file: %w", err)
	}
	if err := os.Rename(certFile, "full-chain.pem"); err != nil {
		return "", fmt.Errorf("failed to rename cert file: %w", err)
	}

	return tempDir, nil
}

// InstallCertsFromDir installs certificates from a directory to Caddy's cert directory
func InstallCertsFromDir(inputCertsDir, hostname, caddyConfig string) error {
	if inputCertsDir == "" {
		return nil
	}

	fmt.Println("Installing certs from", inputCertsDir)
	caddyCertsDir := caddyConfig + "/certs"
	if _, err := os.Stat(caddyCertsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(caddyCertsDir, 0755); err != nil {
			return fmt.Errorf("failed to create Caddy certs directory: %w", err)
		}
	}

	// Use hostname instead of domain to avoid overwriting certificates for different subdomains
	// Sanitize hostname for filesystem safety
	sanitizedHostname := sanitizeHostname(hostname)
	certsDir := caddyCertsDir + "/" + sanitizedHostname
	if _, err := os.Stat(certsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(certsDir, 0755); err != nil {
			return fmt.Errorf("failed to create certs directory: %w", err)
		}
	}

	certs, err := os.ReadDir(inputCertsDir)
	if err != nil {
		return fmt.Errorf("failed to read certs directory: %w", err)
	}

	for _, cert := range certs {
		if cert.IsDir() {
			continue
		}

		certPath := inputCertsDir + "/" + cert.Name()
		newCertPath := certsDir + "/" + cert.Name()

		bytes, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("failed to read cert file: %w", err)
		}

		if err := os.WriteFile(newCertPath, bytes, 0755); err != nil {
			return fmt.Errorf("failed to copy cert file: %w", err)
		}
	}

	fmt.Println("Certs copied successfully!")
	return nil
}

// GenerateAndInstallCerts generates wildcard certificates and installs them to Caddy
func GenerateAndInstallCerts(domain string) error {
	// Generate certificates
	certDir, err := generateWildcardCerts(domain)
	if err != nil {
		return fmt.Errorf("error generating certificates: %w", err)
	}

	// Install certificates to the standard Caddy location
	caddyConfig := os.Getenv("HOME") + "/.config/bitswan/caddy"
	if err := InstallCertsFromDir(certDir, domain, caddyConfig); err != nil {
		return fmt.Errorf("error installing certificates: %w", err)
	}

	// Clean up temporary directory
	defer os.RemoveAll(certDir)

	return nil
}

// generateCertsForHostname generates certificates for a specific hostname using mkcert
func generateCertsForHostname(hostname string) (string, error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "certs-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Store current working directory
	originalDir, err := os.Getwd()
	if err != nil {
		// If we can't get the current directory, use /tmp as fallback
		originalDir = "/tmp"
	}

	// Change to temp directory
	if err := os.Chdir(tempDir); err != nil {
		return "", fmt.Errorf("failed to change to temp directory: %w", err)
	}

	// Ensure we change back to original directory when function returns
	defer os.Chdir(originalDir)

	// Generate certificate for the specific hostname
	cmd := exec.Command("mkcert", hostname)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Generate file names based on hostname
	keyFile := fmt.Sprintf("%s-key.pem", hostname)
	certFile := fmt.Sprintf("%s.pem", hostname)

	// Rename files
	if err := os.Rename(keyFile, "private-key.pem"); err != nil {
		return "", fmt.Errorf("failed to rename key file: %w", err)
	}
	if err := os.Rename(certFile, "full-chain.pem"); err != nil {
		return "", fmt.Errorf("failed to rename cert file: %w", err)
	}

	return tempDir, nil
}

// GenerateAndInstallCertsForHostname generates certificates for a specific hostname and installs them to Caddy
func GenerateAndInstallCertsForHostname(hostname, domain string) error {
	// Generate certificates for the specific hostname
	certDir, err := generateCertsForHostname(hostname)
	if err != nil {
		return fmt.Errorf("error generating certificates: %w", err)
	}

	// Install certificates to the standard Caddy location using hostname instead of domain
	caddyConfig := os.Getenv("HOME") + "/.config/bitswan/caddy"
	if err := InstallCertsFromDir(certDir, hostname, caddyConfig); err != nil {
		return fmt.Errorf("error installing certificates: %w", err)
	}

	// Clean up temporary directory
	defer os.RemoveAll(certDir)

	return nil
}

// InstallTLSCertsForHostname installs TLS certificates and policies for a specific hostname
func InstallTLSCertsForHostname(hostname, domain, workspaceName string) error {
	// Initialize TLS app structure first
	tlsAppSet := getCaddyBaseURL() + "/config/apps/tls"
	if err := InitSet(tlsAppSet, []byte(`{}`)); err != nil {
		return fmt.Errorf("failed to initialize TLS app: %w", err)
	}

	// Initialize certificates structure
	certsSet := getCaddyBaseURL() + "/config/apps/tls/certificates"
	if err := InitSet(certsSet, []byte(`{}`)); err != nil {
		return fmt.Errorf("failed to initialize TLS certificates: %w", err)
	}

	// Initialize load_files array
	loadFilesSet := getCaddyBaseURL() + "/config/apps/tls/certificates/load_files"
	caddyAPITLSBaseUrl := loadFilesSet + "/..."
	if err := InitSet(loadFilesSet, []byte(`[]`)); err != nil {
		return fmt.Errorf("failed to initialize TLS load_files: %w", err)
	}

	// Initialize TLS connection policies
	policiesSet := getCaddyBaseURL() + "/config/apps/http/servers/srv0/tls_connection_policies"
	caddyAPITLSPoliciesBaseUrl := policiesSet + "/..."
	if err := InitSet(policiesSet, []byte(`[]`)); err != nil {
		return fmt.Errorf("failed to initialize TLS connection policies: %w", err)
	}

	// Define TLS policies and certificates for the specific hostname
	tlsPolicy := []TLSPolicy{
		{
			ID: fmt.Sprintf("%s_%s_tlspolicy", workspaceName, strings.ReplaceAll(hostname, ".", "_")),
			Match: TLSMatch{
				SNI: []string{hostname},
			},
			CertificateSelection: TLSCertificateSelection{
				AnyTag: []string{workspaceName},
			},
		},
	}

	tlsLoad := []TLSFileLoad{
		{
			ID:          fmt.Sprintf("%s_%s_tlscerts", workspaceName, strings.ReplaceAll(hostname, ".", "_")),
			Certificate: fmt.Sprintf("/tls/%s/full-chain.pem", sanitizeHostname(hostname)),
			Key:         fmt.Sprintf("/tls/%s/private-key.pem", sanitizeHostname(hostname)),
			Tags:        []string{workspaceName},
		},
	}

	// Send TLS certificates to Caddy
	jsonPayload, err := json.Marshal(tlsLoad)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS certificates payload: %w", err)
	}

	_, err = sendRequest("POST", caddyAPITLSBaseUrl, jsonPayload)
	if err != nil {
		return fmt.Errorf("failed to add TLS certificates to Caddy: %w", err)
	}

	// Send TLS policies to Caddy
	jsonPayload, err = json.Marshal(tlsPolicy)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS policies payload: %w", err)
	}

	_, err = sendRequest("POST", caddyAPITLSPoliciesBaseUrl, jsonPayload)
	if err != nil {
		return fmt.Errorf("failed to add TLS policies to Caddy: %w", err)
	}

	fmt.Println("TLS certificates and policies installed successfully!")
	return nil
}
