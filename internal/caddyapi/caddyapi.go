package caddyapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
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
	url := fmt.Sprintf("http://localhost:2019/id/%s", legacyID)
	
	if _, err := sendRequest("DELETE", url, nil); err != nil {
		return fmt.Errorf("failed to unregister service '%s' using both new and legacy formats: %w", serviceName, err)
	}
	
	fmt.Printf("Successfully unregistered service using legacy format: %s\n", serviceName)
	return nil
}

func InstallTLSCerts(workspaceName, domain string) error {
	caddyAPITLSBaseUrl := "http://localhost:2019/config/apps/tls/certificates/load_files/..."
	caddyAPITLSPoliciesBaseUrl := "http://localhost:2019/config/apps/http/servers/srv0/tls_connection_policies/..."

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
			Certificate: fmt.Sprintf("/tls/%s/full-chain.pem", domain),
			Key:         fmt.Sprintf("/tls/%s/private-key.pem", domain),
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

func InitCaddy() error {
	urls := []string{
		"http://localhost:2019/config/apps/http/servers/srv0/routes",
		"http://localhost:2019/config/apps/http/servers/srv0/listen",
		"http://localhost:2019/config/apps/tls/certificates/load_files",
		"http://localhost:2019/config/apps/http/servers/srv0/tls_connection_policies",
	}

	for idx, url := range urls {
		var payload []byte
		if idx == 1 {
			payload = []byte(`[":80", ":443"]`)
		} else {
			payload = []byte(`[]`)
		}

		_, err := sendRequest("PUT", url, payload)
		if err != nil {
			// Check if this is a 409 error (already exists)
			if strings.Contains(err.Error(), "status code 409") {
				fmt.Println("Ingress is already initialized!")
				return nil
			}
			return fmt.Errorf("failed to initialize Caddy: %w", err)
		}
	}

	fmt.Println("Caddy initialized successfully!")
	return nil
}

func DeleteCaddyRecords(workspaceName string) error {
	// First, try to get the domain from workspace metadata
	// We need to import the config package for this to work
	// For now, we'll handle this differently by checking if we can delete by service routes first
	
	// Try to delete service routes (gitops, editor) by constructing likely hostnames
	// We'll use a more robust approach by deleting directly by the old ID format for TLS items
	
	// Delete service routes that follow hostname pattern
	serviceRoutes := []string{"gitops", "editor"}
	
	// For service routes, we need the domain. Let's try to get it from metadata
	metadataPath := os.Getenv("HOME") + "/.config/bitswan/workspaces/" + workspaceName + "/metadata.yaml"
	
	// Read domain from metadata if available
	var domain string
	if data, err := os.ReadFile(metadataPath); err == nil {
		// Parse YAML to extract domain using yaml.v3
		var md struct {
			Domain string `yaml:"domain"`
		}
		if err := yaml.Unmarshal(data, &md); err == nil {
			domain = md.Domain
		} else {
			fmt.Printf("Warning: failed to parse %s: %v\n", metadataPath, err)
		}
	}
	
	// Delete service routes if we have a domain
	if domain != "" {
		for _, service := range serviceRoutes {
			hostname := fmt.Sprintf("%s-%s.%s", workspaceName, service, domain)
			if err := RemoveRoute(hostname); err != nil {
				// Don't fail completely if one service route fails - it might not exist
				fmt.Printf("Warning: failed to remove route for %s: %v\n", hostname, err)
			}
		}
	}
	
	// Delete TLS-related items using the old direct ID approach
	tlsItems := []string{"tlspolicy", "tlscerts"}
	for _, item := range tlsItems {
		url := fmt.Sprintf("http://localhost:2019/id/%s_%s", workspaceName, item)
		if _, err := sendRequest("DELETE", url, nil); err != nil {
			// Don't fail completely if TLS items fail - they might not exist
			fmt.Printf("Warning: failed to delete %s: %v\n", item, err)
		}
	}
	
	return nil
}

// sanitizeHostname converts a hostname to a safe ID by replacing dots and special chars with underscores
func sanitizeHostname(hostname string) string {
	return strings.ReplaceAll(strings.ReplaceAll(hostname, ".", "_"), "-", "_")
}

// AddRoute adds a generic route for any hostname to upstream mapping
func AddRoute(hostname, upstream string) error {
	caddyAPIRoutesBaseUrl := "http://localhost:2019/config/apps/http/servers/srv0/routes/..."

	// First, remove any existing routes with the same ID to avoid duplicates
	if err := RemoveRoute(hostname); err != nil {
		return fmt.Errorf("failed to remove existing route before adding new one for %s: %w", hostname, err)
	}

	// Create a sanitized ID for the route based on hostname
	routeID := sanitizeHostname(hostname)

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
				Handler: "subroute",
				Routes: []Route{
					{
						Handle: []Handle{
							{
								Handler: "reverse_proxy",
								Upstreams: []Upstream{
									{
										Dial: upstream,
									},
								},
							},
						},
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

	// Send the payload to the Caddy API
	_, err = sendRequest("POST", caddyAPIRoutesBaseUrl, jsonPayload)
	if err != nil {
		return fmt.Errorf("failed to add route for %s to Caddy: %w", hostname, err)
	}

	fmt.Printf("Successfully added route: %s -> %s\n", hostname, upstream)
	return nil
}

// RemoveRoute removes a route by hostname, retrying until 404 is returned
func RemoveRoute(hostname string) error {
	// Create a sanitized ID for the route based on hostname
	routeID := sanitizeHostname(hostname)
	
	// Construct the URL for the specific route
	url := fmt.Sprintf("http://localhost:2019/id/%s", routeID)

	// Keep trying to delete until we get a 404 (route doesn't exist)
	firstRun := true
	for {
		_, err := sendRequest("DELETE", url, nil)
		if err != nil {
			// Check if this is a 404 error (route doesn't exist)
			if strings.Contains(err.Error(), "status code 404") {
				if firstRun {
					fmt.Printf("Route %s already removed or doesn't exist\n", hostname)
				}
				return nil
			}
			// For other errors, return immediately
			return fmt.Errorf("failed to remove route for hostname '%s': %w", hostname, err)
		}
		
		// If we get here, the deletion was successful, continue to check for more routes
		fmt.Printf("Removed route: %s\n", hostname)
		firstRun = false
	}
}

// ListRoutes retrieves and lists all current routes from Caddy
func ListRoutes() ([]Route, error) {
	url := "http://localhost:2019/config/apps/http/servers/srv0/routes"
	
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
	client := &http.Client{}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
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
		return nil, fmt.Errorf("Caddy API returned status code %d for DELETE request", resp.StatusCode)
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
		return nil, fmt.Errorf("Caddy API returned status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}
