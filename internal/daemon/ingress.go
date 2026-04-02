package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/util"
)

// IngressInitRequest represents the request to initialize ingress
type IngressInitRequest struct {
	Verbose bool `json:"verbose"`
}

// IngressInitResponse represents the response from initializing ingress
type IngressInitResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// IngressAddRouteRequest represents the request to add a route
type IngressAddRouteRequest struct {
	Hostname      string `json:"hostname"`
	Upstream      string `json:"upstream"`
	Mkcert        bool   `json:"mkcert"`
	CertsDir      string `json:"certs_dir,omitempty"`
	Secret        string `json:"secret,omitempty"` // Optional JWT token containing workspace ID
	WorkspaceName string `json:"workspace_name,omitempty"`
}

// IngressAddRouteResponse represents the response from adding a route
type IngressAddRouteResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// IngressListRoutesResponse represents the response from listing routes
type IngressListRoutesResponse struct {
	Routes []RouteInfo `json:"routes"`
}

// RouteInfo represents simplified route information
type RouteInfo struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Upstream string `json:"upstream"`
	Terminal bool   `json:"terminal"`
}

// IngressRemoveRouteResponse represents the response from removing a route
type IngressRemoveRouteResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// handleIngress routes ingress-related requests
func (s *Server) handleIngress(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/ingress")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "init":
		s.handleIngressInit(w, r)
	case path == "add-route":
		s.handleIngressAddRoute(w, r)
	case path == "list-routes":
		s.handleIngressListRoutes(w, r)
	case strings.HasPrefix(path, "remove-route/"):
		hostname := strings.TrimPrefix(path, "remove-route/")
		s.handleIngressRemoveRoute(w, r, hostname)
	default:
		writeJSONError(w, "not found", http.StatusNotFound)
	}
}

// handleIngressInit handles POST /ingress/init
func (s *Server) handleIngressInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req IngressInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	newlyInitialized, err := initIngress(req.Verbose)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	var message string
	if newlyInitialized {
		message = "Ingress proxy is ready!"
	} else {
		message = "Ingress proxy is already initialized."
	}
	json.NewEncoder(w).Encode(IngressInitResponse{
		Success: true,
		Message: message,
	})
}

// initIngress initializes the ingress proxy (extracted from cmd/ingress/init.go)
// Returns (newlyInitialized, error) where newlyInitialized is true if initialization happened,
// false if it was already initialized.
func initIngress(verbose bool) (bool, error) {
	// Use HOME for file operations (works inside container and outside)
	// The files are accessible via the container path
	homeDir := os.Getenv("HOME")
	bitswanConfig := homeDir + "/.config/bitswan/"
	traefikConfig := bitswanConfig + "traefik"
	traefikCertsDir := traefikConfig + "/certs"

	traefikProjectName := "bitswan-traefik"

	// Check if Traefik is already running with REST provider support.
	// We test this by pushing an empty state: if it succeeds, Traefik is fully initialized.
	if err := traefikapi.InitTraefik(); err == nil {
		return false, nil // Already running and REST provider is working.
	}

	// Traefik is either not running or is running without REST provider support.
	// Stop and remove any existing container named "traefik" so we can start a fresh one.
	existingIdBytes, _ := exec.Command("docker", "ps", "-q", "-f", "name=traefik").Output()
	if existingId := strings.TrimSpace(string(existingIdBytes)); existingId != "" {
		if verbose {
			fmt.Println("Existing Traefik container does not support REST provider — stopping it to reinitialize...")
		}
		exec.Command("docker", "stop", existingId).Run() //nolint:errcheck
		exec.Command("docker", "rm", existingId).Run()   //nolint:errcheck
	}

	if err := os.MkdirAll(traefikConfig, 0755); err != nil {
		return false, fmt.Errorf("failed to create ingress config directory: %w", err)
	}

	// Create acme directory for Let's Encrypt certificate storage
	acmeDir := traefikConfig + "/acme"
	if err := os.MkdirAll(acmeDir, 0700); err != nil {
		return false, fmt.Errorf("failed to create acme directory: %w", err)
	}

	// Create Traefik static config enabling REST provider, entrypoints, and ACME
	acmeEmail := os.Getenv("BITSWAN_ACME_EMAIL")
	if acmeEmail == "" {
		acmeEmail = "noreply@bitswan.space"
	}
	traefikStaticConfig := fmt.Sprintf(`entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"
api:
  insecure: true
providers:
  rest:
    insecure: true
  docker:
    exposedByDefault: false
    network: bitswan_network
certificatesResolvers:
  letsencrypt:
    acme:
      email: %s
      storage: /acme/acme.json
      httpChallenge:
        entryPoint: web
`, acmeEmail)

	traefikConfigFilePath := traefikConfig + "/traefik.yml"
	if err := os.WriteFile(traefikConfigFilePath, []byte(traefikStaticConfig), 0755); err != nil {
		return false, fmt.Errorf("failed to write traefik.yml: %w", err)
	}

	// For docker-compose, use HOST_HOME if available (docker-compose runs on host)
	// Convert container path to host path for volume mounts
	hostHomeDir := os.Getenv("HOST_HOME")
	traefikConfigForCompose := traefikConfig
	if hostHomeDir != "" && homeDir != hostHomeDir && strings.HasPrefix(traefikConfig, homeDir) {
		// Replace container home with host home for docker-compose volume paths
		traefikConfigForCompose = strings.Replace(traefikConfig, homeDir, hostHomeDir, 1)

		// Ensure directories exist on host before docker-compose tries to mount them
		if err := os.MkdirAll(traefikConfigForCompose, 0755); err != nil {
			return false, fmt.Errorf("failed to create ingress config directory on host: %w", err)
		}
		if err := os.MkdirAll(traefikConfigForCompose+"/certs", 0755); err != nil {
			return false, fmt.Errorf("failed to create ingress certs directory on host: %w", err)
		}
		if err := os.MkdirAll(traefikConfigForCompose+"/acme", 0700); err != nil {
			return false, fmt.Errorf("failed to create ingress acme directory on host: %w", err)
		}

		// Also create/ensure traefik.yml exists on host
		traefikConfigFilePathHost := traefikConfigForCompose + "/traefik.yml"
		if _, err := os.Stat(traefikConfigFilePathHost); os.IsNotExist(err) {
			if err := os.WriteFile(traefikConfigFilePathHost, []byte(traefikStaticConfig), 0755); err != nil {
				return false, fmt.Errorf("failed to write traefik.yml on host: %w", err)
			}
		}
	}

	traefikDockerCompose, err := dockercompose.CreateTraefikDockerComposeFile(traefikConfigForCompose)
	if err != nil {
		return false, fmt.Errorf("failed to create ingress docker-compose file: %w", err)
	}

	traefikDockerComposePath := traefikConfig + "/docker-compose.yml"
	if err := os.WriteFile(traefikDockerComposePath, []byte(traefikDockerCompose), 0755); err != nil {
		return false, fmt.Errorf("failed to write ingress docker-compose file: %w", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		return false, fmt.Errorf("failed to get current directory: %w", err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(traefikConfig); err != nil {
		return false, fmt.Errorf("failed to change directory to ingress config: %w", err)
	}

	traefikDockerComposeCom := exec.Command("docker", "compose", "-p", traefikProjectName, "up", "-d")

	// Create certs directory if it doesn't exist
	if _, err := os.Stat(traefikCertsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(traefikCertsDir, 0740); err != nil {
			return false, fmt.Errorf("failed to create ingress certs directory: %w", err)
		}
	}

	if err := util.RunCommandVerbose(traefikDockerComposeCom, verbose); err != nil {
		return false, fmt.Errorf("failed to start ingress: %w", err)
	}

	// Wait for Traefik to become fully ready. The API port may start accepting
	// connections before the REST provider handler is registered, causing 405
	// responses during the brief startup window. Retry with backoff.
	const maxRetries = 12
	const retryDelay = 3 * time.Second
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		time.Sleep(retryDelay)
		if lastErr = traefikapi.InitTraefik(); lastErr == nil {
			break
		}
		if verbose {
			fmt.Printf("Waiting for Traefik REST provider to be ready (attempt %d/%d): %v\n", i+1, maxRetries, lastErr)
		}
	}
	if lastErr != nil {
		return false, fmt.Errorf("failed to init ingress: %w", lastErr)
	}

	return true, nil
}

// parseJWTToken extracts workspace ID or workspace name from a JWT token
// JWT format: header.payload.signature
// We decode the payload (base64) and extract workspace-id or workspace-name from the claims
// Returns workspace ID if found, otherwise workspace name
func parseJWTToken(tokenString string) (workspaceID string, workspaceName string, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT token format")
	}

	// Decode the payload (second part)
	payload := parts[1]
	// Add padding if needed
	if len(payload)%4 != 0 {
		payload += strings.Repeat("=", 4-len(payload)%4)
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON payload
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Try to extract workspace-id first
	if id, ok := claims["workspace-id"].(string); ok {
		workspaceID = id
	}
	// Also try workspace_id (snake_case)
	if id, ok := claims["workspace_id"].(string); ok && workspaceID == "" {
		workspaceID = id
	}

	// Try to extract workspace-name
	if name, ok := claims["workspace-name"].(string); ok {
		workspaceName = name
	}
	// Also try workspace_name (snake_case)
	if name, ok := claims["workspace_name"].(string); ok && workspaceName == "" {
		workspaceName = name
	}

	if workspaceID == "" && workspaceName == "" {
		return "", "", fmt.Errorf("neither workspace-id nor workspace-name found in JWT token")
	}

	return workspaceID, workspaceName, nil
}

// removeRouteFromIngress removes a route from the ingress proxy by hostname
func removeRouteFromIngress(hostname string) error {
	return traefikapi.RemoveRoute(hostname)
}

// addRouteToIngress is a helper function that adds a route to the global Traefik ingress proxy.
// It can be called directly from workspace_init or from the HTTP handler.
// All routes go to the single global Traefik instance, mirroring how Caddy was used.
func addRouteToIngress(req IngressAddRouteRequest, jwtToken string) error {
	if req.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	if req.Upstream == "" {
		return fmt.Errorf("upstream is required")
	}

	// Determine cert resolver: use ACME for real domains, nothing for .localhost (mkcert handles it)
	certResolver := ""
	if !req.Mkcert && req.CertsDir == "" && !strings.HasSuffix(req.Hostname, ".localhost") {
		certResolver = "letsencrypt"
	}

	// Handle certificate generation/installation before registering the route
	if req.Mkcert {
		if err := traefikapi.InstallTLSCerts(req.Hostname, true, ""); err != nil {
			return fmt.Errorf("failed to generate and install certificates: %w", err)
		}
	} else if req.CertsDir != "" {
		if err := traefikapi.InstallTLSCerts(req.Hostname, false, req.CertsDir); err != nil {
			return fmt.Errorf("failed to install certificates from directory: %w", err)
		}
	}

	// Add route directly to global Traefik: hostname -> upstream
	if err := traefikapi.AddRouteWithTraefik(req.Hostname, req.Upstream, "", certResolver); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	return nil
}

// handleIngressAddRoute handles POST /ingress/add-route
func (s *Server) handleIngressAddRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req IngressAddRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check for JWT token in header for backward compatibility
	jwtToken := r.Header.Get("BITSWAN_AUTOMATION_SERVER_DAEMON_TOKEN")

	if err := addRouteToIngress(req, jwtToken); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(IngressAddRouteResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully added route: %s -> %s", req.Hostname, req.Upstream),
	})
}

// handleIngressListRoutes handles GET /ingress/list-routes
func (s *Server) handleIngressListRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	routes, err := traefikapi.ListRoutes()
	if err != nil {
		writeJSONError(w, "failed to list routes: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to simplified route info
	var routeInfos []RouteInfo
	for _, route := range routes {
		// Extract hostname from route match
		var hostnames []string
		for _, match := range route.Match {
			hostnames = append(hostnames, match.Host...)
		}

		// Extract upstream from route handle (traefik returns flat reverse_proxy at top level)
		var upstreams []string
		for _, handle := range route.Handle {
			if handle.Handler == "reverse_proxy" {
				for _, upstream := range handle.Upstreams {
					upstreams = append(upstreams, upstream.Dial)
				}
			}
		}

		// Only include routes with valid hostname and upstream
		if len(hostnames) > 0 && len(upstreams) > 0 {
			routeInfos = append(routeInfos, RouteInfo{
				ID:       route.ID,
				Hostname: hostnames[0],
				Upstream: upstreams[0],
				Terminal: route.Terminal,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(IngressListRoutesResponse{
		Routes: routeInfos,
	})
}

// handleIngressRemoveRoute handles DELETE /ingress/remove-route/{hostname}
func (s *Server) handleIngressRemoveRoute(w http.ResponseWriter, r *http.Request, hostname string) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if hostname == "" {
		writeJSONError(w, "hostname is required", http.StatusBadRequest)
		return
	}

	if err := traefikapi.RemoveRoute(hostname); err != nil {
		writeJSONError(w, "failed to remove route: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(IngressRemoveRouteResponse{
		Success: true,
		Message: fmt.Sprintf("Removed route: %s", hostname),
	})
}
