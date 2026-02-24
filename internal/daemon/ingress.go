package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
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
	Hostname string `json:"hostname"`
	Upstream string `json:"upstream"`
	Mkcert   bool   `json:"mkcert"`
	CertsDir string `json:"certs_dir,omitempty"`
	Secret   string `json:"secret,omitempty"` // Optional JWT token containing workspace ID
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
	caddyConfig := bitswanConfig + "caddy"
	caddyCertsDir := caddyConfig + "/certs"

	caddyProjectName := "bitswan-caddy"
	// If caddy container exists and caddy dir exists, return success (already initialized)
	caddyContainerId, err := exec.Command("docker", "ps", "-q", "-f", "name=caddy").Output()
	if err != nil {
		return false, fmt.Errorf("failed to check if caddy container exists: %w", err)
	}
	if string(caddyContainerId) != "" {
		return false, nil
	}

	if err := os.MkdirAll(caddyConfig, 0755); err != nil {
		return false, fmt.Errorf("failed to create ingress config directory: %w", err)
	}

	// Create Caddyfile with email and modify admin listener
	caddyfile := `
		{
			email info@bitswan.space
			admin 0.0.0.0:2019
		}`

	caddyfilePath := caddyConfig + "/Caddyfile"
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0755); err != nil {
		return false, fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	// For docker-compose, use HOST_HOME if available (docker-compose runs on host)
	// Convert container path to host path for volume mounts
	hostHomeDir := os.Getenv("HOST_HOME")
	caddyConfigForCompose := caddyConfig
	if hostHomeDir != "" && homeDir != hostHomeDir && strings.HasPrefix(caddyConfig, homeDir) {
		// Replace container home with host home for docker-compose volume paths
		caddyConfigForCompose = strings.Replace(caddyConfig, homeDir, hostHomeDir, 1)

		// Ensure directories exist on host before docker-compose tries to mount them
		// Create the directories on the host if they don't exist
		if err := os.MkdirAll(caddyConfigForCompose, 0755); err != nil {
			return false, fmt.Errorf("failed to create ingress config directory on host: %w", err)
		}
		if err := os.MkdirAll(caddyConfigForCompose+"/data", 0755); err != nil {
			return false, fmt.Errorf("failed to create ingress data directory on host: %w", err)
		}
		if err := os.MkdirAll(caddyConfigForCompose+"/config", 0755); err != nil {
			return false, fmt.Errorf("failed to create ingress config subdirectory on host: %w", err)
		}
		if err := os.MkdirAll(caddyConfigForCompose+"/certs", 0755); err != nil {
			return false, fmt.Errorf("failed to create ingress certs directory on host: %w", err)
		}

		// Also create/ensure Caddyfile exists on host
		caddyfilePathHost := caddyConfigForCompose + "/Caddyfile"
		if _, err := os.Stat(caddyfilePathHost); os.IsNotExist(err) {
			if err := os.WriteFile(caddyfilePathHost, []byte(caddyfile), 0755); err != nil {
				return false, fmt.Errorf("failed to write Caddyfile on host: %w", err)
			}
		}
	}

	caddyDockerCompose, err := dockercompose.CreateCaddyDockerComposeFile(caddyConfigForCompose)
	if err != nil {
		return false, fmt.Errorf("failed to create ingress docker-compose file: %w", err)
	}

	caddyDockerComposePath := caddyConfig + "/docker-compose.yml"
	if err := os.WriteFile(caddyDockerComposePath, []byte(caddyDockerCompose), 0755); err != nil {
		return false, fmt.Errorf("failed to write ingress docker-compose file: %w", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		return false, fmt.Errorf("failed to get current directory: %w", err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(caddyConfig); err != nil {
		return false, fmt.Errorf("failed to change directory to ingress config: %w", err)
	}

	caddyDockerComposeCom := exec.Command("docker", "compose", "-p", caddyProjectName, "up", "-d")

	// Create certs directory if it doesn't exist
	if _, err := os.Stat(caddyCertsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(caddyCertsDir, 0740); err != nil {
			return false, fmt.Errorf("failed to create ingress certs directory: %w", err)
		}
	}

	if err := runCommandVerbose(caddyDockerComposeCom, verbose); err != nil {
		return false, fmt.Errorf("failed to start ingress: %w", err)
	}

	// wait 5s to make sure Caddy is up
	time.Sleep(5 * time.Second)
	if err := caddyapi.InitCaddy(); err != nil {
		return false, fmt.Errorf("failed to init ingress: %w", err)
	}

	return true, nil
}

// initWorkspaceCaddy initializes the workspace sub-caddy
// Returns (newlyInitialized, error) where newlyInitialized is true if initialization happened,
// false if it was already initialized.
func initWorkspaceCaddy(workspaceName string, verbose bool) (bool, error) {
	homeDir := os.Getenv("HOME")
	workspaceConfig := fmt.Sprintf("%s/.config/bitswan/workspaces/%s", homeDir, workspaceName)
	caddyConfig := workspaceConfig + "/caddy"

	caddyProjectName := fmt.Sprintf("bitswan-%s-caddy", workspaceName)
	containerName := fmt.Sprintf("%s__caddy", workspaceName)

	// Check if workspace caddy container already exists
	caddyContainerId, err := exec.Command("docker", "ps", "-q", "-f", fmt.Sprintf("name=%s", containerName)).Output()
	if err != nil {
		return false, fmt.Errorf("failed to check if workspace caddy container exists: %w", err)
	}
	if string(caddyContainerId) != "" {
		return false, nil
	}

	// Create workspace caddy config directory
	if err := os.MkdirAll(caddyConfig, 0755); err != nil {
		return false, fmt.Errorf("failed to create workspace caddy config directory: %w", err)
	}

	// Create minimal Caddyfile with admin API only
	caddyfile := `{
	admin 0.0.0.0:2019
}`

	caddyfilePath := caddyConfig + "/Caddyfile"
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0755); err != nil {
		return false, fmt.Errorf("failed to write workspace Caddyfile: %w", err)
	}

	// For docker-compose, use HOST_HOME if available
	hostHomeDir := os.Getenv("HOST_HOME")
	caddyConfigForCompose := caddyConfig
	if hostHomeDir != "" && homeDir != hostHomeDir && strings.HasPrefix(caddyConfig, homeDir) {
		caddyConfigForCompose = strings.Replace(caddyConfig, homeDir, hostHomeDir, 1)

		// Ensure directories exist on host
		if err := os.MkdirAll(caddyConfigForCompose, 0755); err != nil {
			return false, fmt.Errorf("failed to create workspace caddy config directory on host: %w", err)
		}
		if err := os.MkdirAll(caddyConfigForCompose+"/data", 0755); err != nil {
			return false, fmt.Errorf("failed to create workspace caddy data directory on host: %w", err)
		}
		if err := os.MkdirAll(caddyConfigForCompose+"/config", 0755); err != nil {
			return false, fmt.Errorf("failed to create workspace caddy config subdirectory on host: %w", err)
		}

		// Ensure Caddyfile exists on host
		caddyfilePathHost := caddyConfigForCompose + "/Caddyfile"
		if _, err := os.Stat(caddyfilePathHost); os.IsNotExist(err) {
			if err := os.WriteFile(caddyfilePathHost, []byte(caddyfile), 0755); err != nil {
				return false, fmt.Errorf("failed to write workspace Caddyfile on host: %w", err)
			}
		}
	}

	// Stage networks: dev, staging, prod
	stageNetworks := []string{
		fmt.Sprintf("bitswan_%s_dev", workspaceName),
		fmt.Sprintf("bitswan_%s_staging", workspaceName),
		fmt.Sprintf("bitswan_%s_prod", workspaceName),
	}

	// Generate docker-compose for workspace sub-caddy
	caddyDockerCompose, err := dockercompose.CreateWorkspaceCaddyDockerComposeFile(workspaceName, caddyConfigForCompose, stageNetworks)
	if err != nil {
		return false, fmt.Errorf("failed to create workspace caddy docker-compose file: %w", err)
	}

	caddyDockerComposePath := caddyConfig + "/docker-compose.yml"
	if err := os.WriteFile(caddyDockerComposePath, []byte(caddyDockerCompose), 0755); err != nil {
		return false, fmt.Errorf("failed to write workspace caddy docker-compose file: %w", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		return false, fmt.Errorf("failed to get current directory: %w", err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(caddyConfig); err != nil {
		return false, fmt.Errorf("failed to change directory to workspace caddy config: %w", err)
	}

	caddyDockerComposeCom := exec.Command("docker", "compose", "-p", caddyProjectName, "up", "-d")

	// Create data and config directories if they don't exist
	if _, err := os.Stat(caddyConfig + "/data"); os.IsNotExist(err) {
		if err := os.MkdirAll(caddyConfig+"/data", 0755); err != nil {
			return false, fmt.Errorf("failed to create workspace caddy data directory: %w", err)
		}
	}
	if _, err := os.Stat(caddyConfig + "/config"); os.IsNotExist(err) {
		if err := os.MkdirAll(caddyConfig+"/config", 0755); err != nil {
			return false, fmt.Errorf("failed to create workspace caddy config directory: %w", err)
		}
	}

	if err := runCommandVerbose(caddyDockerComposeCom, verbose); err != nil {
		return false, fmt.Errorf("failed to start workspace caddy: %w", err)
	}

	// Wait for workspace caddy to be up and verify it's running
	time.Sleep(5 * time.Second)

	// Check if container is running
	checkCmd := exec.Command("docker", "ps", "-q", "-f", fmt.Sprintf("name=%s", containerName))
	output, err := checkCmd.Output()
	if err != nil || len(output) == 0 {
		return false, fmt.Errorf("workspace caddy container failed to start")
	}

	// Initialize workspace caddy via API
	// Try to connect via container name (if we're on the same network) or use docker exec
	workspaceCaddyURL := fmt.Sprintf("http://%s:2019", containerName)

	// First try direct connection (if daemon is on bitswan_network)
	client := &http.Client{
		Timeout: 2 * time.Second,
	}
	resp, err := client.Get(workspaceCaddyURL)
	if err == nil {
		defer resp.Body.Close()
		// We can connect directly, use the API
		originalCaddyHost := os.Getenv("BITSWAN_CADDY_HOST")
		os.Setenv("BITSWAN_CADDY_HOST", workspaceCaddyURL)
		defer func() {
			if originalCaddyHost != "" {
				os.Setenv("BITSWAN_CADDY_HOST", originalCaddyHost)
			} else {
				os.Unsetenv("BITSWAN_CADDY_HOST")
			}
		}()

		if err := caddyapi.InitCaddy(); err != nil {
			// Non-fatal - caddy might already be initialized
			if verbose {
				fmt.Printf("Warning: failed to init workspace caddy API (might already be initialized): %v\n", err)
			}
		}
	} else {
		// Can't connect directly, try via docker exec
		if verbose {
			fmt.Printf("Cannot connect directly to workspace caddy, skipping API initialization (will auto-initialize)\n")
		}
	}

	return true, nil
}

// runCommandVerbose runs a command with optional verbose output
func runCommandVerbose(cmd *exec.Cmd, verbose bool) error {
	var stdoutBuf, stderrBuf bytes.Buffer

	if verbose {
		// Set up pipes for real-time streaming
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to create stdout pipe: %w", err)
		}

		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			return fmt.Errorf("failed to create stderr pipe: %w", err)
		}

		// Create multi-writers to both stream and capture output
		stdoutWriter := io.MultiWriter(os.Stdout, &stdoutBuf)
		stderrWriter := io.MultiWriter(os.Stderr, &stderrBuf)

		// Start the command
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start command: %w", err)
		}

		// Copy stdout and stderr in separate goroutines
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(stdoutWriter, stdoutPipe)
		}()

		go func() {
			defer wg.Done()
			io.Copy(stderrWriter, stderrPipe)
		}()

		// Wait for all output to be processed
		wg.Wait()

		// Wait for command to complete
		err = cmd.Wait()
		if err != nil {
			// Include captured output in error message
			fullOutput := stdoutBuf.String() + stderrBuf.String()
			return fmt.Errorf("%w\nOutput:\n%s", err, fullOutput)
		}
		return nil
	} else {
		// Not verbose, just capture output for potential error reporting
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf

		err := cmd.Run()

		// If command failed, return error with output
		if err != nil {
			fullOutput := stdoutBuf.String() + stderrBuf.String()
			return fmt.Errorf("%w\nOutput:\n%s", err, fullOutput)
		}

		return nil
	}
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

// addRouteToIngress is a helper function that adds a route to the ingress proxy
// It can be called directly from workspace_init or from the HTTP handler
func addRouteToIngress(req IngressAddRouteRequest, jwtToken string) error {
	if req.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	if req.Upstream == "" {
		return fmt.Errorf("upstream is required")
	}

	// Check for JWT token in request body (secret parameter) or provided token
	var workspaceName string
	if jwtToken == "" {
		jwtToken = req.Secret
	}

	if jwtToken != "" {
		workspaceID, workspaceNameFromToken, err := parseJWTToken(jwtToken)
		if err != nil {
			// Non-fatal - we can still add the route without workspace name
			// Just continue without workspace name
			_ = err // Acknowledge the error but don't fail
		} else {
			// If we got workspace name directly from token, use it
			if workspaceNameFromToken != "" {
				workspaceName = workspaceNameFromToken
			} else if workspaceID != "" {
				// Otherwise, look up workspace name from workspace ID
				var lookupErr error
				workspaceName, lookupErr = findWorkspaceNameByID(workspaceID)
				if lookupErr != nil {
					return fmt.Errorf("failed to find workspace by ID: %w", lookupErr)
				}
			}
		}
	}

	// Handle certificate generation and installation
	if req.Mkcert {
		// Extract domain from hostname
		parts := strings.Split(req.Hostname, ".")
		if len(parts) < 2 {
			return fmt.Errorf("invalid hostname format: must contain at least one dot")
		}
		domain := strings.Join(parts[1:], ".")

		// Generate certificate for the specific hostname
		if err := caddyapi.GenerateAndInstallCertsForHostname(req.Hostname, domain); err != nil {
			return fmt.Errorf("failed to generate and install certificates: %w", err)
		}

		// Install TLS policies for the specific hostname
		if err := caddyapi.InstallTLSCertsForHostname(req.Hostname, domain, "default"); err != nil {
			return fmt.Errorf("failed to install TLS policies: %w", err)
		}
	} else if req.CertsDir != "" {
		// Install certificates from directory
		caddyConfig := os.Getenv("HOME") + "/.config/bitswan/caddy"
		if err := caddyapi.InstallCertsFromDir(req.CertsDir, req.Hostname, caddyConfig); err != nil {
			return fmt.Errorf("failed to install certificates from directory: %w", err)
		}
	}

	// If secret/JWT token is present, register route in workspace sub-caddy
	// Otherwise, register route in global caddy
	if workspaceName != "" {
		// Get workspace sub-caddy URL
		workspaceCaddyURL := caddyapi.GetWorkspaceCaddyBaseURL(workspaceName)

		// Register route in workspace sub-caddy (direct to upstream)
		if err := caddyapi.AddRouteWithCaddy(req.Hostname, req.Upstream, workspaceCaddyURL); err != nil {
			return fmt.Errorf("failed to add route to workspace sub-caddy: %w", err)
		}

		// Register route in global caddy (proxy to workspace sub-caddy)
		// The global caddy should proxy to the workspace sub-caddy at port 80
		workspaceCaddyUpstream := fmt.Sprintf("%s__caddy:80", workspaceName)
		if err := caddyapi.AddRouteWithCaddy(req.Hostname, workspaceCaddyUpstream, ""); err != nil {
			return fmt.Errorf("failed to add route to global caddy: %w", err)
		}
	} else {
		// No secret/JWT token, add route to global caddy only
		if err := caddyapi.AddRoute(req.Hostname, req.Upstream); err != nil {
			return fmt.Errorf("failed to add route: %w", err)
		}
	}

	return nil
}

// addRouteToIngressWithWorkspace is a convenience function that adds a route with a known workspace name
// This is used by workspace_init which already knows the workspace name
func addRouteToIngressWithWorkspace(hostname, upstream string, workspaceName string, mkcert bool, certsDir string) error {
	req := IngressAddRouteRequest{
		Hostname: hostname,
		Upstream: upstream,
		Mkcert:   mkcert,
		CertsDir: certsDir,
	}

	// Create a simple JWT-like token with workspace name (or we could modify addRouteToIngress to accept workspace name directly)
	// For now, we'll create a minimal token payload with workspace-name
	// Actually, let's modify the approach - if workspaceName is provided, use it directly
	if workspaceName != "" {
		// Get workspace sub-caddy URL
		workspaceCaddyURL := caddyapi.GetWorkspaceCaddyBaseURL(workspaceName)

		// Register route in workspace sub-caddy first (HTTP only, no TLS)
		// Workspace caddy doesn't have TLS certificates - it only handles HTTP
		if err := caddyapi.AddRouteWithCaddy(hostname, upstream, workspaceCaddyURL); err != nil {
			return fmt.Errorf("failed to add route to workspace sub-caddy: %w", err)
		}

		// Handle certificate generation and installation for global caddy only
		// Global caddy handles TLS termination and proxies to workspace caddy
		if mkcert {
			// Extract domain from hostname
			parts := strings.Split(hostname, ".")
			if len(parts) < 2 {
				return fmt.Errorf("invalid hostname format: must contain at least one dot")
			}
			domain := strings.Join(parts[1:], ".")

			// Generate certificate for the specific hostname (installs to global caddy)
			if err := caddyapi.GenerateAndInstallCertsForHostname(hostname, domain); err != nil {
				return fmt.Errorf("failed to generate and install certificates: %w", err)
			}

			// Install TLS policies for the specific hostname in global caddy
			if err := caddyapi.InstallTLSCertsForHostname(hostname, domain, workspaceName); err != nil {
				return fmt.Errorf("failed to install TLS policies: %w", err)
			}
		} else if certsDir != "" {
			// Install certificates from directory to global caddy
			caddyConfig := os.Getenv("HOME") + "/.config/bitswan/caddy"
			if err := caddyapi.InstallCertsFromDir(certsDir, hostname, caddyConfig); err != nil {
				return fmt.Errorf("failed to install certificates from directory: %w", err)
			}
		}

		// Register route in global caddy (proxy to workspace sub-caddy on port 80)
		workspaceCaddyUpstream := fmt.Sprintf("%s__caddy:80", workspaceName)
		if err := caddyapi.AddRouteWithCaddy(hostname, workspaceCaddyUpstream, ""); err != nil {
			return fmt.Errorf("failed to add route to global caddy: %w", err)
		}
	} else {
		// No workspace name, add route to global caddy only
		if err := addRouteToIngress(req, ""); err != nil {
			return err
		}
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

	routes, err := caddyapi.ListRoutes()
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

		// Extract upstream from route handle
		var upstreams []string
		for _, handle := range route.Handle {
			if handle.Handler == "subroute" {
				for _, subRoute := range handle.Routes {
					for _, subHandle := range subRoute.Handle {
						if subHandle.Handler == "reverse_proxy" {
							for _, upstream := range subHandle.Upstreams {
								upstreams = append(upstreams, upstream.Dial)
							}
						}
					}
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

	if err := caddyapi.RemoveRoute(hostname); err != nil {
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
