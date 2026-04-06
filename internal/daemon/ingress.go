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

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/util"
)

// IngressType represents which ingress proxy is in use
type IngressType string

const (
	IngressCaddy   IngressType = "caddy"
	IngressTraefik IngressType = "traefik"
)

// IngressInitRequest represents the request to initialize ingress
type IngressInitRequest struct {
	Verbose     bool   `json:"verbose"`
	IngressType string `json:"ingress_type,omitempty"` // "caddy" or "traefik" (default: auto-detect)
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
	Secret        string `json:"secret,omitempty"`
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

// DetectIngressType checks which ingress proxy is currently running.
// Returns IngressTraefik if Traefik is running, IngressCaddy if Caddy is running.
// If neither is running, returns IngressTraefik (default for new installs).
func DetectIngressType() IngressType {
	// Check for Traefik container
	traefikId, err := exec.Command("docker", "ps", "-q", "-f", "name=^traefik$").Output()
	if err == nil && strings.TrimSpace(string(traefikId)) != "" {
		return IngressTraefik
	}

	// Check for Caddy container
	caddyId, err := exec.Command("docker", "ps", "-q", "-f", "name=^caddy$").Output()
	if err == nil && strings.TrimSpace(string(caddyId)) != "" {
		return IngressCaddy
	}

	// Neither running — default to Traefik for new installs
	return IngressTraefik
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
	case path == "type":
		s.handleIngressType(w, r)
	case path == "migrate":
		s.handleIngressMigrate(w, r)
	case path == "update":
		s.handleIngressUpdate(w, r)
	default:
		writeJSONError(w, "not found", http.StatusNotFound)
	}
}

// handleIngressType handles GET /ingress/type — returns the current ingress type
func (s *Server) handleIngressType(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"type": string(DetectIngressType())})
}

// handleIngressMigrate handles POST /ingress/migrate — migrates from Caddy to Traefik
func (s *Server) handleIngressMigrate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Verbose bool `json:"verbose"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := MigrateCaddyToTraefik(req.Verbose); err != nil {
		writeJSONError(w, "migration failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Successfully migrated from Caddy to Traefik",
	})
}

// handleIngressUpdate handles POST /ingress/update — updates the ingress proxy to the latest version
func (s *Server) handleIngressUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Verbose bool `json:"verbose"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := UpdateIngress(req.Verbose); err != nil {
		writeJSONError(w, "update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Successfully updated ingress proxy",
	})
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

	// If ingress_type is specified, set it as env var for initIngress
	if req.IngressType != "" {
		os.Setenv("BITSWAN_INGRESS_TYPE", req.IngressType)
		defer os.Unsetenv("BITSWAN_INGRESS_TYPE")
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

// initIngress initializes the ingress proxy.
// It first checks if an existing ingress (Caddy or Traefik) is already running.
// For new installs, it starts Traefik (unless BITSWAN_INGRESS_TYPE=caddy).
func initIngress(verbose bool) (bool, error) {
	ingressType := DetectIngressType()

	switch ingressType {
	case IngressCaddy:
		// Caddy is already running, keep using it
		return false, nil
	case IngressTraefik:
		// Check if Traefik is already running and functional
		if err := traefikapi.InitTraefik(); err == nil {
			return false, nil
		}
		// Nothing running — check if user wants to force Caddy
		if strings.EqualFold(os.Getenv("BITSWAN_INGRESS_TYPE"), "caddy") {
			return initCaddyIngress(verbose)
		}
		// Default: start Traefik
		return initTraefikIngress(verbose)
	}

	return false, fmt.Errorf("unknown ingress type")
}

// initCaddyIngress starts a new Caddy ingress proxy.
func initCaddyIngress(verbose bool) (bool, error) {
	homeDir := os.Getenv("HOME")
	bitswanConfig := homeDir + "/.config/bitswan/"
	caddyConfig := bitswanConfig + "caddy"
	caddyCertsDir := caddyConfig + "/certs"

	caddyProjectName := "bitswan-caddy"

	// If caddy container already exists, return
	caddyContainerId, err := exec.Command("docker", "ps", "-q", "-f", "name=caddy").Output()
	if err != nil {
		return false, fmt.Errorf("failed to check if caddy container exists: %w", err)
	}
	if strings.TrimSpace(string(caddyContainerId)) != "" {
		return false, nil
	}

	if err := os.MkdirAll(caddyConfig, 0755); err != nil {
		return false, fmt.Errorf("failed to create ingress config directory: %w", err)
	}

	caddyfile := `
		{
			email info@bitswan.space
			admin 0.0.0.0:2019
		}`

	caddyfilePath := caddyConfig + "/Caddyfile"
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0755); err != nil {
		return false, fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	hostHomeDir := os.Getenv("HOST_HOME")
	caddyConfigForCompose := caddyConfig
	if hostHomeDir != "" && homeDir != hostHomeDir && strings.HasPrefix(caddyConfig, homeDir) {
		caddyConfigForCompose = strings.Replace(caddyConfig, homeDir, hostHomeDir, 1)

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

	caddyDockerComposeCom := exec.Command("docker", "compose", "-p", caddyProjectName, "up", "-d")
	caddyDockerComposeCom.Dir = caddyConfig

	if _, err := os.Stat(caddyCertsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(caddyCertsDir, 0740); err != nil {
			return false, fmt.Errorf("failed to create ingress certs directory: %w", err)
		}
	}

	if err := util.RunCommandVerbose(caddyDockerComposeCom, verbose); err != nil {
		return false, fmt.Errorf("failed to start ingress: %w", err)
	}

	time.Sleep(5 * time.Second)
	if err := caddyapi.InitCaddy(); err != nil {
		return false, fmt.Errorf("failed to init ingress: %w", err)
	}

	return true, nil
}

// initTraefikIngress starts a new Traefik ingress proxy.
func initTraefikIngress(verbose bool) (bool, error) {
	homeDir := os.Getenv("HOME")
	bitswanConfig := homeDir + "/.config/bitswan/"
	traefikConfig := bitswanConfig + "traefik"
	traefikCertsDir := traefikConfig + "/certs"

	traefikProjectName := "bitswan-traefik"

	// Check if Traefik is already running with REST provider support.
	if err := traefikapi.InitTraefik(); err == nil {
		return false, nil
	}

	// Traefik is either not running or is running without REST provider support.
	// Stop and remove any existing container named "traefik" so we can start a fresh one.
	existingIdBytes, _ := exec.Command("docker", "ps", "-q", "-f", "name=traefik").Output()
	if existingId := strings.TrimSpace(string(existingIdBytes)); existingId != "" {
		if verbose {
			fmt.Println("Existing Traefik container does not support REST provider — stopping it to reinitialize...")
		}
		exec.Command("docker", "stop", existingId).Run()
		exec.Command("docker", "rm", existingId).Run()
	}

	if err := os.MkdirAll(traefikConfig, 0755); err != nil {
		return false, fmt.Errorf("failed to create ingress config directory: %w", err)
	}

	// Create acme directory for Let's Encrypt certificate storage
	acmeDir := traefikConfig + "/acme"
	if err := os.MkdirAll(acmeDir, 0700); err != nil {
		return false, fmt.Errorf("failed to create acme directory: %w", err)
	}

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

	hostHomeDir := os.Getenv("HOST_HOME")
	traefikConfigForCompose := traefikConfig
	if hostHomeDir != "" && homeDir != hostHomeDir && strings.HasPrefix(traefikConfig, homeDir) {
		traefikConfigForCompose = strings.Replace(traefikConfig, homeDir, hostHomeDir, 1)

		if err := os.MkdirAll(traefikConfigForCompose, 0755); err != nil {
			return false, fmt.Errorf("failed to create ingress config directory on host: %w", err)
		}
		if err := os.MkdirAll(traefikConfigForCompose+"/certs", 0755); err != nil {
			return false, fmt.Errorf("failed to create ingress certs directory on host: %w", err)
		}
		if err := os.MkdirAll(traefikConfigForCompose+"/acme", 0700); err != nil {
			return false, fmt.Errorf("failed to create ingress acme directory on host: %w", err)
		}

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

	traefikDockerComposeCom := exec.Command("docker", "compose", "-p", traefikProjectName, "up", "-d")
	traefikDockerComposeCom.Dir = traefikConfig

	if _, err := os.Stat(traefikCertsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(traefikCertsDir, 0740); err != nil {
			return false, fmt.Errorf("failed to create ingress certs directory: %w", err)
		}
	}

	if err := util.RunCommandVerbose(traefikDockerComposeCom, verbose); err != nil {
		return false, fmt.Errorf("failed to start ingress: %w", err)
	}

	time.Sleep(5 * time.Second)
	if err := traefikapi.InitTraefik(); err != nil {
		return false, fmt.Errorf("failed to init ingress: %w", err)
	}

	return true, nil
}

// initWorkspaceTraefik initializes a traefik proxy for a workspace.
func initWorkspaceTraefik(workspaceName, domain string, verbose bool) (bool, error) {
	homeDir := os.Getenv("HOME")
	workspaceConfig := fmt.Sprintf("%s/.config/bitswan/workspaces/%s", homeDir, workspaceName)
	traefikConfig := workspaceConfig + "/traefik"

	traefikProjectName := fmt.Sprintf("bitswan-%s-traefik", workspaceName)
	containerName := fmt.Sprintf("%s__traefik", workspaceName)

	// Check if workspace traefik container already exists
	traefikContainerId, err := exec.Command("docker", "ps", "-q", "-f", fmt.Sprintf("name=%s", containerName)).Output()
	if err != nil {
		return false, fmt.Errorf("failed to check if workspace traefik container exists: %w", err)
	}
	if strings.TrimSpace(string(traefikContainerId)) != "" {
		return false, nil
	}

	// Create workspace traefik config directory
	if err := os.MkdirAll(traefikConfig, 0755); err != nil {
		return false, fmt.Errorf("failed to create workspace traefik config directory: %w", err)
	}

	// Traefik static config enabling REST provider and web entrypoint (HTTP only for workspace)
	traefikStaticConfig := `entryPoints:
  web:
    address: ":80"
api:
  insecure: true
providers:
  rest:
    insecure: true
`

	traefikConfigFilePath := traefikConfig + "/traefik.yml"
	if err := os.WriteFile(traefikConfigFilePath, []byte(traefikStaticConfig), 0755); err != nil {
		return false, fmt.Errorf("failed to write workspace traefik.yml: %w", err)
	}

	// For docker-compose, use HOST_HOME if available
	hostHomeDir := os.Getenv("HOST_HOME")
	traefikConfigForCompose := traefikConfig
	if hostHomeDir != "" && homeDir != hostHomeDir && strings.HasPrefix(traefikConfig, homeDir) {
		traefikConfigForCompose = strings.Replace(traefikConfig, homeDir, hostHomeDir, 1)

		if err := os.MkdirAll(traefikConfigForCompose, 0755); err != nil {
			return false, fmt.Errorf("failed to create workspace traefik config directory on host: %w", err)
		}

		traefikConfigFilePathHost := traefikConfigForCompose + "/traefik.yml"
		if _, err := os.Stat(traefikConfigFilePathHost); os.IsNotExist(err) {
			if err := os.WriteFile(traefikConfigFilePathHost, []byte(traefikStaticConfig), 0755); err != nil {
				return false, fmt.Errorf("failed to write workspace traefik.yml on host: %w", err)
			}
		}
	}

	// No stage networks — just bitswan_network for backward compatibility
	traefikDockerCompose, err := dockercompose.CreateWorkspaceTraefikDockerComposeFile(workspaceName, traefikConfigForCompose, domain, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create workspace traefik docker-compose file: %w", err)
	}

	traefikDockerComposePath := traefikConfig + "/docker-compose.yml"
	if err := os.WriteFile(traefikDockerComposePath, []byte(traefikDockerCompose), 0755); err != nil {
		return false, fmt.Errorf("failed to write workspace traefik docker-compose file: %w", err)
	}

	traefikDockerComposeCom := exec.Command("docker", "compose", "-p", traefikProjectName, "up", "-d")
	traefikDockerComposeCom.Dir = traefikConfig

	if err := util.RunCommandVerbose(traefikDockerComposeCom, verbose); err != nil {
		return false, fmt.Errorf("failed to start workspace traefik: %w", err)
	}

	// Wait for workspace traefik to be up and verify it's running
	time.Sleep(5 * time.Second)

	checkCmd := exec.Command("docker", "ps", "-q", "-f", fmt.Sprintf("name=%s", containerName))
	output, err := checkCmd.Output()
	if err != nil || len(output) == 0 {
		return false, fmt.Errorf("workspace traefik container failed to start")
	}

	// Initialize workspace traefik via API
	workspaceTraefikURL := fmt.Sprintf("http://%s:8080", containerName)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(workspaceTraefikURL)
	if err == nil {
		defer resp.Body.Close()
		originalTraefikHost := os.Getenv("BITSWAN_TRAEFIK_HOST")
		os.Setenv("BITSWAN_TRAEFIK_HOST", workspaceTraefikURL)
		defer func() {
			if originalTraefikHost != "" {
				os.Setenv("BITSWAN_TRAEFIK_HOST", originalTraefikHost)
			} else {
				os.Unsetenv("BITSWAN_TRAEFIK_HOST")
			}
		}()

		if err := traefikapi.InitWorkspaceTraefik(); err != nil {
			if verbose {
				fmt.Printf("Warning: failed to init workspace traefik API: %v\n", err)
			}
		}
	} else {
		if verbose {
			fmt.Printf("Cannot connect directly to workspace traefik, skipping API initialization\n")
		}
	}

	return true, nil
}

// parseJWTToken extracts workspace ID or workspace name from a JWT token
func parseJWTToken(tokenString string) (workspaceID string, workspaceName string, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT token format")
	}

	payload := parts[1]
	if len(payload)%4 != 0 {
		payload += strings.Repeat("=", 4-len(payload)%4)
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	if id, ok := claims["workspace-id"].(string); ok {
		workspaceID = id
	}
	if id, ok := claims["workspace_id"].(string); ok && workspaceID == "" {
		workspaceID = id
	}
	if name, ok := claims["workspace-name"].(string); ok {
		workspaceName = name
	}
	if name, ok := claims["workspace_name"].(string); ok && workspaceName == "" {
		workspaceName = name
	}

	if workspaceID == "" && workspaceName == "" {
		return "", "", fmt.Errorf("neither workspace-id nor workspace-name found in JWT token")
	}

	return workspaceID, workspaceName, nil
}

// resolveWorkspaceName extracts workspace name from the request or JWT token.
func resolveWorkspaceName(req IngressAddRouteRequest, jwtToken string) string {
	if req.WorkspaceName != "" {
		return req.WorkspaceName
	}

	if jwtToken == "" {
		jwtToken = req.Secret
	}

	if jwtToken != "" {
		workspaceID, workspaceNameFromToken, err := parseJWTToken(jwtToken)
		if err == nil {
			if workspaceNameFromToken != "" {
				return workspaceNameFromToken
			}
			if workspaceID != "" {
				name, err := findWorkspaceNameByID(workspaceID)
				if err == nil {
					return name
				}
			}
		}
	}

	return ""
}

// addRouteToIngress adds a route using whichever ingress is running.
// For Traefik with a workspace name, it sets up two-tier routing
// (platform traefik → workspace sub-traefik → container).
func addRouteToIngress(req IngressAddRouteRequest, jwtToken string) error {
	if req.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	if req.Upstream == "" {
		return fmt.Errorf("upstream is required")
	}

	ingressType := DetectIngressType()

	switch ingressType {
	case IngressCaddy:
		return addRouteCaddy(req)
	case IngressTraefik:
		workspaceName := resolveWorkspaceName(req, jwtToken)
		return addRouteTraefik(req, workspaceName)
	}

	return fmt.Errorf("no ingress proxy detected")
}

// addRouteCaddy adds a route to Caddy
func addRouteCaddy(req IngressAddRouteRequest) error {
	if req.Mkcert {
		parts := strings.Split(req.Hostname, ".")
		if len(parts) < 2 {
			return fmt.Errorf("invalid hostname format: must contain at least one dot")
		}
		domain := strings.Join(parts[1:], ".")

		if err := caddyapi.GenerateAndInstallCertsForHostname(req.Hostname, domain); err != nil {
			return fmt.Errorf("failed to generate and install certificates: %w", err)
		}
		if err := caddyapi.InstallTLSCertsForHostname(req.Hostname, domain, "default"); err != nil {
			return fmt.Errorf("failed to install TLS policies: %w", err)
		}
	} else if req.CertsDir != "" {
		caddyConfig := os.Getenv("HOME") + "/.config/bitswan/caddy"
		if err := caddyapi.InstallCertsFromDir(req.CertsDir, req.Hostname, caddyConfig); err != nil {
			return fmt.Errorf("failed to install certificates from directory: %w", err)
		}
	}

	return caddyapi.AddRoute(req.Hostname, req.Upstream)
}

// isWorkspaceTraefikRunning checks if a workspace sub-traefik container is running.
func isWorkspaceTraefikRunning(workspaceName string) bool {
	containerName := fmt.Sprintf("%s__traefik", workspaceName)
	out, err := exec.Command("docker", "ps", "-q", "-f", fmt.Sprintf("name=%s", containerName)).Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// addRouteTraefik adds a route to Traefik.
// If a workspace sub-traefik is running, uses two-tier routing (platform → sub-traefik → container).
// Otherwise, adds the route directly to the platform traefik (single-tier).
func addRouteTraefik(req IngressAddRouteRequest, workspaceName string) error {
	certResolver := ""
	if !req.Mkcert && req.CertsDir == "" && !strings.HasSuffix(req.Hostname, ".localhost") {
		certResolver = "letsencrypt"
	}

	// Handle certificates
	if req.Mkcert {
		if err := traefikapi.InstallTLSCerts(req.Hostname, true, ""); err != nil {
			return fmt.Errorf("failed to generate and install certificates: %w", err)
		}
	} else if req.CertsDir != "" {
		if err := traefikapi.InstallTLSCerts(req.Hostname, false, req.CertsDir); err != nil {
			return fmt.Errorf("failed to install certificates from directory: %w", err)
		}
	}

	// If workspace has a sub-traefik running, use two-tier routing
	if workspaceName != "" && isWorkspaceTraefikRunning(workspaceName) {
		workspaceTraefikURL := traefikapi.GetWorkspaceTraefikBaseURL(workspaceName)

		// Add plain HTTP reverse proxy route at workspace sub-traefik
		if err := traefikapi.AddRouteWithTraefik(req.Hostname, req.Upstream, workspaceTraefikURL); err != nil {
			return fmt.Errorf("failed to add route to workspace sub-traefik: %w", err)
		}

		// Add route at platform traefik: hostname → workspace sub-traefik
		workspaceTraefikUpstream := fmt.Sprintf("%s__traefik:80", workspaceName)
		if err := traefikapi.AddRouteWithTraefik(req.Hostname, workspaceTraefikUpstream, "", certResolver); err != nil {
			return fmt.Errorf("failed to add route to platform traefik: %w", err)
		}
	} else {
		// No workspace sub-traefik — single-tier routing at platform traefik
		if err := traefikapi.AddRouteWithTraefik(req.Hostname, req.Upstream, "", certResolver); err != nil {
			return fmt.Errorf("failed to add route: %w", err)
		}
	}

	return nil
}

// removeRouteFromIngress removes a route from whichever ingress is running.
func removeRouteFromIngress(hostname string) error {
	ingressType := DetectIngressType()

	switch ingressType {
	case IngressCaddy:
		return caddyapi.RemoveRoute(hostname)
	case IngressTraefik:
		return traefikapi.RemoveRoute(hostname)
	}

	return fmt.Errorf("no ingress proxy detected")
}

// MigrateCaddyToTraefik migrates from Caddy to Traefik.
// It exports routes from Caddy, stops Caddy, starts Traefik, and re-adds the routes.
func MigrateCaddyToTraefik(verbose bool) error {
	if DetectIngressType() != IngressCaddy {
		return fmt.Errorf("caddy is not running, nothing to migrate")
	}

	// Step 1: Export existing routes from Caddy
	fmt.Println("Exporting routes from Caddy...")
	routes, err := caddyapi.ListRoutes()
	if err != nil {
		return fmt.Errorf("failed to list Caddy routes: %w", err)
	}

	type routeExport struct {
		hostname string
		upstream string
	}
	var exported []routeExport
	for _, route := range routes {
		var hostname, upstream string
		for _, match := range route.Match {
			if len(match.Host) > 0 {
				hostname = match.Host[0]
			}
		}
		for _, handle := range route.Handle {
			if handle.Handler == "reverse_proxy" {
				for _, u := range handle.Upstreams {
					upstream = u.Dial
				}
			}
			// Also check subroutes (Caddy wraps in subroute handler)
			for _, subRoute := range handle.Routes {
				for _, subHandle := range subRoute.Handle {
					if subHandle.Handler == "reverse_proxy" {
						for _, u := range subHandle.Upstreams {
							upstream = u.Dial
						}
					}
				}
			}
		}
		if hostname != "" && upstream != "" {
			exported = append(exported, routeExport{hostname: hostname, upstream: upstream})
		}
	}

	if verbose {
		fmt.Printf("Exported %d routes from Caddy\n", len(exported))
	}

	// Step 2: Stop Caddy
	fmt.Println("Stopping Caddy...")
	stopCmd := exec.Command("docker", "compose", "-p", "bitswan-caddy", "down")
	homeDir := os.Getenv("HOME")
	caddyConfig := homeDir + "/.config/bitswan/caddy"
	stopCmd.Dir = caddyConfig
	if err := util.RunCommandVerbose(stopCmd, verbose); err != nil {
		// Try force remove if compose down fails
		exec.Command("docker", "rm", "-f", "caddy").Run()
	}

	// Step 3: Start Traefik
	fmt.Println("Starting Traefik...")
	if _, err := initTraefikIngress(verbose); err != nil {
		return fmt.Errorf("failed to start Traefik: %w", err)
	}

	// Step 4: Re-add routes to Traefik
	fmt.Println("Migrating routes to Traefik...")
	for _, route := range exported {
		certResolver := ""
		if !strings.HasSuffix(route.hostname, ".localhost") {
			certResolver = "letsencrypt"
		}
		if err := traefikapi.AddRouteWithTraefik(route.hostname, route.upstream, "", certResolver); err != nil {
			fmt.Printf("Warning: failed to migrate route %s -> %s: %v\n", route.hostname, route.upstream, err)
		} else if verbose {
			fmt.Printf("Migrated route: %s -> %s\n", route.hostname, route.upstream)
		}
	}

	fmt.Printf("Migration complete: %d routes migrated from Caddy to Traefik\n", len(exported))
	return nil
}

// UpdateIngress updates the ingress proxy to the latest version.
// It exports routes, stops the container, regenerates config, restarts, and re-adds routes.
func UpdateIngress(verbose bool) error {
	ingressType := DetectIngressType()

	switch ingressType {
	case IngressTraefik:
		return updateTraefik(verbose)
	case IngressCaddy:
		return updateCaddy(verbose)
	}

	return fmt.Errorf("no ingress proxy detected")
}

// updateTraefik updates the Traefik proxy to the latest version
func updateTraefik(verbose bool) error {
	// Step 1: Export existing routes
	fmt.Println("Exporting routes from Traefik...")
	routes, err := traefikapi.ListRoutes()
	if err != nil {
		return fmt.Errorf("failed to list Traefik routes: %w", err)
	}

	type routeExport struct {
		hostname string
		upstream string
	}
	var exported []routeExport
	for _, route := range routes {
		var hostname, upstream string
		for _, match := range route.Match {
			if len(match.Host) > 0 {
				hostname = match.Host[0]
			}
		}
		for _, handle := range route.Handle {
			if handle.Handler == "reverse_proxy" {
				for _, u := range handle.Upstreams {
					upstream = u.Dial
				}
			}
		}
		if hostname != "" && upstream != "" {
			exported = append(exported, routeExport{hostname: hostname, upstream: upstream})
		}
	}

	if verbose {
		fmt.Printf("Exported %d routes from Traefik\n", len(exported))
	}

	// Step 2: Stop Traefik
	fmt.Println("Stopping Traefik...")
	stopCmd := exec.Command("docker", "compose", "-p", "bitswan-traefik", "down")
	homeDir := os.Getenv("HOME")
	traefikConfig := homeDir + "/.config/bitswan/traefik"
	stopCmd.Dir = traefikConfig
	if err := util.RunCommandVerbose(stopCmd, verbose); err != nil {
		// Try force remove if compose down fails
		exec.Command("docker", "rm", "-f", "traefik").Run()
	}

	// Step 3: Pull latest image and regenerate config
	fmt.Println("Pulling latest Traefik image...")
	pullCmd := exec.Command("docker", "pull", "traefik:v3.6")
	if err := util.RunCommandVerbose(pullCmd, verbose); err != nil {
		fmt.Printf("Warning: failed to pull latest image: %v\n", err)
	}

	// Step 4: Start Traefik with new config
	fmt.Println("Starting Traefik...")
	if _, err := initTraefikIngress(verbose); err != nil {
		return fmt.Errorf("failed to start Traefik: %w", err)
	}

	// Step 5: Re-add routes
	fmt.Println("Restoring routes to Traefik...")
	for _, route := range exported {
		certResolver := ""
		if !strings.HasSuffix(route.hostname, ".localhost") {
			certResolver = "letsencrypt"
		}
		if err := traefikapi.AddRouteWithTraefik(route.hostname, route.upstream, "", certResolver); err != nil {
			fmt.Printf("Warning: failed to restore route %s -> %s: %v\n", route.hostname, route.upstream, err)
		} else if verbose {
			fmt.Printf("Restored route: %s -> %s\n", route.hostname, route.upstream)
		}
	}

	fmt.Printf("Update complete: %d routes restored\n", len(exported))
	return nil
}

// updateCaddy updates the Caddy proxy to the latest version
func updateCaddy(verbose bool) error {
	// Step 1: Export existing routes
	fmt.Println("Exporting routes from Caddy...")
	routes, err := caddyapi.ListRoutes()
	if err != nil {
		return fmt.Errorf("failed to list Caddy routes: %w", err)
	}

	type routeExport struct {
		hostname string
		upstream string
	}
	var exported []routeExport
	for _, route := range routes {
		var hostname, upstream string
		for _, match := range route.Match {
			if len(match.Host) > 0 {
				hostname = match.Host[0]
			}
		}
		for _, handle := range route.Handle {
			if handle.Handler == "reverse_proxy" {
				for _, u := range handle.Upstreams {
					upstream = u.Dial
				}
			}
			for _, subRoute := range handle.Routes {
				for _, subHandle := range subRoute.Handle {
					if subHandle.Handler == "reverse_proxy" {
						for _, u := range subHandle.Upstreams {
							upstream = u.Dial
						}
					}
				}
			}
		}
		if hostname != "" && upstream != "" {
			exported = append(exported, routeExport{hostname: hostname, upstream: upstream})
		}
	}

	if verbose {
		fmt.Printf("Exported %d routes from Caddy\n", len(exported))
	}

	// Step 2: Stop Caddy
	fmt.Println("Stopping Caddy...")
	stopCmd := exec.Command("docker", "compose", "-p", "bitswan-caddy", "down")
	homeDir := os.Getenv("HOME")
	caddyConfig := homeDir + "/.config/bitswan/caddy"
	stopCmd.Dir = caddyConfig
	if err := util.RunCommandVerbose(stopCmd, verbose); err != nil {
		exec.Command("docker", "rm", "-f", "caddy").Run()
	}

	// Step 3: Pull latest image
	fmt.Println("Pulling latest Caddy image...")
	pullCmd := exec.Command("docker", "pull", "caddy:2.9")
	if err := util.RunCommandVerbose(pullCmd, verbose); err != nil {
		fmt.Printf("Warning: failed to pull latest image: %v\n", err)
	}

	// Step 4: Start Caddy with new config
	fmt.Println("Starting Caddy...")
	if _, err := initCaddyIngress(verbose); err != nil {
		return fmt.Errorf("failed to start Caddy: %w", err)
	}

	// Step 5: Re-add routes
	fmt.Println("Restoring routes to Caddy...")
	for _, route := range exported {
		if err := caddyapi.AddRoute(route.hostname, route.upstream); err != nil {
			fmt.Printf("Warning: failed to restore route %s -> %s: %v\n", route.hostname, route.upstream, err)
		} else if verbose {
			fmt.Printf("Restored route: %s -> %s\n", route.hostname, route.upstream)
		}
	}

	fmt.Printf("Update complete: %d routes restored\n", len(exported))
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

	ingressType := DetectIngressType()
	var routeInfos []RouteInfo

	switch ingressType {
	case IngressCaddy:
		routes, err := caddyapi.ListRoutes()
		if err != nil {
			writeJSONError(w, "failed to list routes: "+err.Error(), http.StatusInternalServerError)
			return
		}
		for _, route := range routes {
			var hostnames []string
			for _, match := range route.Match {
				hostnames = append(hostnames, match.Host...)
			}
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
			if len(hostnames) > 0 && len(upstreams) > 0 {
				routeInfos = append(routeInfos, RouteInfo{
					ID:       route.ID,
					Hostname: hostnames[0],
					Upstream: upstreams[0],
					Terminal: route.Terminal,
				})
			}
		}

	case IngressTraefik:
		routes, err := traefikapi.ListRoutes()
		if err != nil {
			writeJSONError(w, "failed to list routes: "+err.Error(), http.StatusInternalServerError)
			return
		}
		for _, route := range routes {
			var hostnames []string
			for _, match := range route.Match {
				hostnames = append(hostnames, match.Host...)
			}
			var upstreams []string
			for _, handle := range route.Handle {
				if handle.Handler == "reverse_proxy" {
					for _, upstream := range handle.Upstreams {
						upstreams = append(upstreams, upstream.Dial)
					}
				}
			}
			if len(hostnames) > 0 && len(upstreams) > 0 {
				routeInfos = append(routeInfos, RouteInfo{
					ID:       route.ID,
					Hostname: hostnames[0],
					Upstream: upstreams[0],
					Terminal: route.Terminal,
				})
			}
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

	if err := removeRouteFromIngress(hostname); err != nil {
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
