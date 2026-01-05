package daemon

import (
	"bytes"
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
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	Upstream string   `json:"upstream"`
	Terminal bool     `json:"terminal"`
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

	if err := initIngress(req.Verbose); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(IngressInitResponse{
		Success: true,
		Message: "Ingress proxy is ready!",
	})
}

// initIngress initializes the ingress proxy (extracted from cmd/ingress/init.go)
func initIngress(verbose bool) error {
	bitswanConfig := os.Getenv("HOME") + "/.config/bitswan/"
	caddyConfig := bitswanConfig + "caddy"
	caddyCertsDir := caddyConfig + "/certs"

	caddyProjectName := "bitswan-caddy"
	// If caddy container exists and caddy dir exists, return
	caddyContainerId, err := exec.Command("docker", "ps", "-q", "-f", "name=caddy").Output()
	if err != nil {
		return fmt.Errorf("failed to check if caddy container exists: %w", err)
	}
	if string(caddyContainerId) != "" {
		return fmt.Errorf("caddy already initialized")
	}

	if err := os.MkdirAll(caddyConfig, 0755); err != nil {
		return fmt.Errorf("failed to create ingress config directory: %w", err)
	}

	// Create Caddyfile with email and modify admin listener
	caddyfile := `
		{
			email info@bitswan.space
			admin 0.0.0.0:2019
		}`

	caddyfilePath := caddyConfig + "/Caddyfile"
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0755); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	caddyDockerCompose, err := dockercompose.CreateCaddyDockerComposeFile(caddyConfig)
	if err != nil {
		return fmt.Errorf("failed to create ingress docker-compose file: %w", err)
	}

	caddyDockerComposePath := caddyConfig + "/docker-compose.yml"
	if err := os.WriteFile(caddyDockerComposePath, []byte(caddyDockerCompose), 0755); err != nil {
		return fmt.Errorf("failed to write ingress docker-compose file: %w", err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(caddyConfig); err != nil {
		return fmt.Errorf("failed to change directory to ingress config: %w", err)
	}

	caddyDockerComposeCom := exec.Command("docker", "compose", "-p", caddyProjectName, "up", "-d")

	// Create certs directory if it doesn't exist
	if _, err := os.Stat(caddyCertsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(caddyCertsDir, 0740); err != nil {
			return fmt.Errorf("failed to create ingress certs directory: %w", err)
		}
	}

	if err := runCommandVerbose(caddyDockerComposeCom, verbose); err != nil {
		return fmt.Errorf("failed to start ingress: %w", err)
	}

	// wait 5s to make sure Caddy is up
	time.Sleep(5 * time.Second)
	if err := caddyapi.InitCaddy(); err != nil {
		return fmt.Errorf("failed to init ingress: %w", err)
	}

	return nil
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

	if req.Hostname == "" {
		writeJSONError(w, "hostname is required", http.StatusBadRequest)
		return
	}

	if req.Upstream == "" {
		writeJSONError(w, "upstream is required", http.StatusBadRequest)
		return
	}

	// Handle certificate generation and installation
	if req.Mkcert {
		// Extract domain from hostname
		parts := strings.Split(req.Hostname, ".")
		if len(parts) < 2 {
			writeJSONError(w, "invalid hostname format: must contain at least one dot", http.StatusBadRequest)
			return
		}
		domain := strings.Join(parts[1:], ".")

		// Generate certificate for the specific hostname
		if err := caddyapi.GenerateAndInstallCertsForHostname(req.Hostname, domain); err != nil {
			writeJSONError(w, "failed to generate and install certificates: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Install TLS policies for the specific hostname
		if err := caddyapi.InstallTLSCertsForHostname(req.Hostname, domain, "default"); err != nil {
			writeJSONError(w, "failed to install TLS policies: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else if req.CertsDir != "" {
		// Install certificates from directory
		caddyConfig := os.Getenv("HOME") + "/.config/bitswan/caddy"
		if err := caddyapi.InstallCertsFromDir(req.CertsDir, req.Hostname, caddyConfig); err != nil {
			writeJSONError(w, "failed to install certificates from directory: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := caddyapi.AddRoute(req.Hostname, req.Upstream); err != nil {
		writeJSONError(w, "failed to add route: "+err.Error(), http.StatusInternalServerError)
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

