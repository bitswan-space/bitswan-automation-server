package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

const (
	// SocketDir is the directory containing the automation server daemon socket
	SocketDir = "/var/run/bitswan"
	// SocketPath is the default path for the automation server daemon socket
	SocketPath = "/var/run/bitswan/automation-server.sock"
)

// Server represents the automation server daemon HTTP server
type Server struct {
	version      string
	startTime    time.Time
	listener     net.Listener
	server       *http.Server
	docsServer   *http.Server
	docsListener net.Listener
	token        string
}

// LoadToken reads the token from the config file
func LoadToken() (string, error) {
	cfg := config.NewAutomationServerConfig()
	return cfg.GetLocalServerToken()
}

// StatusResponse represents the response from the /status endpoint
type StatusResponse struct {
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
	UptimeSec int64  `json:"uptime_sec"`
	StartTime string `json:"start_time"`
}

// NewServer creates a new daemon server
func NewServer(version string) *Server {
	return &Server{
		version:   version,
		startTime: time.Now(),
	}
}

// authMiddleware wraps a handler with bearer token authentication
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "missing Authorization header"}`, http.StatusUnauthorized)
			return
		}

		// Check for "Bearer <token>" format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, `{"error": "invalid Authorization header format, expected 'Bearer <token>'"}`, http.StatusUnauthorized)
			return
		}

		if parts[1] != s.token {
			http.Error(w, `{"error": "invalid token"}`, http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// setupRoutes configures the HTTP routes
func (s *Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Health check endpoint (authenticated)
	mux.HandleFunc("/ping", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "pong")
	}))

	// Version endpoint (authenticated)
	mux.HandleFunc("/version", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"version": s.version,
		})
	}))

	// Status endpoint - returns version, uptime, etc. (authenticated)
	mux.HandleFunc("/status", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uptime := time.Since(s.startTime)

		response := StatusResponse{
			Version:   s.version,
			Uptime:    formatDuration(uptime),
			UptimeSec: int64(uptime.Seconds()),
			StartTime: s.startTime.Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))

	// Automation endpoints (authenticated)
	mux.HandleFunc("/automations", s.authMiddleware(s.handleAutomations))
	mux.HandleFunc("/automations/", s.authMiddleware(s.handleAutomations))

	// Workspace endpoints (authenticated)
	mux.HandleFunc("/workspace", s.authMiddleware(s.handleWorkspace))
	mux.HandleFunc("/workspace/", s.authMiddleware(s.handleWorkspace))

	// Certificate authority endpoints (authenticated)
	mux.HandleFunc("/certauthority", s.authMiddleware(s.handleCertAuthority))
	mux.HandleFunc("/certauthority/", s.authMiddleware(s.handleCertAuthority))

	// Ingress endpoints (authenticated)
	mux.HandleFunc("/ingress", s.authMiddleware(s.handleIngress))
	mux.HandleFunc("/ingress/", s.authMiddleware(s.handleIngress))

	// Service endpoints (authenticated)
	mux.HandleFunc("/service", s.authMiddleware(s.handleService))
	mux.HandleFunc("/service/", s.authMiddleware(s.handleService))

	// Job endpoints for interactive operations (authenticated)
	mux.HandleFunc("/jobs", s.authMiddleware(s.handleJobs))
	mux.HandleFunc("/jobs/", s.authMiddleware(s.handleJobs))

	// Docs endpoint (unauthenticated - public access)
	mux.HandleFunc("/api-docs", s.handleDocs)

	return mux
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// Run starts the HTTP server listening on the Unix socket
func (s *Server) Run() error {
	// Load the authentication token
	token, err := LoadToken()
	if err != nil {
		return fmt.Errorf("failed to load authentication token: %w", err)
	}
	s.token = token

	// Install all certificates from the registry into the daemon's certificate store
	if err := installAllCertificatesInDaemon(); err != nil {
		fmt.Printf("Warning: Failed to install certificates in daemon: %v\n", err)
	}

	// Initialize MQTT publisher if AOC is configured (non-blocking, will retry on failure)
	// This ensures MQTT publisher is set up even if AOC wasn't configured at first
	// Pass server reference so MQTT handlers can call internal functions
	initializeMQTTPublisherWithServer(s)

	// Ensure the socket directory exists
	if err := os.MkdirAll(SocketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket file if it exists
	if err := os.Remove(SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket listener: %w", err)
	}
	s.listener = listener

	// Set socket permissions to allow access
	if err := os.Chmod(SocketPath, 0666); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	// Create HTTP server for Unix socket
	s.server = &http.Server{
		Handler: s.setupRoutes(),
	}

	// Create HTTP server for docs (listens on TCP port 8080)
	docsMux := http.NewServeMux()
	docsMux.HandleFunc("/", s.handleDocs) // Root path serves docs
	docsMux.HandleFunc("/api-docs", s.handleDocs)
	s.docsServer = &http.Server{
		Handler: docsMux,
	}

	// Start docs HTTP server on port 8080
	docsListener, err := net.Listen("tcp", fmt.Sprintf(":%d", docsPort))
	if err != nil {
		return fmt.Errorf("failed to create docs HTTP listener: %w", err)
	}
	s.docsListener = docsListener

	// Set up ingress route for docs (with retry logic)
	go func() {
		// Wait a bit for Caddy to be ready
		time.Sleep(2 * time.Second)
		maxRetries := 5
		for i := 0; i < maxRetries; i++ {
			if err := s.setupDocsIngress(); err == nil {
				fmt.Printf("Docs available at http://%s\n", docsHostname)
				break
			}
			if i < maxRetries-1 {
				time.Sleep(2 * time.Second)
			}
		}
	}()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start servers in goroutines
	errChan := make(chan error, 1)
	go func() {
		fmt.Printf("Automation server daemon listening on %s\n", SocketPath)
		fmt.Printf("Version: %s\n", s.version)
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	go func() {
		fmt.Printf("Docs server listening on :%d\n", docsPort)
		if err := s.docsServer.Serve(docsListener); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case err := <-errChan:
		return err
	case sig := <-sigChan:
		fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	if err := s.docsServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("docs server shutdown error: %w", err)
	}

	// Clean up socket file
	os.Remove(SocketPath)

	fmt.Println("Server stopped")
	return nil
}

