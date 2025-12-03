package daemonapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// CommandRequest represents a request to execute a command
type CommandRequest struct {
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Workspace string   `json:"workspace,omitempty"` // Optional workspace context
}

// CommandResponse represents the response from executing a command
type CommandResponse struct {
	Success   bool   `json:"success"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
	ExitCode  int    `json:"exit_code,omitempty"`
}

// Server represents the REST API server
type Server struct {
	tokenManager *TokenManager
	configDir    string
	router       *mux.Router
	server       *http.Server
}

// NewServer creates a new REST API server
func NewServer(configDir string, port int) (*Server, error) {
	tokenManager, err := NewTokenManager(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create token manager: %w", err)
	}
	
	s := &Server{
		tokenManager: tokenManager,
		configDir:    configDir,
		router:       mux.NewRouter(),
	}
	
	s.setupRoutes()
	
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	return s, nil
}

// setupRoutes sets up the HTTP routes
func (s *Server) setupRoutes() {
	// Health check endpoint (no auth required)
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
	
	// Setup REST API routes
	s.setupRESTRoutes()
	
	// Keep legacy execute endpoint for backward compatibility
	s.router.HandleFunc("/api/v1/execute", s.handleExecute).Methods("POST")
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// authenticateRequest authenticates the request using the Authorization header
func (s *Server) authenticateRequest(r *http.Request) (TokenType, string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", fmt.Errorf("missing authorization header")
	}
	
	// Expect "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", "", fmt.Errorf("invalid authorization header format")
	}
	
	tokenType, workspace, err := s.tokenManager.ValidateToken(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("invalid token: %w", err)
	}
	
	return tokenType, workspace, nil
}

// handleExecute handles command execution requests
func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	// Authenticate request
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	
	// Parse request
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	
	// Validate workspace access for workspace tokens
	if tokenType == TokenTypeWorkspace {
		if req.Workspace == "" {
			// Try to infer workspace from command if it's a workspace command
			req.Workspace = s.inferWorkspaceFromCommand(req.Command, req.Args)
		}
		
		if req.Workspace != "" && req.Workspace != tokenWorkspace {
			http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
			return
		}
		
		// Ensure workspace is set for workspace tokens
		if req.Workspace == "" {
			req.Workspace = tokenWorkspace
		}
	}
	
	// Execute command
	output, exitCode, err := s.executeCommand(req.Command, req.Args, req.Workspace)
	
	response := CommandResponse{
		Success:  err == nil && exitCode == 0,
		ExitCode: exitCode,
	}
	
	if err != nil {
		response.Error = err.Error()
	} else {
		response.Output = output
	}
	
	w.Header().Set("Content-Type", "application/json")
	if err != nil || exitCode != 0 {
		w.WriteHeader(http.StatusOK) // Still 200, but success=false
	}
	json.NewEncoder(w).Encode(response)
}

// inferWorkspaceFromCommand tries to infer the workspace from command arguments
func (s *Server) inferWorkspaceFromCommand(command string, args []string) string {
	// For workspace commands, the workspace is usually the first argument
	if strings.HasPrefix(command, "workspace") && len(args) > 0 {
		// Commands like "workspace init <name>" or "workspace remove <name>"
		if len(args) >= 1 {
			return args[0]
		}
	}
	return ""
}

// executeCommand executes a command using the bitswan binary
func (s *Server) executeCommand(command string, args []string, workspace string) (string, int, error) {
	binaryPath := "/usr/local/bin/bitswan"
	
	// Build command arguments
	cmdArgs := []string{command}
	cmdArgs = append(cmdArgs, args...)
	
	// Create command
	cmd := exec.Command(binaryPath, cmdArgs...)
	
	// Set working directory if workspace is specified
	if workspace != "" {
		workspacePath := filepath.Join(s.configDir, "workspaces", workspace)
		if _, err := os.Stat(workspacePath); err == nil {
			cmd.Dir = workspacePath
		}
	}
	
	// Capture output
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	// Execute command
	err := cmd.Run()
	
	// Combine stdout and stderr
	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n" + stderr.String()
	}
	
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}
	
	return output, exitCode, err
}

// @Summary List all tokens
// @Description Get a list of all tokens (requires global token)
// @Tags tokens
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Router /tokens [get]
func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokenType, _, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	
	if tokenType != TokenTypeGlobal {
		http.Error(w, "only global tokens can list tokens", http.StatusForbidden)
		return
	}
	
	tokens := s.tokenManager.ListTokens()
	
	// Don't expose full token values in list
	tokenList := make(map[string]map[string]interface{})
	for value, token := range tokens {
		tokenList[value] = map[string]interface{}{
			"type":        token.Type,
			"workspace":   token.Workspace,
			"description": token.Description,
			"created_at":  token.CreatedAt,
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"tokens": tokenList})
}

// @Summary Create a global token
// @Description Create a new global token (requires global token)
// @Tags tokens
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body object true "Token creation parameters" SchemaExample({"description": "My global token"})
// @Success 200 {object} map[string]string
// @Failure 400 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /tokens/global [post]
func (s *Server) handleCreateGlobalToken(w http.ResponseWriter, r *http.Request) {
	tokenType, _, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	
	if tokenType != TokenTypeGlobal {
		http.Error(w, "only global tokens can create tokens", http.StatusForbidden)
		return
	}
	
	var req struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	
	token, err := s.tokenManager.CreateGlobalToken(req.Description)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// @Summary Create a workspace token
// @Description Create a new workspace-specific token (requires global token)
// @Tags tokens
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body object true "Token creation parameters" SchemaExample({"workspace": "my-workspace", "description": "GitOps token"})
// @Success 200 {object} map[string]string
// @Failure 400 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /tokens/workspace [post]
func (s *Server) handleCreateWorkspaceToken(w http.ResponseWriter, r *http.Request) {
	tokenType, _, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	
	if tokenType != TokenTypeGlobal {
		http.Error(w, "only global tokens can create tokens", http.StatusForbidden)
		return
	}
	
	var req struct {
		Workspace   string `json:"workspace"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	
	if req.Workspace == "" {
		http.Error(w, "workspace is required", http.StatusBadRequest)
		return
	}
	
	token, err := s.tokenManager.CreateWorkspaceToken(req.Workspace, req.Description)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// @Summary Delete a token
// @Description Delete a token (requires global token)
// @Tags tokens
// @Accept json
// @Produce json
// @Security Bearer
// @Param token path string true "Token value"
// @Success 200 {object} map[string]string
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 404 {object} StandardResponse
// @Router /tokens/{token} [delete]
func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	tokenType, _, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	
	if tokenType != TokenTypeGlobal {
		http.Error(w, "only global tokens can delete tokens", http.StatusForbidden)
		return
	}
	
	vars := mux.Vars(r)
	token := vars["token"]
	
	if err := s.tokenManager.DeleteToken(token); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// Start starts the HTTP server
func (s *Server) Start() error {
	return s.server.ListenAndServe()
}

// Stop stops the HTTP server
func (s *Server) Stop() error {
	return s.server.Close()
}

