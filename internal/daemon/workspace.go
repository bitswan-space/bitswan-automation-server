package daemon

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// WorkspaceSelectRequest represents the request body for selecting a workspace
type WorkspaceSelectRequest struct {
	Workspace string `json:"workspace"`
}

// WorkspaceSelectResponse represents the response from workspace select
type WorkspaceSelectResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Workspace string `json:"workspace"`
}

// WorkspaceListResponse represents the response from listing workspaces
type WorkspaceListResponse struct {
	Workspaces      []string `json:"workspaces"`
	ActiveWorkspace string   `json:"active_workspace"`
}

// handleWorkspace routes workspace-related requests
func (s *Server) handleWorkspace(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/workspace")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "" || path == "list":
		s.handleWorkspaceList(w, r)
	case path == "select":
		s.handleWorkspaceSelect(w, r)
	default:
		writeJSONError(w, "not found", http.StatusNotFound)
	}
}

// handleWorkspaceList handles GET /workspace or /workspace/list
func (s *Server) handleWorkspaceList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bitswanDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan")
	workspacesDir := filepath.Join(bitswanDir, "workspaces")

	var workspaces []string

	// Check if workspaces directory exists
	if _, err := os.Stat(workspacesDir); !os.IsNotExist(err) {
		files, err := os.ReadDir(workspacesDir)
		if err != nil {
			writeJSONError(w, "failed to read workspaces directory: "+err.Error(), http.StatusInternalServerError)
			return
		}
		for _, file := range files {
			if file.IsDir() {
				workspaces = append(workspaces, file.Name())
			}
		}
	}

	// Get active workspace
	cfg := config.NewAutomationServerConfig()
	activeWorkspace, _ := cfg.GetActiveWorkspace()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(WorkspaceListResponse{
		Workspaces:      workspaces,
		ActiveWorkspace: activeWorkspace,
	})
}

// handleWorkspaceSelect handles POST /workspace/select
func (s *Server) handleWorkspaceSelect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WorkspaceSelectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace name is required", http.StatusBadRequest)
		return
	}

	// Validate workspace exists
	bitswanDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan")
	workspacesDir := filepath.Join(bitswanDir, "workspaces")
	workspacePath := filepath.Join(workspacesDir, req.Workspace)

	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		// List available workspaces for the error message
		var availableWorkspaces []string
		files, _ := os.ReadDir(workspacesDir)
		for _, file := range files {
			if file.IsDir() {
				availableWorkspaces = append(availableWorkspaces, file.Name())
			}
		}

		if len(availableWorkspaces) > 0 {
			writeJSONError(w, "invalid workspace '"+req.Workspace+"'. Available: "+strings.Join(availableWorkspaces, ", "), http.StatusBadRequest)
		} else {
			writeJSONError(w, "invalid workspace '"+req.Workspace+"'. No workspaces available.", http.StatusBadRequest)
		}
		return
	}

	// Set active workspace
	cfg := config.NewAutomationServerConfig()
	if err := cfg.SetActiveWorkspace(req.Workspace); err != nil {
		writeJSONError(w, "failed to set active workspace: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(WorkspaceSelectResponse{
		Success:   true,
		Message:   "Active workspace set to '" + req.Workspace + "'",
		Workspace: req.Workspace,
	})
}

