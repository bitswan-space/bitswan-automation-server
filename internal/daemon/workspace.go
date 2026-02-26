package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
	Workspaces      []WorkspaceInfo `json:"workspaces"`
	ActiveWorkspace string          `json:"active_workspace"`
}

// WorkspaceInfo contains detailed information about a workspace
type WorkspaceInfo struct {
	Name         string `json:"name"`
	Domain       string `json:"domain,omitempty"`
	EditorURL    string `json:"editor_url,omitempty"`
	GitopsURL    string `json:"gitops_url,omitempty"`
	SSHPublicKey string `json:"ssh_public_key,omitempty"`
	VSCodePassword string `json:"vscode_password,omitempty"`
	GitopsSecret string `json:"gitops_secret,omitempty"`
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
	case path == "init":
		s.handleWorkspaceInit(w, r)
	case path == "update":
		s.handleWorkspaceUpdate(w, r)
	case path == "remove":
		s.handleWorkspaceRemove(w, r)
	case path == "sync":
		s.handleWorkspaceSync(w, r)
	case path == "connect-to-aoc":
		s.handleWorkspaceConnectToAOC(w, r)
	case path == "start":
		s.handleWorkspaceStart(w, r)
	case path == "stop":
		s.handleWorkspaceStop(w, r)
	case path == "restart":
		s.handleWorkspaceRestart(w, r)
	default:
		writeJSONError(w, "not found", http.StatusNotFound)
	}
}

type WorkspaceRunRequest struct {
	// Args are the original CLI args excluding the binary, e.g.:
	// ["workspace","init","foo","--domain","bs-foo.localhost"]
	Args []string `json:"args"`
}

// WorkspaceRemoveRequest represents the request body for removing a workspace
type WorkspaceRemoveRequest struct {
	Workspace string `json:"workspace"`
}

func (s *Server) handleWorkspaceInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WorkspaceRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Args) < 2 || req.Args[0] != "workspace" || req.Args[1] != "init" {
		writeJSONError(w, "invalid args: expected prefix ['workspace','init',...]", http.StatusBadRequest)
		return
	}

	// Stream logs (NDJSON)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Redirect stdout to stream logs
	stdoutMutex.Lock()
	oldStdout := os.Stdout
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		stdoutMutex.Unlock()
		WriteLogEntry(w, "error", fmt.Sprintf("Failed to create pipe: %v", err))
		return
	}

	os.Stdout = wPipe
	stdoutMutex.Unlock()

	defer func() {
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rPipe.Close()
		wPipe.Close()
	}()

	logWriter := NewLogStreamWriter(w, "info")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := rPipe.Read(buf)
			if n > 0 {
				logWriter.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				WriteLogEntry(w, "error", fmt.Sprintf("Error reading from pipe: %v", err))
				break
			}
		}
	}()

	// Parse args and run init logic
	err = s.runWorkspaceInit(req.Args[2:])
	wPipe.Close()
	wg.Wait()

	if err != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", err))
	}
}

func (s *Server) handleWorkspaceUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WorkspaceRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Args) < 2 || req.Args[0] != "workspace" || req.Args[1] != "update" {
		writeJSONError(w, "invalid args: expected prefix ['workspace','update',...]", http.StatusBadRequest)
		return
	}

	// Stream logs (NDJSON)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Redirect stdout to stream logs
	stdoutMutex.Lock()
	oldStdout := os.Stdout
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		stdoutMutex.Unlock()
		WriteLogEntry(w, "error", fmt.Sprintf("Failed to create pipe: %v", err))
		return
	}

	os.Stdout = wPipe
	stdoutMutex.Unlock()

	defer func() {
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rPipe.Close()
		wPipe.Close()
	}()

	logWriter := NewLogStreamWriter(w, "info")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := rPipe.Read(buf)
			if n > 0 {
				logWriter.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				WriteLogEntry(w, "error", fmt.Sprintf("Error reading from pipe: %v", err))
				break
			}
		}
	}()

	// Parse args and run update logic
	err = s.runWorkspaceUpdate(req.Args[2:])
	wPipe.Close()
	wg.Wait()

	if err != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", err))
	}
}

// handleWorkspaceList handles GET /workspace or /workspace/list
func (s *Server) handleWorkspaceList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	long := r.URL.Query().Get("long") == "true"
	showPasswords := r.URL.Query().Get("passwords") == "true"

	result, err := GetWorkspaceList(long, showPasswords)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
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

func (s *Server) handleWorkspaceRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WorkspaceRemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace name is required", http.StatusBadRequest)
		return
	}

	// Stream logs (NDJSON)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Redirect stdout to stream logs
	stdoutMutex.Lock()
	oldStdout := os.Stdout
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		stdoutMutex.Unlock()
		WriteLogEntry(w, "error", fmt.Sprintf("Failed to create pipe: %v", err))
		return
	}

	os.Stdout = wPipe
	stdoutMutex.Unlock()

	defer func() {
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rPipe.Close()
		wPipe.Close()
	}()

	logWriter := NewLogStreamWriter(w, "info")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := rPipe.Read(buf)
			if n > 0 {
				logWriter.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				WriteLogEntry(w, "error", fmt.Sprintf("Error reading from pipe: %v", err))
				break
			}
		}
	}()

	// Run remove logic
	err = RunWorkspaceRemove(req.Workspace, wPipe)
	wPipe.Close()
	wg.Wait()

	if err != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", err))
	}
}

// handleWorkspaceSync handles POST /workspace/sync - manually triggers workspace list sync to AOC
func (s *Server) handleWorkspaceSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Sync workspace list to AOC via REST API
	if err := syncWorkspaceListToAOC(); err != nil {
		writeJSONError(w, "failed to sync workspace list: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Workspace list synced successfully",
	})
}

// handleWorkspaceConnectToAOC handles POST /workspace/connect-to-aoc - connects existing workspaces to AOC
func (s *Server) handleWorkspaceConnectToAOC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WorkspaceConnectToAOCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Stream logs (NDJSON)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Redirect stdout to stream logs
	stdoutMutex.Lock()
	oldStdout := os.Stdout
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		stdoutMutex.Unlock()
		WriteLogEntry(w, "error", fmt.Sprintf("Failed to create pipe: %v", err))
		return
	}

	os.Stdout = wPipe
	stdoutMutex.Unlock()

	defer func() {
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rPipe.Close()
		wPipe.Close()
	}()

	logWriter := NewLogStreamWriter(w, "info")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := rPipe.Read(buf)
			if n > 0 {
				logWriter.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				WriteLogEntry(w, "error", fmt.Sprintf("Error reading from pipe: %v", err))
				break
			}
		}
	}()

	// Run the connect logic
	err = s.runWorkspaceConnectToAOC(req)
	wPipe.Close()
	wg.Wait()

	if err != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", err))
	}
}

