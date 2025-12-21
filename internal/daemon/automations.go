package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// AutomationListResponse represents the response from the list automations endpoint
type AutomationListResponse struct {
	Automations []automations.Automation `json:"automations"`
}

// AutomationLogsResponse represents the response from the logs endpoint
type AutomationLogsResponse struct {
	Status string   `json:"status"`
	Logs   []string `json:"logs"`
}

// AutomationActionResponse represents the response from action endpoints
type AutomationActionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// writeJSONError writes a JSON error response
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

// writeJSONSuccess writes a JSON success response
func writeJSONSuccess(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AutomationActionResponse{Success: true, Message: message})
}

// getWorkspaceFromRequest gets the workspace from the query parameter or falls back to active workspace
func getWorkspaceFromRequest(r *http.Request, w http.ResponseWriter) (string, bool) {
	// Check if workspace is specified in query parameter
	workspaceName := r.URL.Query().Get("workspace")
	if workspaceName != "" {
		return workspaceName, true
	}

	// Fall back to active workspace
	cfg := config.NewAutomationServerConfig()
	workspaceName, err := cfg.GetActiveWorkspace()
	if err != nil {
		writeJSONError(w, "failed to get active workspace: "+err.Error()+". Use --workspace flag to specify a workspace.", http.StatusInternalServerError)
		return "", false
	}
	if workspaceName == "" {
		writeJSONError(w, "no active workspace configured. Use --workspace flag to specify a workspace or run 'bitswan workspace select' to set one.", http.StatusBadRequest)
		return "", false
	}
	return workspaceName, true
}

// handleListAutomations handles GET /automations
func (s *Server) handleListAutomations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workspaceName, ok := getWorkspaceFromRequest(r, w)
	if !ok {
		return
	}

	automationsList, err := automations.GetAutomations(workspaceName)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AutomationListResponse{Automations: automationsList})
}

// handleAutomationLogs handles GET /automations/{id}/logs
func (s *Server) handleAutomationLogs(w http.ResponseWriter, r *http.Request, deploymentID string) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workspaceName, ok := getWorkspaceFromRequest(r, w)
	if !ok {
		return
	}

	lines := 0
	if linesStr := r.URL.Query().Get("lines"); linesStr != "" {
		lines, _ = strconv.Atoi(linesStr)
	}

	automation := automations.Automation{
		DeploymentID: deploymentID,
		Workspace:    workspaceName,
	}

	logs, err := automation.GetLogs(lines)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AutomationLogsResponse{
		Status: logs.Status,
		Logs:   logs.Logs,
	})
}

// handleAutomationStart handles POST /automations/{id}/start
func (s *Server) handleAutomationStart(w http.ResponseWriter, r *http.Request, deploymentID string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workspaceName, ok := getWorkspaceFromRequest(r, w)
	if !ok {
		return
	}

	automation := automations.Automation{
		DeploymentID: deploymentID,
		Workspace:    workspaceName,
	}

	if err := automation.Start(); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONSuccess(w, "Automation "+deploymentID+" started successfully")
}

// handleAutomationStop handles POST /automations/{id}/stop
func (s *Server) handleAutomationStop(w http.ResponseWriter, r *http.Request, deploymentID string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workspaceName, ok := getWorkspaceFromRequest(r, w)
	if !ok {
		return
	}

	automation := automations.Automation{
		DeploymentID: deploymentID,
		Workspace:    workspaceName,
	}

	if err := automation.Stop(); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONSuccess(w, "Automation "+deploymentID+" stopped successfully")
}

// handleAutomationRestart handles POST /automations/{id}/restart
func (s *Server) handleAutomationRestart(w http.ResponseWriter, r *http.Request, deploymentID string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workspaceName, ok := getWorkspaceFromRequest(r, w)
	if !ok {
		return
	}

	automation := automations.Automation{
		DeploymentID: deploymentID,
		Workspace:    workspaceName,
	}

	if err := automation.Restart(); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONSuccess(w, "Automation "+deploymentID+" restarted successfully")
}

// handleAutomationRemove handles DELETE /automations/{id}
func (s *Server) handleAutomationRemove(w http.ResponseWriter, r *http.Request, deploymentID string) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workspaceName, ok := getWorkspaceFromRequest(r, w)
	if !ok {
		return
	}

	automation := automations.Automation{
		DeploymentID: deploymentID,
		Workspace:    workspaceName,
	}

	if err := automation.Remove(); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONSuccess(w, "Automation "+deploymentID+" removed successfully")
}

// handleAutomations is the main router for /automations endpoints
func (s *Server) handleAutomations(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/automations")
	path = strings.TrimPrefix(path, "/")

	// GET /automations - list all automations
	if path == "" {
		s.handleListAutomations(w, r)
		return
	}

	// Parse the path to get deployment ID and action
	parts := strings.Split(path, "/")
	deploymentID := parts[0]

	if len(parts) == 1 {
		// DELETE /automations/{id} - remove automation
		if r.Method == http.MethodDelete {
			s.handleAutomationRemove(w, r, deploymentID)
			return
		}
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if len(parts) == 2 {
		action := parts[1]
		switch action {
		case "logs":
			s.handleAutomationLogs(w, r, deploymentID)
		case "start":
			s.handleAutomationStart(w, r, deploymentID)
		case "stop":
			s.handleAutomationStop(w, r, deploymentID)
		case "restart":
			s.handleAutomationRestart(w, r, deploymentID)
		default:
			writeJSONError(w, "unknown action", http.StatusNotFound)
		}
		return
	}

	writeJSONError(w, "invalid path", http.StatusNotFound)
}

// PullAndDeployRequest represents the request body for pull-and-deploy
type PullAndDeployRequest struct {
	Workspace string `json:"workspace"`
	Branch    string `json:"branch"`
	Force     bool   `json:"force"`
	NoBuild   bool   `json:"no_build"`
}

func (s *Server) handlePullAndDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PullAndDeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	if req.Branch == "" {
		writeJSONError(w, "branch is required", http.StatusBadRequest)
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

	// Run pull-and-deploy logic
	err = RunPullAndDeploy(req.Workspace, req.Branch, req.Force, req.NoBuild, wPipe)
	wPipe.Close()
	wg.Wait()

	if err != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", err))
	}
}
