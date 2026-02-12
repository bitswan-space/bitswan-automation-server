package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
)

// stdoutMutex protects stdout redirection from concurrent requests
var stdoutMutex sync.Mutex

// ServiceEnableRequest represents the request to enable a service
type ServiceEnableRequest struct {
	ServiceType    string                 `json:"service_type"` // "editor", "kafka", "couchdb"
	Workspace      string                 `json:"workspace"`
	Stage          string                 `json:"stage,omitempty"`
	EditorImage    string                 `json:"editor_image,omitempty"`
	OAuthConfig    map[string]interface{} `json:"oauth_config,omitempty"` // OAuth config as JSON object
	TrustCA        bool                   `json:"trust_ca,omitempty"`
	KafkaImage     string                 `json:"kafka_image,omitempty"`
	UIImage        string                 `json:"ui_image,omitempty"`
	ZookeeperImage string                 `json:"zookeeper_image,omitempty"`
	CouchDBImage   string                 `json:"couchdb_image,omitempty"`
}

// ServiceDisableRequest represents the request to disable a service
type ServiceDisableRequest struct {
	ServiceType  string `json:"service_type"`
	Workspace    string `json:"workspace"`
	Stage string `json:"stage,omitempty"`
}

// ServiceStatusRequest represents the request to get service status
type ServiceStatusRequest struct {
	ServiceType   string `json:"service_type"`
	Workspace     string `json:"workspace"`
	Stage         string `json:"stage,omitempty"`
	ShowPasswords bool   `json:"show_passwords"`
}

// ServiceStartRequest represents the request to start a service
type ServiceStartRequest struct {
	ServiceType  string `json:"service_type"`
	Workspace    string `json:"workspace"`
	Stage string `json:"stage,omitempty"`
}

// ServiceStopRequest represents the request to stop a service
type ServiceStopRequest struct {
	ServiceType  string `json:"service_type"`
	Workspace    string `json:"workspace"`
	Stage string `json:"stage,omitempty"`
}

// ServiceUpdateRequest represents the request to update a service
type ServiceUpdateRequest struct {
	ServiceType    string `json:"service_type"`
	Workspace      string `json:"workspace"`
	Stage          string `json:"stage,omitempty"`
	EditorImage    string `json:"editor_image,omitempty"`
	TrustCA        bool   `json:"trust_ca,omitempty"`
	KafkaImage     string `json:"kafka_image,omitempty"`
	ZookeeperImage string `json:"zookeeper_image,omitempty"`
	CouchDBImage   string `json:"couchdb_image,omitempty"`
}

// ServiceBackupRequest represents the request to backup CouchDB
type ServiceBackupRequest struct {
	Workspace    string `json:"workspace"`
	BackupPath   string `json:"backup_path"`
	Stage string `json:"stage,omitempty"`
}

// ServiceRestoreRequest represents the request to restore CouchDB
type ServiceRestoreRequest struct {
	Workspace    string `json:"workspace"`
	BackupPath   string `json:"backup_path"`
	Force        bool   `json:"force"`
	Stage string `json:"stage,omitempty"`
}

// ServiceResponse represents a generic service response
type ServiceResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// gitopsServiceRequest is the JSON body sent to the gitops /services/ endpoints
type gitopsServiceRequest struct {
	Stage string `json:"stage,omitempty"`
	Image        string `json:"image,omitempty"`
	KafkaImage   string `json:"kafka_image,omitempty"`
	UIImage      string `json:"ui_image,omitempty"`
	BackupPath   string `json:"backup_path,omitempty"`
	Force        bool   `json:"force,omitempty"`
}

// proxyToGitops forwards a service request to the gitops API and relays the response.
// method: HTTP method (GET, POST)
// workspace: workspace name for metadata lookup
// gitopsPath: path after the gitops base URL (e.g., "/services/couchdb/enable")
// body: JSON body to send (nil for GET requests)
func proxyToGitops(w http.ResponseWriter, method, workspace, gitopsPath string, body interface{}) {
	metadata, err := config.GetWorkspaceMetadata(workspace)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("failed to get workspace metadata: %v", err), http.StatusInternalServerError)
		return
	}

	reqURL := fmt.Sprintf("%s%s", metadata.GitopsURL, gitopsPath)
	reqURL = automations.TransformURLForDaemon(reqURL, workspace)

	var resp *http.Response
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			writeJSONError(w, fmt.Sprintf("failed to marshal request body: %v", err), http.StatusInternalServerError)
			return
		}
		req, err := http.NewRequest(method, reqURL, bytes.NewReader(bodyBytes))
		if err != nil {
			writeJSONError(w, fmt.Sprintf("failed to create request: %v", err), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+metadata.GitopsSecret)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			writeJSONError(w, fmt.Sprintf("failed to send request to gitops: %v", err), http.StatusBadGateway)
			return
		}
	} else {
		resp, err = automations.SendAutomationRequest(method, reqURL, metadata.GitopsSecret)
		if err != nil {
			writeJSONError(w, fmt.Sprintf("failed to send request to gitops: %v", err), http.StatusBadGateway)
			return
		}
	}
	defer resp.Body.Close()

	// Relay the response from gitops back to the client
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("failed to read gitops response: %v", err), http.StatusBadGateway)
		return
	}

	// Copy content-type from gitops response
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}

	if resp.StatusCode >= 400 {
		// Extract detail message from FastAPI error response
		var detail struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(respBody, &detail) == nil && detail.Detail != "" {
			writeJSONError(w, detail.Detail, resp.StatusCode)
		} else {
			writeJSONError(w, string(respBody), resp.StatusCode)
		}
		return
	}

	// Wrap successful response in ServiceResponse format for CLI compatibility
	var gitopsData interface{}
	if err := json.Unmarshal(respBody, &gitopsData); err != nil {
		// If not valid JSON, return raw
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ServiceResponse{
		Success: true,
		Message: "ok",
		Data:    gitopsData,
	})
}

// handleService routes service-related requests
func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/service")
	path = strings.TrimPrefix(path, "/")

	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		writeJSONError(w, "invalid path: expected /service/{service_type}/{action}", http.StatusBadRequest)
		return
	}

	serviceType := parts[0]
	action := parts[1]

	switch action {
	case "enable":
		s.handleServiceEnable(w, r, serviceType)
	case "disable":
		s.handleServiceDisable(w, r, serviceType)
	case "status":
		s.handleServiceStatus(w, r, serviceType)
	case "start":
		s.handleServiceStart(w, r, serviceType)
	case "stop":
		s.handleServiceStop(w, r, serviceType)
	case "update":
		s.handleServiceUpdate(w, r, serviceType)
	case "backup":
		if serviceType == "couchdb" {
			s.handleServiceBackup(w, r)
		} else {
			writeJSONError(w, "backup only available for couchdb", http.StatusBadRequest)
		}
	case "restore":
		if serviceType == "couchdb" {
			s.handleServiceRestore(w, r)
		} else {
			writeJSONError(w, "restore only available for couchdb", http.StatusBadRequest)
		}
	default:
		writeJSONError(w, "unknown action: "+action, http.StatusNotFound)
	}
}

// handleServiceEnable handles POST /service/{service_type}/enable
func (s *Server) handleServiceEnable(w http.ResponseWriter, r *http.Request, serviceType string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ServiceEnableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	switch serviceType {
	case "editor":
		// Editor stays managed locally by the automation server
		s.handleEditorEnableLocal(w, req)
	case "kafka", "couchdb":
		// Proxy to gitops
		gitopsBody := gitopsServiceRequest{
			Stage: req.Stage,
			Image:        req.CouchDBImage,
			KafkaImage:   req.KafkaImage,
			UIImage:      req.UIImage,
		}
		proxyToGitops(w, "POST", req.Workspace, fmt.Sprintf("/services/%s/enable", serviceType), gitopsBody)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
	}
}

// handleServiceDisable handles POST /service/{service_type}/disable
func (s *Server) handleServiceDisable(w http.ResponseWriter, r *http.Request, serviceType string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ServiceDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	switch serviceType {
	case "editor":
		err := s.disableEditorService(req.Workspace)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ServiceResponse{
			Success: true,
			Message: "editor service disabled successfully",
		})
	case "kafka", "couchdb":
		gitopsBody := gitopsServiceRequest{Stage: req.Stage}
		proxyToGitops(w, "POST", req.Workspace, fmt.Sprintf("/services/%s/disable", serviceType), gitopsBody)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
	}
}

// handleServiceStatus handles GET /service/{service_type}/status
func (s *Server) handleServiceStatus(w http.ResponseWriter, r *http.Request, serviceType string) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workspace := r.URL.Query().Get("workspace")
	showPasswords := r.URL.Query().Get("show_passwords") == "true"
	stage := r.URL.Query().Get("stage")

	if workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	switch serviceType {
	case "editor":
		statusData, err := s.getEditorStatus(workspace, showPasswords)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ServiceResponse{
			Success: true,
			Data:    statusData,
		})
	case "kafka", "couchdb":
		// Build query string for gitops
		gitopsPath := fmt.Sprintf("/services/%s/status?stage=%s&show_passwords=%v", serviceType, stage, showPasswords)
		proxyToGitops(w, "GET", workspace, gitopsPath, nil)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
	}
}

// handleServiceStart handles POST /service/{service_type}/start
func (s *Server) handleServiceStart(w http.ResponseWriter, r *http.Request, serviceType string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ServiceStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	switch serviceType {
	case "editor":
		err := s.startEditorService(req.Workspace)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ServiceResponse{
			Success: true,
			Message: "editor service started successfully",
		})
	case "kafka", "couchdb":
		gitopsBody := gitopsServiceRequest{Stage: req.Stage}
		proxyToGitops(w, "POST", req.Workspace, fmt.Sprintf("/services/%s/start", serviceType), gitopsBody)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
	}
}

// handleServiceStop handles POST /service/{service_type}/stop
func (s *Server) handleServiceStop(w http.ResponseWriter, r *http.Request, serviceType string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ServiceStopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	switch serviceType {
	case "editor":
		err := s.stopEditorService(req.Workspace)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ServiceResponse{
			Success: true,
			Message: "editor service stopped successfully",
		})
	case "kafka", "couchdb":
		gitopsBody := gitopsServiceRequest{Stage: req.Stage}
		proxyToGitops(w, "POST", req.Workspace, fmt.Sprintf("/services/%s/stop", serviceType), gitopsBody)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
	}
}

// handleServiceUpdate handles POST /service/{service_type}/update
func (s *Server) handleServiceUpdate(w http.ResponseWriter, r *http.Request, serviceType string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ServiceUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	switch serviceType {
	case "editor":
		err := s.updateEditorService(req)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ServiceResponse{
			Success: true,
			Message: "editor service updated successfully",
		})
	case "kafka", "couchdb":
		gitopsBody := gitopsServiceRequest{
			Stage: req.Stage,
			Image:        req.CouchDBImage,
			KafkaImage:   req.KafkaImage,
		}
		proxyToGitops(w, "POST", req.Workspace, fmt.Sprintf("/services/%s/update", serviceType), gitopsBody)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
	}
}

// handleServiceBackup handles POST /service/couchdb/backup
func (s *Server) handleServiceBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ServiceBackupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	gitopsBody := gitopsServiceRequest{
		Stage: req.Stage,
		BackupPath:   req.BackupPath,
	}
	proxyToGitops(w, "POST", req.Workspace, "/services/couchdb/backup", gitopsBody)
}

// handleServiceRestore handles POST /service/couchdb/restore
func (s *Server) handleServiceRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ServiceRestoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	gitopsBody := gitopsServiceRequest{
		Stage: req.Stage,
		BackupPath:   req.BackupPath,
		Force:        req.Force,
	}
	proxyToGitops(w, "POST", req.Workspace, "/services/couchdb/restore", gitopsBody)
}

// proxyCouchDBRestore sends a CouchDB restore request to gitops and returns any error.
// Used by the interactive job runner in jobs.go.
func (s *Server) proxyCouchDBRestore(workspace, stage, backupPath string) error {
	metadata, err := config.GetWorkspaceMetadata(workspace)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	reqURL := fmt.Sprintf("%s/services/couchdb/restore", metadata.GitopsURL)
	reqURL = automations.TransformURLForDaemon(reqURL, workspace)

	body := gitopsServiceRequest{
		Stage:      stage,
		BackupPath: backupPath,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+metadata.GitopsSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request to gitops: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gitops restore error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// =============================================================================
// Editor service — handled locally by the automation server (not proxied)
// =============================================================================

// handleEditorEnableLocal runs the editor enable flow locally with stdout streaming
func (s *Server) handleEditorEnableLocal(w http.ResponseWriter, req ServiceEnableRequest) {
	// Set up streaming response
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Create a pipe to capture stdout
	stdoutMutex.Lock()
	oldStdout := os.Stdout
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		stdoutMutex.Unlock()
		WriteLogEntry(w, "error", fmt.Sprintf("Failed to create pipe: %v", err))
		return
	}

	// Redirect stdout to the pipe
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
			n, readErr := rPipe.Read(buf)
			if n > 0 {
				logWriter.Write(buf[:n])
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				WriteLogEntry(w, "error", fmt.Sprintf("Error reading from pipe: %v", readErr))
				break
			}
		}
	}()

	operationErr := s.enableEditorService(req)

	wPipe.Close()
	wg.Wait()

	if operationErr != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", operationErr))
	}
}

func (s *Server) enableEditorService(req ServiceEnableRequest) error {
	editorService, err := services.NewEditorService(req.Workspace)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}

	if editorService.IsEnabled() {
		return fmt.Errorf("Editor service is already enabled for workspace '%s'", req.Workspace)
	}

	metadata, err := editorService.GetMetadata()
	if err != nil {
		return fmt.Errorf("failed to read workspace metadata: %w", err)
	}

	gitopsSecretToken := metadata.GitopsSecret
	domain := metadata.Domain

	bitswanEditorImage := req.EditorImage
	if bitswanEditorImage == "" {
		bitswanEditorImage = "bitswan/bitswan-editor:latest"
	}

	var oauthConfig *oauth.Config
	if req.OAuthConfig != nil {
		oauthJSON, err := json.Marshal(req.OAuthConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal OAuth config: %w", err)
		}
		if err := json.Unmarshal(oauthJSON, &oauthConfig); err != nil {
			return fmt.Errorf("failed to parse OAuth config: %w", err)
		}
	}

	if err := editorService.Enable(gitopsSecretToken, bitswanEditorImage, domain, oauthConfig, req.TrustCA); err != nil {
		return err
	}

	if err := editorService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start editor container: %w", err)
	}

	if err := editorService.WaitForEditorReady(); err != nil {
		return fmt.Errorf("editor failed to start properly: %w", err)
	}

	return nil
}

func (s *Server) disableEditorService(workspace string) error {
	editorService, err := services.NewEditorService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}

	if !editorService.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'", workspace)
	}

	return editorService.Disable()
}

func (s *Server) getEditorStatus(workspace string, showPasswords bool) (map[string]interface{}, error) {
	editorService, err := services.NewEditorService(workspace)
	if err != nil {
		return nil, fmt.Errorf("failed to create Editor service: %w", err)
	}

	status := map[string]interface{}{
		"enabled": editorService.IsEnabled(),
		"running": editorService.IsContainerRunning(),
	}

	if editorService.IsEnabled() {
		status["workspace_path"] = editorService.WorkspacePath
		if showPasswords {
			if password, err := editorService.GetEditorPassword(); err == nil {
				status["password"] = password
			}
		}
	}

	return status, nil
}

func (s *Server) startEditorService(workspace string) error {
	editorService, err := services.NewEditorService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}

	if !editorService.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'", workspace)
	}

	if editorService.IsContainerRunning() {
		return nil // Already running
	}

	if err := editorService.StartContainer(); err != nil {
		return err
	}

	return editorService.WaitForEditorReady()
}

func (s *Server) stopEditorService(workspace string) error {
	editorService, err := services.NewEditorService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}

	if !editorService.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'", workspace)
	}

	if !editorService.IsContainerRunning() {
		return nil // Already stopped
	}

	return editorService.StopContainer()
}

func (s *Server) updateEditorService(req ServiceUpdateRequest) error {
	editorService, err := services.NewEditorService(req.Workspace)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}

	if !editorService.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'", req.Workspace)
	}

	if err := editorService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop editor container: %w", err)
	}

	if req.TrustCA {
		if err := editorService.UpdateCertificates(req.TrustCA); err != nil {
			return fmt.Errorf("failed to update certificates: %w", err)
		}
	}

	if req.EditorImage != "" {
		if err := editorService.UpdateImage(req.EditorImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		if err := editorService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
	}

	if err := editorService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start editor container: %w", err)
	}

	return editorService.WaitForEditorReady()
}
