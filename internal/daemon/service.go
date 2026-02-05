package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
)

// stdoutMutex protects stdout redirection from concurrent requests
var stdoutMutex sync.Mutex

// ServiceEnableRequest represents the request to enable a service
type ServiceEnableRequest struct {
	ServiceType    string                 `json:"service_type"` // "editor", "kafka", "couchdb"
	Workspace      string                 `json:"workspace"`
	EditorImage    string                 `json:"editor_image,omitempty"`
	OAuthConfig    map[string]interface{} `json:"oauth_config,omitempty"` // OAuth config as JSON object
	TrustCA        bool                   `json:"trust_ca,omitempty"`
	KafkaImage     string                 `json:"kafka_image,omitempty"`
	ZookeeperImage string                 `json:"zookeeper_image,omitempty"`
	CouchDBImage   string                 `json:"couchdb_image,omitempty"`
}

// ServiceDisableRequest represents the request to disable a service
type ServiceDisableRequest struct {
	ServiceType string `json:"service_type"`
	Workspace   string `json:"workspace"`
}

// ServiceStatusRequest represents the request to get service status
type ServiceStatusRequest struct {
	ServiceType   string `json:"service_type"`
	Workspace     string `json:"workspace"`
	ShowPasswords bool   `json:"show_passwords"`
}

// ServiceStartRequest represents the request to start a service
type ServiceStartRequest struct {
	ServiceType string `json:"service_type"`
	Workspace   string `json:"workspace"`
}

// ServiceStopRequest represents the request to stop a service
type ServiceStopRequest struct {
	ServiceType string `json:"service_type"`
	Workspace   string `json:"workspace"`
}

// ServiceUpdateRequest represents the request to update a service
type ServiceUpdateRequest struct {
	ServiceType    string `json:"service_type"`
	Workspace      string `json:"workspace"`
	EditorImage    string `json:"editor_image,omitempty"`
	TrustCA        bool   `json:"trust_ca,omitempty"`
	KafkaImage     string `json:"kafka_image,omitempty"`
	ZookeeperImage string `json:"zookeeper_image,omitempty"`
	CouchDBImage   string `json:"couchdb_image,omitempty"`
}

// ServiceBackupRequest represents the request to backup CouchDB
type ServiceBackupRequest struct {
	Workspace  string `json:"workspace"`
	BackupPath string `json:"backup_path"`
}

// ServiceRestoreRequest represents the request to restore CouchDB
type ServiceRestoreRequest struct {
	Workspace  string `json:"workspace"`
	BackupPath string `json:"backup_path"`
	Force      bool   `json:"force"`
}

// ServiceResponse represents a generic service response
type ServiceResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    interface{} `json:"data,omitempty"`
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
		// Always restore stdout, even on error
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rPipe.Close()
		wPipe.Close()
	}()

	// Create a log stream writer that formats output as NDJSON
	logWriter := NewLogStreamWriter(w, "info")

	// Use a WaitGroup to wait for goroutines
	var wg sync.WaitGroup

	// Start goroutine to read from pipe and stream logs
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := rPipe.Read(buf)
			if n > 0 {
				// Write to log stream writer (which formats as NDJSON)
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

	// Run the service enable operation
	var operationErr error
	switch serviceType {
	case "editor":
		operationErr = s.enableEditorService(req)
	case "kafka":
		operationErr = s.enableKafkaService(req)
	case "couchdb":
		operationErr = s.enableCouchDBService(req)
	default:
		operationErr = fmt.Errorf("unknown service type: %s", serviceType)
	}

	// Close the write end of the pipe to signal EOF
	wPipe.Close()

	// Wait for log streaming to finish
	wg.Wait()

	// Send final result only if there was an error (success message already printed by service)
	if operationErr != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", operationErr))
	}
	// Don't send duplicate success message - the service already printed it
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

	var err error
	switch serviceType {
	case "editor":
		err = s.disableEditorService(req.Workspace)
	case "kafka":
		err = s.disableKafkaService(req.Workspace)
	case "couchdb":
		err = s.disableCouchDBService(req.Workspace)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
		return
	}

	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ServiceResponse{
		Success: true,
		Message: fmt.Sprintf("%s service disabled successfully", serviceType),
	})
}

// handleServiceStatus handles GET /service/{service_type}/status
func (s *Server) handleServiceStatus(w http.ResponseWriter, r *http.Request, serviceType string) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workspace := r.URL.Query().Get("workspace")
	showPasswords := r.URL.Query().Get("show_passwords") == "true"

	if workspace == "" {
		writeJSONError(w, "workspace is required", http.StatusBadRequest)
		return
	}

	var statusData interface{}
	var err error
	switch serviceType {
	case "editor":
		statusData, err = s.getEditorStatus(workspace, showPasswords)
	case "kafka":
		statusData, err = s.getKafkaStatus(workspace, showPasswords)
	case "couchdb":
		statusData, err = s.getCouchDBStatus(workspace, showPasswords)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
		return
	}

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

	var err error
	switch serviceType {
	case "editor":
		err = s.startEditorService(req.Workspace)
	case "kafka":
		err = s.startKafkaService(req.Workspace)
	case "couchdb":
		err = s.startCouchDBService(req.Workspace)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
		return
	}

	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ServiceResponse{
		Success: true,
		Message: fmt.Sprintf("%s service started successfully", serviceType),
	})
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

	var err error
	switch serviceType {
	case "editor":
		err = s.stopEditorService(req.Workspace)
	case "kafka":
		err = s.stopKafkaService(req.Workspace)
	case "couchdb":
		err = s.stopCouchDBService(req.Workspace)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
		return
	}

	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ServiceResponse{
		Success: true,
		Message: fmt.Sprintf("%s service stopped successfully", serviceType),
	})
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

	var err error
	switch serviceType {
	case "editor":
		err = s.updateEditorService(req)
	case "kafka":
		err = s.updateKafkaService(req)
	case "couchdb":
		err = s.updateCouchDBService(req)
	default:
		writeJSONError(w, "unknown service type: "+serviceType, http.StatusBadRequest)
		return
	}

	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ServiceResponse{
		Success: true,
		Message: fmt.Sprintf("%s service updated successfully", serviceType),
	})
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
		// Always restore stdout, even on error
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rPipe.Close()
		wPipe.Close()
	}()

	// Create a log stream writer that formats output as NDJSON
	logWriter := NewLogStreamWriter(w, "info")

	// Use a WaitGroup to wait for goroutines
	var wg sync.WaitGroup

	// Start goroutine to read from pipe and stream logs
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := rPipe.Read(buf)
			if n > 0 {
				// Write to log stream writer (which formats as NDJSON)
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

	// Run the backup operation
	operationErr := s.backupCouchDB(req.Workspace, req.BackupPath)

	// Close the write end of the pipe to signal EOF
	wPipe.Close()

	// Wait for log streaming to finish
	wg.Wait()

	// Send final result only if there was an error (success message already printed by service)
	if operationErr != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", operationErr))
	}
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
		// Always restore stdout, even on error
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rPipe.Close()
		wPipe.Close()
	}()

	// Create a log stream writer that formats output as NDJSON
	logWriter := NewLogStreamWriter(w, "info")

	// Use a WaitGroup to wait for goroutines
	var wg sync.WaitGroup

	// Start goroutine to read from pipe and stream logs
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := rPipe.Read(buf)
			if n > 0 {
				// Write to log stream writer (which formats as NDJSON)
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

	// Run the restore operation
	operationErr := s.restoreCouchDB(req.Workspace, req.BackupPath, req.Force)

	// Close the write end of the pipe to signal EOF
	wPipe.Close()

	// Wait for log streaming to finish
	wg.Wait()

	// Send final result only if there was an error (success message already printed by service)
	if operationErr != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", operationErr))
	}
}

// Implementation functions that delegate to the services package

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
		// Convert map to JSON and then to oauth.Config
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
			// Get password if available
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

func (s *Server) enableKafkaService(req ServiceEnableRequest) error {
	kafkaService, err := services.NewKafkaService(req.Workspace)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}

	if kafkaService.IsEnabled() {
		return fmt.Errorf("Kafka service is already enabled for workspace '%s'", req.Workspace)
	}

	return kafkaService.Enable()
}

func (s *Server) disableKafkaService(workspace string) error {
	kafkaService, err := services.NewKafkaService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}

	if !kafkaService.IsEnabled() {
		return fmt.Errorf("Kafka service is not enabled for workspace '%s'", workspace)
	}

	return kafkaService.Disable()
}

func (s *Server) getKafkaStatus(workspace string, showPasswords bool) (map[string]interface{}, error) {
	kafkaService, err := services.NewKafkaService(workspace)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka service: %w", err)
	}

	status := map[string]interface{}{
		"enabled": kafkaService.IsEnabled(),
		"running": kafkaService.IsContainerRunning(),
	}

	if kafkaService.IsEnabled() {
		status["workspace_path"] = kafkaService.WorkspacePath
	}

	return status, nil
}

func (s *Server) startKafkaService(workspace string) error {
	kafkaService, err := services.NewKafkaService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}

	if !kafkaService.IsEnabled() {
		return fmt.Errorf("Kafka service is not enabled for workspace '%s'", workspace)
	}

	if kafkaService.IsContainerRunning() {
		return nil // Already running
	}

	return kafkaService.StartContainer()
}

func (s *Server) stopKafkaService(workspace string) error {
	kafkaService, err := services.NewKafkaService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}

	if !kafkaService.IsEnabled() {
		return fmt.Errorf("Kafka service is not enabled for workspace '%s'", workspace)
	}

	if !kafkaService.IsContainerRunning() {
		return nil // Already stopped
	}

	return kafkaService.StopContainer()
}

func (s *Server) updateKafkaService(req ServiceUpdateRequest) error {
	kafkaService, err := services.NewKafkaService(req.Workspace)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}

	if !kafkaService.IsEnabled() {
		return fmt.Errorf("Kafka service is not enabled for workspace '%s'", req.Workspace)
	}

	if err := kafkaService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop Kafka containers: %w", err)
	}

	if req.KafkaImage != "" || req.ZookeeperImage != "" {
		if err := kafkaService.UpdateImages(req.KafkaImage, req.ZookeeperImage); err != nil {
			return fmt.Errorf("failed to update images: %w", err)
		}
	} else {
		if err := kafkaService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
	}

	return kafkaService.StartContainer()
}

func (s *Server) enableCouchDBService(req ServiceEnableRequest) error {
	couchdbService, err := services.NewCouchDBService(req.Workspace)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	if couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is already enabled for workspace '%s'", req.Workspace)
	}

	return couchdbService.Enable()
}

func (s *Server) disableCouchDBService(workspace string) error {
	couchdbService, err := services.NewCouchDBService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'", workspace)
	}

	return couchdbService.Disable()
}

func (s *Server) getCouchDBStatus(workspace string, showPasswords bool) (map[string]interface{}, error) {
	couchdbService, err := services.NewCouchDBService(workspace)
	if err != nil {
		return nil, fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	status := map[string]interface{}{
		"enabled": couchdbService.IsEnabled(),
		"running": couchdbService.IsContainerRunning(),
	}

	if couchdbService.IsEnabled() {
		status["workspace_path"] = couchdbService.WorkspacePath
	}

	return status, nil
}

func (s *Server) startCouchDBService(workspace string) error {
	couchdbService, err := services.NewCouchDBService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'", workspace)
	}

	if couchdbService.IsContainerRunning() {
		return nil // Already running
	}

	return couchdbService.StartContainer()
}

func (s *Server) stopCouchDBService(workspace string) error {
	couchdbService, err := services.NewCouchDBService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'", workspace)
	}

	if !couchdbService.IsContainerRunning() {
		return nil // Already stopped
	}

	return couchdbService.StopContainer()
}

func (s *Server) updateCouchDBService(req ServiceUpdateRequest) error {
	couchdbService, err := services.NewCouchDBService(req.Workspace)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'", req.Workspace)
	}

	if err := couchdbService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop CouchDB container: %w", err)
	}

	if req.CouchDBImage != "" {
		if err := couchdbService.UpdateImage(req.CouchDBImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		if err := couchdbService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
	}

	return couchdbService.StartContainer()
}

func (s *Server) backupCouchDB(workspace, backupPath string) error {
	couchdbService, err := services.NewCouchDBService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'", workspace)
	}

	return couchdbService.Backup(backupPath)
}

func (s *Server) restoreCouchDB(workspace, backupPath string, force bool) error {
	couchdbService, err := services.NewCouchDBService(workspace)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'", workspace)
	}

	return couchdbService.Restore(backupPath, force)
}
