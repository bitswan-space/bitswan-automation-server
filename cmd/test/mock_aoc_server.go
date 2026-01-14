package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MockAOCServer is a simple HTTP server that mocks AOC API endpoints
type MockAOCServer struct {
	server     *http.Server
	emqxSecret string
	serverID   string
	orgID      string
	emqxURL    string
	emqxPort   int
}

// NewMockAOCServer creates a new mock AOC server
func NewMockAOCServer(port int, emqxSecret, serverID, orgID, emqxURL string, emqxPort int) *MockAOCServer {
	m := &MockAOCServer{
		emqxSecret: emqxSecret,
		serverID:   serverID,
		orgID:      orgID,
		emqxURL:    emqxURL,
		emqxPort:   emqxPort,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/automation_server/info", m.handleServerInfo)
	mux.HandleFunc("/api/automation_server/emqx/jwt", m.handleEmqxJWT)
	mux.HandleFunc("/api/automation_server/workspaces/", m.handleWorkspaces)

	m.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	return m
}

// Start starts the mock server
func (m *MockAOCServer) Start() error {
	return m.server.ListenAndServe()
}

// Stop stops the mock server
func (m *MockAOCServer) Stop() error {
	return m.server.Close()
}

// handleServerInfo handles the automation server info endpoint
func (m *MockAOCServer) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"automation_server_id": m.serverID,
		"keycloak_org_id":      m.orgID,
		"name":                 "CI Test Server",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleEmqxJWT handles the EMQX JWT endpoint
func (m *MockAOCServer) handleEmqxJWT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create JWT token for EMQX
	// The token should have the username (server ID) and mountpoint in client_attrs
	// Format matches Django's create_mqtt_token function
	exp := time.Now().Add(1000 * 7 * 24 * time.Hour) // ~1000 weeks like Django
	claims := jwt.MapClaims{
		"exp":      exp.Unix(),
		"username": m.serverID,
		"client_attrs": map[string]interface{}{
			"mountpoint": fmt.Sprintf("/orgs/%s/automation-servers/%s", m.orgID, m.serverID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(m.emqxSecret))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate token: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the URL and token
	// Hardcode to use WSS through ingress with /mqtt path
	brokerURL := "wss://mqtt.bitswan.localhost:443/mqtt"
	response := map[string]interface{}{
		"url":   brokerURL,
		"token": tokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRegisterWorkspace handles the workspace registration endpoint
func (m *MockAOCServer) handleRegisterWorkspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var requestBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// Generate a fake workspace ID
	workspaceID := fmt.Sprintf("workspace-%d", time.Now().Unix())

	response := map[string]interface{}{
		"id":                   workspaceID,
		"name":                 requestBody["name"],
		"automation_server_id": m.serverID,
	}

	if editorURL, ok := requestBody["editor_url"].(string); ok {
		response["editor_url"] = editorURL
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// handleWorkspaces handles workspace-related endpoints
func (m *MockAOCServer) handleWorkspaces(w http.ResponseWriter, r *http.Request) {
	// Parse the path to extract workspace ID if present
	// Path format: /api/automation_server/workspaces/{workspace_id}/emqx/jwt
	path := r.URL.Path
	pathParts := strings.Split(strings.TrimPrefix(path, "/api/automation_server/workspaces/"), "/")

	if len(pathParts) == 1 && pathParts[0] == "" {
		// POST /api/automation_server/workspaces/ - register workspace
		m.handleRegisterWorkspace(w, r)
		return
	}

	if len(pathParts) >= 3 && pathParts[1] == "emqx" && pathParts[2] == "jwt" {
		// GET /api/automation_server/workspaces/{workspace_id}/emqx/jwt - get workspace MQTT JWT
		workspaceID := pathParts[0]
		m.handleWorkspaceEmqxJWT(w, r, workspaceID)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleWorkspaceEmqxJWT handles the workspace-specific EMQX JWT endpoint
func (m *MockAOCServer) handleWorkspaceEmqxJWT(w http.ResponseWriter, r *http.Request, workspaceID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create JWT token for EMQX (same format as automation server JWT)
	exp := time.Now().Add(1000 * 7 * 24 * time.Hour)
	claims := jwt.MapClaims{
		"exp":      exp.Unix(),
		"username": workspaceID, // Use workspace ID as username
		"client_attrs": map[string]interface{}{
			"mountpoint": fmt.Sprintf("/orgs/%s/automation-servers/%s/workspaces/%s", m.orgID, m.serverID, workspaceID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(m.emqxSecret))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate token: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the URL and token (same format as automation server JWT)
	brokerURL := "wss://mqtt.bitswan.localhost:443/mqtt"
	response := map[string]interface{}{
		"url":   brokerURL,
		"token": tokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
