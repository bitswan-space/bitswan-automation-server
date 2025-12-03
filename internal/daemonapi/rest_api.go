package daemonapi

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/commands"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"
)

// setupRESTRoutes sets up the RESTful API routes
func (s *Server) setupRESTRoutes() {
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Swagger documentation
	s.router.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/swagger/doc.json"),
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	))

	// Workspace endpoints
	workspaceAPI := api.PathPrefix("/workspaces").Subrouter()
	workspaceAPI.HandleFunc("", s.handleListWorkspaces).Methods("GET")
	workspaceAPI.HandleFunc("", s.handleInitWorkspace).Methods("POST")
	workspaceAPI.HandleFunc("/{name}", s.handleRemoveWorkspace).Methods("DELETE")
	workspaceAPI.HandleFunc("/{name}", s.handleUpdateWorkspace).Methods("PUT")
	workspaceAPI.HandleFunc("/{name}/select", s.handleSelectWorkspace).Methods("POST")
	workspaceAPI.HandleFunc("/{name}/open", s.handleOpenWorkspace).Methods("POST")
	workspaceAPI.HandleFunc("/{name}/pull-and-deploy", s.handlePullAndDeploy).Methods("POST")

	// Service endpoints
	serviceAPI := api.PathPrefix("/workspaces/{workspace}/services").Subrouter()
	serviceAPI.HandleFunc("/{service}/enable", s.handleEnableService).Methods("POST")
	serviceAPI.HandleFunc("/{service}/disable", s.handleDisableService).Methods("POST")
	serviceAPI.HandleFunc("/{service}/status", s.handleServiceStatus).Methods("GET")

	// Automation endpoints
	automationAPI := api.PathPrefix("/workspaces/{workspace}/automations").Subrouter()
	automationAPI.HandleFunc("", s.handleListAutomations).Methods("GET")
	automationAPI.HandleFunc("/{automation}/logs", s.handleAutomationLogs).Methods("GET")
	automationAPI.HandleFunc("/{automation}/start", s.handleStartAutomation).Methods("POST")
	automationAPI.HandleFunc("/{automation}/stop", s.handleStopAutomation).Methods("POST")
	automationAPI.HandleFunc("/{automation}/restart", s.handleRestartAutomation).Methods("POST")
	automationAPI.HandleFunc("/{automation}", s.handleRemoveAutomation).Methods("DELETE")

	// Register endpoint
	api.HandleFunc("/register", s.handleRegister).Methods("POST")

	// Ingress endpoints
	ingressAPI := api.PathPrefix("/ingress").Subrouter()
	ingressAPI.HandleFunc("/init", s.handleInitIngress).Methods("POST")
	ingressAPI.HandleFunc("/routes", s.handleListIngressRoutes).Methods("GET")
	ingressAPI.HandleFunc("/routes", s.handleAddIngressRoute).Methods("POST")
	ingressAPI.HandleFunc("/routes/{path:.*}", s.handleRemoveIngressRoute).Methods("DELETE")

	// Certificate authority endpoints
	caAPI := api.PathPrefix("/certauthorities").Subrouter()
	caAPI.HandleFunc("", s.handleListCertAuthorities).Methods("GET")
	caAPI.HandleFunc("", s.handleAddCertAuthority).Methods("POST")
	caAPI.HandleFunc("/{name}", s.handleRemoveCertAuthority).Methods("DELETE")

	// Token management endpoints (keep existing)
	api.HandleFunc("/tokens", s.handleListTokens).Methods("GET")
	api.HandleFunc("/tokens/global", s.handleCreateGlobalToken).Methods("POST")
	api.HandleFunc("/tokens/workspace", s.handleCreateWorkspaceToken).Methods("POST")
	api.HandleFunc("/tokens/{token}", s.handleDeleteToken).Methods("DELETE")
}

// @Summary List all workspaces
// @Description Get a list of all available workspaces
// @Tags workspaces
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces [get]
func (s *Server) handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	output, exitCode, err := s.executeCommand("workspace", []string{"list"}, "")
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Initialize a new workspace
// @Description Initialize a new Bitswan workspace
// @Tags workspaces
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body WorkspaceInitRequest true "Workspace initialization parameters"
// @Success 200 {object} StandardResponse
// @Failure 400 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces [post]
func (s *Server) handleInitWorkspace(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req WorkspaceInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// Validate workspace access for workspace tokens
	if tokenType == TokenTypeWorkspace && req.Name != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	// Generate workspace token before executing init
	var workspaceToken string
	workspaceToken, err = s.tokenManager.CreateWorkspaceToken(req.Name, fmt.Sprintf("GitOps token for workspace %s", req.Name))
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create workspace token: %v", err))
		return
	}

	// Execute the command logic directly
	opts := commands.WorkspaceInitOptions{
		WorkspaceName:      req.Name,
		RemoteRepo:         req.Remote,
		WorkspaceBranch:    req.Branch,
		Domain:             req.Domain,
		CertsDir:           req.CertsDir,
		Verbose:            req.Verbose,
		MkCerts:            req.MkCerts,
		NoIde:              req.NoIde,
		SetHosts:           req.SetHosts,
		Local:              req.Local,
		GitopsImage:        req.GitopsImage,
		EditorImage:        req.EditorImage,
		GitopsDevSourceDir: req.GitopsDevSourceDir,
		OauthConfigFile:    req.OauthConfig,
		NoOauth:            req.NoOauth,
		SSHPort:            req.SSHPort,
		WorkspaceToken:     workspaceToken,
	}

	err = commands.ExecuteWorkspaceInit(opts)

	output := ""
	exitCode := 0
	if err != nil {
		output = err.Error()
		exitCode = 1
	}

	s.sendResponse(w, output, exitCode, err)
}

// @Summary Remove a workspace
// @Description Remove an existing workspace
// @Tags workspaces
// @Accept json
// @Produce json
// @Security Bearer
// @Param name path string true "Workspace name"
// @Param request body WorkspaceRemoveRequest false "Remove options"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{name} [delete]
func (s *Server) handleRemoveWorkspace(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["name"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	var req WorkspaceRemoveRequest
	req.Name = workspaceName
	// Try to decode body, but it's optional
	json.NewDecoder(r.Body).Decode(&req)

	args := []string{"workspace", "remove"}
	if req.Yes {
		args = append(args, "--yes")
	}
	args = append(args, workspaceName)

	output, exitCode, err := s.executeCommand("workspace", args[1:], workspaceName)
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Update a workspace
// @Description Update workspace configuration
// @Tags workspaces
// @Accept json
// @Produce json
// @Security Bearer
// @Param name path string true "Workspace name"
// @Param request body WorkspaceUpdateRequest true "Update parameters"
// @Success 200 {object} StandardResponse
// @Failure 400 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{name} [put]
func (s *Server) handleUpdateWorkspace(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["name"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	var req WorkspaceUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	args := []string{"workspace", "update", workspaceName}
	if req.GitopsImage != "" {
		args = append(args, "--gitops-image", req.GitopsImage)
	}
	if req.Staging {
		args = append(args, "--staging")
	}
	if req.TrustCA {
		args = append(args, "--trust-ca")
	}

	output, exitCode, err := s.executeCommand("workspace", args[1:], workspaceName)
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Select a workspace
// @Description Set a workspace as the active workspace
// @Tags workspaces
// @Accept json
// @Produce json
// @Security Bearer
// @Param name path string true "Workspace name"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{name}/select [post]
func (s *Server) handleSelectWorkspace(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["name"]

	output, exitCode, err := s.executeCommand("workspace", []string{"select", workspaceName}, workspaceName)
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Open a workspace
// @Description Open a workspace in the browser
// @Tags workspaces
// @Accept json
// @Produce json
// @Security Bearer
// @Param name path string true "Workspace name"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{name}/open [post]
func (s *Server) handleOpenWorkspace(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["name"]

	output, exitCode, err := s.executeCommand("workspace", []string{"open", workspaceName}, workspaceName)
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Pull and deploy
// @Description Pull a branch and deploy automations
// @Tags workspaces
// @Accept json
// @Produce json
// @Security Bearer
// @Param name path string true "Workspace name"
// @Param request body WorkspacePullAndDeployRequest true "Pull and deploy parameters"
// @Success 200 {object} StandardResponse
// @Failure 400 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{name}/pull-and-deploy [post]
func (s *Server) handlePullAndDeploy(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["name"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	var req WorkspacePullAndDeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Branch == "" {
		s.sendErrorResponse(w, http.StatusBadRequest, "branch is required")
		return
	}

	args := []string{"workspace", "pull-and-deploy", workspaceName, "--branch", req.Branch}
	if req.Force {
		args = append(args, "--force")
	}
	if req.NoBuild {
		args = append(args, "--no-build")
	}

	output, exitCode, err := s.executeCommand("workspace", args[1:], workspaceName)
	s.sendResponse(w, output, exitCode, err)
}

// Service handlers
// @Summary Enable a service
// @Description Enable a service for a workspace
// @Tags services
// @Accept json
// @Produce json
// @Security Bearer
// @Param workspace path string true "Workspace name"
// @Param service path string true "Service type" Enums(couchdb, kafka, editor)
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{workspace}/services/{service}/enable [post]
func (s *Server) handleEnableService(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["workspace"]
	serviceType := vars["service"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	output, exitCode, err := s.executeCommand("workspace", []string{"service", serviceType, "enable"}, workspaceName)
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Disable a service
// @Description Disable a service for a workspace
// @Tags services
// @Accept json
// @Produce json
// @Security Bearer
// @Param workspace path string true "Workspace name"
// @Param service path string true "Service type" Enums(couchdb, kafka, editor)
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{workspace}/services/{service}/disable [post]
func (s *Server) handleDisableService(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["workspace"]
	serviceType := vars["service"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	output, exitCode, err := s.executeCommand("workspace", []string{"service", serviceType, "disable"}, workspaceName)
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Get service status
// @Description Get the status of a service
// @Tags services
// @Accept json
// @Produce json
// @Security Bearer
// @Param workspace path string true "Workspace name"
// @Param service path string true "Service type" Enums(couchdb, kafka, editor)
// @Param show_passwords query bool false "Show passwords" default(false)
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{workspace}/services/{service}/status [get]
func (s *Server) handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["workspace"]
	serviceType := vars["service"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	args := []string{"workspace", "service", serviceType, "status"}
	if r.URL.Query().Get("show_passwords") == "true" {
		args = append(args, "--passwords")
	}

	output, exitCode, err := s.executeCommand("workspace", args[1:], workspaceName)
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Register with AOC
// @Description Register the automation server with AOC
// @Tags registration
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body RegisterRequest true "Registration parameters"
// @Success 200 {object} StandardResponse
// @Failure 400 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /register [post]
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	output, exitCode, err := s.executeCommand("register", []string{req.AOCUrl}, "")
	s.sendResponse(w, output, exitCode, err)
}

// Ingress handlers
// @Summary List ingress routes
// @Description Get a list of all ingress routes
// @Tags ingress
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /ingress/routes [get]
func (s *Server) handleListIngressRoutes(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	output, exitCode, err := s.executeCommand("ingress", []string{"list-routes"}, "")
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Add an ingress route
// @Description Add a new ingress route
// @Tags ingress
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body IngressAddRouteRequest true "Route parameters"
// @Success 200 {object} StandardResponse
// @Failure 400 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /ingress/routes [post]
func (s *Server) handleAddIngressRoute(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req IngressAddRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	args := []string{"ingress", "add-route", req.Path, req.Target}
	if req.WorkspaceName != "" {
		args = append(args, "--workspace", req.WorkspaceName)
	}

	output, exitCode, err := s.executeCommand("ingress", args[1:], req.WorkspaceName)
	s.sendResponse(w, output, exitCode, err)
}

// @Summary Remove an ingress route
// @Description Remove an ingress route
// @Tags ingress
// @Accept json
// @Produce json
// @Security Bearer
// @Param path path string true "Route path"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /ingress/routes/{path} [delete]
func (s *Server) handleRemoveIngressRoute(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	path := vars["path"]

	output, exitCode, err := s.executeCommand("ingress", []string{"remove-route", path}, "")
	s.sendResponse(w, output, exitCode, err)
}

// Automation handlers
// @Summary List automations
// @Description Get a list of all automations in a workspace
// @Tags automations
// @Accept json
// @Produce json
// @Security Bearer
// @Param workspace path string true "Workspace name"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{workspace}/automations [get]
func (s *Server) handleListAutomations(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["workspace"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	automationsList, err := automations.GetAutomations(workspaceName)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to list automations: %v", err))
		return
	}

	// Convert to JSON
	output, err := json.MarshalIndent(automationsList, "", "  ")
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal automations: %v", err))
		return
	}

	s.sendResponse(w, string(output), 0, nil)
}

// @Summary Get automation logs
// @Description Get logs for a specific automation
// @Tags automations
// @Accept json
// @Produce json
// @Security Bearer
// @Param workspace path string true "Workspace name"
// @Param automation path string true "Automation deployment ID"
// @Param lines query int false "Number of log lines to retrieve" default(0)
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{workspace}/automations/{automation}/logs [get]
func (s *Server) handleAutomationLogs(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["workspace"]
	automationID := vars["automation"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	lines := 0
	if linesStr := r.URL.Query().Get("lines"); linesStr != "" {
		lines, _ = strconv.Atoi(linesStr)
	}

	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get workspace metadata: %v", err))
		return
	}

	url := fmt.Sprintf("%s/automations/%s/logs", metadata.GitopsURL, automationID)
	if lines > 0 {
		url += fmt.Sprintf("?lines=%d", lines)
	}

	resp, err := automations.SendAutomationRequest("GET", url, metadata.GitopsSecret)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("error creating request: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get logs from automation: %s, response: %s", resp.Status, string(body)))
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("error reading response: %v", err))
		return
	}

	s.sendResponse(w, string(body), 0, nil)
}

// @Summary Start an automation
// @Description Start a specific automation
// @Tags automations
// @Accept json
// @Produce json
// @Security Bearer
// @Param workspace path string true "Workspace name"
// @Param automation path string true "Automation deployment ID"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{workspace}/automations/{automation}/start [post]
func (s *Server) handleStartAutomation(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["workspace"]
	automationID := vars["automation"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get workspace metadata: %v", err))
		return
	}

	url := fmt.Sprintf("%s/automations/%s/start", metadata.GitopsURL, automationID)
	resp, err := automations.SendAutomationRequest("POST", url, metadata.GitopsSecret)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to send request: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to start automation, status code: %d, response: %s", resp.StatusCode, string(body)))
		return
	}

	s.sendResponse(w, fmt.Sprintf("Automation %s started successfully", automationID), 0, nil)
}

// @Summary Stop an automation
// @Description Stop a specific automation
// @Tags automations
// @Accept json
// @Produce json
// @Security Bearer
// @Param workspace path string true "Workspace name"
// @Param automation path string true "Automation deployment ID"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{workspace}/automations/{automation}/stop [post]
func (s *Server) handleStopAutomation(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["workspace"]
	automationID := vars["automation"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get workspace metadata: %v", err))
		return
	}

	url := fmt.Sprintf("%s/automations/%s/stop", metadata.GitopsURL, automationID)
	resp, err := automations.SendAutomationRequest("POST", url, metadata.GitopsSecret)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to send request: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to stop automation, status code: %d, response: %s", resp.StatusCode, string(body)))
		return
	}

	s.sendResponse(w, fmt.Sprintf("Automation %s stopped successfully", automationID), 0, nil)
}

// @Summary Restart an automation
// @Description Restart a specific automation
// @Tags automations
// @Accept json
// @Produce json
// @Security Bearer
// @Param workspace path string true "Workspace name"
// @Param automation path string true "Automation deployment ID"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{workspace}/automations/{automation}/restart [post]
func (s *Server) handleRestartAutomation(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["workspace"]
	automationID := vars["automation"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get workspace metadata: %v", err))
		return
	}

	url := fmt.Sprintf("%s/automations/%s/restart", metadata.GitopsURL, automationID)
	resp, err := automations.SendAutomationRequest("POST", url, metadata.GitopsSecret)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to send request: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to restart automation, status code: %d, response: %s", resp.StatusCode, string(body)))
		return
	}

	s.sendResponse(w, fmt.Sprintf("Automation %s restarted successfully", automationID), 0, nil)
}

// @Summary Remove an automation
// @Description Remove a specific automation
// @Tags automations
// @Accept json
// @Produce json
// @Security Bearer
// @Param workspace path string true "Workspace name"
// @Param automation path string true "Automation deployment ID"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 403 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /workspaces/{workspace}/automations/{automation} [delete]
func (s *Server) handleRemoveAutomation(w http.ResponseWriter, r *http.Request) {
	tokenType, tokenWorkspace, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	workspaceName := vars["workspace"]
	automationID := vars["automation"]

	// Validate workspace access
	if tokenType == TokenTypeWorkspace && workspaceName != tokenWorkspace {
		http.Error(w, "workspace token can only access its own workspace", http.StatusForbidden)
		return
	}

	automation := automations.Automation{
		DeploymentID: automationID,
		Workspace:    workspaceName,
	}

	err = automation.Remove()
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to remove automation: %v", err))
		return
	}

	s.sendResponse(w, fmt.Sprintf("Automation %s removed successfully", automationID), 0, nil)
}

// Ingress init handler
// @Summary Initialize ingress
// @Description Initialize the ingress proxy
// @Tags ingress
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body IngressInitRequest false "Init options"
// @Success 200 {object} StandardResponse
// @Failure 400 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /ingress/init [post]
func (s *Server) handleInitIngress(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req IngressInitRequest
	// Try to decode body, but it's optional
	json.NewDecoder(r.Body).Decode(&req)

	err := commands.InitIngress(req.Verbose)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to initialize ingress: %v", err))
		return
	}

	s.sendResponse(w, "Ingress proxy initialized successfully", 0, nil)
}

// Certificate authority handlers
// @Summary List certificate authorities
// @Description Get a list of all certificate authorities
// @Tags certauthorities
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /certauthorities [get]
func (s *Server) handleListCertAuthorities(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	certDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "certauthorities")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create certauthorities directory: %v", err))
		return
	}

	files, err := os.ReadDir(certDir)
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to read certauthorities directory: %v", err))
		return
	}

	var certList []map[string]interface{}
	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".crt") || strings.HasSuffix(file.Name(), ".pem")) {
			info, _ := file.Info()
			certList = append(certList, map[string]interface{}{
				"name":    file.Name(),
				"size_kb": float64(info.Size()) / 1024,
			})
		}
	}

	output, err := json.MarshalIndent(certList, "", "  ")
	if err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal certificate list: %v", err))
		return
	}

	s.sendResponse(w, string(output), 0, nil)
}

// @Summary Add a certificate authority
// @Description Add a new certificate authority
// @Tags certauthorities
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body CertAuthorityAddRequest true "Certificate authority data"
// @Success 200 {object} StandardResponse
// @Failure 400 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /certauthorities [post]
func (s *Server) handleAddCertAuthority(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req CertAuthorityAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Certificate == "" {
		s.sendErrorResponse(w, http.StatusBadRequest, "certificate is required")
		return
	}

	certDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "certauthorities")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create certauthorities directory: %v", err))
		return
	}

	// Determine the target filename
	var targetName string
	if req.Name != "" {
		targetName = req.Name
		if !strings.HasSuffix(targetName, ".crt") && !strings.HasSuffix(targetName, ".pem") {
			targetName += ".crt"
		}
	} else {
		targetName = "certificate.crt"
	}

	targetPath := filepath.Join(certDir, targetName)

	// Check if file already exists
	if _, err := os.Stat(targetPath); err == nil {
		s.sendErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("certificate authority '%s' already exists", targetName))
		return
	}

	// Write the certificate file
	if err := os.WriteFile(targetPath, []byte(req.Certificate), 0644); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to write certificate: %v", err))
		return
	}

	s.sendResponse(w, fmt.Sprintf("Certificate authority '%s' added successfully", targetName), 0, nil)
}

// @Summary Remove a certificate authority
// @Description Remove a certificate authority
// @Tags certauthorities
// @Accept json
// @Produce json
// @Security Bearer
// @Param name path string true "Certificate authority name"
// @Success 200 {object} StandardResponse
// @Failure 401 {object} StandardResponse
// @Failure 404 {object} StandardResponse
// @Failure 500 {object} StandardResponse
// @Router /certauthorities/{name} [delete]
func (s *Server) handleRemoveCertAuthority(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.authenticateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	certName := vars["name"]

	certDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "certauthorities")
	certPath := filepath.Join(certDir, certName)

	// Check if file exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		s.sendErrorResponse(w, http.StatusNotFound, fmt.Sprintf("certificate authority '%s' not found", certName))
		return
	}

	// Remove the file
	if err := os.Remove(certPath); err != nil {
		s.sendErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to remove certificate: %v", err))
		return
	}

	s.sendResponse(w, fmt.Sprintf("Certificate authority '%s' removed successfully", certName), 0, nil)
}

// Helper functions
func (s *Server) sendResponse(w http.ResponseWriter, output string, exitCode int, err error) {
	w.Header().Set("Content-Type", "application/json")

	response := StandardResponse{
		Success:  err == nil && exitCode == 0,
		Output:   output,
		ExitCode: exitCode,
	}

	if err != nil {
		response.Error = err.Error()
	}

	if !response.Success {
		w.WriteHeader(http.StatusOK) // Still 200, but success=false
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) sendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(StandardResponse{
		Success: false,
		Error:   message,
	})
}
