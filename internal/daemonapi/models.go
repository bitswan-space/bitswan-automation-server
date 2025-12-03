package daemonapi

// WorkspaceInitRequest represents a request to initialize a workspace
// @Description Request to initialize a new workspace
type WorkspaceInitRequest struct {
	Name              string `json:"name" example:"my-workspace" binding:"required"`
	Remote            string `json:"remote,omitempty" example:"git@github.com:user/repo.git"`
	Branch            string `json:"branch,omitempty" example:"main"`
	Domain            string `json:"domain,omitempty" example:"example.com"`
	EditorImage       string `json:"editor_image,omitempty" example:"bitswan/bitswan-editor:latest"`
	GitopsImage       string `json:"gitops_image,omitempty" example:"bitswan/gitops:latest"`
	OauthConfig       string `json:"oauth_config,omitempty" example:"/path/to/oauth-config.yaml"`
	NoOauth           bool   `json:"no_oauth,omitempty" example:"false"`
	SSHPort           string `json:"ssh_port,omitempty" example:"443"`
	MkCerts           bool   `json:"mk_certs,omitempty" example:"false"`
	SetHosts          bool   `json:"set_hosts,omitempty" example:"false"`
	Local             bool   `json:"local,omitempty" example:"false"`
	NoIde             bool   `json:"no_ide,omitempty" example:"false"`
	CertsDir          string `json:"certs_dir,omitempty" example:"/etc/certs"`
	GitopsDevSourceDir string `json:"gitops_dev_source_dir,omitempty" example:"/path/to/source"`
	Verbose           bool   `json:"verbose,omitempty" example:"false"`
}

// WorkspaceRemoveRequest represents a request to remove a workspace
// @Description Request to remove an existing workspace
type WorkspaceRemoveRequest struct {
	Name string `json:"name" example:"my-workspace" binding:"required"`
	Yes  bool   `json:"yes,omitempty" example:"false"`
}

// WorkspaceUpdateRequest represents a request to update a workspace
// @Description Request to update workspace configuration
type WorkspaceUpdateRequest struct {
	Name            string `json:"name" example:"my-workspace" binding:"required"`
	GitopsImage     string `json:"gitops_image,omitempty" example:"bitswan/gitops:latest"`
	Staging         bool   `json:"staging,omitempty" example:"false"`
	TrustCA         bool   `json:"trust_ca,omitempty" example:"true"`
}

// WorkspaceSelectRequest represents a request to select a workspace
// @Description Request to select an active workspace
type WorkspaceSelectRequest struct {
	Name string `json:"name" example:"my-workspace" binding:"required"`
}

// WorkspacePullAndDeployRequest represents a request to pull and deploy
// @Description Request to pull a branch and deploy automations
type WorkspacePullAndDeployRequest struct {
	WorkspaceName string `json:"workspace_name" example:"my-workspace" binding:"required"`
	Branch        string `json:"branch" example:"main" binding:"required"`
	Force         bool   `json:"force,omitempty" example:"false"`
	NoBuild       bool   `json:"no_build,omitempty" example:"false"`
}

// AutomationListRequest represents a request to list automations
// @Description Request to list automations in a workspace
type AutomationListRequest struct {
	WorkspaceName string `json:"workspace_name,omitempty" example:"my-workspace"`
}

// AutomationRemoveRequest represents a request to remove an automation
// @Description Request to remove an automation
type AutomationRemoveRequest struct {
	WorkspaceName string `json:"workspace_name" example:"my-workspace" binding:"required"`
	AutomationName string `json:"automation_name" example:"my-automation" binding:"required"`
}

// AutomationStartRequest represents a request to start an automation
// @Description Request to start an automation
type AutomationStartRequest struct {
	WorkspaceName string `json:"workspace_name" example:"my-workspace" binding:"required"`
	AutomationName string `json:"automation_name" example:"my-automation" binding:"required"`
}

// AutomationStopRequest represents a request to stop an automation
// @Description Request to stop an automation
type AutomationStopRequest struct {
	WorkspaceName string `json:"workspace_name" example:"my-workspace" binding:"required"`
	AutomationName string `json:"automation_name" example:"my-automation" binding:"required"`
}

// AutomationRestartRequest represents a request to restart an automation
// @Description Request to restart an automation
type AutomationRestartRequest struct {
	WorkspaceName string `json:"workspace_name" example:"my-workspace" binding:"required"`
	AutomationName string `json:"automation_name" example:"my-automation" binding:"required"`
}

// AutomationLogsRequest represents a request to get automation logs
// @Description Request to get automation logs
type AutomationLogsRequest struct {
	WorkspaceName string `json:"workspace_name" example:"my-workspace" binding:"required"`
	AutomationName string `json:"automation_name" example:"my-automation" binding:"required"`
	Lines         int    `json:"lines,omitempty" example:"100"`
}

// ServiceEnableRequest represents a request to enable a service
// @Description Request to enable a workspace service
type ServiceEnableRequest struct {
	WorkspaceName string `json:"workspace_name" example:"my-workspace" binding:"required"`
	ServiceType   string `json:"service_type" example:"couchdb" binding:"required" enums:"couchdb,kafka,editor"`
}

// ServiceDisableRequest represents a request to disable a service
// @Description Request to disable a workspace service
type ServiceDisableRequest struct {
	WorkspaceName string `json:"workspace_name" example:"my-workspace" binding:"required"`
	ServiceType   string `json:"service_type" example:"couchdb" binding:"required" enums:"couchdb,kafka,editor"`
}

// ServiceStatusRequest represents a request to get service status
// @Description Request to get service status
type ServiceStatusRequest struct {
	WorkspaceName string `json:"workspace_name" example:"my-workspace" binding:"required"`
	ServiceType   string `json:"service_type" example:"couchdb" binding:"required" enums:"couchdb,kafka,editor"`
	ShowPasswords bool   `json:"show_passwords,omitempty" example:"false"`
}

// RegisterRequest represents a request to register with AOC
// @Description Request to register automation server with AOC
type RegisterRequest struct {
	AOCUrl string `json:"aoc_url" example:"https://aoc.example.com" binding:"required"`
}

// IngressAddRouteRequest represents a request to add an ingress route
// @Description Request to add an ingress route
type IngressAddRouteRequest struct {
	Path        string `json:"path" example:"/api" binding:"required"`
	Target      string `json:"target" example:"http://service:8080" binding:"required"`
	WorkspaceName string `json:"workspace_name,omitempty" example:"my-workspace"`
}

// IngressRemoveRouteRequest represents a request to remove an ingress route
// @Description Request to remove an ingress route
type IngressRemoveRouteRequest struct {
	Path        string `json:"path" example:"/api" binding:"required"`
	WorkspaceName string `json:"workspace_name,omitempty" example:"my-workspace"`
}

// IngressInitRequest represents a request to initialize ingress
// @Description Request to initialize ingress proxy
type IngressInitRequest struct {
	Verbose bool `json:"verbose,omitempty" example:"false"`
}

// CertAuthorityAddRequest represents a request to add a certificate authority
// @Description Request to add a certificate authority
type CertAuthorityAddRequest struct {
	Certificate string `json:"certificate" example:"-----BEGIN CERTIFICATE-----..." binding:"required"`
	Name        string `json:"name,omitempty" example:"my-ca"`
}

// CertAuthorityRemoveRequest represents a request to remove a certificate authority
// @Description Request to remove a certificate authority
type CertAuthorityRemoveRequest struct {
	Name string `json:"name" example:"my-ca.crt" binding:"required"`
}

// StandardResponse represents a standard API response
// @Description Standard API response
type StandardResponse struct {
	Success   bool   `json:"success" example:"true"`
	Message   string `json:"message,omitempty" example:"Operation completed successfully"`
	Output    string `json:"output,omitempty" example:"Command output here..."`
	Error     string `json:"error,omitempty" example:"Error message if failed"`
	ExitCode  int    `json:"exit_code,omitempty" example:"0"`
}

