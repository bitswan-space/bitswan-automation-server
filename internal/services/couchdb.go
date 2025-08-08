package services

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/dchest/uniuri"
	"gopkg.in/yaml.v3"
)

// CouchDBService manages CouchDB service deployment for workspaces
type CouchDBService struct {
	WorkspaceName string
	WorkspacePath string
}

// NewCouchDBService creates a new CouchDB service manager
func NewCouchDBService(workspaceName string) (*CouchDBService, error) {
	workspacePath := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "workspaces", workspaceName)
	
	// Check if workspace exists
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace '%s' does not exist", workspaceName)
	}
	
	return &CouchDBService{
		WorkspaceName: workspaceName,
		WorkspacePath: workspacePath,
	}, nil
}

// CouchDBSecrets represents the secrets for CouchDB
type CouchDBSecrets struct {
	User     string
	Password string
	Host     string
}

// GenerateSecrets creates new secrets for CouchDB
func (c *CouchDBService) GenerateSecrets() *CouchDBSecrets {
	return &CouchDBSecrets{
		User:     "admin",
		Password: uniuri.NewLen(32),
		Host:     c.WorkspaceName + "__couchdb",
	}
}

// SaveSecrets saves CouchDB secrets to the workspace secrets directory
func (c *CouchDBService) SaveSecrets(secrets *CouchDBSecrets) error {
	secretsDir := filepath.Join(c.WorkspacePath, "secrets")
	
	// Ensure secrets directory exists
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}
	
	// Create the secrets content
	secretsContent := fmt.Sprintf("COUCHDB_USER=%s\nCOUCHDB_PASSWORD=%s\nCOUCHDB_HOST=%s\n",
		secrets.User, secrets.Password, secrets.Host)
	
	secretsFile := filepath.Join(secretsDir, "couchdb")
	if err := os.WriteFile(secretsFile, []byte(secretsContent), 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}
	
	fmt.Printf("CouchDB secrets saved to: %s\n", secretsFile)
	return nil
}

// CreateDockerCompose generates a docker-compose.yml file for CouchDB
func (c *CouchDBService) CreateDockerCompose() (string, error) {
	secretsPath := filepath.Join(c.WorkspacePath, "secrets", "couchdb")
	
	// Construct the docker-compose data structure
	dockerCompose := map[string]interface{}{
		"services": map[string]interface{}{
			"couchdb": map[string]interface{}{
				"image":          "couchdb:3.3",
				"container_name": c.WorkspaceName + "__couchdb",
				"restart":        "unless-stopped",
				"env_file":       []string{secretsPath},
				"volumes":        []string{"couchdb-data:/opt/couchdb/data"},
				"networks":       []string{"bitswan_network"},
			},
		},
		"volumes": map[string]interface{}{
			"couchdb-data": nil,
		},
		"networks": map[string]interface{}{
			"bitswan_network": map[string]interface{}{
				"external": true,
			},
		},
	}
	
	var buf bytes.Buffer
	
	// Serialize the docker-compose data structure to YAML
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("failed to encode docker-compose data structure: %w", err)
	}
	
	return buf.String(), nil
}

// SaveDockerCompose saves the docker-compose.yml file to the deployment directory
func (c *CouchDBService) SaveDockerCompose(composeContent string) error {
	deploymentDir := filepath.Join(c.WorkspacePath, "deployment")
	
	// Ensure deployment directory exists
	if err := os.MkdirAll(deploymentDir, 0755); err != nil {
		return fmt.Errorf("failed to create deployment directory: %w", err)
	}
	
	composeFile := filepath.Join(deploymentDir, "docker-compose-couchdb.yml")
	if err := os.WriteFile(composeFile, []byte(composeContent), 0644); err != nil {
		return fmt.Errorf("failed to write docker-compose file: %w", err)
	}
	
	fmt.Printf("CouchDB docker-compose file saved to: %s\n", composeFile)
	return nil
}

// Enable enables the CouchDB service for the workspace
func (c *CouchDBService) Enable() error {
	fmt.Printf("Enabling CouchDB service for workspace '%s'\n", c.WorkspaceName)
	
	// Generate secrets
	secrets := c.GenerateSecrets()
	if err := c.SaveSecrets(secrets); err != nil {
		return fmt.Errorf("failed to save secrets: %w", err)
	}
	
	// Create docker-compose file
	composeContent, err := c.CreateDockerCompose()
	if err != nil {
		return fmt.Errorf("failed to create docker-compose content: %w", err)
	}
	
	if err := c.SaveDockerCompose(composeContent); err != nil {
		return fmt.Errorf("failed to save docker-compose file: %w", err)
	}
	
	// Start the CouchDB container using docker-compose
	if err := c.StartContainer(); err != nil {
		return fmt.Errorf("failed to start CouchDB container: %w", err)
	}
	
	// Register with Caddy
	if err := c.RegisterWithCaddy(); err != nil {
		return fmt.Errorf("failed to register with Caddy: %w", err)
	}
	
	fmt.Println("CouchDB service enabled successfully!")
	fmt.Printf("Username: %s\n", secrets.User)
	fmt.Printf("Password: %s\n", secrets.Password)
	
	// Show access URLs
	if err := c.ShowAccessInfo(); err != nil {
		fmt.Printf("Warning: could not show access URLs: %v\n", err)
	}
	
	return nil
}

// Disable disables the CouchDB service for the workspace
func (c *CouchDBService) Disable() error {
	fmt.Printf("Disabling CouchDB service for workspace '%s'\n", c.WorkspaceName)
	
	// Stop and remove the CouchDB container
	if err := c.StopContainer(); err != nil {
		fmt.Printf("Warning: failed to stop CouchDB container: %v\n", err)
	}
	
	// Unregister from Caddy
	if err := c.UnregisterFromCaddy(); err != nil {
		fmt.Printf("Warning: failed to unregister from Caddy: %v\n", err)
	}
	
	// Remove secrets file
	secretsFile := filepath.Join(c.WorkspacePath, "secrets", "couchdb")
	if err := os.Remove(secretsFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove secrets file: %w", err)
	}
	
	// Remove docker-compose file
	composeFile := filepath.Join(c.WorkspacePath, "deployment", "docker-compose-couchdb.yml")
	if err := os.Remove(composeFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove docker-compose file: %w", err)
	}
	
	fmt.Println("CouchDB service disabled successfully!")
	
	return nil
}

// IsEnabled checks if CouchDB service is enabled for the workspace
func (c *CouchDBService) IsEnabled() bool {
	secretsFile := filepath.Join(c.WorkspacePath, "secrets", "couchdb")
	composeFile := filepath.Join(c.WorkspacePath, "deployment", "docker-compose-couchdb.yml")
	
	_, secretsExists := os.Stat(secretsFile)
	_, composeExists := os.Stat(composeFile)
	
	return secretsExists == nil && composeExists == nil
}

// RegisterWithCaddy registers the CouchDB service with Caddy
func (c *CouchDBService) RegisterWithCaddy() error {
	// Get workspace metadata to get the domain
	metadata, err := c.getWorkspaceMetadata()
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}
	
	if metadata.Domain == "" {
		return fmt.Errorf("no domain configured for workspace '%s'", c.WorkspaceName)
	}
	
	// Create hostname in the format: workspacename--couchdb.domain
	hostname := fmt.Sprintf("%s--couchdb.%s", c.WorkspaceName, metadata.Domain)
	
	// Register with Caddy using the container name as upstream
	upstream := fmt.Sprintf("%s__couchdb:5984", c.WorkspaceName)
	
	if err := caddyapi.AddRoute(hostname, upstream); err != nil {
		return fmt.Errorf("failed to register CouchDB route: %w", err)
	}
	
	fmt.Printf("Registered CouchDB with Caddy: %s -> %s\n", hostname, upstream)
	return nil
}

// UnregisterFromCaddy removes the CouchDB service from Caddy
func (c *CouchDBService) UnregisterFromCaddy() error {
	// Get workspace metadata to get the domain
	metadata, err := c.getWorkspaceMetadata()
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}
	
	if metadata.Domain == "" {
		return fmt.Errorf("no domain configured for workspace '%s'", c.WorkspaceName)
	}
	
	// Create hostname in the format: workspacename--couchdb.domain
	hostname := fmt.Sprintf("%s--couchdb.%s", c.WorkspaceName, metadata.Domain)
	
	if err := caddyapi.RemoveRoute(hostname); err != nil {
		return fmt.Errorf("failed to unregister CouchDB route: %w", err)
	}
	
	fmt.Printf("Unregistered CouchDB from Caddy: %s\n", hostname)
	return nil
}

// getWorkspaceMetadata retrieves workspace metadata
func (c *CouchDBService) getWorkspaceMetadata() (*config.Metadata, error) {
	metadata := config.GetWorkspaceMetadata(c.WorkspaceName)
	return &metadata, nil
}

// ShowAccessInfo displays access information for the CouchDB service
func (c *CouchDBService) ShowAccessInfo() error {
	metadata, err := c.getWorkspaceMetadata()
	if err != nil {
		return err
	}
	
	fmt.Println("\nCouchDB Access Information:")
	
	if metadata.Domain != "" {
		hostname := fmt.Sprintf("%s--couchdb.%s", c.WorkspaceName, metadata.Domain)
		fmt.Printf("  Web access: https://%s\n", hostname)
		fmt.Printf("  Admin UI:   https://%s/_utils/\n", hostname)
	} else {
		fmt.Printf("  No domain configured - web access not available\n")
	}
	
	return nil
}

// StartContainer starts the CouchDB container using docker-compose
func (c *CouchDBService) StartContainer() error {
	deploymentDir := filepath.Join(c.WorkspacePath, "deployment")
	composeFile := filepath.Join(deploymentDir, "docker-compose-couchdb.yml")
	
	// Check if docker-compose file exists
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		return fmt.Errorf("docker-compose file not found: %s", composeFile)
	}
	
	projectName := fmt.Sprintf("%s-couchdb", c.WorkspaceName)
	
	fmt.Printf("Starting CouchDB container (project: %s)...\n", projectName)
	
	// Run docker-compose up -d
	cmd := exec.Command("docker", "compose", "-f", composeFile, "-p", projectName, "up", "-d")
	cmd.Dir = deploymentDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start CouchDB container: %w\nOutput: %s", err, string(output))
	}
	
	fmt.Printf("CouchDB container started successfully!\n")
	return nil
}

// StopContainer stops and removes the CouchDB container
func (c *CouchDBService) StopContainer() error {
	deploymentDir := filepath.Join(c.WorkspacePath, "deployment")
	composeFile := filepath.Join(deploymentDir, "docker-compose-couchdb.yml")
	
	projectName := fmt.Sprintf("%s-couchdb", c.WorkspaceName)
	
	fmt.Printf("Stopping CouchDB container (project: %s)...\n", projectName)
	
	// Run docker-compose down
	cmd := exec.Command("docker", "compose", "-f", composeFile, "-p", projectName, "down")
	cmd.Dir = deploymentDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop CouchDB container: %w\nOutput: %s", err, string(output))
	}
	
	fmt.Printf("CouchDB container stopped successfully!\n")
	return nil
}

// IsContainerRunning checks if the CouchDB container is currently running
func (c *CouchDBService) IsContainerRunning() bool {
	containerName := fmt.Sprintf("%s__couchdb", c.WorkspaceName)
	
	cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return string(output) != ""
}

// ShowCredentials displays the CouchDB credentials from the secrets file
func (c *CouchDBService) ShowCredentials() error {
	secretsFile := filepath.Join(c.WorkspacePath, "secrets", "couchdb")
	
	// Read the secrets file
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		return fmt.Errorf("failed to read secrets file: %w", err)
	}
	
	fmt.Println("\nCouchDB Credentials:")
	
	// Parse and display the credentials
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		if strings.HasPrefix(line, "COUCHDB_USER=") {
			user := strings.TrimPrefix(line, "COUCHDB_USER=")
			fmt.Printf("  Username: %s\n", user)
		} else if strings.HasPrefix(line, "COUCHDB_PASSWORD=") {
			password := strings.TrimPrefix(line, "COUCHDB_PASSWORD=")
			fmt.Printf("  Password: %s\n", password)
		}
	}
	
	return nil
} 