package services

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"gopkg.in/yaml.v3"
)

// CodingAgentService manages Coding Agent service deployment for workspaces
type CodingAgentService struct {
	WorkspaceName string
	WorkspacePath string
}

// NewCodingAgentService creates a new Coding Agent service manager
func NewCodingAgentService(workspaceName string) (*CodingAgentService, error) {
	// Always use HOME for file operations (works inside container and outside)
	homeDir := os.Getenv("HOME")
	workspacePath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)

	// Check if workspace exists
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace '%s' does not exist", workspaceName)
	}

	return &CodingAgentService{
		WorkspaceName: workspaceName,
		WorkspacePath: workspacePath,
	}, nil
}

// CodingAgentDevConfig holds dev mode configuration
type CodingAgentDevConfig struct {
	DevMode   bool
	SourceDir string // path to bitswan-agent source directory
}

// CreateDockerCompose generates a docker-compose-coding-agent.yml file for Coding Agent
func (c *CodingAgentService) CreateDockerCompose(gitopsAgentSecret, codingAgentImage, domain string) (string, error) {
	return c.CreateDockerComposeWithDevMode(gitopsAgentSecret, codingAgentImage, domain, nil)
}

// CreateDockerComposeWithDevMode generates docker-compose with optional dev mode support
func (c *CodingAgentService) CreateDockerComposeWithDevMode(gitopsAgentSecret, codingAgentImage, domain string, devConfig *CodingAgentDevConfig) (string, error) {
	// For docker-compose files, use HOST_HOME if available (docker-compose runs on host)
	// Convert container path to host path for volume mounts
	homeDir := os.Getenv("HOME")
	hostHomeDir := os.Getenv("HOST_HOME")
	if hostHomeDir == "" {
		hostHomeDir = homeDir
	}

	// Convert WorkspacePath (container path) to host path for docker-compose
	gitopsPath := c.WorkspacePath
	if homeDir != hostHomeDir && strings.HasPrefix(gitopsPath, homeDir) {
		// Replace container home with host home for docker-compose volume paths
		gitopsPath = strings.Replace(gitopsPath, homeDir, hostHomeDir, 1)
	}

	workspaceName := c.WorkspaceName

	if codingAgentImage == "" {
		codingAgentImage = "bitswan/coding-agent:latest"
	}

	// Read the editor's public SSH key
	sshPubKey := ""
	pubKeyPath := filepath.Join(c.WorkspacePath, "ssh", "id_ed25519.pub")
	if data, err := os.ReadFile(pubKeyPath); err == nil {
		sshPubKey = strings.TrimSpace(string(data))
	}

	envVars := []string{
		"BITSWAN_GITOPS_URL=" + fmt.Sprintf("http://%s-gitops:8079", workspaceName),
		"BITSWAN_GITOPS_AGENT_SECRET=" + gitopsAgentSecret,
		"BITSWAN_WORKSPACE_NAME=" + workspaceName,
	}
	if sshPubKey != "" {
		envVars = append(envVars, "EDITOR_SSH_PUBLIC_KEY="+sshPubKey)
	}

	volumes := []string{
		gitopsPath + "/workspace/worktrees:/workspace/worktrees:z",
		gitopsPath + "/coding-agent-home:/home/agent:z",
		gitopsPath + "/coding-agent-sessions:/var/log/agent-sessions:z",
	}

	// Dev mode: mount source files directly into the container
	if devConfig != nil && devConfig.DevMode && devConfig.SourceDir != "" {
		srcDir := devConfig.SourceDir
		// Convert to host path if needed
		if homeDir != hostHomeDir && strings.HasPrefix(srcDir, homeDir) {
			srcDir = strings.Replace(srcDir, homeDir, hostHomeDir, 1)
		}
		volumes = append(volumes,
			srcDir+"/agent-session-wrapper:/usr/local/bin/agent-session-wrapper:z",
			srcDir+"/AGENTS-inside-container.md:/AGENTS.md:z",
		)
	}

	bitswanCodingAgent := map[string]interface{}{
		"image":    codingAgentImage,
		"restart":  "always",
		"hostname": workspaceName + "-coding-agent",
		"networks": []string{"bitswan_network"},
		"environment": envVars,
		"volumes":  volumes,
	}

	// Construct the docker-compose data structure
	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"bitswan-coding-agent": bitswanCodingAgent,
		},
		"networks": map[string]interface{}{
			"bitswan_network": map[string]interface{}{
				"external": true,
			},
		},
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("failed to encode coding-agent docker-compose: %w", err)
	}

	return buf.String(), nil
}

// SaveDockerCompose saves the docker-compose-coding-agent.yml file
func (c *CodingAgentService) SaveDockerCompose(content string) error {
	deploymentDir := filepath.Join(c.WorkspacePath, "deployment")
	dockerComposePath := filepath.Join(deploymentDir, "docker-compose-coding-agent.yml")

	if err := os.WriteFile(dockerComposePath, []byte(content), 0755); err != nil {
		return fmt.Errorf("failed to write docker-compose-coding-agent.yml: %w", err)
	}

	fmt.Printf("Coding Agent docker-compose saved to: %s\n", dockerComposePath)
	return nil
}

// Enable enables the Coding Agent service for the workspace
func (c *CodingAgentService) Enable(gitopsAgentSecret, codingAgentImage, domain string) error {
	// Check if already enabled
	if c.IsEnabled() {
		return fmt.Errorf("Coding Agent service is already enabled for workspace '%s'", c.WorkspaceName)
	}

	// Create coding-agent-home directory
	codingAgentHomeDir := filepath.Join(c.WorkspacePath, "coding-agent-home")
	if err := os.MkdirAll(codingAgentHomeDir, 0755); err != nil {
		return fmt.Errorf("failed to create coding-agent-home directory: %w", err)
	}

	// Create coding-agent-sessions directory
	codingAgentSessionsDir := filepath.Join(c.WorkspacePath, "coding-agent-sessions")
	if err := os.MkdirAll(codingAgentSessionsDir, 0755); err != nil {
		return fmt.Errorf("failed to create coding-agent-sessions directory: %w", err)
	}

	// Create workspace/worktrees directory
	worktreesDir := filepath.Join(c.WorkspacePath, "workspace", "worktrees")
	if err := os.MkdirAll(worktreesDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace/worktrees directory: %w", err)
	}

	hostOsTmp := runtime.GOOS

	if hostOsTmp == "linux" {
		// Change ownership for Linux
		dirs := []struct {
			path string
			name string
		}{
			{codingAgentHomeDir, "coding-agent-home"},
			{codingAgentSessionsDir, "coding-agent-sessions"},
			{worktreesDir, "workspace/worktrees"},
		}

		for _, dir := range dirs {
			var chownCom *exec.Cmd
			if os.Geteuid() == 0 {
				chownCom = exec.Command("chown", "-R", "1000:1000", dir.path)
			} else {
				chownCom = exec.Command("sudo", "chown", "-R", "1000:1000", dir.path)
			}
			if err := c.runCommand(chownCom); err != nil {
				return fmt.Errorf("failed to change ownership of %s folder: %w", dir.name, err)
			}
		}
	}

	// Generate docker-compose content
	dockerComposeContent, err := c.CreateDockerCompose(gitopsAgentSecret, codingAgentImage, domain)
	if err != nil {
		return fmt.Errorf("failed to create docker-compose content: %w", err)
	}

	// Save docker-compose file
	if err := c.SaveDockerCompose(dockerComposeContent); err != nil {
		return fmt.Errorf("failed to save docker-compose file: %w", err)
	}

	fmt.Printf("Coding Agent service enabled for workspace '%s'\n", c.WorkspaceName)
	return nil
}

// Disable disables the Coding Agent service for the workspace
func (c *CodingAgentService) Disable() error {
	// Check if enabled
	if !c.IsEnabled() {
		return fmt.Errorf("Coding Agent service is not enabled for workspace '%s'", c.WorkspaceName)
	}

	// Stop containers if running
	if c.IsContainerRunning() {
		if err := c.StopContainer(); err != nil {
			return fmt.Errorf("failed to stop coding-agent container: %w", err)
		}
	}

	// Remove docker-compose file
	dockerComposePath := filepath.Join(c.WorkspacePath, "deployment", "docker-compose-coding-agent.yml")
	if err := os.Remove(dockerComposePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove docker-compose-coding-agent.yml: %w", err)
	}

	fmt.Printf("Coding Agent service disabled for workspace '%s'\n", c.WorkspaceName)
	return nil
}

// IsEnabled checks if the Coding Agent service is enabled
func (c *CodingAgentService) IsEnabled() bool {
	dockerComposePath := filepath.Join(c.WorkspacePath, "deployment", "docker-compose-coding-agent.yml")
	_, err := os.Stat(dockerComposePath)
	return err == nil
}

// IsContainerRunning checks if Coding Agent containers are running
func (c *CodingAgentService) IsContainerRunning() bool {
	cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s-coding-agent", c.WorkspaceName), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return len(lines) > 0 && lines[0] != ""
}

// StartContainer starts the Coding Agent containers
func (c *CodingAgentService) StartContainer() error {
	deploymentDir := filepath.Join(c.WorkspacePath, "deployment")
	projectName := c.WorkspaceName + "-coding-agent"

	cmd := exec.Command("docker", "compose", "-f", "docker-compose-coding-agent.yml", "-p", projectName, "up", "-d")
	cmd.Dir = deploymentDir

	fmt.Printf("Starting Coding Agent container for workspace '%s'...\n", c.WorkspaceName)
	return c.runCommand(cmd)
}

// StopContainer stops the Coding Agent containers
func (c *CodingAgentService) StopContainer() error {
	deploymentDir := filepath.Join(c.WorkspacePath, "deployment")
	projectName := c.WorkspaceName + "-coding-agent"

	cmd := exec.Command("docker", "compose", "-f", "docker-compose-coding-agent.yml", "-p", projectName, "down")
	cmd.Dir = deploymentDir

	fmt.Printf("Stopping Coding Agent container for workspace '%s'...\n", c.WorkspaceName)
	return c.runCommand(cmd)
}

// GetMetadata reads workspace metadata using the centralized function
func (c *CodingAgentService) GetMetadata() (*config.WorkspaceMetadata, error) {
	metadata, err := config.GetWorkspaceMetadata(c.WorkspaceName)
	if err != nil {
		return nil, err
	}
	return &metadata, nil
}

// runCommand executes a command with error handling
func (c *CodingAgentService) runCommand(cmd *exec.Cmd) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// UpdateImage updates the docker-compose-coding-agent.yml file with a new image
func (c *CodingAgentService) UpdateImage(newImage string) error {
	if newImage == "" {
		newImage = "bitswan/coding-agent:latest"
	}

	// Read the current docker-compose-coding-agent.yml file
	composePath := filepath.Join(c.WorkspacePath, "deployment", "docker-compose-coding-agent.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose-coding-agent.yml: %w", err)
	}

	// Parse the YAML
	var compose map[string]interface{}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return fmt.Errorf("failed to parse docker-compose-coding-agent.yml: %w", err)
	}

	// Update the image in the bitswan-coding-agent service
	if services, ok := compose["services"].(map[string]interface{}); ok {
		if codingAgentService, ok := services["bitswan-coding-agent"].(map[string]interface{}); ok {
			codingAgentService["image"] = newImage
		} else {
			return fmt.Errorf("bitswan-coding-agent service not found in docker-compose-coding-agent.yml")
		}
	} else {
		return fmt.Errorf("services section not found in docker-compose-coding-agent.yml")
	}

	// Write the updated file back
	updatedData, err := yaml.Marshal(compose)
	if err != nil {
		return fmt.Errorf("failed to marshal updated docker-compose: %w", err)
	}

	if err := os.WriteFile(composePath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write updated docker-compose-coding-agent.yml: %w", err)
	}

	return nil
}
