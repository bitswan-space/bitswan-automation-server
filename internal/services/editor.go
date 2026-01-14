package services

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/certauthority"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
	"gopkg.in/yaml.v3"
)

// EditorService manages Editor service deployment for workspaces
type EditorService struct {
	WorkspaceName string
	WorkspacePath string
}

// NewEditorService creates a new Editor service manager
func NewEditorService(workspaceName string) (*EditorService, error) {
	// Always use HOME for file operations (works inside container and outside)
	// WorkspacePath will be used for docker-compose files, which need host paths
	homeDir := os.Getenv("HOME")
	workspacePath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)

	// Check if workspace exists
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace '%s' does not exist", workspaceName)
	}

	return &EditorService{
		WorkspaceName: workspaceName,
		WorkspacePath: workspacePath,
	}, nil
}

// EditorDevConfig holds dev mode configuration for the editor
type EditorDevConfig struct {
	DevMode            bool
	EditorDevSourceDir string
}

// CreateDockerCompose generates a docker-compose-editor.yml file for Editor
func (e *EditorService) CreateDockerCompose(gitopsSecretToken, bitswanEditorImage, domain string, oauthConfig *oauth.Config, mqttEnvVars []string, trustCA bool) (string, error) {
	return e.CreateDockerComposeWithDevMode(gitopsSecretToken, bitswanEditorImage, domain, oauthConfig, mqttEnvVars, trustCA, nil)
}

// CreateDockerComposeWithDevMode generates a docker-compose-editor.yml file for Editor with optional dev mode support
func (e *EditorService) CreateDockerComposeWithDevMode(gitopsSecretToken, bitswanEditorImage, domain string, oauthConfig *oauth.Config, mqttEnvVars []string, trustCA bool, devConfig *EditorDevConfig) (string, error) {
	// For docker-compose files, use HOST_HOME if available (docker-compose runs on host)
	// Convert container path to host path for volume mounts
	homeDir := os.Getenv("HOME")
	hostHomeDir := os.Getenv("HOST_HOME")
	if hostHomeDir == "" {
		hostHomeDir = homeDir
	}
	
	// Convert WorkspacePath (container path) to host path for docker-compose
	gitopsPath := e.WorkspacePath
	if homeDir != hostHomeDir && strings.HasPrefix(gitopsPath, homeDir) {
		// Replace container home with host home for docker-compose volume paths
		gitopsPath = strings.Replace(gitopsPath, homeDir, hostHomeDir, 1)
	}
	
	workspaceName := e.WorkspaceName
	workspaceCommonNetwork := fmt.Sprintf("bitswan_%s_common", workspaceName)
	// Also convert bitswan-src path for examples mount
	bitswanSrcPath := filepath.Dir(filepath.Dir(gitopsPath)) + "/bitswan-src"

	bitswanEditor := map[string]interface{}{
		"image":    bitswanEditorImage,
		"restart":  "always",
		"hostname": workspaceName + "-editor",
		"networks": []string{"bitswan_network", workspaceCommonNetwork},
		"environment": []string{
			"BITSWAN_DEPLOY_URL=" + fmt.Sprintf("http://%s-gitops:8079", workspaceName),
			"BITSWAN_DEPLOY_SECRET=" + gitopsSecretToken,
			"BITSWAN_GITOPS_DIR=/workspace",
		},
		"volumes": []string{
			gitopsPath + "/workspace:/workspace/workspace:z",
			gitopsPath + "/secrets:/workspace/secrets:z",
			gitopsPath + "/coder-home:/home/coder:z",
			gitopsPath + "/ssh:/workspace/.ssh:ro",
			bitswanSrcPath + "/examples:/workspace/examples:ro",
		},
	}

	if oauthConfig != nil {
		oauthEnvVars := oauth.CreateOAuthEnvVars(oauthConfig, "editor", workspaceName, domain)
		bitswanEditor["environment"] = append(bitswanEditor["environment"].([]string), oauthEnvVars...)
	}

	// Append MQTT env variables when workspace is connected to AOC
	if len(mqttEnvVars) > 0 {
		bitswanEditor["environment"] = append(bitswanEditor["environment"].([]string), mqttEnvVars...)
	}

	// Mount certificate authorities if specified
	caVolumes, caEnvVars := certauthority.GetCACertMountConfig(trustCA)
	if len(caVolumes) > 0 {
		bitswanEditor["volumes"] = append(bitswanEditor["volumes"].([]string), caVolumes...)
		bitswanEditor["environment"] = append(bitswanEditor["environment"].([]string), caEnvVars...)
	}

	// Add dev mode configuration if provided
	if devConfig != nil && devConfig.DevMode {
		bitswanEditor["environment"] = append(bitswanEditor["environment"].([]string), "BITSWAN_DEV_MODE=true")

		// Mount editor extension source directory for live development
		if devConfig.EditorDevSourceDir != "" {
			bitswanEditor["volumes"] = append(bitswanEditor["volumes"].([]string),
				devConfig.EditorDevSourceDir+":/opt/bitswan-extension-dev:z")
			bitswanEditor["environment"] = append(bitswanEditor["environment"].([]string),
				"BITSWAN_EXTENSION_DEV_DIR=/opt/bitswan-extension-dev")
		}
	}

	// Construct the docker-compose data structure
	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"bitswan-editor": bitswanEditor,
		},
		"networks": map[string]interface{}{
			"bitswan_network": map[string]interface{}{
				"external": true,
			},
			workspaceCommonNetwork: map[string]interface{}{
				"external": true,
			},
		},
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("failed to encode editor docker-compose: %w", err)
	}

	return buf.String(), nil
}

// SaveDockerCompose saves the docker-compose-editor.yml file
func (e *EditorService) SaveDockerCompose(content string) error {
	deploymentDir := filepath.Join(e.WorkspacePath, "deployment")
	dockerComposePath := filepath.Join(deploymentDir, "docker-compose-editor.yml")

	if err := os.WriteFile(dockerComposePath, []byte(content), 0755); err != nil {
		return fmt.Errorf("failed to write docker-compose-editor.yml: %w", err)
	}

	fmt.Printf("Editor docker-compose saved to: %s\n", dockerComposePath)
	return nil
}

// Enable enables the Editor service for the workspace
func (e *EditorService) Enable(gitopsSecretToken, bitswanEditorImage, domain string, oauthConfig *oauth.Config, trustCA bool) error {
	// Check if already enabled
	if e.IsEnabled() {
		return fmt.Errorf("Editor service is already enabled for workspace '%s'", e.WorkspaceName)
	}

	// Create coder-home directory to persist /home/coder between restarts
	coderHomeDir := filepath.Join(e.WorkspacePath, "coder-home")
	if err := os.MkdirAll(coderHomeDir, 0755); err != nil {
		return fmt.Errorf("failed to create coder-home directory: %w", err)
	}

	hostOsTmp := runtime.GOOS
	secretsDir := filepath.Join(e.WorkspacePath, "secrets")
	gitopsWorkspace := filepath.Join(e.WorkspacePath, "workspace")

	if hostOsTmp == "linux" {
		// Change ownership for Linux
		// Check if we're running as root (daemon runs as root)
		var chownCom *exec.Cmd
		if os.Geteuid() == 0 {
			// Running as root, no need for sudo
			chownCom = exec.Command("chown", "-R", "1000:1000", secretsDir)
		} else {
			// Not root, use sudo
			chownCom = exec.Command("sudo", "chown", "-R", "1000:1000", secretsDir)
		}
		if err := e.runCommand(chownCom); err != nil {
			return fmt.Errorf("failed to change ownership of secrets folder: %w", err)
		}
		if os.Geteuid() == 0 {
			chownCom = exec.Command("chown", "-R", "1000:1000", coderHomeDir)
		} else {
			chownCom = exec.Command("sudo", "chown", "-R", "1000:1000", coderHomeDir)
		}
		if err := e.runCommand(chownCom); err != nil {
			return fmt.Errorf("failed to change ownership of coder-home folder: %w", err)
		}
		if os.Geteuid() == 0 {
			chownCom = exec.Command("chown", "-R", "1000:1000", gitopsWorkspace)
		} else {
			chownCom = exec.Command("sudo", "chown", "-R", "1000:1000", gitopsWorkspace)
		}
		if err := e.runCommand(chownCom); err != nil {
			return fmt.Errorf("failed to change ownership of workspace folder: %w", err)
		}
	}

	// Read metadata to get MQTT environment variables
	var mqttEnvVars []string
	metadata, err := e.GetMetadata()
	if err == nil && metadata.MqttUsername != nil {
		mqttEnvVars = append(mqttEnvVars, "MQTT_USERNAME="+*metadata.MqttUsername)
		mqttEnvVars = append(mqttEnvVars, "MQTT_PASSWORD="+*metadata.MqttPassword)
		mqttEnvVars = append(mqttEnvVars, "MQTT_BROKER="+*metadata.MqttBroker)
		mqttEnvVars = append(mqttEnvVars, "MQTT_PORT="+fmt.Sprint(*metadata.MqttPort))
		mqttEnvVars = append(mqttEnvVars, "MQTT_TOPIC="+*metadata.MqttTopic)
	}

	if oauthConfig != nil && metadata.MqttUsername != nil {
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_BROKER="+*metadata.MqttBroker)
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_PORT="+fmt.Sprint(*metadata.MqttPort))
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_ALLOWED_GROUPS_TOPIC=/groups")
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_USERNAME="+*metadata.MqttUsername)
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_PASSWORD="+*metadata.MqttPassword)
	}

	// Generate docker-compose content
	dockerComposeContent, err := e.CreateDockerCompose(gitopsSecretToken, bitswanEditorImage, domain, oauthConfig, mqttEnvVars, trustCA)
	if err != nil {
		return fmt.Errorf("failed to create docker-compose content: %w", err)
	}

	// Save docker-compose file
	if err := e.SaveDockerCompose(dockerComposeContent); err != nil {
		return fmt.Errorf("failed to save docker-compose file: %w", err)
	}

	// Register Editor service with Caddy
	if err := caddyapi.RegisterServiceWithCaddy("editor", e.WorkspaceName, domain, fmt.Sprintf("%s-editor:9999", e.WorkspaceName)); err != nil {
		return fmt.Errorf("failed to register Editor service with caddy: %w", err)
	}

	fmt.Printf("Editor service enabled for workspace '%s'\n", e.WorkspaceName)
	return nil
}

// Disable disables the Editor service for the workspace
func (e *EditorService) Disable() error {
	// Check if enabled
	if !e.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'", e.WorkspaceName)
	}

	// Stop containers if running
	if e.IsContainerRunning() {
		if err := e.StopContainer(); err != nil {
			return fmt.Errorf("failed to stop editor container: %w", err)
		}
	}

	// Remove docker-compose file
	dockerComposePath := filepath.Join(e.WorkspacePath, "deployment", "docker-compose-editor.yml")
	if err := os.Remove(dockerComposePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove docker-compose-editor.yml: %w", err)
	}

	// Remove coder-home directory
	coderHomeDir := filepath.Join(e.WorkspacePath, "coder-home")
	if err := os.RemoveAll(coderHomeDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove coder-home directory: %w", err)
	}

	// Get domain from metadata for Caddy cleanup
	metadata, err := e.GetMetadata()
	if err == nil && metadata.Domain != "" {
		// Remove from Caddy (best effort)
		caddyapi.UnregisterCaddyService("editor", e.WorkspaceName, metadata.Domain)
	}

	fmt.Printf("Editor service disabled for workspace '%s'\n", e.WorkspaceName)
	return nil
}

// IsEnabled checks if the Editor service is enabled
func (e *EditorService) IsEnabled() bool {
	dockerComposePath := filepath.Join(e.WorkspacePath, "deployment", "docker-compose-editor.yml")
	_, err := os.Stat(dockerComposePath)
	return err == nil
}

// IsContainerRunning checks if Editor containers are running
func (e *EditorService) IsContainerRunning() bool {
	cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s-editor", e.WorkspaceName), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return len(lines) > 0 && lines[0] != ""
}

// StartContainer starts the Editor containers
func (e *EditorService) StartContainer() error {
	deploymentDir := filepath.Join(e.WorkspacePath, "deployment")
	projectName := e.WorkspaceName + "-editor"

	cmd := exec.Command("docker", "compose", "-f", "docker-compose-editor.yml", "-p", projectName, "up", "-d")
	cmd.Dir = deploymentDir

	fmt.Printf("Starting Editor container for workspace '%s'...\n", e.WorkspaceName)
	return e.runCommand(cmd)
}

// StopContainer stops the Editor containers
func (e *EditorService) StopContainer() error {
	deploymentDir := filepath.Join(e.WorkspacePath, "deployment")
	projectName := e.WorkspaceName + "-editor"

	cmd := exec.Command("docker", "compose", "-f", "docker-compose-editor.yml", "-p", projectName, "down")
	cmd.Dir = deploymentDir

	fmt.Printf("Stopping Editor container for workspace '%s'...\n", e.WorkspaceName)
	return e.runCommand(cmd)
}

// ShowAccessInfo displays access information for the Editor service
func (e *EditorService) ShowAccessInfo() error {
	metadata, err := e.GetMetadata()
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	if metadata.EditorURL != nil {
		fmt.Printf("Editor URL: %s\n", *metadata.EditorURL)
	}

	return nil
}

// ShowCredentials displays Editor credentials
func (e *EditorService) ShowCredentials() error {
	if !e.IsContainerRunning() {
		return fmt.Errorf("Editor container is not running")
	}

	// Get editor password from container
	password, err := e.getEditorPassword()
	if err != nil {
		return fmt.Errorf("failed to get editor password: %w", err)
	}

	fmt.Printf("Editor Password: %s\n", password)
	return nil
}

// GetEditorPassword retrieves the editor password from the container (public version)
func (e *EditorService) GetEditorPassword() (string, error) {
	containerName := e.WorkspaceName + "-editor-bitswan-editor-1"
	cmd := exec.Command("docker", "exec", containerName, "cat", "/home/coder/.config/code-server/config.yaml")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Bitswan Editor password: %w", err)
	}

	var editorConfig EditorConfig
	if err := yaml.Unmarshal(output, &editorConfig); err != nil {
		return "", fmt.Errorf("failed to unmarshal editor config: %w", err)
	}

	return editorConfig.Password, nil
}

// getEditorPassword retrieves the editor password from the container (private version for internal use)
func (e *EditorService) getEditorPassword() (string, error) {
	return e.GetEditorPassword()
}

// WaitForEditorReady waits for the editor service to be ready by monitoring logs
func (e *EditorService) WaitForEditorReady() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	deploymentDir := filepath.Join(e.WorkspacePath, "deployment")
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", "docker-compose-editor.yml", "-p", e.WorkspaceName+"-editor", "logs", "-f", "bitswan-editor")
	cmd.Dir = deploymentDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start docker compose logs command: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	readyChan := make(chan struct{})

	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "HTTP server listening on") {
				close(readyChan)
				return
			}
		}
	}()

	select {
	case <-readyChan:
		// Server is ready, kill the log streaming process
		if err := cmd.Process.Kill(); err != nil {
			// Just log this error, don't fail the function
			fmt.Printf("Warning: failed to kill log streaming process: %v\n", err)
		}
		return nil
	case <-ctx.Done():
		// Timeout or cancellation
		if err := cmd.Process.Kill(); err != nil {
			fmt.Printf("Warning: failed to kill log streaming process: %v\n", err)
		}
		return fmt.Errorf("timeout waiting for editor server to be ready")
	}
}

// EditorConfig represents the editor configuration
type EditorConfig struct {
	BindAddress string `yaml:"bind-addr"`
	Auth        string `yaml:"auth"`
	Password    string `yaml:"password"`
	Cert        bool   `yaml:"cert"`
}

// GetMetadata reads workspace metadata using the centralized function
func (e *EditorService) GetMetadata() (*config.WorkspaceMetadata, error) {
	metadata, err := config.GetWorkspaceMetadata(e.WorkspaceName)
	if err != nil {
		return nil, err
	}
	return &metadata, nil
}

// runCommand executes a command with error handling
func (e *EditorService) runCommand(cmd *exec.Cmd) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// UpdateImage updates the docker-compose-editor.yml file with a new image
func (e *EditorService) UpdateImage(newImage string) error {
	if newImage == "" {
		latestVersion, err := e.getLatestVersion()
		if err != nil {
			return fmt.Errorf("failed to get latest version: %w", err)
		}
		newImage = "bitswan/bitswan-editor:" + latestVersion
	}

	// Read the current docker-compose-editor.yml file
	composePath := filepath.Join(e.WorkspacePath, "deployment", "docker-compose-editor.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose-editor.yml: %w", err)
	}

	// Parse the YAML
	var compose map[string]interface{}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return fmt.Errorf("failed to parse docker-compose-editor.yml: %w", err)
	}

	// Update the image in the bitswan-editor service
	if services, ok := compose["services"].(map[string]interface{}); ok {
		if editorService, ok := services["bitswan-editor"].(map[string]interface{}); ok {
			editorService["image"] = newImage
		} else {
			return fmt.Errorf("bitswan-editor service not found in docker-compose-editor.yml")
		}
	} else {
		return fmt.Errorf("services section not found in docker-compose-editor.yml")
	}

	// Write the updated file back
	updatedData, err := yaml.Marshal(compose)
	if err != nil {
		return fmt.Errorf("failed to marshal updated docker-compose: %w", err)
	}

	if err := os.WriteFile(composePath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write updated docker-compose-editor.yml: %w", err)
	}

	return nil
}

// UpdateToLatest updates the editor service to the latest version from DockerHub
func (e *EditorService) UpdateToLatest() error {
	return e.UpdateImage("")
}

// UpdateToLatestWithStaging updates the editor service to the latest version from DockerHub, optionally using staging
func (e *EditorService) UpdateToLatestWithStaging(staging bool) error {
	var latestVersion string
	var err error
	if staging {
		latestVersion, err = dockerhub.GetLatestEditorStagingVersion()
		if err != nil {
			return fmt.Errorf("failed to get latest staging version: %w", err)
		}
		newImage := "bitswan/bitswan-editor-staging:" + latestVersion
		return e.UpdateImage(newImage)
	}
	return e.UpdateToLatest()
}

// getLatestVersion gets the latest version from DockerHub
func (e *EditorService) getLatestVersion() (string, error) {
	return dockerhub.GetLatestEditorVersion()
}

// UpdateCertificates updates the docker-compose file with updated certificate configuration
func (e *EditorService) UpdateCertificates(trustCA bool) error {
	// Check if enabled
	if !e.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'", e.WorkspaceName)
	}

	// Get certificate mount configuration
	caVolumes, caEnvVars := certauthority.GetCACertMountConfig(trustCA)

	// Read the current docker-compose-editor.yml file
	composePath := filepath.Join(e.WorkspacePath, "deployment", "docker-compose-editor.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose-editor.yml: %w", err)
	}

	// Parse the YAML
	var compose map[string]interface{}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return fmt.Errorf("failed to parse docker-compose-editor.yml: %w", err)
	}

	// Update volumes and environment in the bitswan-editor service
	if services, ok := compose["services"].(map[string]interface{}); ok {
		if editorService, ok := services["bitswan-editor"].(map[string]interface{}); ok {
			// Update volumes - remove old CA cert volumes and add new ones
			if volumes, ok := editorService["volumes"].([]interface{}); ok {
				// Filter out old CA cert volumes
				var filteredVolumes []interface{}
				for _, vol := range volumes {
					volStr := fmt.Sprintf("%v", vol)
					// Keep volumes that are not CA cert related
					if !strings.Contains(volStr, "/usr/local/share/ca-certificates/custom") &&
						!strings.Contains(volStr, "/ca-certs") {
						filteredVolumes = append(filteredVolumes, vol)
					}
				}
				// Add new CA cert volumes
				for _, vol := range caVolumes {
					filteredVolumes = append(filteredVolumes, vol)
				}
				editorService["volumes"] = filteredVolumes
			} else if len(caVolumes) > 0 {
				// No volumes exist, just add the CA cert volumes
				volumesList := make([]interface{}, len(caVolumes))
				for i, v := range caVolumes {
					volumesList[i] = v
				}
				editorService["volumes"] = volumesList
			}

			// Update environment variables - remove old CA cert env vars and add new ones
			if envVars, ok := editorService["environment"].([]interface{}); ok {
				// Filter out old CA cert environment variables
				var filteredEnvVars []interface{}
				for _, env := range envVars {
					envStr := fmt.Sprintf("%v", env)
					// Keep env vars that are not CA cert related
					if !strings.Contains(envStr, "UPDATE_CA_CERTIFICATES") &&
						!strings.Contains(envStr, "REQUESTS_CA_BUNDLE") {
						filteredEnvVars = append(filteredEnvVars, env)
					}
				}
				// Add new CA cert environment variables
				for _, env := range caEnvVars {
					filteredEnvVars = append(filteredEnvVars, env)
				}
				editorService["environment"] = filteredEnvVars
			} else if len(caEnvVars) > 0 {
				// No environment exists, just add the CA cert env vars
				envList := make([]interface{}, len(caEnvVars))
				for i, v := range caEnvVars {
					envList[i] = v
				}
				editorService["environment"] = envList
			}
		} else {
			return fmt.Errorf("bitswan-editor service not found in docker-compose-editor.yml")
		}
	} else {
		return fmt.Errorf("services section not found in docker-compose-editor.yml")
	}

	// Write the updated file back
	updatedData, err := yaml.Marshal(compose)
	if err != nil {
		return fmt.Errorf("failed to marshal updated docker-compose: %w", err)
	}

	if err := os.WriteFile(composePath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write updated docker-compose-editor.yml: %w", err)
	}

	return nil
}

// RegenerateDockerCompose fully regenerates the docker-compose-editor.yml file from metadata
// This ensures all configuration changes (volumes, environment, dev mode, etc.) are propagated to existing workspaces
func (e *EditorService) RegenerateDockerCompose(editorImage string, staging bool, trustCA bool) error {
	// Check if enabled
	if !e.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'", e.WorkspaceName)
	}

	// Read metadata to get configuration
	metadata, err := e.GetMetadata()
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	// Get the editor image - use custom if provided, otherwise get latest
	var bitswanEditorImage string
	if editorImage != "" {
		bitswanEditorImage = editorImage
	} else {
		var latestVersion string
		if staging {
			latestVersion, err = dockerhub.GetLatestEditorStagingVersion()
			if err != nil {
				return fmt.Errorf("failed to get latest staging version: %w", err)
			}
			bitswanEditorImage = "bitswan/bitswan-editor-staging:" + latestVersion
		} else {
			latestVersion, err = e.getLatestVersion()
			if err != nil {
				return fmt.Errorf("failed to get latest version: %w", err)
			}
			bitswanEditorImage = "bitswan/bitswan-editor:" + latestVersion
		}
	}

	// Prepare MQTT environment variables from metadata
	var mqttEnvVars []string
	if metadata.MqttUsername != nil {
		mqttEnvVars = append(mqttEnvVars, "MQTT_USERNAME="+*metadata.MqttUsername)
		mqttEnvVars = append(mqttEnvVars, "MQTT_PASSWORD="+*metadata.MqttPassword)
		mqttEnvVars = append(mqttEnvVars, "MQTT_BROKER="+*metadata.MqttBroker)
		mqttEnvVars = append(mqttEnvVars, "MQTT_PORT="+fmt.Sprint(*metadata.MqttPort))
		mqttEnvVars = append(mqttEnvVars, "MQTT_TOPIC="+*metadata.MqttTopic)
	}

	// Get OAuth config if it exists
	var oauthConfig *oauth.Config
	oauthConfig, err = oauth.GetOauthConfig(e.WorkspaceName)
	if err != nil {
		// OAuth config not found or failed to load locally
		// If workspace is connected to AOC, try to fetch OAuth config from AOC
		if metadata.WorkspaceId != nil && *metadata.WorkspaceId != "" {
			fmt.Printf("OAuth config not found locally, attempting to fetch from AOC for workspace '%s'...\n", e.WorkspaceName)
			aocClient, aocErr := aoc.NewAOCClient()
			if aocErr == nil {
				fetchedConfig, fetchErr := aocClient.GetOAuthConfig(*metadata.WorkspaceId)
				if fetchErr == nil {
					oauthConfig = fetchedConfig
					// Save the fetched config to disk for future use
					if saveErr := oauth.SaveOauthConfig(e.WorkspaceName, oauthConfig); saveErr != nil {
						fmt.Printf("Warning: failed to save OAuth config to disk: %v\n", saveErr)
					} else {
						fmt.Printf("OAuth config fetched from AOC and saved successfully\n")
					}
				} else {
					fmt.Printf("Warning: failed to fetch OAuth config from AOC: %v\n", fetchErr)
					oauthConfig = nil
				}
			} else {
				fmt.Printf("Warning: failed to create AOC client to fetch OAuth config: %v\n", aocErr)
				oauthConfig = nil
			}
		} else {
			// Not connected to AOC, OAuth config not available
			oauthConfig = nil
		}
	}

	// Add OAuth-related MQTT env vars if both OAuth and MQTT are configured
	if oauthConfig != nil && metadata.MqttUsername != nil {
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_BROKER="+*metadata.MqttBroker)
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_PORT="+fmt.Sprint(*metadata.MqttPort))
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_ALLOWED_GROUPS_TOPIC=/groups")
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_USERNAME="+*metadata.MqttUsername)
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_PASSWORD="+*metadata.MqttPassword)
	}

	// Prepare dev mode configuration
	var devConfig *EditorDevConfig
	if metadata.DevMode {
		devConfig = &EditorDevConfig{
			DevMode: true,
		}
		if metadata.EditorDevSourceDir != nil {
			devConfig.EditorDevSourceDir = *metadata.EditorDevSourceDir
		}
		fmt.Printf("Dev mode enabled for editor (extension source: %s)\n", devConfig.EditorDevSourceDir)
	}

	// Generate docker-compose content
	dockerComposeContent, err := e.CreateDockerComposeWithDevMode(
		metadata.GitopsSecret,
		bitswanEditorImage,
		metadata.Domain,
		oauthConfig,
		mqttEnvVars,
		trustCA,
		devConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to create docker-compose content: %w", err)
	}

	// Save docker-compose file
	if err := e.SaveDockerCompose(dockerComposeContent); err != nil {
		return fmt.Errorf("failed to save docker-compose file: %w", err)
	}

	fmt.Printf("Editor docker-compose regenerated for workspace '%s'\n", e.WorkspaceName)
	return nil
}
