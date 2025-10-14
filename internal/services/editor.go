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

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
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
	workspacePath := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "workspaces", workspaceName)

	// Check if workspace exists
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace '%s' does not exist", workspaceName)
	}

	return &EditorService{
		WorkspaceName: workspaceName,
		WorkspacePath: workspacePath,
	}, nil
}

// CreateDockerCompose generates a docker-compose-editor.yml file for Editor
func (e *EditorService) CreateDockerCompose(gitopsSecretToken, bitswanEditorImage, domain string, oauthConfig *oauth.Config, mqttEnvVars []string) (string, error) {
	gitopsPath := e.WorkspacePath
	workspaceName := e.WorkspaceName
	sshDir := gitopsPath + "/ssh"

	bitswanEditor := map[string]interface{}{
		"image":    bitswanEditorImage,
		"restart":  "always",
		"hostname": workspaceName + "-editor",
		"networks": []string{"bitswan_network"},
		"environment": []string{
			"BITSWAN_DEPLOY_URL=" + fmt.Sprintf("http://%s-gitops:8079", workspaceName),
			"BITSWAN_DEPLOY_SECRET=" + gitopsSecretToken,
			"BITSWAN_GITOPS_DIR=/home/coder/workspace",
		},
		"volumes": []string{
			gitopsPath + "/workspace:/home/coder/workspace/workspace:z",
			gitopsPath + "/secrets:/home/coder/workspace/secrets:z",
			gitopsPath + "/codeserver-config:/home/coder/.config/code-server/:z",
			filepath.Dir(filepath.Dir(gitopsPath)) + "/bitswan-src/examples:/home/coder/workspace/examples:ro",
			sshDir + ":/home/coder/.ssh:z",
		},
	}

	if oauthConfig != nil {
		// Use provider from config or default to keycloak-oidc
		provider := "keycloak-oidc"
		if oauthConfig.Provider != nil {
			provider = *oauthConfig.Provider
		}

		// Use http address from config or default
		httpAddress := "0.0.0.0:9999"
		if oauthConfig.HttpAddress != nil {
			httpAddress = *oauthConfig.HttpAddress
		}

		// Use scope from config or default
		scope := "openid email profile group_membership"
		if oauthConfig.Scope != nil {
			scope = *oauthConfig.Scope
		}

		// Use groups claim from config or default
		groupsClaim := "group_membership"
		if oauthConfig.GroupsClaim != nil {
			groupsClaim = *oauthConfig.GroupsClaim
		}

		oauthEnvVars := []string{
			"OAUTH_ENABLED=true", // This is the trigger entrypoint script
			"OAUTH2_PROXY_PROVIDER=" + provider,
			"OAUTH2_PROXY_HTTP_ADDRESS=" + httpAddress,
			"OAUTH2_PROXY_CLIENT_ID=" + oauthConfig.ClientId,
			"OAUTH2_PROXY_CLIENT_SECRET=" + oauthConfig.ClientSecret,
			"OAUTH2_PROXY_COOKIE_SECRET=" + oauthConfig.CookieSecret,
			"OAUTH2_PROXY_OIDC_ISSUER_URL=" + oauthConfig.IssuerUrl,
			"OAUTH2_PROXY_REDIRECT_URL=https://" + fmt.Sprintf("%s-editor", workspaceName) + "." + domain + "/oauth2/callback",
			"OAUTH2_PROXY_EMAIL_DOMAINS=" + strings.Join(oauthConfig.EmailDomains, ","),
			"OAUTH2_PROXY_OIDC_GROUPS_CLAIM=" + groupsClaim,
			"OAUTH2_PROXY_SCOPE=" + scope,
			"OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256",
			"OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true",
		}

		// Add custom endpoint URLs if provided, otherwise construct from issuer URL
		if oauthConfig.LoginUrl != nil || oauthConfig.RedeemUrl != nil || oauthConfig.JwksUrl != nil || oauthConfig.ValidateUrl != nil {
			// If any custom endpoint is provided, enable manual discovery mode
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_SKIP_OIDC_DISCOVERY=true")

			if oauthConfig.LoginUrl != nil {
				oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_LOGIN_URL="+*oauthConfig.LoginUrl)
			} else {
				oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_LOGIN_URL="+oauthConfig.IssuerUrl+"/protocol/openid-connect/auth")
			}

			if oauthConfig.RedeemUrl != nil {
				oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_REDEEM_URL="+*oauthConfig.RedeemUrl)
			} else {
				oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_REDEEM_URL="+oauthConfig.IssuerUrl+"/protocol/openid-connect/token")
			}

			if oauthConfig.JwksUrl != nil {
				oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_OIDC_JWKS_URL="+*oauthConfig.JwksUrl)
			} else {
				oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_OIDC_JWKS_URL="+oauthConfig.IssuerUrl+"/protocol/openid-connect/certs")
			}

			if oauthConfig.ValidateUrl != nil {
				oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_VALIDATE_URL="+*oauthConfig.ValidateUrl)
			} else {
				oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_VALIDATE_URL="+oauthConfig.IssuerUrl+"/protocol/openid-connect/userinfo")
			}
		} else if strings.Contains(oauthConfig.IssuerUrl, "localhost") {
			oauthEnvVars = append(oauthEnvVars,
				"OAUTH2_PROXY_SKIP_OIDC_DISCOVERY=true",
				"OAUTH2_PROXY_OIDC_JWKS_URL="+oauthConfig.IssuerUrl+"/protocol/openid-connect/certs",
				"OAUTH2_PROXY_LOGIN_URL="+oauthConfig.IssuerUrl+"/protocol/openid-connect/auth",
				"OAUTH2_PROXY_REDEEM_URL="+oauthConfig.IssuerUrl+"/protocol/openid-connect/token",
				"OAUTH2_PROXY_VALIDATE_URL="+oauthConfig.IssuerUrl+"/protocol/openid-connect/userinfo")
		}

		// Add optional flags
		if oauthConfig.SetAuthorizationHeader != nil && *oauthConfig.SetAuthorizationHeader {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_SET_AUTHORIZATION_HEADER=true")
		}
		if oauthConfig.PassAccessToken != nil && *oauthConfig.PassAccessToken {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_PASS_ACCESS_TOKEN=true")
		}

		// Add localhost-specific SSL settings if needed
		if strings.Contains(oauthConfig.IssuerUrl, "localhost") {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY=true")
		}

		if len(oauthConfig.AllowedGroups) > 0 {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_ALLOWED_GROUPS="+strings.Join(oauthConfig.AllowedGroups, ","))
		}

		// Add oauth environment variables to bitswanEditor
		bitswanEditor["environment"] = append(bitswanEditor["environment"].([]string), oauthEnvVars...)
	}

	// Append MQTT env variables when workspace is connected to AOC
	if len(mqttEnvVars) > 0 {
		bitswanEditor["environment"] = append(bitswanEditor["environment"].([]string), mqttEnvVars...)
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
func (e *EditorService) Enable(gitopsSecretToken, bitswanEditorImage, domain string, oauthConfig *oauth.Config) error {
	// Check if already enabled
	if e.IsEnabled() {
		return fmt.Errorf("Editor service is already enabled for workspace '%s'", e.WorkspaceName)
	}

	// Create codeserver config directory
	codeserverConfigDir := filepath.Join(e.WorkspacePath, "codeserver-config")
	if err := os.MkdirAll(codeserverConfigDir, 0700); err != nil {
		return fmt.Errorf("failed to create codeserver config directory: %w", err)
	}

	hostOsTmp := runtime.GOOS
	secretsDir := filepath.Join(e.WorkspacePath, "secrets")
	gitopsWorkspace := filepath.Join(e.WorkspacePath, "workspace")

	if hostOsTmp == "linux" {
		// Change ownership for Linux
		chownCom := exec.Command("sudo", "chown", "-R", "1000:1000", secretsDir)
		if err := e.runCommand(chownCom); err != nil {
			return fmt.Errorf("failed to change ownership of secrets folder: %w", err)
		}
		chownCom = exec.Command("sudo", "chown", "-R", "1000:1000", codeserverConfigDir)
		if err := e.runCommand(chownCom); err != nil {
			return fmt.Errorf("failed to change ownership of codeserver config folder: %w", err)
		}
		chownCom = exec.Command("sudo", "chown", "-R", "1000:1000", gitopsWorkspace)
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
	dockerComposeContent, err := e.CreateDockerCompose(gitopsSecretToken, bitswanEditorImage, domain, oauthConfig, mqttEnvVars)
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

	// Remove codeserver config directory
	codeserverConfigDir := filepath.Join(e.WorkspacePath, "codeserver-config")
	if err := os.RemoveAll(codeserverConfigDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove codeserver-config directory: %w", err)
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

// getLatestVersion gets the latest version from DockerHub
func (e *EditorService) getLatestVersion() (string, error) {
	return dockerhub.GetLatestEditorVersion()
}
