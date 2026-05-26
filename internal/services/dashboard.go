package services

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/certauthority"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
	"gopkg.in/yaml.v3"
)

// DashboardService manages the workspace-dashboard sidecar deployment for a workspace.
// It owns its own docker-compose-dashboard.yml file and lifecycle, fully independent
// from EditorService
type DashboardService struct {
	WorkspaceName string
	WorkspacePath string
}

// NewDashboardService creates a new Dashboard service manager.
func NewDashboardService(workspaceName string) (*DashboardService, error) {
	homeDir := os.Getenv("HOME")
	workspacePath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)

	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace '%s' does not exist", workspaceName)
	}

	return &DashboardService{
		WorkspaceName: workspaceName,
		WorkspacePath: workspacePath,
	}, nil
}

// DashboardDevConfig holds dev mode configuration for the dashboard.
// Dev mode is implied by a non-empty SourceDir — there's no separate flag.
type DashboardDevConfig struct {
	SourceDir string
}

// CreateDockerCompose generates docker-compose-dashboard.yml content.
func (d *DashboardService) CreateDockerCompose(gitopsSecretToken, bitswanDashboardImage, domain string, oauthConfig *oauth.Config, mqttEnvVars []string, trustCA bool) (string, error) {
	return d.CreateDockerComposeWithDevMode(gitopsSecretToken, bitswanDashboardImage, domain, oauthConfig, mqttEnvVars, trustCA, nil)
}

// CreateDockerComposeWithDevMode generates the dashboard's docker-compose file with optional dev-mode mount.
func (d *DashboardService) CreateDockerComposeWithDevMode(gitopsSecretToken, bitswanDashboardImage, domain string, oauthConfig *oauth.Config, mqttEnvVars []string, trustCA bool, devConfig *DashboardDevConfig) (string, error) {
	homeDir := os.Getenv("HOME")
	hostHomeDir := os.Getenv("HOST_HOME")
	if hostHomeDir == "" {
		hostHomeDir = homeDir
	}

	gitopsPath := d.WorkspacePath
	if homeDir != hostHomeDir && strings.HasPrefix(gitopsPath, homeDir) {
		gitopsPath = strings.Replace(gitopsPath, homeDir, hostHomeDir, 1)
	}

	workspaceName := d.WorkspaceName

	bitswanDashboard := map[string]interface{}{
		"image":    bitswanDashboardImage,
		"restart":  "always",
		"hostname": workspaceName + "-dashboard",
		"networks": []string{"bitswan_network"},
		"environment": []string{
			"BITSWAN_WORKSPACE_NAME=" + workspaceName,
			"BITSWAN_DEPLOY_URL=" + fmt.Sprintf("http://%s-gitops:8079", workspaceName),
			"BITSWAN_DEPLOY_SECRET=" + gitopsSecretToken,
			"PORT=8080",
			"INTERNAL_PORT=8081",
		},
		"volumes": []string{
			gitopsPath + "/workspace:/workspace/workspace:z",
			// SSH key for connecting to the coding-agent container. Shared
			// with bitswan-editor — the dashboard authenticates as the same
			// principal that's already in the agent's authorized_keys.
			gitopsPath + "/ssh:/workspace/.ssh:ro",
			// Read-only view of session transcripts (.meta.json + .cast)
			// written by the coding-agent wrapper, for the dashboard's
			// session list + asciinema playback.
			gitopsPath + "/coding-agent-sessions:/workspace/agent-sessions:ro",
			// Read-only view of the coding-agent's $HOME so the dashboard can
			// resolve per-user Claude transcripts (`.claude_<slug>/projects/...`)
			// as well as the legacy shared `.claude/projects/...` for session
			// titles. Mounting the whole home rather than just `.claude` lets
			// the dashboard see every user's config dir without us hard-coding
			// the slug set.
			gitopsPath + "/coding-agent-home:/workspace/agent-home:ro",
		},
	}

	if oauthConfig != nil {
		dashboardOAuthEnvVars := oauth.CreateOAuthEnvVars(oauthConfig, "dashboard", workspaceName, domain)
		bitswanDashboard["environment"] = append(bitswanDashboard["environment"].([]string), dashboardOAuthEnvVars...)
		if extraHosts := oauth.BuildExtraHosts(oauthConfig); len(extraHosts) > 0 {
			bitswanDashboard["extra_hosts"] = extraHosts
		}
	}

	if len(mqttEnvVars) > 0 {
		bitswanDashboard["environment"] = append(bitswanDashboard["environment"].([]string), mqttEnvVars...)
	}

	caVolumes, caEnvVars := certauthority.GetCACertMountConfig(trustCA)
	if len(caVolumes) > 0 {
		bitswanDashboard["volumes"] = append(bitswanDashboard["volumes"].([]string), caVolumes...)
		bitswanDashboard["environment"] = append(bitswanDashboard["environment"].([]string), caEnvVars...)
	}

	// Hot-reload dev mode: mount the source directory and let the container's
	// entrypoint run `npm install` + `npm run dev` instead of the pre-built bundle.
	if devConfig != nil && devConfig.SourceDir != "" {
		dashboardDevContainerPath := "/workspace/dashboard-src"
		bitswanDashboard["volumes"] = append(bitswanDashboard["volumes"].([]string),
			devConfig.SourceDir+":"+dashboardDevContainerPath+":z")
		bitswanDashboard["environment"] = append(bitswanDashboard["environment"].([]string),
			"BITSWAN_DEV_MODE=true",
			"BITSWAN_DASHBOARD_DEV_DIR="+dashboardDevContainerPath,
		)
	}

	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"bitswan-dashboard": bitswanDashboard,
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
		return "", fmt.Errorf("failed to encode dashboard docker-compose: %w", err)
	}
	return buf.String(), nil
}

// SaveDockerCompose writes docker-compose-dashboard.yml to the workspace deployment directory.
func (d *DashboardService) SaveDockerCompose(content string) error {
	deploymentDir := filepath.Join(d.WorkspacePath, "deployment")
	if err := os.MkdirAll(deploymentDir, 0755); err != nil {
		return fmt.Errorf("failed to create deployment directory: %w", err)
	}
	dockerComposePath := filepath.Join(deploymentDir, "docker-compose-dashboard.yml")
	if err := os.WriteFile(dockerComposePath, []byte(content), 0755); err != nil {
		return fmt.Errorf("failed to write docker-compose-dashboard.yml: %w", err)
	}
	fmt.Printf("Dashboard docker-compose saved to: %s\n", dockerComposePath)
	return nil
}

// Enable generates docker-compose-dashboard.yml from metadata + the supplied image and OAuth config.
func (d *DashboardService) Enable(gitopsSecretToken, bitswanDashboardImage, domain string, oauthConfig *oauth.Config, trustCA bool) error {
	if d.IsEnabled() {
		return fmt.Errorf("Dashboard service is already enabled for workspace '%s'", d.WorkspaceName)
	}

	metadata, _ := d.GetMetadata()

	var mqttEnvVars []string
	if metadata != nil && metadata.MqttUsername != nil {
		mqttEnvVars = append(mqttEnvVars, "MQTT_USERNAME="+*metadata.MqttUsername)
		mqttEnvVars = append(mqttEnvVars, "MQTT_PASSWORD="+*metadata.MqttPassword)
		mqttEnvVars = append(mqttEnvVars, "MQTT_BROKER="+*metadata.MqttBroker)
		mqttEnvVars = append(mqttEnvVars, "MQTT_PORT="+fmt.Sprint(*metadata.MqttPort))
		mqttEnvVars = append(mqttEnvVars, "MQTT_TOPIC="+*metadata.MqttTopic)
	}

	if oauthConfig != nil && metadata != nil && metadata.MqttUsername != nil {
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_BROKER="+*metadata.MqttBroker)
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_PORT="+fmt.Sprint(*metadata.MqttPort))
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_ALLOWED_GROUPS_TOPIC=/groups")
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_USERNAME="+*metadata.MqttUsername)
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_PASSWORD="+*metadata.MqttPassword)
	}

	// Dev-mode is purely a function of whether a source dir is set in metadata.
	var devConfig *DashboardDevConfig
	if metadata != nil && metadata.DashboardDevSourceDir != nil && *metadata.DashboardDevSourceDir != "" {
		devConfig = &DashboardDevConfig{SourceDir: *metadata.DashboardDevSourceDir}
		fmt.Printf("Dashboard dev mode enabled (source: %q)\n", devConfig.SourceDir)
	}

	content, err := d.CreateDockerComposeWithDevMode(gitopsSecretToken, bitswanDashboardImage, domain, oauthConfig, mqttEnvVars, trustCA, devConfig)
	if err != nil {
		return fmt.Errorf("failed to create docker-compose content: %w", err)
	}
	if err := d.SaveDockerCompose(content); err != nil {
		return err
	}
	fmt.Printf("Dashboard service enabled for workspace '%s'\n", d.WorkspaceName)
	return nil
}

// Disable removes the docker-compose file and stops the container.
func (d *DashboardService) Disable() error {
	if !d.IsEnabled() {
		return fmt.Errorf("Dashboard service is not enabled for workspace '%s'", d.WorkspaceName)
	}
	if d.IsContainerRunning() {
		if err := d.StopContainer(); err != nil {
			return fmt.Errorf("failed to stop dashboard container: %w", err)
		}
	}
	dockerComposePath := filepath.Join(d.WorkspacePath, "deployment", "docker-compose-dashboard.yml")
	if err := os.Remove(dockerComposePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove docker-compose-dashboard.yml: %w", err)
	}
	fmt.Printf("Dashboard service disabled for workspace '%s'\n", d.WorkspaceName)
	return nil
}

// IsEnabled returns true when the workspace has a docker-compose-dashboard.yml.
func (d *DashboardService) IsEnabled() bool {
	dockerComposePath := filepath.Join(d.WorkspacePath, "deployment", "docker-compose-dashboard.yml")
	_, err := os.Stat(dockerComposePath)
	return err == nil
}

// IsContainerRunning returns true when the dashboard container is running.
func (d *DashboardService) IsContainerRunning() bool {
	cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s-dashboard", d.WorkspaceName), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return len(lines) > 0 && lines[0] != ""
}

// StartContainer runs `docker compose up -d` against docker-compose-dashboard.yml.
func (d *DashboardService) StartContainer() error {
	deploymentDir := filepath.Join(d.WorkspacePath, "deployment")
	projectName := d.WorkspaceName + "-dashboard"
	cmd := exec.Command("docker", "compose", "-f", "docker-compose-dashboard.yml", "-p", projectName, "up", "-d", "--pull", "missing")
	cmd.Dir = deploymentDir
	fmt.Printf("Starting Dashboard container for workspace '%s'...\n", d.WorkspaceName)
	return d.runCommand(cmd)
}

// StopContainer runs `docker compose down` against docker-compose-dashboard.yml.
func (d *DashboardService) StopContainer() error {
	deploymentDir := filepath.Join(d.WorkspacePath, "deployment")
	projectName := d.WorkspaceName + "-dashboard"
	cmd := exec.Command("docker", "compose", "-f", "docker-compose-dashboard.yml", "-p", projectName, "down")
	cmd.Dir = deploymentDir
	fmt.Printf("Stopping Dashboard container for workspace '%s'...\n", d.WorkspaceName)
	return d.runCommand(cmd)
}

// WaitForDashboardReady blocks until the dashboard's Fastify server logs that it's listening,
// or the timeout expires.
func (d *DashboardService) WaitForDashboardReady() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	deploymentDir := filepath.Join(d.WorkspacePath, "deployment")
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", "docker-compose-dashboard.yml", "-p", d.WorkspaceName+"-dashboard", "logs", "-f", "bitswan-dashboard")
	cmd.Dir = deploymentDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start docker compose logs command: %w", err)
	}

	readyCh := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		acc := ""
		for {
			n, readErr := stdout.Read(buf)
			if n > 0 {
				acc += string(buf[:n])
				// Fastify logs include "Server listening at" or similar; be liberal.
				if strings.Contains(acc, "listening") || strings.Contains(acc, "Listening") {
					close(readyCh)
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	select {
	case <-readyCh:
		_ = cmd.Process.Kill()
		return nil
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		return fmt.Errorf("timeout waiting for dashboard server to be ready")
	}
}

// RegenerateDockerCompose fully regenerates docker-compose-dashboard.yml from metadata.
func (d *DashboardService) RegenerateDockerCompose(dashboardImage string, staging bool, trustCA bool) error {
	if !d.IsEnabled() {
		return fmt.Errorf("Dashboard service is not enabled for workspace '%s'", d.WorkspaceName)
	}

	metadata, err := d.GetMetadata()
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	var bitswanDashboardImage string
	if dashboardImage != "" {
		bitswanDashboardImage = dashboardImage
	} else {
		bitswanDashboardImage, err = dockerhub.ResolveDashboardImage(staging)
		if err != nil {
			return fmt.Errorf("failed to get latest workspace-dashboard image: %w", err)
		}
	}

	var mqttEnvVars []string
	if metadata.MqttUsername != nil {
		mqttEnvVars = append(mqttEnvVars, "MQTT_USERNAME="+*metadata.MqttUsername)
		mqttEnvVars = append(mqttEnvVars, "MQTT_PASSWORD="+*metadata.MqttPassword)
		mqttEnvVars = append(mqttEnvVars, "MQTT_BROKER="+*metadata.MqttBroker)
		mqttEnvVars = append(mqttEnvVars, "MQTT_PORT="+fmt.Sprint(*metadata.MqttPort))
		mqttEnvVars = append(mqttEnvVars, "MQTT_TOPIC="+*metadata.MqttTopic)
	}

	oauthConfig, oauthErr := oauth.GetOauthConfig(d.WorkspaceName)
	if oauthErr != nil {
		if metadata.WorkspaceId != nil && *metadata.WorkspaceId != "" {
			fmt.Printf("OAuth config not found locally for dashboard, attempting AOC fetch for workspace '%s'...\n", d.WorkspaceName)
			if aocClient, aocErr := aoc.NewAOCClient(); aocErr == nil {
				if fetched, fErr := aocClient.GetOAuthConfig(*metadata.WorkspaceId); fErr == nil {
					oauthConfig = fetched
					if saveErr := oauth.SaveOauthConfig(d.WorkspaceName, oauthConfig); saveErr != nil {
						fmt.Printf("Warning: failed to save OAuth config to disk: %v\n", saveErr)
					}
				} else {
					oauthConfig = nil
				}
			} else {
				oauthConfig = nil
			}
		} else {
			oauthConfig = nil
		}
	}

	if oauthConfig != nil && metadata.MqttUsername != nil {
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_BROKER="+*metadata.MqttBroker)
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_PORT="+fmt.Sprint(*metadata.MqttPort))
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_ALLOWED_GROUPS_TOPIC=/groups")
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_USERNAME="+*metadata.MqttUsername)
		mqttEnvVars = append(mqttEnvVars, "OAUTH2_PROXY_MQTT_PASSWORD="+*metadata.MqttPassword)
	}

	var devConfig *DashboardDevConfig
	if metadata.DashboardDevSourceDir != nil && *metadata.DashboardDevSourceDir != "" {
		devConfig = &DashboardDevConfig{SourceDir: *metadata.DashboardDevSourceDir}
		fmt.Printf("Dashboard dev mode enabled (source: %q)\n", devConfig.SourceDir)
	}

	content, err := d.CreateDockerComposeWithDevMode(
		metadata.GitopsSecret,
		bitswanDashboardImage,
		metadata.Domain,
		oauthConfig,
		mqttEnvVars,
		trustCA,
		devConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to create docker-compose content: %w", err)
	}
	if err := d.SaveDockerCompose(content); err != nil {
		return err
	}
	fmt.Printf("Dashboard docker-compose regenerated for workspace '%s'\n", d.WorkspaceName)
	return nil
}

// UpdateImage rewrites docker-compose-dashboard.yml with a new image tag.
// Used by `bitswan service dashboard update --dashboard-image`.
func (d *DashboardService) UpdateImage(newImage string) error {
	if newImage == "" {
		v, err := dockerhub.GetLatestDashboardVersion()
		if err != nil {
			return fmt.Errorf("failed to get latest dashboard version: %w", err)
		}
		newImage = "bitswan/workspace-dashboard:" + v
	}

	composePath := filepath.Join(d.WorkspacePath, "deployment", "docker-compose-dashboard.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose-dashboard.yml: %w", err)
	}
	var compose map[string]interface{}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return fmt.Errorf("failed to parse docker-compose-dashboard.yml: %w", err)
	}
	svcs, ok := compose["services"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("services section not found in docker-compose-dashboard.yml")
	}
	entry, ok := svcs["bitswan-dashboard"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("bitswan-dashboard service not found in docker-compose-dashboard.yml")
	}
	entry["image"] = newImage

	updated, err := yaml.Marshal(compose)
	if err != nil {
		return fmt.Errorf("failed to marshal updated docker-compose: %w", err)
	}
	if err := os.WriteFile(composePath, updated, 0644); err != nil {
		return fmt.Errorf("failed to write updated docker-compose-dashboard.yml: %w", err)
	}
	return nil
}

// UpdateToLatest pulls the latest non-staging tag.
func (d *DashboardService) UpdateToLatest() error {
	return d.UpdateImage("")
}

// GetMetadata reads workspace metadata using the centralized helper.
func (d *DashboardService) GetMetadata() (*config.WorkspaceMetadata, error) {
	metadata, err := config.GetWorkspaceMetadata(d.WorkspaceName)
	if err != nil {
		return nil, err
	}
	return &metadata, nil
}

func (d *DashboardService) runCommand(cmd *exec.Cmd) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}
