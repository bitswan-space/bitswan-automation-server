package workspace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"gopkg.in/yaml.v3"
)

// MetadataInit represents the workspace metadata structure
type MetadataInit struct {
	Domain             string  `yaml:"domain"`
	EditorURL          *string `yaml:"editor-url,omitempty"`
	GitopsURL          string  `yaml:"gitops-url"`
	GitopsSecret       string  `yaml:"gitops-secret"`
	WorkspaceId        *string `yaml:"workspace_id,omitempty"`
	MqttUsername       *string `yaml:"mqtt_username,omitempty"`
	MqttPassword       *string `yaml:"mqtt_password,omitempty"`
	MqttBroker         *string `yaml:"mqtt_broker,omitempty"`
	MqttPort           *int    `yaml:"mqtt_port,omitempty"`
	MqttTopic          *string `yaml:"mqtt_topic,omitempty"`
	GitopsDevSourceDir *string `yaml:"gitops-dev-source-dir,omitempty"`
}

// UpdateWorkspaceDeployment updates the workspace deployment with new AOC and MQTT configuration
func UpdateWorkspaceDeployment(workspaceName string, customGitopsImage ...string) error {
	workspacePath := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "workspaces", workspaceName)
	metadataPath := filepath.Join(workspacePath, "metadata.yaml")

	// Read metadata
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read metadata.yaml: %w", err)
	}

	var metadata MetadataInit
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal metadata.yaml: %w", err)
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

	// Prepare AOC environment variables
	var aocEnvVars []string
	aocClient, err := aoc.NewAOCClient()
	if err == nil && metadata.WorkspaceId != nil {
		automationServerToken, err := aocClient.GetAutomationServerToken()
		if err != nil {
			return fmt.Errorf("failed to get automation server token: %w", err)
		}
		aocEnvVars = aocClient.GetAOCEnvironmentVariables(*metadata.WorkspaceId, automationServerToken)
	}

	// Get gitops image - use custom image if provided, otherwise get latest
	var gitopsImage string
	if len(customGitopsImage) > 0 && customGitopsImage[0] != "" {
		gitopsImage = customGitopsImage[0]
		fmt.Printf("Using custom gitops image: %s\n", gitopsImage)
	} else {
		// Get latest gitops image
		gitopsLatestVersion, err := dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/gitops/tags/")
		if err != nil {
			fmt.Printf("    ⚠️  Failed to get latest gitops version, using 'latest': %v\n", err)
			gitopsLatestVersion = "latest"
		}
		gitopsImage = "bitswan/gitops:" + gitopsLatestVersion
	}

	// Get GitOps dev source directory if set
	var gitopsDevSourceDir string
	if metadata.GitopsDevSourceDir != nil {
		gitopsDevSourceDir = *metadata.GitopsDevSourceDir
	}

	// Create docker-compose configuration
	config := &dockercompose.DockerComposeConfig{
		GitopsPath:         workspacePath,
		WorkspaceName:      workspaceName,
		GitopsImage:        gitopsImage,
		Domain:             metadata.Domain,
		MqttEnvVars:        mqttEnvVars,
		AocEnvVars:         aocEnvVars,
		GitopsDevSourceDir: gitopsDevSourceDir,
	}

	// Use existing gitops secret
	compose, _, err := config.CreateDockerComposeFileWithSecret(metadata.GitopsSecret)
	if err != nil {
		return fmt.Errorf("failed to create docker-compose file: %w", err)
	}

	// Write the new docker-compose file
	dockerComposeFilePath := filepath.Join(workspacePath, "deployment", "docker-compose.yml")
	if err := os.WriteFile(dockerComposeFilePath, []byte(compose), 0755); err != nil {
		return fmt.Errorf("failed to write docker-compose file: %w", err)
	}

	// Restart gitops service
	dockerComposePath := filepath.Join(workspacePath, "deployment")
	projectName := workspaceName + "-site"
	
	commands := [][]string{
		{"docker", "compose", "down"},
		{"docker", "compose", "-p", projectName, "up", "-d", "--remove-orphans"},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dockerComposePath
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute %v: %w", args, err)
		}
	}

	return nil
}
