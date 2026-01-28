package workspace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
	"gopkg.in/yaml.v3"
)

// UpdateWorkspaceDeployment updates the workspace deployment with new AOC and MQTT configuration
func UpdateWorkspaceDeployment(workspaceName string, customGitopsImage string, staging bool, trustCA bool) error {
	// Use HOME for file operations (works inside container and outside)
	// The workspace files are accessible via the container path
	homeDir := os.Getenv("HOME")
	workspacePath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)
	metadataPath := filepath.Join(workspacePath, "metadata.yaml")

	// Read metadata
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read metadata.yaml: %w", err)
	}

	var metadata config.WorkspaceMetadata
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
			// AOC is not configured or token is not available, skip AOC env vars
			// This is not a fatal error - workspace can function without AOC
		} else {
			aocEnvVars = aocClient.GetAOCEnvironmentVariables(*metadata.WorkspaceId, automationServerToken)
		}
	}

	// Create OAuth environment variables for GitOps if OAuth is configured (optional)
	var oauthEnvVars []string
	var keycloakURL string
	oauthConfig, _ := oauth.GetOauthConfig(workspaceName)
	if oauthConfig != nil {
		oauthEnvVars = oauth.CreateOAuthEnvVars(oauthConfig, "gitops", workspaceName, metadata.Domain)
		keycloakURL = oauthConfig.IssuerUrl
	}

	// Get gitops image - use custom image if provided, otherwise get latest
	var gitopsImage string
	if customGitopsImage != "" {
		gitopsImage = customGitopsImage
		fmt.Printf("Using custom gitops image: %s\n", gitopsImage)
	} else {
		// Get latest gitops image
		var gitopsLatestVersion string
		var err error
		if staging {
			gitopsLatestVersion, err = dockerhub.GetLatestGitopsStagingVersion()
			if err != nil {
				fmt.Printf("    ⚠️  Failed to get latest gitops-staging version, using 'latest': %v\n", err)
				gitopsLatestVersion = "latest"
			}
			gitopsImage = "bitswan/gitops-staging:" + gitopsLatestVersion
		} else {
			gitopsLatestVersion, err = dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/gitops/tags/")
			if err != nil {
				fmt.Printf("    ⚠️  Failed to get latest gitops version, using 'latest': %v\n", err)
				gitopsLatestVersion = "latest"
			}
			gitopsImage = "bitswan/gitops:" + gitopsLatestVersion
		}
	}

	// Get GitOps dev source directory if set
	var gitopsDevSourceDir string
	if metadata.GitopsDevSourceDir != nil {
		gitopsDevSourceDir = *metadata.GitopsDevSourceDir
	}

	// Pass container path to CreateDockerComposeFileWithSecret
	// It needs container path for file operations, but will convert to host path for volume mounts
	// Create docker-compose configuration
	config := &dockercompose.DockerComposeConfig{
		GitopsPath:         workspacePath,
		WorkspaceName:      workspaceName,
		GitopsImage:        gitopsImage,
		Domain:             metadata.Domain,
		MqttEnvVars:        mqttEnvVars,
		AocEnvVars:         aocEnvVars,
		OAuthEnvVars:       oauthEnvVars,
		GitopsDevSourceDir: gitopsDevSourceDir,
		TrustCA:            trustCA,
		KeycloakURL:        keycloakURL,
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

	fmt.Println("Stopping existing GitOps containers...")
	downCmd := exec.Command("docker", "compose", "down")
	downCmd.Dir = dockerComposePath
	downCmd.Stdout = os.Stdout
	downCmd.Stderr = os.Stderr
	if err := downCmd.Run(); err != nil {
		return fmt.Errorf("failed to stop containers: %w", err)
	}
	fmt.Println("GitOps containers stopped.")

	fmt.Println("Starting GitOps containers...")
	upCmd := exec.Command("docker", "compose", "-p", projectName, "up", "-d", "--remove-orphans")
	upCmd.Dir = dockerComposePath
	upCmd.Stdout = os.Stdout
	upCmd.Stderr = os.Stderr
	if err := upCmd.Run(); err != nil {
		return fmt.Errorf("failed to start containers: %w", err)
	}
	fmt.Println("GitOps containers restarted successfully!")

	return nil
}
