package dockercompose

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/certauthority"
	"github.com/dchest/uniuri"
	"gopkg.in/yaml.v3"
)

type OS int

const (
	WindowsMac OS = iota
	Linux
)

// DockerComposeConfig holds the configuration required for creating a docker-compose file
type DockerComposeConfig struct {
	GitopsPath         string
	WorkspaceName      string
	GitopsImage        string
	Domain             string
	MqttEnvVars        []string
	AocEnvVars         []string
	OAuthEnvVars       []string
	GitopsDevSourceDir string
	TrustCA            bool
}

// CreateDockerComposeFile creates a docker-compose YAML content and returns it along with the generated secret token
func (config *DockerComposeConfig) CreateDockerComposeFile() (string, string, error) {
	return config.CreateDockerComposeFileWithSecret("")
}

// CreateDockerComposeFileWithSecret creates a docker-compose YAML content with an optional existing secret
func (config *DockerComposeConfig) CreateDockerComposeFileWithSecret(existingSecret string) (string, string, error) {
	// Convert container path to host path for volume mounts (docker-compose runs on host)
	// But use container path for file operations
	gitopsPathForVolumes := config.GitopsPath
	homeDir := os.Getenv("HOME")
	hostHomeDir := os.Getenv("HOST_HOME")
	if hostHomeDir != "" && homeDir != hostHomeDir && strings.HasPrefix(config.GitopsPath, homeDir) {
		// Replace container home with host home for docker-compose volume paths
		gitopsPathForVolumes = strings.Replace(config.GitopsPath, homeDir, hostHomeDir, 1)
	}
	
	sshDir := gitopsPathForVolumes + "/ssh"
	gitConfig := os.Getenv("HOME") + "/.gitconfig"

	hostOsTmp := runtime.GOOS

	var hostOs OS
	switch hostOsTmp {
	case "windows", "darwin":
		hostOs = WindowsMac
	case "linux":
		hostOs = Linux
	default:
		return "", "", fmt.Errorf("unsupported host OS: %s", hostOsTmp)
	}

	// Use existing secret if provided, otherwise generate a new one
	var gitopsSecretToken string
	if existingSecret != "" {
		gitopsSecretToken = existingSecret
	} else {
		gitopsSecretToken = uniuri.NewLen(64)
	}

	gitopsService := map[string]interface{}{
		"image":    config.GitopsImage,
		"restart":  "always",
		"hostname": config.WorkspaceName + "-gitops",
		"networks": []string{"bitswan_network"},
		"volumes": []string{
			gitopsPathForVolumes + "/gitops:/gitops/gitops:z",
			gitopsPathForVolumes + "/secrets:/gitops/secrets:z",
			sshDir + ":/home/user1000/.ssh:z",
			"/var/run/docker.sock:/var/run/docker.sock",
		},
		"environment": []string{
			"BITSWAN_GITOPS_DIR=/gitops",
			"BITSWAN_GITOPS_DIR_HOST=" + gitopsPathForVolumes,
			"BITSWAN_GITOPS_SECRET=" + gitopsSecretToken,
			"BITSWAN_GITOPS_DOMAIN=" + config.Domain,
			"BITSWAN_WORKSPACE_NAME=" + config.WorkspaceName,
		},
	}

	// Append AOC env variables when workspace is registered as an automation server
	if len(config.AocEnvVars) > 0 {
		gitopsService["environment"] = append(gitopsService["environment"].([]string), config.AocEnvVars...)
	}

	// Append MQTT env variables when workspace is registered as an automation server
	if len(config.MqttEnvVars) > 0 {
		gitopsService["environment"] = append(gitopsService["environment"].([]string), config.MqttEnvVars...)
	}

	// Append OAuth env variables when OAuth is configured
	if len(config.OAuthEnvVars) > 0 {
		gitopsService["environment"] = append(gitopsService["environment"].([]string), config.OAuthEnvVars...)
		// Add oauth2-proxy binary path as environment variable
		oauth2ProxyPath := os.Getenv("HOME") + "/.config/bitswan/oauth2-proxy"
		gitopsService["environment"] = append(gitopsService["environment"].([]string), "OAUTH2_PROXY_PATH="+oauth2ProxyPath)
	}

	// Add dev source directory volume mount and DEBUG env var if provided
	if config.GitopsDevSourceDir != "" {
		gitopsService["volumes"] = append(gitopsService["volumes"].([]string), config.GitopsDevSourceDir+":/src:z")
		gitopsService["environment"] = append(gitopsService["environment"].([]string), "DEBUG=true")
	}

	// Mount certificate authorities if specified
	caVolumes, caEnvVars := certauthority.GetCACertMountConfig(config.TrustCA)
	if len(caVolumes) > 0 {
		gitopsService["volumes"] = append(gitopsService["volumes"].([]string), caVolumes...)
		gitopsService["environment"] = append(gitopsService["environment"].([]string), caEnvVars...)
	}

	// Add workspace directory mount and rewrite git path for all OS
	workspaceDir := gitopsPathForVolumes + "/workspace/:/workspace-repo/:z"
	if hostOs == WindowsMac {
		gitopsVolumes := []string{
			gitConfig + ":/root/.gitconfig:z",
			workspaceDir,
		}
		gitopsService["volumes"] = append(gitopsService["volumes"].([]string), gitopsVolumes...)
	} else if hostOs == Linux {
		// For Linux, also mount workspace directory
		gitopsVolumes := []string{
			workspaceDir,
		}
		gitopsService["volumes"] = append(gitopsService["volumes"].([]string), gitopsVolumes...)
	}

	// Rewrite .git in worktree for all OS to use container path
	gitdir := "gitdir: /workspace-repo/.git/worktrees/gitops"
	if err := os.WriteFile(config.GitopsPath+"/gitops/.git", []byte(gitdir), 0644); err != nil {
		return "", "", fmt.Errorf("failed to rewrite gitops worktree .git file: %w", err)
	}

	// Construct the docker-compose data structure
	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"bitswan-gitops": gitopsService,
		},
		"networks": map[string]interface{}{
			"bitswan_network": map[string]interface{}{
				"external": true,
			},
		},
	}

	var buf bytes.Buffer

	// Serialize the docker-compose data structure to YAML and write it to the file
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2) // Optional: Set indentation
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", "", fmt.Errorf("failed to encode docker-compose data structure: %w", err)
	}

	return buf.String(), gitopsSecretToken, nil
}

func CreateCaddyDockerComposeFile(caddyPath string) (string, error) {
	caddyVolumes := []string{
		caddyPath + "/Caddyfile:/etc/caddy/Caddyfile:z",
		caddyPath + "/data:/data:z",
		caddyPath + "/config:/config:z",
		caddyPath + "/certs:/tls:z",
	}

	// Construct the docker-compose data structure
	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"caddy": map[string]interface{}{
				"image":          "caddy:2.9",
				"restart":        "always",
				"container_name": "caddy",
				"ports":          []string{"80:80", "443:443", "2019:2019"},
				"networks":       []string{"bitswan_network"},
				"volumes":        caddyVolumes,
				"entrypoint":     []string{"caddy", "run", "--resume", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"},
			},
		},
		"networks": map[string]interface{}{
			"bitswan_network": map[string]interface{}{
				"external": true,
			},
		},
	}

	var buf bytes.Buffer

	// Serialize the docker-compose data structure to YAML and write it to the file
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2) // Optional: Set indentation
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("failed to encode docker-compose data structure: %w", err)
	}

	return buf.String(), nil
}
