package dockercompose

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
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
	LocalRemotePath    string // Host path to local repository (if using local remote)
	LocalRemoteName    string // Mount name for local repository (used for mount point path)
	KeycloakURL        string // Keycloak base URL for authentication
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

	// Container manager sidecar: workspace-scoped Docker socket proxy.
	// Gitops talks to this instead of the real Docker socket.
	composeProject := strings.ToLower(config.WorkspaceName) + "-site"
	// Container manager gets its own socket directory so it doesn't
	// share /var/run/bitswan/ with the daemon socket (which would
	// let gitops bypass the proxy via the daemon).
	cmSocketDir := "/var/run/bitswan-cm-" + config.WorkspaceName
	containerManagerService := map[string]interface{}{
		"image":          "bitswan/container-manager:latest",
		"restart":        "always",
		"container_name": config.WorkspaceName + "-container-manager",
		"networks":       []string{"bitswan_network"},
		"volumes": []string{
			"/var/run/docker.sock:/var/run/docker.sock:ro",
			cmSocketDir + ":" + cmSocketDir,
		},
		"environment": []string{
			"BITSWAN_WORKSPACE_NAME=" + config.WorkspaceName,
			"BITSWAN_COMPOSE_PROJECT=" + composeProject,
			"CONTAINER_MANAGER_SOCKET=" + cmSocketDir + "/container-manager.sock",
		},
	}

	// Mount built-in automation templates so the gitops `template_service`
	// can scaffold new automations from the same `examples/` tree the editor
	// reads. The path mirrors the computation in editor.go.
	bitswanSrcPath := filepath.Dir(filepath.Dir(gitopsPathForVolumes)) + "/bitswan-src"

	gitopsService := map[string]interface{}{
		"image":    config.GitopsImage,
		"restart":  "always",
		"hostname": config.WorkspaceName + "-gitops",
		"networks": []string{"bitswan_network"},
		"depends_on": []string{"container-manager"},
		"volumes": []string{
			gitopsPathForVolumes + "/gitops:/gitops/gitops:z",
			gitopsPathForVolumes + "/secrets:/gitops/secrets:z",
			sshDir + ":/home/user1000/.ssh:z",
			// Container-manager socket for Docker operations
			cmSocketDir + ":" + cmSocketDir + ":ro",
			// Daemon socket for ingress route registration (read-only)
			"/var/run/bitswan:/var/run/bitswan:ro",
			// Built-in automation templates for the gitops template_service.
			bitswanSrcPath + "/examples:/workspace/examples:ro",
		},
		"environment": []string{
			"BITSWAN_GITOPS_DIR=/gitops",
			"BITSWAN_GITOPS_DIR_HOST=" + gitopsPathForVolumes,
			"BITSWAN_GITOPS_SECRET=" + gitopsSecretToken,
			"BITSWAN_GITOPS_DOMAIN=" + config.Domain,
			"BITSWAN_WORKSPACE_NAME=" + config.WorkspaceName,
			"BITSWAN_STAGE_NETWORKS=true",
			"BITSWAN_CERTS_DIR=" + homeDir + "/.config/bitswan/certauthorities",
			// Docker operations go through the container-manager proxy
			"DOCKER_HOST=unix://" + cmSocketDir + "/container-manager.sock",
		},
	}

	// Add Keycloak URL if configured
	if config.KeycloakURL != "" {
		gitopsService["environment"] = append(gitopsService["environment"].([]string), "KEYCLOAK_URL="+config.KeycloakURL)
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
	
	// If this workspace has a local remote repository, mount it so GitOps can access it
	if config.LocalRemotePath != "" && config.LocalRemoteName != "" {
		// Mount local repository to /remote-repos/<name> for GitOps to access
		// The mount name is used to construct the mount point path
		localRemoteMount := config.LocalRemotePath + ":/remote-repos/" + config.LocalRemoteName + ":ro"
		gitopsService["volumes"] = append(gitopsService["volumes"].([]string), localRemoteMount)
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
			"bitswan-gitops":    gitopsService,
			"container-manager": containerManagerService,
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

// CreateTraefikDockerComposeFile creates a docker-compose file for global Traefik.
// networks parameter is optional - if provided, adds those networks along with bitswan_network.
func CreateTraefikDockerComposeFile(traefikPath string, networks ...string) (string, error) {
	traefikVolumes := []string{
		traefikPath + "/traefik.yml:/etc/traefik/traefik.yml:z",
		traefikPath + "/certs:/tls:z",
		traefikPath + "/acme:/acme:z",
		"/var/run/docker.sock:/var/run/docker.sock:ro",
	}

	traefikNetworks := []string{"bitswan_network"}
	traefikNetworks = append(traefikNetworks, networks...)

	networksMap := map[string]interface{}{
		"bitswan_network": map[string]interface{}{
			"external": true,
		},
	}
	for _, network := range networks {
		networksMap[network] = map[string]interface{}{
			"external": true,
		}
	}

	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"traefik": map[string]interface{}{
				"image":          "traefik:v3.6",
				"restart":        "always",
				"container_name": "traefik",
				"ports":          []string{"80:80", "443:443", "127.0.0.1:9080:8080"},
				"networks":       traefikNetworks,
				"volumes":        traefikVolumes,
			},
		},
		"networks": networksMap,
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("failed to encode docker-compose data structure: %w", err)
	}

	return buf.String(), nil
}

// CreateVPNTraefikDockerComposeFile creates a docker-compose file for the VPN-internal Traefik.
// It has no host ports — only reachable from VPN clients via the WireGuard server.
// traefikPath: path to the VPN traefik config directory (e.g., ~/.config/bitswan/traefik-protected)
func CreateVPNTraefikDockerComposeFile(traefikPath string, certDirs ...string) (string, error) {
	traefikVolumes := []string{
		traefikPath + "/traefik.yml:/etc/traefik/traefik.yml:z",
		traefikPath + "/tls-config.yml:/etc/traefik/tls-config.yml:ro",
	}
	// Mount CA cert directory for TLS if provided
	for _, certDir := range certDirs {
		if certDir != "" {
			traefikVolumes = append(traefikVolumes, certDir+":/certs:ro")
		}
	}

	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"traefik-protected": map[string]interface{}{
				"image":          "traefik:v3.6",
				"restart":        "always",
				"container_name": "traefik-protected",
				// No host ports — only reachable from VPN subnet
				"networks": []string{"bitswan_network", "bitswan_protected_network"},
				"volumes":  traefikVolumes,
			},
		},
		"networks": map[string]interface{}{
			"bitswan_network": map[string]interface{}{
				"external": true,
			},
			"bitswan_protected_network": map[string]interface{}{
				"external": true,
			},
		},
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("failed to encode docker-compose data structure: %w", err)
	}

	return buf.String(), nil
}


// CreateWorkspaceTraefikDockerComposeFile creates a docker-compose file for workspace sub-traefik.
// workspaceName: name of the workspace (used for container name)
// traefikPath: path to traefik config directory
// domain: the public domain — used to generate Docker labels so the global Traefik auto-discovers this sub-traefik.
// networks: list of additional networks (bitswan_network is always included)
func CreateWorkspaceTraefikDockerComposeFile(workspaceName, traefikPath, domain string, networks []string) (string, error) {
	traefikVolumes := []string{
		traefikPath + "/traefik.yml:/etc/traefik/traefik.yml:z",
		// Mount the dynamic config directory for the file provider
		traefikPath + ":/dynamic:ro",
	}

	traefikNetworks := []string{"bitswan_network"}
	traefikNetworks = append(traefikNetworks, networks...)

	networksMap := map[string]interface{}{
		"bitswan_network": map[string]interface{}{
			"external": true,
		},
	}
	for _, network := range networks {
		networksMap[network] = map[string]interface{}{
			"external": true,
		}
	}

	containerName := fmt.Sprintf("%s__traefik", workspaceName)

	// Workspace's own traefik. Deliberately NOT exposing any
	// `traefik.enable=true` docker labels — those would auto-create
	// routes on the platform traefik via the docker provider, which
	// is exactly what we don't want: the workspace traefik should
	// only be reachable through the protected-ingress chain
	// (bitswan-protected-proxy → MFA gate → traefik-protected →
	// <ws>__traefik:80 → workspace service). Platform-traefik routes
	// for <ws>-editor.<domain> are pushed via REST to point at
	// bitswan-protected-proxy. Keeping all routing inside the
	// protected chain keeps every endpoint internal-by-default and
	// preserves docker network isolation.
	serviceMap := map[string]interface{}{
		"image":          "traefik:v3.6",
		"restart":        "always",
		"container_name": containerName,
		"networks":       traefikNetworks,
		"volumes":        traefikVolumes,
		// `traefik.enable=false` makes the intent explicit — even if
		// the platform traefik's docker provider enumerates this
		// container (which it does, since we share bitswan_network),
		// it won't try to discover routes on it.
		"labels": map[string]string{"traefik.enable": "false"},
	}
	_ = domain // domain no longer used for labels (kept for compatibility)

	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"traefik": serviceMap,
		},
		"networks": networksMap,
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("failed to encode docker-compose data structure: %w", err)
	}

	return buf.String(), nil
}
