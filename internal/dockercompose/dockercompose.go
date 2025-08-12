package dockercompose

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

	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
	"github.com/dchest/uniuri"
	"gopkg.in/yaml.v3"
)

type OS int

const (
	WindowsMac OS = iota
	Linux
)

func CreateDockerComposeFile(gitopsPath, workspaceName, gitopsImage, bitswanEditorImage, domain string, noIde bool, mqttEnvVars []string, aocEnvVars []string, oauthConfig *oauth.Config) (string, string, error) {
	sshDir := os.Getenv("HOME") + "/.ssh"
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

	// generate a random secret token
	gitopsSecretToken := uniuri.NewLen(64)

	gitopsService := map[string]interface{}{
		"image":    gitopsImage,
		"restart":  "always",
		"hostname": workspaceName + "-gitops",
		"networks": []string{"bitswan_network"},
		"volumes": []string{
			gitopsPath + "/gitops:/gitops/gitops:z",
			gitopsPath + "/secrets:/gitops/secrets:z",
			sshDir + ":/root/.ssh:z",
			"/var/run/docker.sock:/var/run/docker.sock",
		},
		"environment": []string{
			"BITSWAN_GITOPS_DIR=/gitops",
			"BITSWAN_GITOPS_DIR_HOST=" + gitopsPath,
			"BITSWAN_GITOPS_SECRET=" + gitopsSecretToken,
			"BITSWAN_GITOPS_DOMAIN=" + domain,
			"BITSWAN_WORKSPACE_NAME=" + workspaceName,
		},
	}

	// Append AOC env variables when workspace is registered as an automation server
	if len(aocEnvVars) > 0 {
		gitopsService["environment"] = append(gitopsService["environment"].([]string), aocEnvVars...)
	}

	// Append AOC env variables when workspace is registered as an automation server
	if len(mqttEnvVars) > 0 {
		gitopsService["environment"] = append(gitopsService["environment"].([]string), mqttEnvVars...)
	}

	if hostOs == WindowsMac {
		gitopsVolumes := []string{
			gitConfig + ":/root/.gitconfig:z",
			gitopsPath + "/workspace/.git:/workspace-repo/.git:z",
		}

		gitopsService["volumes"] = append(gitopsService["volumes"].([]string), gitopsVolumes...)

		// Rewrite .git in worktree because it's calling git command inside the container (only for Windows and Mac)
		gitdir := "gitdir: /workspace-repo/.git/worktrees/gitops"
		if err := os.WriteFile(gitopsPath+"/gitops/.git", []byte(gitdir), 0644); err != nil {
			return "", "", fmt.Errorf("failed to rewrite gitops worktree .git file: %w", err)
		}
	} else if hostOs == Linux {
		gitopsService["privileged"] = true
		gitopsService["pid"] = "host"

		gitopsEnvVars := []string{
			"HOST_PATH=$PATH",
			"HOST_HOME=$HOME",
			"HOST_USER=$USER",
		}
		gitopsService["environment"] = append(gitopsService["environment"].([]string), gitopsEnvVars...)
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

	if !noIde {
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
			oauthEnvVars := []string{
				"OAUTH_ENABLED=true", // This is the trigger entrypoint script
				"OAUTH2_PROXY_PROVIDER=keycloak-oidc",
				"OAUTH2_PROXY_CLIENT_ID=" + oauthConfig.ClientId,
				"OAUTH2_PROXY_CLIENT_SECRET=" + oauthConfig.ClientSecret,
				"OAUTH2_PROXY_COOKIE_SECRET=" + oauthConfig.CookieSecret,
				"OAUTH2_PROXY_OIDC_ISSUER_URL=" + oauthConfig.IssuerUrl,
				"OAUTH2_PROXY_REDIRECT_URL=https://" + fmt.Sprintf("%s-editor", workspaceName) + "." + domain + "/oauth2/callback",
				"OAUTH2_PROXY_EMAIL_DOMAINS=" + strings.Join(oauthConfig.EmailDomains, ","),
				"OAUTH2_PROXY_OIDC_GROUPS_CLAIM=group_membership",
				"OAUTH2_PROXY_SCOPE=openid email profile group_membership",
				"OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256",
				"OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true",
			}

			if len(oauthConfig.AllowedGroups) > 0 {
				oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_ALLOWED_GROUPS="+strings.Join(oauthConfig.AllowedGroups, ","))
			}

			bitswanEditor["environment"] = append(bitswanEditor["environment"].([]string), oauthEnvVars...)

		}

		dockerCompose["services"].(map[string]interface{})["bitswan-editor"] = bitswanEditor
		dockerCompose["volumes"] = map[string]interface{}{
			"bitswan-editor-data": nil,
		}
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

func CreateCaddyDockerComposeFile(caddyPath, domain string) (string, error) {
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

type EditorConfig struct {
	BindAddress string `yaml:"bind-addr"`
	Auth        string `yaml:"auth"`
	Password    string `yaml:"password"`
	Cert        bool   `yaml:"cert"`
}

func GetEditorPassword(workspaceName string) (string, error) {
	// Once the editor is ready, get the password
	getBitswanEditorPasswordCom := exec.Command("docker", "exec", workspaceName+"-site-bitswan-editor-1", "cat", "/home/coder/.config/code-server/config.yaml")
	out, err := getBitswanEditorPasswordCom.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Bitswan Editor password: %w", err)
	}

	var editorConfig EditorConfig
	if err := yaml.Unmarshal(out, &editorConfig); err != nil {
		return "", fmt.Errorf("failed to unmarshal editor config: %w", err)
	}

	return editorConfig.Password, nil
}

func WaitForEditorReady(workspaceName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "compose", "-p", workspaceName+"-site", "logs", "-f", "bitswan-editor")

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
