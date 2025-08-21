package dockercompose

import (
	"bytes"
	"fmt"
	"os"
	"runtime"

	"github.com/dchest/uniuri"
	"gopkg.in/yaml.v3"
)

type OS int

const (
	WindowsMac OS = iota
	Linux
)


func CreateDockerComposeFile(gitopsPath, workspaceName, gitopsImage, domain string, mqttEnvVars []string, aocEnvVars []string, gitopsDevSourceDir string) (string, string, error) {
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

	// Append MQTT env variables when workspace is registered as an automation server
	if len(mqttEnvVars) > 0 {
		gitopsService["environment"] = append(gitopsService["environment"].([]string), mqttEnvVars...)
	}

	// Add dev source directory volume mount and DEBUG env var if provided
	if gitopsDevSourceDir != "" {
		gitopsService["volumes"] = append(gitopsService["volumes"].([]string), gitopsDevSourceDir+":/src:z")
		gitopsService["environment"] = append(gitopsService["environment"].([]string), "DEBUG=true")
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


