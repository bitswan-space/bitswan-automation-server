package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
	"github.com/bitswan-space/bitswan-workspaces/internal/ssh"
)

// GetWorkspaceList returns a list of workspaces with optional detailed information
func GetWorkspaceList(long, showPasswords bool) (*WorkspaceListResponse, error) {
	// Use HOME for file operations (works inside container and outside)
	// The workspace files are accessible via the container path
	homeDir := os.Getenv("HOME")
	bitswanDir := filepath.Join(homeDir, ".config", "bitswan")
	workspacesDir := filepath.Join(bitswanDir, "workspaces")

	var workspaces []WorkspaceInfo

	// Check if workspaces directory exists
	if _, err := os.Stat(workspacesDir); !os.IsNotExist(err) {
		files, err := os.ReadDir(workspacesDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read workspaces directory: %w", err)
		}
		for _, file := range files {
			if file.IsDir() {
				workspaceName := file.Name()
				workspaceInfo := WorkspaceInfo{
					Name: workspaceName,
				}

				if long {
					// Get metadata
					domain, editorURL, gitopsURL := getMetaData(workspaceName, workspacesDir)
					workspaceInfo.Domain = domain
					workspaceInfo.EditorURL = editorURL
					workspaceInfo.GitopsURL = gitopsURL

					// Get SSH public key
					workspacePath := filepath.Join(workspacesDir, workspaceName)
					if ssh.SSHKeyExists(workspacePath) {
						publicKey, err := ssh.GetSSHPublicKey(workspacePath)
						if err == nil {
							workspaceInfo.SSHPublicKey = strings.TrimSpace(publicKey)
						}
					}
				}

				if showPasswords {
					// Get VSCode server password
					editorService, err := services.NewEditorService(workspaceName)
					if err == nil {
						vscodePassword, _ := editorService.GetEditorPassword()
						workspaceInfo.VSCodePassword = vscodePassword
					}

					// Get GitOps secret
					gitopsSecret, _ := getGitOpsSecret(workspaceName, workspacesDir)
					workspaceInfo.GitopsSecret = gitopsSecret
				}

				workspaces = append(workspaces, workspaceInfo)
			}
		}
	}

	// Get active workspace
	cfg := config.NewAutomationServerConfig()
	activeWorkspace, _ := cfg.GetActiveWorkspace()

	return &WorkspaceListResponse{
		Workspaces:      workspaces,
		ActiveWorkspace: activeWorkspace,
	}, nil
}

func getMetaData(workspaceName string, workspacesDir string) (string, string, string) {
	// Path to metadata.yaml file
	metadataPath := filepath.Join(workspacesDir, workspaceName, "metadata.yaml")

	// Check if metadata file exists
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		return "", "", ""
	}

	// Read metadata file
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return "", "", ""
	}

	// Parse YAML
	var metadata struct {
		Domain    string `yaml:"domain"`
		EditorURL string `yaml:"editor-url"`
		GitopsURL string `yaml:"gitops-url"`
	}

	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return "", "", ""
	}

	return metadata.Domain, metadata.EditorURL, metadata.GitopsURL
}

func getGitOpsSecret(workspace string, workspacesDir string) (string, error) {
	// Read docker-compose.yml file
	composeFilePath := filepath.Join(workspacesDir, workspace, "deployment", "docker-compose.yml")

	data, err := os.ReadFile(composeFilePath)
	if err != nil {
		return "", err
	}

	// Parse YAML to extract the secret
	var composeConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &composeConfig); err != nil {
		return "", err
	}

	// Navigate through the YAML structure to find the secret
	services, ok := composeConfig["services"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("services section not found")
	}

	editorService, ok := services["bitswan-gitops"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("editor service not found")
	}

	env, ok := editorService["environment"].([]interface{})
	if !ok {
		return "", fmt.Errorf("environment section not found")
	}

	// Look for the BITSWAN_GITOPS_SECRET in the environment variables
	for _, item := range env {
		envVar, ok := item.(string)
		if !ok {
			continue
		}

		if strings.HasPrefix(envVar, "BITSWAN_GITOPS_SECRET=") {
			parts := strings.SplitN(envVar, "=", 2)
			if len(parts) == 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("GitOps secret not found")
}

