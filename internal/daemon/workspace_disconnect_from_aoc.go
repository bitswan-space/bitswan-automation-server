package daemon

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
	"github.com/bitswan-space/bitswan-workspaces/internal/workspace"
	"gopkg.in/yaml.v3"
)

// runDisconnectFromAOC disconnects from AOC by cleaning up all AOC-related config
func (s *Server) runDisconnectFromAOC() error {
	// 1. Stop MQTT monitor and disconnect
	stopMQTTMonitor()
	publisher := GetMQTTPublisher()
	publisher.Disconnect()

	// 2. Clean up workspace metadata and OAuth configs, collect deployable workspace names
	workspaceNames, err := cleanupWorkspaceAOCConfig()
	if err != nil {
		fmt.Printf("Warning: Failed to clean up some workspace configs: %v\n", err)
	}

	// 3. Clear AOC settings from the main config
	cfg := config.NewAutomationServerConfig()
	if err := cfg.ClearAOCSettings(); err != nil {
		return fmt.Errorf("failed to clear AOC settings: %w", err)
	}

	// 4. Regenerate docker-compose files and restart services for each workspace
	if len(workspaceNames) > 0 {
		fmt.Printf("Restarting %d workspace(s)...\n", len(workspaceNames))
		for _, name := range workspaceNames {
			fmt.Printf("  Restarting '%s'...\n", name)
			if err := restartWorkspace(name); err != nil {
				fmt.Printf("  Warning: Failed to restart workspace '%s': %v\n", name, err)
			}
		}
	}

	// 5. Fix file ownership — the daemon runs as root so files we wrote
	//    (metadata.yaml, docker-compose files) end up root-owned.
	homeDir := os.Getenv("HOME")
	workspacesDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces")
	if err := chownRecursive(workspacesDir); err != nil {
		fmt.Printf("Warning: Failed to fix file ownership: %v\n", err)
	}

	fmt.Println("\nDisconnected from AOC.")
	return nil
}

// restartWorkspace regenerates docker-compose files and restarts gitops + editor
// for a single workspace. Unlike runWorkspaceUpdate this skips example updates
// and does not wait for the editor health check.
func restartWorkspace(workspaceName string) error {
	// Regenerate and restart gitops
	if err := workspace.UpdateWorkspaceDeployment(workspaceName, "", false, false); err != nil {
		return fmt.Errorf("gitops: %w", err)
	}

	// Regenerate and restart editor if enabled
	editorService, err := services.NewEditorService(workspaceName)
	if err != nil {
		return nil // workspace doesn't exist or isn't set up, skip
	}
	if !editorService.IsEnabled() {
		return nil
	}

	if err := editorService.StopContainer(); err != nil {
		return fmt.Errorf("editor stop: %w", err)
	}
	if err := fixEditorPermissions(workspaceName); err != nil {
		return fmt.Errorf("editor permissions: %w", err)
	}
	if err := editorService.RegenerateDockerCompose("", false, false); err != nil {
		return fmt.Errorf("editor regenerate: %w", err)
	}
	if err := editorService.StartContainer(); err != nil {
		return fmt.Errorf("editor start: %w", err)
	}

	return nil
}

// cleanupWorkspaceAOCConfig removes OAuth config files and clears MQTT metadata from all workspaces.
// Returns the list of workspace names that have a full deployment (metadata.yaml + deployment dir)
// and should be restarted.
func cleanupWorkspaceAOCConfig() ([]string, error) {
	homeDir := os.Getenv("HOME")
	workspacesDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces")

	entries, err := os.ReadDir(workspacesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read workspaces directory: %w", err)
	}

	var deployableWorkspaces []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		workspaceName := entry.Name()
		workspacePath := filepath.Join(workspacesDir, workspaceName)
		metadataPath := filepath.Join(workspacePath, "metadata.yaml")
		deploymentDir := filepath.Join(workspacePath, "deployment")

		// Remove oauth-config.yaml if present
		oauthConfigPath := filepath.Join(workspacePath, "oauth-config.yaml")
		if _, err := os.Stat(oauthConfigPath); err == nil {
			if err := os.Remove(oauthConfigPath); err != nil {
				fmt.Printf("  Warning: Failed to remove OAuth config for workspace '%s': %v\n", workspaceName, err)
			}
		}

		// Clear MQTT and workspace_id fields from metadata.yaml
		if err := clearWorkspaceAOCMetadata(metadataPath); err != nil {
			continue
		}

		// Only restart workspaces that have a full deployment
		if _, err := os.Stat(deploymentDir); err == nil {
			deployableWorkspaces = append(deployableWorkspaces, workspaceName)
		}
	}

	return deployableWorkspaces, nil
}

// clearWorkspaceAOCMetadata clears AOC-related fields from a workspace's metadata.yaml
func clearWorkspaceAOCMetadata(metadataPath string) error {
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var metadata config.WorkspaceMetadata
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	metadata.WorkspaceId = nil
	metadata.MqttUsername = nil
	metadata.MqttPassword = nil
	metadata.MqttBroker = nil
	metadata.MqttPort = nil
	metadata.MqttTopic = nil

	return metadata.SaveToFile(metadataPath)
}
