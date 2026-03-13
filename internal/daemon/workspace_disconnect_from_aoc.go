package daemon

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"gopkg.in/yaml.v3"
)

// runDisconnectFromAOC disconnects from AOC by cleaning up all AOC-related config
func (s *Server) runDisconnectFromAOC() error {
	// 1. Disconnect MQTT
	publisher := GetMQTTPublisher()
	publisher.Disconnect()

	// 2. Clean up workspace metadata and OAuth configs, collect workspace names
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
			if err := s.runWorkspaceUpdate([]string{name}); err != nil {
				fmt.Printf("  Warning: Failed to restart workspace '%s': %v\n", name, err)
			}
		}
	}

	// 5. Fix file ownership — the daemon runs as root so files we wrote
	//    (metadata.yaml, docker-compose files) end up root-owned.
	//    Restore ownership to user 1000 for the entire workspaces directory.
	homeDir := os.Getenv("HOME")
	workspacesDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces")
	if err := chownRecursive(workspacesDir); err != nil {
		fmt.Printf("Warning: Failed to fix file ownership: %v\n", err)
	}

	fmt.Println("\nDisconnected from AOC.")
	return nil
}

// cleanupWorkspaceAOCConfig removes OAuth config files and clears MQTT metadata from all workspaces.
// Returns the list of workspace names that were cleaned up.
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

	var workspaceNames []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		workspaceName := entry.Name()
		workspacePath := filepath.Join(workspacesDir, workspaceName)
		workspaceNames = append(workspaceNames, workspaceName)

		// Remove oauth-config.yaml
		oauthConfigPath := filepath.Join(workspacePath, "oauth-config.yaml")
		if _, err := os.Stat(oauthConfigPath); err == nil {
			if err := os.Remove(oauthConfigPath); err != nil {
				fmt.Printf("  Warning: Failed to remove OAuth config for workspace '%s': %v\n", workspaceName, err)
			}
		}

		// Clear MQTT and workspace_id fields from metadata.yaml
		metadataPath := filepath.Join(workspacePath, "metadata.yaml")
		if err := clearWorkspaceAOCMetadata(metadataPath); err != nil {
			fmt.Printf("  Warning: Failed to clear metadata for workspace '%s': %v\n", workspaceName, err)
		}
	}

	return workspaceNames, nil
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
