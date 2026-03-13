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
	fmt.Println("Disconnecting MQTT connection...")
	publisher := GetMQTTPublisher()
	publisher.Disconnect()
	fmt.Println("MQTT connection disconnected.")

	// 2. Clean up workspace metadata and OAuth configs, collect workspace names
	fmt.Println("Cleaning up workspace configurations...")
	workspaceNames, err := cleanupWorkspaceAOCConfig()
	if err != nil {
		fmt.Printf("Warning: Failed to clean up some workspace configs: %v\n", err)
	}

	// 3. Clear AOC settings from the main config
	fmt.Println("Removing AOC credentials...")
	cfg := config.NewAutomationServerConfig()
	if err := cfg.ClearAOCSettings(); err != nil {
		return fmt.Errorf("failed to clear AOC settings: %w", err)
	}

	// 4. Regenerate docker-compose files and restart services for each workspace
	// This removes OAuth/MQTT env vars from docker-compose and restarts editor/gitops
	if len(workspaceNames) > 0 {
		fmt.Println("\nUpdating workspace deployments...")
		for _, name := range workspaceNames {
			fmt.Printf("\n🔄 Updating workspace '%s'...\n", name)
			if err := s.runWorkspaceUpdate([]string{name}); err != nil {
				fmt.Printf("  Warning: Failed to update workspace '%s': %v\n", name, err)
				continue
			}
			fmt.Printf("  ✅ Workspace '%s' updated and services restarted.\n", name)
		}
	}

	fmt.Println("\nSuccessfully disconnected from AOC.")
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
				fmt.Printf("  Warning: Failed to remove %s: %v\n", oauthConfigPath, err)
			} else {
				fmt.Printf("  Removed OAuth config for workspace '%s'\n", workspaceName)
			}
		}

		// Clear MQTT and workspace_id fields from metadata.yaml
		metadataPath := filepath.Join(workspacePath, "metadata.yaml")
		if err := clearWorkspaceAOCMetadata(metadataPath, workspaceName); err != nil {
			fmt.Printf("  Warning: Failed to update metadata for workspace '%s': %v\n", workspaceName, err)
		}
	}

	return workspaceNames, nil
}

// clearWorkspaceAOCMetadata clears AOC-related fields from a workspace's metadata.yaml
func clearWorkspaceAOCMetadata(metadataPath, workspaceName string) error {
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

	if err := metadata.SaveToFile(metadataPath); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	fmt.Printf("  Cleared AOC metadata for workspace '%s'\n", workspaceName)
	return nil
}
