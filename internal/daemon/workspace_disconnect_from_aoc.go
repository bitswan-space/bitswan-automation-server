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

	// 2. Clean up workspace metadata and OAuth configs
	fmt.Println("Cleaning up workspace configurations...")
	if err := cleanupWorkspaceAOCConfig(); err != nil {
		fmt.Printf("Warning: Failed to clean up some workspace configs: %v\n", err)
	}

	// 3. Clear AOC settings from the main config
	fmt.Println("Removing AOC credentials...")
	cfg := config.NewAutomationServerConfig()
	if err := cfg.ClearAOCSettings(); err != nil {
		return fmt.Errorf("failed to clear AOC settings: %w", err)
	}

	fmt.Println("\nSuccessfully disconnected from AOC.")
	return nil
}

// cleanupWorkspaceAOCConfig removes OAuth config files and clears MQTT metadata from all workspaces
func cleanupWorkspaceAOCConfig() error {
	homeDir := os.Getenv("HOME")
	workspacesDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces")

	entries, err := os.ReadDir(workspacesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read workspaces directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		workspaceName := entry.Name()
		workspacePath := filepath.Join(workspacesDir, workspaceName)

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

	return nil
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
