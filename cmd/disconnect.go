package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func newDisconnectFromAOCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "disconnect-from-aoc",
		Short:        "Disconnect automation server from AOC",
		Long:         "Disconnect this automation server from its current AOC instance. This removes AOC credentials, OAuth config, and MQTT settings from workspace metadata. Workspaces and their data are preserved.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if actually registered
			cfg := config.NewAutomationServerConfig()
			settings, err := cfg.GetAutomationOperationsCenterSettings()
			if err != nil || settings.AccessToken == "" {
				return fmt.Errorf("this automation server is not registered to any AOC instance")
			}

			fmt.Printf("This automation server is registered to AOC at %s (server ID: %s).\n\n", settings.AOCUrl, settings.AutomationServerId)
			fmt.Println("Disconnecting will:")
			fmt.Println("  - Remove AOC credentials from the server config")
			fmt.Println("  - Remove OAuth config files from all workspaces")
			fmt.Println("  - Clear MQTT connection settings from workspace metadata")
			fmt.Println("  - Disconnect the MQTT connection")
			fmt.Println()
			fmt.Println("Your workspaces and their data will NOT be deleted.")
			fmt.Println()
			fmt.Print("Type 'yes' to confirm: ")

			reader := bufio.NewReader(os.Stdin)
			confirmation, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}

			if strings.TrimSpace(confirmation) != "yes" {
				fmt.Println("Disconnect cancelled.")
				return nil
			}

			fmt.Println()

			// 1. Disconnect MQTT via daemon
			fmt.Println("Disconnecting MQTT connection...")
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Printf("Warning: Could not connect to daemon: %v\n", err)
				fmt.Println("MQTT will be disconnected when the daemon restarts.")
			} else {
				if err := client.DisconnectMQTT(); err != nil {
					fmt.Printf("Warning: Failed to disconnect MQTT: %v\n", err)
				} else {
					fmt.Println("MQTT connection disconnected.")
				}
			}

			// 2. Clean up workspace metadata and OAuth configs
			fmt.Println("Cleaning up workspace configurations...")
			if err := cleanupWorkspaceAOCConfig(); err != nil {
				fmt.Printf("Warning: Failed to clean up some workspace configs: %v\n", err)
			}

			// 3. Clear AOC settings from the main config
			fmt.Println("Removing AOC credentials...")
			if err := cfg.ClearAOCSettings(); err != nil {
				return fmt.Errorf("failed to clear AOC settings: %w", err)
			}

			fmt.Println()
			fmt.Println("Successfully disconnected from AOC.")
			fmt.Println("You can register with a new AOC instance using 'bitswan register'.")

			return nil
		},
	}

	return cmd
}

// cleanupWorkspaceAOCConfig removes OAuth config files and clears MQTT metadata from all workspaces
func cleanupWorkspaceAOCConfig() error {
	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

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

	// Clear AOC-related fields
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
