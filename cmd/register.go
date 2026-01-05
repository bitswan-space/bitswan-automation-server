package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)



func newRegisterCmd() *cobra.Command {
	var serverName string
	var aocUrl string
	var otp string
	var automationServerId string

	cmd := &cobra.Command{
		Use:          "register",
		Short:        "Register automation server with AOC using OTP",
		Long:         "Register automation server with AOC using OTP. Both the OTP and automation server ID must be obtained from the web interface.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if otp == "" {
				return fmt.Errorf("OTP is required. Use --otp flag to provide the OTP from the web interface")
			}

			if serverName == "" {
				return fmt.Errorf("server name is required. Use --name flag to provide a name for your automation server")
			}

			if automationServerId == "" {
				return fmt.Errorf("automation server ID is required. Use --server-id flag to provide the automation server ID from the web interface")
			}

			// Create AOC client with OTP
			aocClient, err := aoc.NewAOCClientWithOTP(aocUrl, otp, automationServerId)
			if err != nil {
				return fmt.Errorf("failed to create AOC client: %w", err)
			}

			// Get automation server info to verify connection
			serverInfo, err := aocClient.GetAutomationServerInfo()
			if err != nil {
				return fmt.Errorf("failed to get automation server info: %w", err)
			}

			// Save the configuration
			if err := aocClient.SaveConfig(); err != nil {
				return fmt.Errorf("failed to save configuration: %w", err)
			}

			fmt.Printf("✅ Successfully registered automation server '%s' with ID: %s\n", serverInfo.Name, serverInfo.AutomationServerId)
			fmt.Println("Access token, AOC URL, and Automation server ID have been saved to ~/.config/bitswan/automation_server_config.toml.")

			// Now connect existing workspaces to AOC
			fmt.Println("\n🔗 Connecting existing workspaces to AOC...")
			return connectExistingWorkspacesToAOC(aocUrl, serverInfo.AutomationServerId, aocClient.GetAccessToken())
		},
	}

	cmd.Flags().StringVar(&serverName, "name", "", "Server name (required)")
	cmd.Flags().StringVar(&aocUrl, "aoc-api", "https://api.bitswan.space", "Automation operation server URL")
	cmd.Flags().StringVar(&otp, "otp", "", "One-time password from web interface (required)")
	cmd.Flags().StringVar(&automationServerId, "server-id", "", "Automation server ID from web interface (required)")

	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("otp")
	cmd.MarkFlagRequired("server-id")

	return cmd
}


// connectExistingWorkspacesToAOC finds all existing workspaces and connects them to AOC
func connectExistingWorkspacesToAOC(aocUrl, automationServerId, accessToken string) error {
	workspacesDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "workspaces")

	// Check if directory exists
	if _, err := os.Stat(workspacesDir); os.IsNotExist(err) {
		fmt.Println("ℹ️  No existing workspaces found to connect to AOC.")
		return nil
	}

	// Read directory entries
	entries, err := os.ReadDir(workspacesDir)
	if err != nil {
		return fmt.Errorf("failed to read workspaces directory: %w", err)
	}

	var workspaceNames []string
	for _, entry := range entries {
		if entry.IsDir() {
			workspaceNames = append(workspaceNames, entry.Name())
		}
	}

	if len(workspaceNames) == 0 {
		fmt.Println("ℹ️  No existing workspaces found to connect to AOC.")
		return nil
	}

	fmt.Printf("📋 Found %d existing workspace(s) to connect to AOC:\n", len(workspaceNames))
	for _, name := range workspaceNames {
		fmt.Printf("  • %s\n", name)
	}

	// Process each workspace
	for i, workspaceName := range workspaceNames {
		fmt.Printf("\n🔄 Processing workspace %d/%d: %s\n", i+1, len(workspaceNames), workspaceName)

		if err := connectWorkspaceToAOC(workspaceName, aocUrl, automationServerId, accessToken); err != nil {
			fmt.Printf("❌ Failed to connect workspace '%s' to AOC: %v\n", workspaceName, err)
			continue
		}

		fmt.Printf("✅ Successfully connected workspace '%s' to AOC\n", workspaceName)
	}

	fmt.Println("\n🎉 All existing workspaces have been processed!")
	return nil
}

// connectWorkspaceToAOC connects a single workspace to AOC by updating its metadata and docker-compose
func connectWorkspaceToAOC(workspaceName, aocUrl, automationServerId, accessToken string) error {
	fmt.Printf("  📝 Reading existing metadata for workspace '%s'...\n", workspaceName)

	workspacePath := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "workspaces", workspaceName)
	metadataPath := filepath.Join(workspacePath, "metadata.yaml")

	// Check if metadata file exists
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		return fmt.Errorf("metadata.yaml not found for workspace '%s'", workspaceName)
	}

	// Read existing metadata
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read metadata.yaml: %w", err)
	}

	var metadata config.WorkspaceMetadata
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal metadata.yaml: %w", err)
	}

	// Create AOC client
	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		return fmt.Errorf("failed to create AOC client: %w", err)
	}

	// Register workspace with AOC if not already registered
	var workspaceId string
	if metadata.WorkspaceId == nil || *metadata.WorkspaceId == "" {
		fmt.Printf("  🆕 Registering workspace '%s' with AOC...\n", workspaceName)
		workspaceId, err = aocClient.RegisterWorkspace(workspaceName, metadata.EditorURL)
		if err != nil {
			return fmt.Errorf("failed to register workspace with AOC: %w", err)
		}
		fmt.Printf("  ✅ Workspace registered with ID: %s\n", workspaceId)
	} else {
		workspaceId = *metadata.WorkspaceId
		fmt.Printf("  ℹ️  Workspace already registered with ID: %s\n", workspaceId)
	}

	// Get MQTT credentials for the workspace
	fmt.Printf("  📡 Getting MQTT credentials for workspace...\n")
	mqttCreds, err := aocClient.GetMQTTCredentials(workspaceId)
	if err != nil {
		// Check if this is a 404 error, which means the workspace was deleted from AOC
		if strings.Contains(err.Error(), "404 Not Found") {
			fmt.Printf("  ⚠️  Workspace ID %s not found in AOC (404), clearing and re-registering...\n", workspaceId)

			// Clear the workspace ID from metadata
			metadata.WorkspaceId = nil

			// Re-register the workspace with AOC
			fmt.Printf("  🆕 Re-registering workspace '%s' with AOC...\n", workspaceName)
			newWorkspaceId, err := aocClient.RegisterWorkspace(workspaceName, metadata.EditorURL)
			if err != nil {
				return fmt.Errorf("failed to re-register workspace with AOC: %w", err)
			}
			workspaceId = newWorkspaceId
			fmt.Printf("  ✅ Workspace re-registered with ID: %s\n", workspaceId)

			// Try to get MQTT credentials again with the new workspace ID
			fmt.Printf("  📡 Getting MQTT credentials for re-registered workspace...\n")
			mqttCreds, err = aocClient.GetMQTTCredentials(workspaceId)
			if err != nil {
				return fmt.Errorf("failed to get MQTT credentials for re-registered workspace: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get MQTT credentials: %w", err)
		}
	}
	fmt.Printf("  ✅ MQTT credentials received successfully!\n")

	// Update metadata with new MQTT credentials and workspace ID
	fmt.Printf("  💾 Updating metadata with MQTT credentials...\n")
	metadata.WorkspaceId = &workspaceId
	metadata.MqttUsername = &mqttCreds.Username
	metadata.MqttPassword = &mqttCreds.Password
	metadata.MqttBroker = &mqttCreds.Broker
	metadata.MqttPort = &mqttCreds.Port
	metadata.MqttTopic = &mqttCreds.Topic

	// Save updated metadata
	if err := metadata.SaveToFile(metadataPath); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	fmt.Printf("  ✅ Metadata updated successfully!\n")

	// Actually update the workspace deployment via daemon
	fmt.Printf("  🔄 Updating workspace deployment with new AOC and MQTT configuration...\n")
	client, err := daemon.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create daemon client (daemon may not be running): %w", err)
	}

	// Use workspace update command to refresh the deployment with new AOC/MQTT config
	updateArgs := []string{
		"workspace", "update",
		workspaceName,
	}
	if err := client.WorkspaceUpdate(updateArgs); err != nil {
		return fmt.Errorf("failed to update workspace deployment: %w", err)
	}
	fmt.Printf("  ✅ Workspace deployment updated and services restarted!\n")

	return nil
}


