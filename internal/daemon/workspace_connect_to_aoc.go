package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"gopkg.in/yaml.v3"
)

// WorkspaceConnectToAOCRequest represents the request to connect workspaces to AOC
type WorkspaceConnectToAOCRequest struct {
	AOCUrl             string `json:"aoc_url"`
	AutomationServerId string `json:"automation_server_id"`
	AccessToken        string `json:"access_token"`
}

// runWorkspaceConnectToAOC connects all existing workspaces to AOC
func (s *Server) runWorkspaceConnectToAOC(req WorkspaceConnectToAOCRequest) error {
	// Use HOME directly - inside container this is /root
	homeDir := os.Getenv("HOME")
	workspacesDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces")

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

		if err := s.connectWorkspaceToAOC(workspaceName, req.AOCUrl, req.AutomationServerId, req.AccessToken); err != nil {
			fmt.Printf("❌ Failed to connect workspace '%s' to AOC: %v\n", workspaceName, err)
			continue
		}

		fmt.Printf("✅ Successfully connected workspace '%s' to AOC\n", workspaceName)
	}

	fmt.Println("\n🎉 All existing workspaces have been processed!")
	return nil
}

// connectWorkspaceToAOC connects a single workspace to AOC by updating its metadata and docker-compose
func (s *Server) connectWorkspaceToAOC(workspaceName, aocUrl, automationServerId, accessToken string) error {
	fmt.Printf("  📝 Reading existing metadata for workspace '%s'...\n", workspaceName)

	// Use HOME directly - inside container this is /root
	homeDir := os.Getenv("HOME")
	workspacePath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)
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
		workspaceId, err = aocClient.RegisterWorkspace(workspaceName, metadata.EditorURL, metadata.Domain)
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
			newWorkspaceId, err := aocClient.RegisterWorkspace(workspaceName, metadata.EditorURL, metadata.Domain)
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

	// Save updated metadata (daemon runs as root, so no permission issues)
	if err := metadata.SaveToFile(metadataPath); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	fmt.Printf("  ✅ Metadata updated successfully!\n")

	// Actually update the workspace deployment via daemon
	fmt.Printf("  🔄 Updating workspace deployment with new AOC and MQTT configuration...\n")
	
	// Use workspace update command to refresh the deployment with new AOC/MQTT config
	// runWorkspaceUpdate expects just the workspace name (it parses flags internally)
	updateArgs := []string{workspaceName}
	if err := s.runWorkspaceUpdate(updateArgs); err != nil {
		return fmt.Errorf("failed to update workspace deployment: %w", err)
	}
	fmt.Printf("  ✅ Workspace deployment updated and services restarted!\n")

	return nil
}
