package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/workspace"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}


type ApiListResponse[T any] struct {
	Status   string  `json:"status"`            // "success" or "error"
	Message  *string `json:"message,omitempty"` // optional
	Count    int     `json:"count"`
	Next     *string `json:"next"`     // can be null
	Previous *string `json:"previous"` // can be null
	Results  []T     `json:"results"`
}

type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type AutomationServer struct {
	AutomationServerId string `json:"automation_server_id"`
}


func newRegisterCmd() *cobra.Command {
	var serverName string
	var aocUrl string
	intervalSeconds := 5

	cmd := &cobra.Command{
		Use:          "register",
		Short:        "Register automation server with AOC",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := sendRequest("POST", fmt.Sprintf("%s/api/cli/register/", aocUrl), nil, "")
			if err != nil {
				return fmt.Errorf("error sending request: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to register workspace: %s", resp.Status)
			}

			var deviceAuthorizationResponse DeviceAuthorizationResponse
			body, _ := io.ReadAll(resp.Body)
			err = json.Unmarshal([]byte(body), &deviceAuthorizationResponse)
			if err != nil {
				return fmt.Errorf("error decoding JSON: %w", err)
			}

			fmt.Printf("Please visit the following URL to authorize the device:\n%s\n", deviceAuthorizationResponse.VerificationURIComplete)

			for {
				resp, err = sendRequest("GET", fmt.Sprintf(
					"%s/api/cli/register?device_code=%s", aocUrl, deviceAuthorizationResponse.DeviceCode), nil, "")
				if err != nil {
					return fmt.Errorf("error sending request: %w", err)
				}

				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					break
				}

				// Parse error response
				var errResp map[string]interface{}
				body, _ = io.ReadAll(resp.Body)
				if err := json.Unmarshal(body, &errResp); err != nil {
					return fmt.Errorf("error parsing error response: %v", err)
				}

				switch errResp["error"] {
				case "authorization_pending":
					// keep polling
				case "slow_down":
					intervalSeconds += 5
				case "expired_token", "access_denied":
					return fmt.Errorf("authorization failed: %s", errResp["error"])
				default:
					return fmt.Errorf("unexpected error: %s", errResp["error"])
				}

				// Wait before next poll
				time.Sleep(time.Duration(intervalSeconds) * time.Second)
			}

			var tokenResponse TokenResponse
			body, _ = io.ReadAll(resp.Body)
			err = json.Unmarshal([]byte(body), &tokenResponse)
			if err != nil {
				return fmt.Errorf("error decoding JSON: %w", err)
			}

			resp, err = sendRequest("GET", fmt.Sprintf("%s/api/orgs", aocUrl), nil, tokenResponse.AccessToken)
			if err != nil {
				return fmt.Errorf("error sending request: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to get user organizations: %s", resp.Status)
			}

			var orgListResponse ApiListResponse[Org]
			body, _ = io.ReadAll(resp.Body)
			err = json.Unmarshal([]byte(body), &orgListResponse)
			if err != nil {
				return fmt.Errorf("error decoding JSON: %w", err)
			}

			if orgListResponse.Count == 0 {
				return fmt.Errorf("no organizations found")
			}

			orgs := []string{}
			for _, org := range orgListResponse.Results {
				orgs = append(orgs, org.Name)
			}

			var orgId string
			if orgListResponse.Count > 1 {
				prompt := promptui.Select{
					Label: "You belong to multiple organizations. Select an Organization",
					Items: orgs,
				}

				_, result, err := prompt.Run()
				if err != nil {
					return fmt.Errorf("error selecting organization: %w", err)
				}

				for _, org := range orgListResponse.Results {
					if org.Name == result {
						orgId = org.ID
						break
					}
				}
			} else {
				orgId = orgListResponse.Results[0].ID
			}

			payload, err := json.Marshal(map[string]interface{}{
				"keycloak_org_id": orgId,
				"name":            serverName,
			})
			if err != nil {
				return fmt.Errorf("error marshalling payload: %w", err)
			}

			resp, err = sendRequest(
				"POST", fmt.Sprintf("%s/api/automation-servers/", aocUrl), payload, tokenResponse.AccessToken)
			if err != nil {
				return fmt.Errorf("error sending request: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("failed to register automation server: %s", resp.Status)
			}

			var automationServer AutomationServer
			body, _ = io.ReadAll(resp.Body)
			err = json.Unmarshal([]byte(body), &automationServer)
			if err != nil {
				return fmt.Errorf("error decoding JSON: %w", err)
			}

			err = saveAutomationServerYaml(
				aocUrl,
				automationServer.AutomationServerId,
				tokenResponse.AccessToken,
			)
			if err != nil {
				return fmt.Errorf("error saving automation server yaml: %w", err)
			}

			fmt.Printf("✅ Successfully registered workspace as automation server. You can close the browser tab.\n")
			fmt.Println("Access token, AOC BE URL, and Automation server ID have been saved to ~/.config/bitswan/aoc/automation_server.yaml.")

			// Now connect existing workspaces to AOC
			fmt.Println("\n🔗 Connecting existing workspaces to AOC...")
			return connectExistingWorkspacesToAOC(aocUrl, automationServer.AutomationServerId, tokenResponse.AccessToken)
		},
	}

	cmd.Flags().StringVar(&serverName, "name", "", "Server name")
	cmd.Flags().StringVar(&aocUrl, "aoc-api", "https://api.bitswan.space", "Automation operation server URL")

	return cmd
}

func sendRequest(method, url string, payload []byte, bearerToken string) (*http.Response, error) {
	// Create a new GET request
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))

	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set the request headers
	req.Header.Add("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	// Create HTTP client and send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %w", err)
	}
	return resp, nil
}

func saveAutomationServerYaml(aocUrl string, automationServerId string, accessToken string) error {
	automationServerYaml := aoc.AutomationServerYaml{
		AOCUrl:             aocUrl,
		AutomationServerId: automationServerId,
		AccessToken:        accessToken,
	}

	aocDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "aoc")

	// Marshal to YAML
	yamlData, err := yaml.Marshal(automationServerYaml)
	if err != nil {
		return fmt.Errorf("failed to marshal automation server yaml: %w", err)
	}

	// Write to file
	automationServerYamlPath := filepath.Join(aocDir, "automation_server.yaml")
	if err := os.WriteFile(automationServerYamlPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write automation server yaml file: %w", err)
	}

	return nil

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

	var metadata workspace.MetadataInit
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal metadata.yaml: %w", err)
	}

	// Create AOC client
	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		return fmt.Errorf("failed to create AOC client: %w", err)
	}

	// Get automation server token
	fmt.Printf("  🔑 Getting automation server token...\n")
	_, err = aocClient.GetAutomationServerToken()
	if err != nil {
		return fmt.Errorf("failed to get automation server token: %w", err)
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
		return fmt.Errorf("failed to get MQTT credentials: %w", err)
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
	yamlData, err := yaml.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}

	fmt.Printf("  ✅ Metadata updated successfully!\n")

	// Actually update the workspace deployment  
	fmt.Printf("  🔄 Updating workspace deployment with new AOC and MQTT configuration...\n")
	if err := workspace.UpdateWorkspaceDeployment(workspaceName); err != nil {
		return fmt.Errorf("failed to update workspace deployment: %w", err)
	}
	fmt.Printf("  ✅ Workspace deployment updated and services restarted!\n")
	
	return nil
}


