package aoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// AutomationServerYaml represents the automation server configuration
type AutomationServerYaml struct {
	AOCUrl             string `yaml:"aoc_url"`
	AutomationServerId string `yaml:"automation_server_id"`
	AccessToken        string `yaml:"access_token"`
}

// AutomationServerTokenResponse represents the automation server token response
type AutomationServerTokenResponse struct {
	Token string `json:"token"`
}

// WorkspacePostResponse represents the response from workspace registration
type WorkspacePostResponse struct {
	Id                 string `json:"id"`
	Name               string `json:"name"`
	KeycloakOrgId      string `json:"keycloak_org_id"`
	AutomationServerId string `json:"automation_server_id"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

// EmqxGetResponse represents the EMQX JWT response
type EmqxGetResponse struct {
	Url   string `json:"url"`
	Token string `json:"token"`
}

// MQTTCredentials contains MQTT connection information
type MQTTCredentials struct {
	Username string
	Password string
	Broker   string
	Port     int
	Topic    string
}

// AOCClient handles AOC API interactions
type AOCClient struct {
	config *AutomationServerYaml
}

// NewAOCClient creates a new AOC client from the automation server config
func NewAOCClient() (*AOCClient, error) {
	bitswanConfig := os.Getenv("HOME") + "/.config/bitswan/"
	automationServerConfig := filepath.Join(bitswanConfig, "aoc", "automation_server.yaml")
	
	if _, err := os.Stat(automationServerConfig); os.IsNotExist(err) {
		return nil, fmt.Errorf("automation server config not found")
	}

	yamlFile, err := os.ReadFile(automationServerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to read automation_server.yaml: %w", err)
	}

	var config AutomationServerYaml
	if err := yaml.Unmarshal(yamlFile, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal automation_server.yaml: %w", err)
	}

	return &AOCClient{config: &config}, nil
}

// GetAutomationServerToken gets the automation server token
func (c *AOCClient) GetAutomationServerToken() (string, error) {
	resp, err := c.sendRequest("GET", fmt.Sprintf("%s/api/automation-servers/token", c.config.AOCUrl), nil)
	if err != nil {
		return "", fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get automation server token: %s", resp.Status)
	}

	var tokenResponse AutomationServerTokenResponse
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &tokenResponse)
	if err != nil {
		return "", fmt.Errorf("error decoding JSON: %w", err)
	}

	return tokenResponse.Token, nil
}

// RegisterWorkspace registers a workspace with AOC
func (c *AOCClient) RegisterWorkspace(workspaceName string, editorURL *string) (string, error) {
	payload := map[string]interface{}{
		"name":                 workspaceName,
		"automation_server_id": c.config.AutomationServerId,
		"keycloak_org_id":      "00000000-0000-0000-0000-000000000000",
	}

	if editorURL != nil {
		payload["editor_url"] = *editorURL
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := c.sendRequest("POST", fmt.Sprintf("%s/api/workspaces/", c.config.AOCUrl), jsonBytes)
	if err != nil {
		return "", fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("failed to register workspace: %s", resp.Status)
	}

	var workspaceResponse WorkspacePostResponse
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &workspaceResponse)
	if err != nil {
		return "", fmt.Errorf("error decoding JSON: %w", err)
	}

	return workspaceResponse.Id, nil
}

// GetMQTTCredentials gets MQTT credentials for a workspace
func (c *AOCClient) GetMQTTCredentials(workspaceId string) (*MQTTCredentials, error) {
	url := fmt.Sprintf("%s/api/workspaces/%s/emqx/jwt", c.config.AOCUrl, workspaceId)
	resp, err := c.sendRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get EMQX JWT from %s: %s", url, resp.Status)
	}

	var emqxResponse EmqxGetResponse
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &emqxResponse)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}

	// Parse MQTT URL
	urlParts := strings.Split(emqxResponse.Url, ":")
	emqxUrl, emqxPort := urlParts[0], urlParts[1]
	emqxPortInt, err := strconv.Atoi(emqxPort)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MQTT port: %w", err)
	}

	return &MQTTCredentials{
		Username: workspaceId,
		Password: emqxResponse.Token,
		Broker:   emqxUrl,
		Port:     emqxPortInt,
		Topic:    "/topology",
	}, nil
}

// GetAOCEnvironmentVariables creates AOC environment variables
func (c *AOCClient) GetAOCEnvironmentVariables(workspaceId, automationServerToken string) []string {
	aocUrl := c.config.AOCUrl
	// Replace .localhost hostname with Docker service name for internal communication
	if strings.Contains(aocUrl, ".localhost") {
		// Extract the path part after the hostname
		urlParts := strings.Split(strings.TrimPrefix(aocUrl, "http://"), "/")
		path := ""
		if len(urlParts) > 1 {
			path = "/" + strings.Join(urlParts[1:], "/")
		}
		aocUrl = "http://aoc-bitswan-backend:8000" + path
	}
	
	return []string{
		"BITSWAN_WORKSPACE_ID=" + workspaceId,
		"BITSWAN_AOC_URL=" + aocUrl,
		"BITSWAN_AOC_TOKEN=" + automationServerToken,
	}
}

// GetMQTTEnvironmentVariables creates MQTT environment variables from credentials
func GetMQTTEnvironmentVariables(creds *MQTTCredentials) []string {
	broker := creds.Broker
	// Replace .localhost hostname with Docker service name for internal communication
	if strings.Contains(broker, ".localhost") {
		broker = "aoc-emqx"
	}
	
	return []string{
		"MQTT_USERNAME=" + creds.Username,
		"MQTT_PASSWORD=" + creds.Password,
		"MQTT_BROKER=" + broker,
		"MQTT_PORT=" + fmt.Sprint(creds.Port),
		"MQTT_TOPIC=" + creds.Topic,
	}
}

// sendRequest is a helper method for making HTTP requests
func (c *AOCClient) sendRequest(method, url string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if c.config.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.AccessToken)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %w", err)
	}
	return resp, nil
}

// GetConfig returns the AOC configuration
func (c *AOCClient) GetConfig() *AutomationServerYaml {
	return c.config
}
