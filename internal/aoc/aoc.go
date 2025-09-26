package aoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// OTPExchangeRequest represents the OTP exchange request
type OTPExchangeRequest struct {
	OTP                string `json:"otp"`
	AutomationServerId string `json:"automation_server_id"`
}

// OTPExchangeResponse represents the OTP exchange response
type OTPExchangeResponse struct {
	AccessToken        string `json:"access_token"`
	AutomationServerId string `json:"automation_server_id"`
	ExpiresAt          string `json:"expires_at"`
}

// AutomationServerInfo represents the automation server information
type AutomationServerInfo struct {
	Id                 int    `json:"id"`
	Name               string `json:"name"`
	AutomationServerId string `json:"automation_server_id"`
	IsConnected        bool   `json:"is_connected"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

// WorkspacePostResponse represents the response from workspace registration
type WorkspacePostResponse struct {
	Id                 string `json:"id"`
	Name               string `json:"name"`
	AutomationServerId string `json:"automation_server_id"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

// WorkspaceListResponse represents the response from workspace listing
type WorkspaceListResponse struct {
	Count    int                    `json:"count"`
	Next     *string                `json:"next"`
	Previous *string                `json:"previous"`
	Results  []WorkspacePostResponse `json:"results"`
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
	configManager *config.AutomationServerConfig
	settings      *config.AutomationServerSettings
}

// NewAOCClient creates a new AOC client from the automation server config
func NewAOCClient() (*AOCClient, error) {
	configManager := config.NewAutomationServerConfig()
	
	settings, err := configManager.GetAutomationServerSettings()
	if err != nil {
		return nil, fmt.Errorf("failed to load automation server settings: %w", err)
	}

	return &AOCClient{
		configManager: configManager,
		settings:      settings,
	}, nil
}

// NewAOCClientWithOTP creates a new AOC client by exchanging OTP for access token
func NewAOCClientWithOTP(aocUrl, otp, automationServerId string) (*AOCClient, error) {
	configManager := config.NewAutomationServerConfig()
	
	// Create temporary settings for OTP exchange
	tempSettings := &config.AutomationServerSettings{
		AOCUrl:             aocUrl,
		AutomationServerId: automationServerId,
	}

	client := &AOCClient{
		configManager: configManager,
		settings:      tempSettings,
	}

	// Exchange OTP for access token
	accessToken, expiresAt, err := client.ExchangeOTP(otp, automationServerId)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange OTP: %w", err)
	}

	// Update settings with token
	client.settings.AccessToken = accessToken
	client.settings.ExpiresAt = expiresAt

	return client, nil
}

// ExchangeOTP exchanges an OTP for an access token
func (c *AOCClient) ExchangeOTP(otp, automationServerId string) (string, string, error) {
	payload := OTPExchangeRequest{
		OTP:                otp,
		AutomationServerId: automationServerId,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal OTP request: %w", err)
	}

	resp, err := c.sendRequest("POST", fmt.Sprintf("%s/api/automation_server/exchange-otp/", c.settings.AOCUrl), jsonBytes)
	if err != nil {
		return "", "", fmt.Errorf("error sending OTP exchange request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("failed to exchange OTP: %s - %s", resp.Status, string(body))
	}

	var otpResponse OTPExchangeResponse
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &otpResponse)
	if err != nil {
		return "", "", fmt.Errorf("error decoding OTP response: %w", err)
	}

	return otpResponse.AccessToken, otpResponse.ExpiresAt, nil
}

// GetAutomationServerInfo gets the automation server information
func (c *AOCClient) GetAutomationServerInfo() (*AutomationServerInfo, error) {
	resp, err := c.sendRequest("GET", fmt.Sprintf("%s/api/automation_server/info/", c.settings.AOCUrl), nil)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get automation server info: %s", resp.Status)
	}

	var serverInfo AutomationServerInfo
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &serverInfo)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}

	return &serverInfo, nil
}

// GetAutomationServerToken gets the automation server token (deprecated, use GetAutomationServerInfo)
func (c *AOCClient) GetAutomationServerToken() (string, error) {
	// For backward compatibility, return the stored access token
	if c.settings.AccessToken == "" {
		return "", fmt.Errorf("no access token available")
	}
	return c.settings.AccessToken, nil
}

// RegisterWorkspace registers a workspace with AOC
func (c *AOCClient) RegisterWorkspace(workspaceName string, editorURL *string) (string, error) {
	payload := map[string]interface{}{
		"name":                 workspaceName,
		"automation_server_id": c.settings.AutomationServerId,
	}

	if editorURL != nil {
		payload["description"] = fmt.Sprintf("Workspace with editor URL: %s", *editorURL)
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := c.sendRequest("POST", fmt.Sprintf("%s/api/automation_server/workspaces/", c.settings.AOCUrl), jsonBytes)
	if err != nil {
		return "", fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to register workspace: %s - %s", resp.Status, string(body))
	}

	var workspaceResponse WorkspacePostResponse
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &workspaceResponse)
	if err != nil {
		return "", fmt.Errorf("error decoding JSON: %w", err)
	}

	return workspaceResponse.Id, nil
}

// ListWorkspaces lists all workspaces for the automation server
func (c *AOCClient) ListWorkspaces() (*WorkspaceListResponse, error) {
	resp, err := c.sendRequest("GET", fmt.Sprintf("%s/api/automation_server/workspaces/", c.settings.AOCUrl), nil)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list workspaces: %s - %s", resp.Status, string(body))
	}

	var workspaceList WorkspaceListResponse
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &workspaceList)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}

	return &workspaceList, nil
}

// UpdateWorkspace updates an existing workspace
func (c *AOCClient) UpdateWorkspace(workspaceId, name, description string) error {
	payload := map[string]interface{}{
		"name": name,
	}
	if description != "" {
		payload["description"] = description
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := c.sendRequest("PUT", fmt.Sprintf("%s/api/automation_server/workspaces/%s/", c.settings.AOCUrl, workspaceId), jsonBytes)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update workspace: %s - %s", resp.Status, string(body))
	}

	return nil
}

// DeleteWorkspace deletes a workspace
func (c *AOCClient) DeleteWorkspace(workspaceId string) error {
	resp, err := c.sendRequest("DELETE", fmt.Sprintf("%s/api/automation_server/workspaces/%s/", c.settings.AOCUrl, workspaceId), nil)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete workspace: %s - %s", resp.Status, string(body))
	}

	return nil
}

// GetMQTTCredentials gets MQTT credentials for a workspace
func (c *AOCClient) GetMQTTCredentials(workspaceId string) (*MQTTCredentials, error) {
	url := fmt.Sprintf("%s/api/automation_server/workspaces/%s/emqx/jwt/", c.settings.AOCUrl, workspaceId)
	resp, err := c.sendRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get EMQX JWT from %s: %s - %s", url, resp.Status, string(body))
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
		Username: c.settings.AutomationServerId, // Use automation server ID as username
		Password: emqxResponse.Token,
		Broker:   emqxUrl,
		Port:     emqxPortInt,
		Topic:    "/topology",
	}, nil
}

// GetAOCEnvironmentVariables creates AOC environment variables
func (c *AOCClient) GetAOCEnvironmentVariables(workspaceId, automationServerToken string) []string {
	aocUrl := c.settings.AOCUrl
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

// SaveConfig saves the current configuration to the automation server config file
func (c *AOCClient) SaveConfig() error {
	return c.configManager.UpdateAutomationServer(*c.settings)
}

// sendRequest is a helper method for making HTTP requests
func (c *AOCClient) sendRequest(method, url string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if c.settings.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.settings.AccessToken)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %w", err)
	}
	return resp, nil
}

// GetAccessToken returns the current access token
func (c *AOCClient) GetAccessToken() string {
	return c.settings.AccessToken
}
