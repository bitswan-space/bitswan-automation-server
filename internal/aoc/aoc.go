package aoc

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
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
	config *config.AutomationServerConfig
	settings      *config.AutomationOperationsCenterSettings
}

// NewAOCClient creates a new AOC client from the automation server config
func NewAOCClient() (*AOCClient, error) {
	cfg := config.NewAutomationServerConfig()

	settings, err := cfg.GetAutomationOperationsCenterSettings()
	if err != nil {
		return nil, fmt.Errorf("failed to load automation server settings: %w", err)
	}

	return &AOCClient{
		config: cfg,
		settings:      settings,
	}, nil
}

// NewAOCClientWithOTP creates a new AOC client by exchanging OTP for access token
func NewAOCClientWithOTP(aocUrl, otp, automationServerId string) (*AOCClient, error) {
	cfg := config.NewAutomationServerConfig()

	// Create temporary settings for OTP exchange
	tempSettings := &config.AutomationOperationsCenterSettings{
		AOCUrl:             aocUrl,
		AutomationServerId: automationServerId,
	}

	client := &AOCClient{
		config: cfg,
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

	resp, err := c.sendRequest("POST", fmt.Sprintf("%s/api/automation_server/exchange-otp", c.settings.AOCUrl), jsonBytes)
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
	resp, err := c.sendRequest("GET", fmt.Sprintf("%s/api/automation_server/info", c.settings.AOCUrl), nil)
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
		payload["editor_url"] = *editorURL
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

// GetAutomationServerMQTTCredentials gets MQTT credentials for the automation server itself
func (c *AOCClient) GetAutomationServerMQTTCredentials() (*MQTTCredentials, error) {
	url := fmt.Sprintf("%s/api/automation_server/emqx/jwt", c.settings.AOCUrl)
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

	// Parse MQTT URL (format: "host:port" or "protocol://host:port")
	mqttUrl := emqxResponse.Url
	// Remove protocol prefix if present
	if strings.Contains(mqttUrl, "://") {
		parts := strings.Split(mqttUrl, "://")
		if len(parts) > 1 {
			mqttUrl = parts[1]
		}
	}
	
	urlParts := strings.Split(mqttUrl, ":")
	if len(urlParts) < 2 {
		return nil, fmt.Errorf("invalid MQTT URL format: %s", emqxResponse.Url)
	}
	
	emqxUrl := urlParts[0]
	emqxPort := urlParts[1]
	emqxPortInt, err := strconv.Atoi(emqxPort)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MQTT port: %w", err)
	}
	
	// Convert WebSocket ports to standard MQTT port if needed
	// Port 8084 is WebSocket, 1883 is standard MQTT
	if emqxPortInt == 8084 || emqxPortInt == 8083 {
		emqxPortInt = 1883
	}

	return &MQTTCredentials{
		Username: c.settings.AutomationServerId, // Use automation server ID as username
		Password: emqxResponse.Token,
		Broker:   emqxUrl,
		Port:     emqxPortInt,
		Topic:    "workspace/init", // Daemon subscribes to workspace topics
	}, nil
}

// KeycloakClientSecretResponse represents the Keycloak client secret response
type KeycloakClientSecretResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	IssuerURL    string `json:"issuer_url"`
}

func (c *AOCClient) GetKeycloakClientSecret(workspaceId string) (*KeycloakClientSecretResponse, error) {
	url := fmt.Sprintf("%s/api/automation_server/workspaces/%s/keycloak/client-secret", c.settings.AOCUrl, workspaceId)
	resp, err := c.sendRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get Keycloak client secret from %s: %s - %s", url, resp.Status, string(body))
	}

	var response KeycloakClientSecretResponse
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &response)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}

	return &response, nil
}

func generateCookieSecret() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	for i := range b {
		b[i] = alphabet[int(random[i])%len(alphabet)]
	}
	return string(b), nil
}

func (c *AOCClient) GetOAuthConfig(workspaceId string) (*oauth.Config, error) {
	keycloakInfo, err := c.GetKeycloakClientSecret(workspaceId)
	if err != nil {
		return nil, fmt.Errorf("failed to get Keycloak client secret: %w", err)
	}

	cookieSecret, err := generateCookieSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate cookie secret: %w", err)
	}

	provider := "keycloak-oidc"
	httpAddr := "0.0.0.0:9999"
	scope := "openid email profile group_membership"
	groupsClaim := "group_membership"

	oauthConfig := &oauth.Config{
		ClientId:      keycloakInfo.ClientID,
		ClientSecret:  keycloakInfo.ClientSecret,
		IssuerUrl:     keycloakInfo.IssuerURL,
		Provider:      &provider,
		HttpAddress:   &httpAddr,
		Scope:         &scope,
		GroupsClaim:   &groupsClaim,
		EmailDomains:  []string{"*"},
		AllowedGroups: []string{},
		CookieSecret:  cookieSecret,
	}
	return oauthConfig, nil
}

// GetAOCEnvironmentVariables creates AOC environment variables
func (c *AOCClient) GetAOCEnvironmentVariables(workspaceId, automationServerToken string) []string {
	aocUrl := c.settings.AOCUrl
	// Replace .localhost hostname with Docker service name for internal communication
	if strings.Contains(aocUrl, ".localhost") {
		aocUrl = "http://api.bitswan.localhost"
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
	return c.config.UpdateAutomationServer(*c.settings)
}

// createHTTPClient creates an HTTP client that trusts mkcert certificates and certificates from certauthorities directory
func createHTTPClient() (*http.Client, error) {
	// Get the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	// Create a certificate pool that includes system certificates
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		// Fallback to empty pool if system cert pool fails
		caCertPool = x509.NewCertPool()
	}

	certsLoaded := false

	// First, try to load certificates from certauthorities directory
	certAuthDir := filepath.Join(homeDir, ".config", "bitswan", "certauthorities")
	if entries, err := os.ReadDir(certAuthDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".pem") && !strings.HasSuffix(name, ".crt") {
				continue
			}
			certPath := filepath.Join(certAuthDir, name)
			caCert, err := os.ReadFile(certPath)
			if err != nil {
				continue
			}
			if caCertPool.AppendCertsFromPEM(caCert) {
				certsLoaded = true
			}
		}
	}

	// Also check for mkcert root CA as a fallback
	mkcertPath := filepath.Join(homeDir, ".local", "share", "mkcert", "rootCA.pem")
	if caCert, err := os.ReadFile(mkcertPath); err == nil {
		if caCertPool.AppendCertsFromPEM(caCert) {
			certsLoaded = true
		}
	}

	// If no custom certificates were loaded, use default client
	if !certsLoaded {
		return &http.Client{}, nil
	}

	// Create TLS configuration that trusts the custom CAs
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	// Create HTTP client with custom transport
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return client, nil
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

	client, err := createHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP client: %w", err)
	}

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