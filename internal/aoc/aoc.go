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

	httplocalhost "github.com/bitswan-space/bitswan-workspaces/internal/http"
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
	KeycloakOrgId      string `json:"keycloak_org_id"`
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
	Protocol string // Protocol: tcp, ssl, ws, wss
	URL      string // Full URL with protocol (e.g., wss://host:port)
}

// AOCClient handles AOC API interactions
type AOCClient struct {
	config *config.AutomationServerConfig
	settings      *config.AutomationOperationsCenterSettings
}

// NewAOCClient creates a new AOC client from the automation server config
// Returns an error if AOC is not configured (no access_token)
func NewAOCClient() (*AOCClient, error) {
	cfg := config.NewAutomationServerConfig()

	settings, err := cfg.GetAutomationOperationsCenterSettings()
	if err != nil {
		return nil, fmt.Errorf("failed to load automation server settings: %w", err)
	}

	// Check if AOC is actually configured (has access_token)
	if settings.AccessToken == "" {
		return nil, fmt.Errorf("AOC not configured: access_token is not set")
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
func (c *AOCClient) RegisterWorkspace(workspaceName string, editorURL *string, domain string) (string, error) {
	payload := map[string]interface{}{
		"name":                 workspaceName,
		"automation_server_id": c.settings.AutomationServerId,
	}

	if editorURL != nil {
		payload["editor_url"] = *editorURL
	}

	if domain != "" {
		payload["domain"] = domain
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

// SyncWorkspaceList syncs the workspace list with AOC
// Accepts a list of workspace entries (with id and name) and ensures AOC database matches
func (c *AOCClient) SyncWorkspaceList(workspaces []map[string]interface{}) error {
	payload := map[string]interface{}{
		"workspaces": workspaces,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := c.sendRequest("POST", fmt.Sprintf("%s/api/automation_server/workspaces/sync/", c.settings.AOCUrl), jsonBytes)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to sync workspace list: %s - %s", resp.Status, string(body))
	}

	return nil
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
	url := fmt.Sprintf("%s/api/automation_server/workspaces/%s/emqx/jwt", c.settings.AOCUrl, workspaceId)
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

	// Parse MQTT URL - use the same logic as GetAutomationServerMQTTCredentials
	mqttURL := emqxResponse.Url
	
	// Determine protocol and extract host:port
	var protocol string
	var hostPort string
	
	if strings.HasPrefix(mqttURL, "wss://") {
		protocol = "wss"
		hostPort = strings.TrimPrefix(mqttURL, "wss://")
	} else if strings.HasPrefix(mqttURL, "ws://") {
		protocol = "ws"
		hostPort = strings.TrimPrefix(mqttURL, "ws://")
	} else if strings.HasPrefix(mqttURL, "ssl://") {
		protocol = "ssl"
		hostPort = strings.TrimPrefix(mqttURL, "ssl://")
	} else if strings.HasPrefix(mqttURL, "tls://") {
		protocol = "tls"
		hostPort = strings.TrimPrefix(mqttURL, "tls://")
	} else if strings.HasPrefix(mqttURL, "tcp://") {
		protocol = "tcp"
		hostPort = strings.TrimPrefix(mqttURL, "tcp://")
	} else if strings.HasPrefix(mqttURL, "mqtt://") {
		protocol = "tcp" // mqtt:// is equivalent to tcp://
		hostPort = strings.TrimPrefix(mqttURL, "mqtt://")
	} else {
		// No protocol specified, default to tcp
		protocol = "tcp"
		hostPort = mqttURL
	}
	
	// Parse host and port
	// hostPort might be "host:port" or "host:port/path"
	// Extract port before any path separator
	var emqxUrl string
	var emqxPortInt int
	
	// Check if there's a port specified (contains ":")
	if strings.Contains(hostPort, ":") {
		// Split on ":" to get host and port+path
		parts := strings.SplitN(hostPort, ":", 2)
		emqxUrl = parts[0]
		portAndPath := parts[1]
		
		// Extract port (before "/" if path is present)
		if strings.Contains(portAndPath, "/") {
			portStr := strings.Split(portAndPath, "/")[0]
			emqxPortInt, err = strconv.Atoi(portStr)
		} else {
			emqxPortInt, err = strconv.Atoi(portAndPath)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse MQTT port: %w", err)
		}
	} else {
		// No port specified, use default based on protocol
		emqxUrl = hostPort
		if strings.Contains(emqxUrl, "/") {
			emqxUrl = strings.Split(emqxUrl, "/")[0]
		}
		switch protocol {
		case "wss", "ssl", "tls":
			emqxPortInt = 443
		case "ws":
			emqxPortInt = 80
		default:
			emqxPortInt = 1883
		}
	}

	return &MQTTCredentials{
		Username: workspaceId, // Use workspace ID as username for workspace-specific credentials
		Password: emqxResponse.Token,
		Broker:   emqxUrl,
		Port:     emqxPortInt,
		Protocol: protocol,
		URL:      mqttURL, // Preserve full URL with protocol
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

	// Parse MQTT URL - preserve the protocol from the API response
	// The URL might be in format: wss://host:port, ws://host:port, ssl://host:port, tcp://host:port, or host:port
	mqttURL := emqxResponse.Url
	
	// Determine protocol and extract host:port
	var protocol string
	var hostPort string
	
	if strings.HasPrefix(mqttURL, "wss://") {
		protocol = "wss"
		hostPort = strings.TrimPrefix(mqttURL, "wss://")
	} else if strings.HasPrefix(mqttURL, "ws://") {
		protocol = "ws"
		hostPort = strings.TrimPrefix(mqttURL, "ws://")
	} else if strings.HasPrefix(mqttURL, "ssl://") {
		protocol = "ssl"
		hostPort = strings.TrimPrefix(mqttURL, "ssl://")
	} else if strings.HasPrefix(mqttURL, "tls://") {
		protocol = "tls"
		hostPort = strings.TrimPrefix(mqttURL, "tls://")
	} else if strings.HasPrefix(mqttURL, "tcp://") {
		protocol = "tcp"
		hostPort = strings.TrimPrefix(mqttURL, "tcp://")
	} else if strings.HasPrefix(mqttURL, "mqtt://") {
		protocol = "tcp" // mqtt:// is equivalent to tcp://
		hostPort = strings.TrimPrefix(mqttURL, "mqtt://")
	} else {
		// No protocol specified, default to tcp
		protocol = "tcp"
		hostPort = mqttURL
	}
	
	// Parse host and port
	// hostPort might be "host:port" or "host:port/path"
	// Extract port before any path separator
	var emqxUrl string
	var emqxPortInt int
	
	// Check if there's a port specified (contains ":")
	if strings.Contains(hostPort, ":") {
		// Split on ":" to get host and port+path
		urlParts := strings.SplitN(hostPort, ":", 2)
		emqxUrl = urlParts[0]
		
		// Extract port (before "/" if path is present)
		portPart := urlParts[1]
		if strings.Contains(portPart, "/") {
			portPart = strings.Split(portPart, "/")[0]
		}
		
		var err error
		emqxPortInt, err = strconv.Atoi(portPart)
		if err != nil {
			return nil, fmt.Errorf("failed to parse MQTT port: %w", err)
		}
	} else {
		// No port specified, use default port based on protocol
		// Remove any path from hostname
		if strings.Contains(hostPort, "/") {
			emqxUrl = strings.Split(hostPort, "/")[0]
		} else {
			emqxUrl = hostPort
		}
		switch protocol {
		case "wss":
			emqxPortInt = 443 // Default HTTPS/WSS port
		case "ws":
			emqxPortInt = 80 // Default HTTP/WS port
		case "ssl", "tls":
			emqxPortInt = 8883 // Default MQTT SSL port
		case "tcp":
			emqxPortInt = 1883 // Default MQTT TCP port
		default:
			return nil, fmt.Errorf("unknown protocol %s and no port specified in URL: %s", protocol, emqxResponse.Url)
		}
	}
	
	// Store the full URL with protocol for the daemon to use
	// For WSS connections, preserve the path from the original URL if present
	fullURL := fmt.Sprintf("%s://%s:%d", protocol, emqxUrl, emqxPortInt)
	if strings.HasPrefix(protocol, "wss") || strings.HasPrefix(protocol, "ws") {
		// Check if original URL had a path (e.g., /mqtt)
		if strings.Contains(emqxResponse.Url, "/") {
			// Extract path from original URL
			urlParts := strings.SplitN(emqxResponse.Url, "/", 4)
			if len(urlParts) >= 4 {
				// Reconstruct with path: protocol://host:port/path
				path := "/" + strings.Join(urlParts[3:], "/")
				fullURL = fmt.Sprintf("%s://%s:%d%s", protocol, emqxUrl, emqxPortInt, path)
			}
		}
	}
	
	// For Docker internal communication, use the hostname directly
	// Replace .localhost hostname with Docker service name if needed
	internalHost := emqxUrl
	if emqxUrl == "aoc-emqx" || strings.Contains(emqxUrl, "localhost") {
		internalHost = "aoc-emqx"
	}

	return &MQTTCredentials{
		Username: c.settings.AutomationServerId, // Use automation server ID as username
		Password: emqxResponse.Token,
		Broker:   internalHost,
		Port:     emqxPortInt,
		Protocol: protocol,
		URL:      fullURL,
		Topic:    "/workspaces", // Topic for publishing workspace lists
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

// createHTTPClient creates an HTTP client that trusts mkcert certificates
func createHTTPClient() (*http.Client, error) {
	// Get the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	// Path to mkcert root CA
	mkcertPath := filepath.Join(homeDir, ".local", "share", "mkcert", "rootCA.pem")

	// Check if mkcert root CA exists
	if _, err := os.Stat(mkcertPath); os.IsNotExist(err) {
		// If mkcert CA doesn't exist, use default client
		return &http.Client{}, nil
	}

	// Read the mkcert root CA certificate
	caCert, err := os.ReadFile(mkcertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read mkcert root CA: %w", err)
	}

	// Create a certificate pool that includes system certificates
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		// Fallback to empty pool if system cert pool fails
		caCertPool = x509.NewCertPool()
	}

	// Add the mkcert root CA to the pool
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse mkcert root CA")
	}

	// Create TLS configuration that trusts the mkcert CA
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
// It automatically retries with Docker network alias if localhost connection fails
func (c *AOCClient) sendRequest(method, requestURL string, payload []byte) (*http.Response, error) {
	var resp *http.Response
	var err error

	// Use the retry wrapper
	err = httplocalhost.RetryWithLocalhostAlias(requestURL, func() error {
		var retryErr error
		resp, retryErr = c.sendRequestOnce(method, requestURL, payload)
		return retryErr
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

// sendRequestOnce performs a single HTTP request without retry logic
func (c *AOCClient) sendRequestOnce(method, requestURL string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, requestURL, bytes.NewBuffer(payload))
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
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	return resp, nil
}

// GetAccessToken returns the current access token
func (c *AOCClient) GetAccessToken() string {
	return c.settings.AccessToken
}