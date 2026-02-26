package daemon

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// expectedVersion is the version the CLI expects the daemon to have
var expectedVersion string

// updateCallback is called when the daemon version doesn't match the expected version
var updateCallback func() error

// SetVersionCheck configures the daemon client to check version on connection
// and auto-update if versions don't match. The callback should stop the old daemon,
// remove it, and start a new one with the current binary.
func SetVersionCheck(version string, callback func() error) {
	expectedVersion = version
	updateCallback = callback
}

// Client is an HTTP client that communicates with the daemon over Unix socket
type Client struct {
	httpClient *http.Client
	socketPath string
	token      string
}

// NewClient creates a new daemon client
func NewClient() (*Client, error) {
	return NewClientWithSocket(SocketPath)
}

// NewClientWithSocket creates a new daemon client with a custom socket path and verifies the daemon is running
func NewClientWithSocket(socketPath string) (*Client, error) {
	token, err := LoadToken()
	if err != nil {
		return nil, fmt.Errorf("automation server daemon is not initialized: %w", err)
	}

	client := &Client{
		socketPath: socketPath,
		token:      token,
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
			Timeout: 10 * time.Second,
		},
	}

	// Verify the daemon is running by pinging it
	if err := client.Ping(); err != nil {
		return nil, fmt.Errorf("automation server daemon is not running: %w", err)
	}

	// Check if version matches and auto-update if needed
	if expectedVersion != "" && updateCallback != nil {
		daemonVersion, err := client.GetVersion()
		if err != nil {
			// Could not get version, daemon might be old - try to update
			fmt.Println("Could not determine daemon version, updating daemon...")
			if updateErr := updateCallback(); updateErr != nil {
				return nil, fmt.Errorf("failed to update daemon: %w", updateErr)
			}
			// Reconnect after update
			return NewClientWithSocket(socketPath)
		}

		if daemonVersion != expectedVersion {
			fmt.Printf("Daemon version (%s) differs from CLI version (%s), updating daemon...\n", daemonVersion, expectedVersion)
			if updateErr := updateCallback(); updateErr != nil {
				return nil, fmt.Errorf("failed to update daemon: %w", updateErr)
			}
			// Reconnect after update (clear version check to avoid infinite loop)
			oldExpected := expectedVersion
			expectedVersion = ""
			client, err = NewClientWithSocket(socketPath)
			expectedVersion = oldExpected
			return client, err
		}
	}

	return client, nil
}

// doRequest performs an HTTP request with authentication
func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.httpClient.Do(req)
}

// DoRequest is a public wrapper for doRequest
func (c *Client) DoRequest(req *http.Request) (*http.Response, error) {
	return c.doRequest(req)
}

func (c *Client) doStreamingRequest(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	streamingClient := &http.Client{
		Transport: c.httpClient.Transport,
		Timeout:   0,
	}
	return streamingClient.Do(req)
}

// Ping checks if the daemon is running
func (c *Client) Ping() error {
	req, err := http.NewRequest("GET", "http://unix/ping", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// GetStatus returns the daemon status
func (c *Client) GetStatus() (*StatusResponse, error) {
	req, err := http.NewRequest("GET", "http://unix/status", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var status StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &status, nil
}

// GetVersion returns the daemon version
func (c *Client) GetVersion() (string, error) {
	req, err := http.NewRequest("GET", "http://unix/version", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return "", fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result["version"], nil
}

// buildURL builds a URL with optional workspace query parameter
func buildURL(base string, workspace string) string {
	if workspace != "" {
		if strings.Contains(base, "?") {
			return base + "&workspace=" + workspace
		}
		return base + "?workspace=" + workspace
	}
	return base
}

// ListAutomations returns the list of automations
func (c *Client) ListAutomations(workspace string) (*AutomationListResponse, error) {
	url := buildURL("http://unix/automations", workspace)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result AutomationListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetAutomationLogs returns the logs for an automation
func (c *Client) GetAutomationLogs(deploymentID string, lines int, workspace string) (*AutomationLogsResponse, error) {
	url := fmt.Sprintf("http://unix/automations/%s/logs", deploymentID)
	if lines > 0 {
		url += fmt.Sprintf("?lines=%d", lines)
	}
	url = buildURL(url, workspace)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result AutomationLogsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// StartAutomation starts an automation
func (c *Client) StartAutomation(deploymentID string, workspace string) error {
	url := buildURL(fmt.Sprintf("http://unix/automations/%s/start", deploymentID), workspace)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// StopAutomation stops an automation
func (c *Client) StopAutomation(deploymentID string, workspace string) error {
	url := buildURL(fmt.Sprintf("http://unix/automations/%s/stop", deploymentID), workspace)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RestartAutomation restarts an automation
func (c *Client) RestartAutomation(deploymentID string, workspace string) error {
	url := buildURL(fmt.Sprintf("http://unix/automations/%s/restart", deploymentID), workspace)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveAutomation removes an automation
func (c *Client) RemoveAutomation(deploymentID string, workspace string) error {
	url := buildURL(fmt.Sprintf("http://unix/automations/%s", deploymentID), workspace)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SelectWorkspace selects a workspace as the active workspace
func (c *Client) SelectWorkspace(workspace string) error {
	reqBody := WorkspaceSelectRequest{Workspace: workspace}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/workspace/select", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListWorkspaces returns the list of workspaces and the active workspace
func (c *Client) ListWorkspaces(long, showPasswords bool) (*WorkspaceListResponse, error) {
	url := "http://unix/workspace/list"
	if long || showPasswords {
		url += "?"
		params := []string{}
		if long {
			params = append(params, "long=true")
		}
		if showPasswords {
			params = append(params, "passwords=true")
		}
		url += strings.Join(params, "&")
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result WorkspaceListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// ListCertAuthorities returns the list of certificate authorities
func (c *Client) ListCertAuthorities() (*CertAuthorityListResponse, error) {
	req, err := http.NewRequest("GET", "http://unix/certauthority/list", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result CertAuthorityListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// AddCertAuthority adds a certificate authority from a file
func (c *Client) AddCertAuthority(sourcePath string, targetName string) (*CertAuthorityAddResponse, error) {
	// Read the source file
	fileContent, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read source file: %w", err)
	}

	// Encode as base64
	encodedContent := base64.StdEncoding.EncodeToString(fileContent)

	reqBody := CertAuthorityAddRequest{
		FileName:    targetName,
		FileContent: encodedContent,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/certauthority/add", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result CertAuthorityAddResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// RemoveCertAuthority removes a certificate authority
func (c *Client) RemoveCertAuthority(certName string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("http://unix/certauthority/remove/%s", certName), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// InitIngress initializes the ingress proxy
func (c *Client) InitIngress(verbose bool) (*IngressInitResponse, error) {
	reqBody := IngressInitRequest{Verbose: verbose}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/ingress/init", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result IngressInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// AddIngressRoute adds a route to the ingress proxy
func (c *Client) AddIngressRoute(hostname, upstream string, mkcert bool, certsDir string) (*IngressAddRouteResponse, error) {
	reqBody := IngressAddRouteRequest{
		Hostname: hostname,
		Upstream: upstream,
		Mkcert:   mkcert,
		CertsDir: certsDir,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/ingress/add-route", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result IngressAddRouteResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// ListIngressRoutes lists all routes in the ingress proxy
func (c *Client) ListIngressRoutes() (*IngressListRoutesResponse, error) {
	req, err := http.NewRequest("GET", "http://unix/ingress/list-routes", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result IngressListRoutesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// RemoveIngressRoute removes a route from the ingress proxy
func (c *Client) RemoveIngressRoute(hostname string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("http://unix/ingress/remove-route/%s", hostname), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// EnableService enables a service (editor, kafka, or couchdb) with streaming logs
func (c *Client) EnableService(serviceType, workspace string, options map[string]interface{}) (*ServiceResponse, error) {
	reqBody := ServiceEnableRequest{
		ServiceType: serviceType,
		Workspace:   workspace,
	}

	// Set service-specific options
	if stage, ok := options["stage"].(string); ok {
		reqBody.Stage = stage
	}
	if editorImage, ok := options["editor_image"].(string); ok {
		reqBody.EditorImage = editorImage
	}
	if oauthConfig, ok := options["oauth_config"].(map[string]interface{}); ok {
		reqBody.OAuthConfig = oauthConfig
	}
	if trustCA, ok := options["trust_ca"].(bool); ok {
		reqBody.TrustCA = trustCA
	}
	if kafkaImage, ok := options["kafka_image"].(string); ok {
		reqBody.KafkaImage = kafkaImage
	}
	if zookeeperImage, ok := options["zookeeper_image"].(string); ok {
		reqBody.ZookeeperImage = zookeeperImage
	}
	if couchdbImage, ok := options["couchdb_image"].(string); ok {
		reqBody.CouchDBImage = couchdbImage
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://unix/service/%s/enable", serviceType), strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Check if response is streaming NDJSON
	if resp.Header.Get("Content-Type") == "application/x-ndjson" {
		return c.streamLogs(resp.Body, os.Stdout)
	}

	// Fallback to regular JSON response
	var result ServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// WorkspaceInit runs `bitswan workspace init ...` via the daemon with NDJSON streaming.
func (c *Client) WorkspaceInit(args []string) error {
	bodyBytes, err := json.Marshal(WorkspaceRunRequest{Args: args})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/workspace/init", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	_, err = c.streamLogs(resp.Body, os.Stdout)
	return err
}

// WorkspaceUpdate runs `bitswan workspace update ...` via the daemon with NDJSON streaming.
func (c *Client) WorkspaceUpdate(args []string) error {
	bodyBytes, err := json.Marshal(WorkspaceRunRequest{Args: args})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/workspace/update", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	_, err = c.streamLogs(resp.Body, os.Stdout)
	return err
}

// WorkspaceConnectToAOC connects existing workspaces to AOC via the daemon with NDJSON streaming.
func (c *Client) WorkspaceConnectToAOC(aocUrl, automationServerId, accessToken string) error {
	reqBody := WorkspaceConnectToAOCRequest{
		AOCUrl:             aocUrl,
		AutomationServerId: automationServerId,
		AccessToken:        accessToken,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/workspace/connect-to-aoc", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	_, err = c.streamLogs(resp.Body, os.Stdout)
	return err
}

// WorkspaceRemove runs `bitswan workspace remove ...` via the daemon with NDJSON streaming.
func (c *Client) WorkspaceRemove(workspaceName string) error {
	bodyBytes, err := json.Marshal(WorkspaceRemoveRequest{Workspace: workspaceName})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/workspace/remove", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	_, err = c.streamLogs(resp.Body, os.Stdout)
	return err
}

// WorkspaceStart starts all services in a workspace via the daemon with NDJSON streaming.
func (c *Client) WorkspaceStart(workspaceName string, automationsOnly bool) error {
	return c.workspaceStartStopRequest("start", workspaceName, automationsOnly)
}

// WorkspaceStop stops all services in a workspace via the daemon with NDJSON streaming.
func (c *Client) WorkspaceStop(workspaceName string, automationsOnly bool) error {
	return c.workspaceStartStopRequest("stop", workspaceName, automationsOnly)
}

// WorkspaceRestart restarts all services in a workspace via the daemon with NDJSON streaming.
func (c *Client) WorkspaceRestart(workspaceName string, automationsOnly bool) error {
	return c.workspaceStartStopRequest("restart", workspaceName, automationsOnly)
}

func (c *Client) workspaceStartStopRequest(action, workspaceName string, automationsOnly bool) error {
	bodyBytes, err := json.Marshal(WorkspaceStartStopRequest{
		Workspace:       workspaceName,
		AutomationsOnly: automationsOnly,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/workspace/"+action, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	_, err = c.streamLogs(resp.Body, os.Stdout)
	return err
}

// PullAndDeploy runs `bitswan pull-and-deploy ...` via the daemon with NDJSON streaming.
func (c *Client) PullAndDeploy(workspaceName, branchName string) error {
	bodyBytes, err := json.Marshal(PullAndDeployRequest{
		Workspace: workspaceName,
		Branch:    branchName,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/automations/pull-and-deploy/", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid or missing token")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	_, err = c.streamLogs(resp.Body, os.Stdout)
	return err
}

// streamLogs reads NDJSON from the response and displays logs in real-time
func (c *Client) streamLogs(body io.Reader, output io.Writer) (*ServiceResponse, error) {
	scanner := bufio.NewScanner(body)
	var lastEntry LogEntry
	var hasError bool

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry LogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			// If it's not valid JSON, print it as-is
			s := string(line)
			if strings.HasSuffix(s, "\n") {
				fmt.Fprint(output, s)
			} else {
				fmt.Fprintln(output, s)
			}
			continue
		}

		lastEntry = entry

		// Display the log message
		// entry.Message often already contains trailing newlines; avoid adding extras.
		if strings.HasSuffix(entry.Message, "\n") {
			fmt.Fprint(output, entry.Message)
		} else {
			fmt.Fprintln(output, entry.Message)
		}

		// Track if we encountered an error
		if entry.Level == "error" {
			hasError = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading stream: %w", err)
	}

	// Return result based on last entry
	if hasError {
		msg := strings.TrimSpace(lastEntry.Message)
		if msg == "" {
			msg = "operation failed"
		}
		return nil, fmt.Errorf("%s", msg)
	}

	return &ServiceResponse{
		Success: true,
		// The stream already printed everything; keep Message empty to avoid CLI re-printing
		Message: "",
	}, nil
}

// DisableService disables a service
func (c *Client) DisableService(serviceType, workspace, stage string) (*ServiceResponse, error) {
	reqBody := ServiceDisableRequest{
		ServiceType: serviceType,
		Workspace:   workspace,
		Stage:       stage,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://unix/service/%s/disable", serviceType), strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result ServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetServiceStatus gets the status of a service
func (c *Client) GetServiceStatus(serviceType, workspace, stage string, showPasswords bool) (*ServiceResponse, error) {
	url := fmt.Sprintf("http://unix/service/%s/status?workspace=%s", serviceType, workspace)
	if stage != "" {
		url += "&stage=" + stage
	}
	if showPasswords {
		url += "&show_passwords=true"
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result ServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// StartService starts a service
func (c *Client) StartService(serviceType, workspace, stage string) (*ServiceResponse, error) {
	reqBody := ServiceStartRequest{
		ServiceType: serviceType,
		Workspace:   workspace,
		Stage:       stage,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://unix/service/%s/start", serviceType), strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result ServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// StopService stops a service
func (c *Client) StopService(serviceType, workspace, stage string) (*ServiceResponse, error) {
	reqBody := ServiceStopRequest{
		ServiceType: serviceType,
		Workspace:   workspace,
		Stage:       stage,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://unix/service/%s/stop", serviceType), strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result ServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// UpdateService updates a service
func (c *Client) UpdateService(serviceType, workspace string, options map[string]interface{}) (*ServiceResponse, error) {
	reqBody := ServiceUpdateRequest{
		ServiceType: serviceType,
		Workspace:   workspace,
	}

	// Set service-specific options
	if stage, ok := options["stage"].(string); ok {
		reqBody.Stage = stage
	}
	if editorImage, ok := options["editor_image"].(string); ok {
		reqBody.EditorImage = editorImage
	}
	if trustCA, ok := options["trust_ca"].(bool); ok {
		reqBody.TrustCA = trustCA
	}
	if kafkaImage, ok := options["kafka_image"].(string); ok {
		reqBody.KafkaImage = kafkaImage
	}
	if zookeeperImage, ok := options["zookeeper_image"].(string); ok {
		reqBody.ZookeeperImage = zookeeperImage
	}
	if couchdbImage, ok := options["couchdb_image"].(string); ok {
		reqBody.CouchDBImage = couchdbImage
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://unix/service/%s/update", serviceType), strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result ServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// BackupCouchDB creates a backup of CouchDB
func (c *Client) BackupCouchDB(workspace, stage, backupPath string) (*ServiceResponse, error) {
	reqBody := ServiceBackupRequest{
		Workspace:  workspace,
		BackupPath: backupPath,
		Stage:      stage,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/service/couchdb/backup", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Check Content-Type to determine response format
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-ndjson") {
		// Stream logs to stdout and return result
		return c.streamLogs(resp.Body, os.Stdout)
	}

	// Fall back to JSON response for backwards compatibility
	var result ServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// RestoreCouchDB restores CouchDB from a backup
func (c *Client) RestoreCouchDB(workspace, backupPath string, force bool) (*ServiceResponse, error) {
	reqBody := ServiceRestoreRequest{
		Workspace:  workspace,
		BackupPath: backupPath,
		Force:      force,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/service/couchdb/restore", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: invalid or missing token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Check Content-Type to determine response format
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-ndjson") {
		// Stream logs to stdout and return result
		return c.streamLogs(resp.Body, os.Stdout)
	}

	// Fall back to JSON response for backwards compatibility
	var result ServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// CreateJob creates a new interactive job
func (c *Client) CreateJob(jobType, workspace string, params map[string]interface{}) (string, error) {
	reqBody := map[string]interface{}{
		"type":      jobType,
		"workspace": workspace,
		"params":    params,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "http://unix/jobs", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return "", fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create job: %s", string(body))
	}

	var result struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.JobID, nil
}

// ClientJobLogEntry represents a log entry from a job stream
type ClientJobLogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Prompt  string `json:"prompt,omitempty"`
	Type    string `json:"type,omitempty"`
	State   string `json:"state,omitempty"`
	Error   string `json:"error,omitempty"`
}

// StreamJobOutput streams job output and handles prompts interactively
func (c *Client) StreamJobOutput(jobID string, output io.Writer, input io.Reader) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://unix/jobs/%s/stream", jobID), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doStreamingRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to stream job: %s", string(body))
	}

	scanner := bufio.NewScanner(resp.Body)
	inputReader := bufio.NewReader(input)

	for scanner.Scan() {
		var entry ClientJobLogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		// Handle completion
		if entry.Type == "complete" {
			if entry.Error != "" {
				return fmt.Errorf("%s", entry.Error)
			}
			return nil
		}

		// Handle prompt - need to get user input
		if entry.Prompt != "" {
			fmt.Fprint(output, entry.Prompt)

			// Read user input
			userInput, err := inputReader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}

			// Send input to job
			if err := c.SendJobInput(jobID, strings.TrimSpace(userInput)); err != nil {
				return fmt.Errorf("failed to send input: %w", err)
			}
			continue
		}

		// Regular log message
		if entry.Message != "" {
			fmt.Fprintln(output, entry.Message)
		}
	}

	return scanner.Err()
}

// SendJobInput sends input to a waiting job
func (c *Client) SendJobInput(jobID, input string) error {
	reqBody := map[string]string{"input": input}
	bodyBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", fmt.Sprintf("http://unix/jobs/%s/input", jobID), strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to send input: %s", string(body))
	}

	return nil
}

// RestoreCouchDBInteractive restores CouchDB using the interactive job API
func (c *Client) RestoreCouchDBInteractive(workspace, stage, backupPath string) error {
	// Create the job
	params := map[string]interface{}{
		"backup_path": backupPath,
	}
	if stage != "" {
		params["stage"] = stage
	}
	jobID, err := c.CreateJob("couchdb_restore", workspace, params)
	if err != nil {
		return err
	}

	// Stream output and handle prompts
	return c.StreamJobOutput(jobID, os.Stdout, os.Stdin)
}
