package daemonapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Client represents a client for the daemon REST API
type Client struct {
	baseURL string
	token   string
	timeout time.Duration
}

// NewClient creates a new daemon API client
func NewClient(baseURL string, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		timeout: 30 * time.Second,
	}
}

// ExecuteCommand executes a command via the daemon API
func (c *Client) ExecuteCommand(command string, args []string, workspace string) (*CommandResponse, error) {
	req := CommandRequest{
		Command:   command,
		Args:      args,
		Workspace: workspace,
	}
	
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	url := fmt.Sprintf("%s/api/v1/execute", c.baseURL)
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	
	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}
	
	var cmdResp CommandResponse
	if err := json.Unmarshal(body, &cmdResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &cmdResp, nil
}

// CheckDaemonRunning checks if the daemon container is running
func CheckDaemonRunning() (bool, error) {
	cmd := exec.Command("docker", "ps", "--filter", "name=bitswan-automation-server-daemon", "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("failed to check daemon status: %w", err)
	}
	
	return len(output) > 0, nil
}

// GetDaemonContainerName returns the daemon container name
func GetDaemonContainerName() string {
	return "bitswan-automation-server-daemon"
}

// ExecuteInDaemon executes a command inside the daemon container using docker exec
func ExecuteInDaemon(command string, args ...string) error {
	containerName := GetDaemonContainerName()
	
	// Build docker exec command
	execArgs := []string{"exec", containerName, command}
	execArgs = append(execArgs, args...)
	
	cmd := exec.Command("docker", execArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	return cmd.Run()
}

// GetDefaultBaseURL returns the default base URL for the daemon API
func GetDefaultBaseURL() string {
	// The daemon runs in a container, so we need to connect to it
	// We'll use localhost since the daemon exposes the port to the host
	return "http://localhost:8080"
}

// GetGlobalToken retrieves a global token from the config or environment
func GetGlobalToken() (string, error) {
	// First check environment variable
	if token := os.Getenv("BITSWAN_DAEMON_TOKEN"); token != "" {
		return token, nil
	}
	
	// Try to load from token manager (look for any global token)
	configDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan")
	tokenManager, err := NewTokenManager(configDir)
	if err == nil {
		allTokens := tokenManager.ListTokens()
		for tokenValue, token := range allTokens {
			if token.Type == TokenTypeGlobal {
				return tokenValue, nil
			}
		}
	}
	
	return "", fmt.Errorf("no token found. Set BITSWAN_DAEMON_TOKEN environment variable or create a global token via the daemon API")
}

