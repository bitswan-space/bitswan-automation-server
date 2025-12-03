package daemonapi

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ExecuteViaDockerExec executes a command via docker exec + curl to the REST API
// This is used when running the CLI outside the daemon container
func ExecuteViaDockerExec(command string, args []string, workspace string) error {
	// Check if daemon is running
	running, err := CheckDaemonRunning()
	if err != nil {
		return fmt.Errorf("failed to check daemon status: %w", err)
	}

	if !running {
		return fmt.Errorf("daemon is not running. Please start it with: bitswan automation-server-daemon init")
	}

	// Get global token
	token, err := GetGlobalToken()
	if err != nil {
		return fmt.Errorf("no global token found. Set BITSWAN_DAEMON_TOKEN environment variable or create one via the daemon API")
	}

	// Use docker exec to run curl inside the daemon container
	// The daemon container can access localhost:8080 directly
	containerName := GetDaemonContainerName()

	// Special handling for CA add command - read certificate file
	if command == "ca" || command == "certauthority" {
		if len(args) > 0 && args[0] == "add" && len(args) >= 2 {
			// Read certificate file content
			certPath := args[1]
			certContent, err := os.ReadFile(certPath)
			if err == nil {
				// Replace the file path with the content in args for endpoint mapper
				args[1] = "CERT_CONTENT:" + string(certContent)
			}
		}
	}

	// Get REST endpoint for this command
	method, endpoint, payload := getRESTEndpoint(command, args, workspace)

	// If no specific endpoint found, fall back to legacy execute endpoint
	if endpoint == "" || endpoint == "/api/v1/execute" {
		requestPayload := CommandRequest{
			Command:   command,
			Args:      args,
			Workspace: workspace,
		}

		jsonPayload, err := json.Marshal(requestPayload)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		payload = string(jsonPayload)
		method = "POST"
		endpoint = "/api/v1/execute"
	}

	// Build curl command
	var curlCmd string
	if payload != "" {
		curlCmd = fmt.Sprintf(
			"curl -s -X %s http://localhost:8080%s -H 'Content-Type: application/json' -H 'Authorization: Bearer %s' -d '%s'",
			method,
			endpoint,
			token,
			strings.ReplaceAll(payload, "'", "'\\''"), // Escape single quotes for shell
		)
	} else {
		curlCmd = fmt.Sprintf(
			"curl -s -X %s http://localhost:8080%s -H 'Content-Type: application/json' -H 'Authorization: Bearer %s'",
			method,
			endpoint,
			token,
		)
	}

	// Execute via docker exec
	execCmd := exec.Command("docker", "exec", "-i", containerName, "sh", "-c", curlCmd)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("failed to execute command via daemon: %w", err)
	}

	// Parse response from stdout (curl output)
	// The response is JSON, but we've already streamed it to stdout
	// For now, we'll rely on the exit code
	return nil
}

// ExecuteViaDockerExecWithResponse executes a command and returns the response
func ExecuteViaDockerExecWithResponse(command string, args []string, workspace string) (*CommandResponse, error) {
	// Check if daemon is running
	running, err := CheckDaemonRunning()
	if err != nil {
		return nil, fmt.Errorf("failed to check daemon status: %w", err)
	}

	if !running {
		return nil, fmt.Errorf("daemon is not running. Please start it with: bitswan automation-server-daemon init")
	}

	// Get global token
	token, err := GetGlobalToken()
	if err != nil {
		return nil, fmt.Errorf("no global token found. Set BITSWAN_DAEMON_TOKEN environment variable")
	}

	// Use docker exec to run curl inside the daemon container
	containerName := GetDaemonContainerName()

	// Special handling for CA add command - read certificate file
	if command == "ca" || command == "certauthority" {
		if len(args) > 0 && args[0] == "add" && len(args) >= 2 {
			// Read certificate file content
			certPath := args[1]
			certContent, err := os.ReadFile(certPath)
			if err == nil {
				// Replace the file path with the content in args for endpoint mapper
				args[1] = "CERT_CONTENT:" + string(certContent)
			}
		}
	}

	// Get REST endpoint for this command
	method, endpoint, payload := getRESTEndpoint(command, args, workspace)

	// If no specific endpoint found, fall back to legacy execute endpoint
	if endpoint == "" || endpoint == "/api/v1/execute" {
		requestPayload := CommandRequest{
			Command:   command,
			Args:      args,
			Workspace: workspace,
		}

		jsonPayload, err := json.Marshal(requestPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		payload = string(jsonPayload)
		method = "POST"
		endpoint = "/api/v1/execute"
	}

	// Build curl command
	var curlCmd string
	if payload != "" {
		curlCmd = fmt.Sprintf(
			"curl -s -X %s http://localhost:8080%s -H 'Content-Type: application/json' -H 'Authorization: Bearer %s' -d '%s'",
			method,
			endpoint,
			token,
			strings.ReplaceAll(payload, "'", "'\\''"), // Escape single quotes for shell
		)
	} else {
		curlCmd = fmt.Sprintf(
			"curl -s -X %s http://localhost:8080%s -H 'Content-Type: application/json' -H 'Authorization: Bearer %s'",
			method,
			endpoint,
			token,
		)
	}

	// Execute via docker exec and capture output
	execCmd := exec.Command("docker", "exec", containerName, "sh", "-c", curlCmd)
	output, err := execCmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("command failed: %s", string(exitError.Stderr))
		}
		return nil, fmt.Errorf("failed to execute command via daemon: %w", err)
	}

	// Parse JSON response
	var response CommandResponse
	if err := json.Unmarshal(output, &response); err != nil {
		// If it's not JSON, it might be direct output
		return &CommandResponse{
			Success: true,
			Output:  string(output),
		}, nil
	}

	return &response, nil
}
