package daemonapi

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ExecuteWorkspaceInitViaDockerExec calls the REST API via docker exec to initialize a workspace
func ExecuteWorkspaceInitViaDockerExec(req WorkspaceInitRequest) error {
	return executeRESTViaDockerExec("POST", "/api/v1/workspaces", req)
}

// ExecuteWorkspaceRemoveViaDockerExec calls the REST API via docker exec to remove a workspace
func ExecuteWorkspaceRemoveViaDockerExec(req WorkspaceRemoveRequest) error {
	return executeRESTViaDockerExec("DELETE", fmt.Sprintf("/api/v1/workspaces/%s", req.Name), req)
}

// ExecuteWorkspaceUpdateViaDockerExec calls the REST API via docker exec to update a workspace
func ExecuteWorkspaceUpdateViaDockerExec(req WorkspaceUpdateRequest) error {
	return executeRESTViaDockerExec("PUT", fmt.Sprintf("/api/v1/workspaces/%s", req.Name), req)
}

// ExecuteWorkspaceSelectViaDockerExec calls the REST API via docker exec to select a workspace
func ExecuteWorkspaceSelectViaDockerExec(workspaceName string) error {
	return executeRESTViaDockerExec("POST", fmt.Sprintf("/api/v1/workspaces/%s/select", workspaceName), nil)
}

// ExecuteWorkspaceOpenViaDockerExec calls the REST API via docker exec to open a workspace
func ExecuteWorkspaceOpenViaDockerExec(workspaceName string) error {
	return executeRESTViaDockerExec("POST", fmt.Sprintf("/api/v1/workspaces/%s/open", workspaceName), nil)
}

// ExecuteWorkspacePullAndDeployViaDockerExec calls the REST API via docker exec
func ExecuteWorkspacePullAndDeployViaDockerExec(req WorkspacePullAndDeployRequest) error {
	return executeRESTViaDockerExec("POST", fmt.Sprintf("/api/v1/workspaces/%s/pull-and-deploy", req.WorkspaceName), req)
}

// executeRESTViaDockerExec is a helper that executes a REST API call via docker exec + curl
func executeRESTViaDockerExec(method, endpoint string, payload interface{}) error {
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
	
	containerName := GetDaemonContainerName()
	
	// Build curl command
	var curlCmd string
	if payload != nil {
		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		curlCmd = fmt.Sprintf(
			"curl -s -X %s http://localhost:8080%s -H 'Content-Type: application/json' -H 'Authorization: Bearer %s' -d '%s'",
			method,
			endpoint,
			token,
			strings.ReplaceAll(string(jsonPayload), "'", "'\\''"), // Escape single quotes for shell
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
	
	return nil
}

