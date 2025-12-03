package daemonapi

import (
	"fmt"
	"os"
	"os/exec"
)

// ShouldUseDaemon checks if commands should be executed via the daemon
// Returns true if we're not running inside the daemon container
func ShouldUseDaemon() bool {
	// Check if we're running inside the daemon container
	// The daemon container has a specific environment or we can check the container name
	containerName := os.Getenv("HOSTNAME")
	if containerName == "bitswan-automation-server-daemon" {
		return false
	}
	
	// Also check if we're being called from within docker exec
	// This is a simple heuristic - if BITSWAN_DAEMON_EXEC is set, we're being called via docker exec
	if os.Getenv("BITSWAN_DAEMON_EXEC") != "" {
		return false
	}
	
	return true
}

// ExecuteViaDaemon executes a command via the daemon REST API using docker exec + curl
func ExecuteViaDaemon(command string, args []string, workspace string) error {
	return ExecuteViaDockerExec(command, args, workspace)
}

// GetWorkspaceToken retrieves a workspace token from environment or config
func GetWorkspaceToken(workspace string) (string, error) {
	// First check environment variable
	if token := os.Getenv("BITSWAN_WORKSPACE_TOKEN"); token != "" {
		return token, nil
	}
	
	// TODO: Load from workspace metadata if needed
	return "", fmt.Errorf("no workspace token found for workspace %s", workspace)
}

// ExecuteCommand executes a command either directly or via daemon
func ExecuteCommand(command string, args []string, workspace string) error {
	if ShouldUseDaemon() {
		return ExecuteViaDaemon(command, args, workspace)
	}
	
	// Execute directly (we're in the daemon)
	binaryPath := "/usr/local/bin/bitswan"
	cmdArgs := []string{command}
	cmdArgs = append(cmdArgs, args...)
	
	cmd := exec.Command(binaryPath, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	return cmd.Run()
}

