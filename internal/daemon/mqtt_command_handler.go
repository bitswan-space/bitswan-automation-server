package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// WorkspaceCreateRequest represents a workspace create request from MQTT
type WorkspaceCreateRequest struct {
	RequestID          string `json:"request-id"`
	Name               string `json:"name"`
	Remote             string `json:"remote,omitempty"`
	Branch             string `json:"branch,omitempty"`
	Domain             string `json:"domain,omitempty"`
	CertsDir           string `json:"certs-dir,omitempty"`
	Verbose            bool   `json:"verbose,omitempty"`
	MkCerts            bool   `json:"mkcerts,omitempty"`
	NoIde              bool   `json:"no-ide,omitempty"`
	SetHosts           bool   `json:"set-hosts,omitempty"`
	Local              bool   `json:"local,omitempty"`
	GitopsImage        string `json:"gitops-image,omitempty"`
	EditorImage        string `json:"editor-image,omitempty"`
	GitopsDevSourceDir string `json:"gitops-dev-source-dir,omitempty"`
	OauthConfigFile    string `json:"oauth-config,omitempty"`
	NoOauth            bool   `json:"no-oauth,omitempty"`
	SshPort            string `json:"ssh-port,omitempty"`
}

// WorkspaceDeleteRequest represents a workspace delete request from MQTT
type WorkspaceDeleteRequest struct {
	RequestID string `json:"request-id"`
	ID        string `json:"id"`             // Workspace ID (required)
	Name      string `json:"name,omitempty"` // Workspace name (optional, for backwards compatibility)
}

// LogMessage represents a log message in Docker JSON log format
type LogMessage struct {
	RequestID string `json:"request-id"`
	Time      string `json:"time"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

// ResultMessage represents the final result message
type ResultMessage struct {
	RequestID string `json:"request-id"`
	Success   bool   `json:"success"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
}

// handleWorkspaceCreate handles workspace create requests via MQTT
func (p *MQTTPublisher) handleWorkspaceCreate(client mqtt.Client, msg mqtt.Message) {
	var req WorkspaceCreateRequest
	if err := json.Unmarshal(msg.Payload(), &req); err != nil {
		p.publishLog(req.RequestID, "error", fmt.Sprintf("Failed to parse create request: %v", err))
		p.publishResult(req.RequestID, false, "", fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	if req.Name == "" {
		p.publishLog(req.RequestID, "error", "Workspace name is required")
		p.publishResult(req.RequestID, false, "", "Workspace name is required")
		return
	}

	p.publishLog(req.RequestID, "info", fmt.Sprintf("Starting workspace creation: %s", req.Name))

	// Build args for runWorkspaceInit
	args := []string{}
	if req.Remote != "" {
		args = append(args, "--remote", req.Remote)
	}
	if req.Branch != "" {
		args = append(args, "--branch", req.Branch)
	}
	if req.Domain != "" {
		args = append(args, "--domain", req.Domain)
	}
	if req.CertsDir != "" {
		args = append(args, "--certs-dir", req.CertsDir)
	}
	if req.Verbose {
		args = append(args, "--verbose")
	}
	if req.MkCerts {
		args = append(args, "--mkcerts")
	}
	if req.NoIde {
		args = append(args, "--no-ide")
	}
	if req.SetHosts {
		args = append(args, "--set-hosts")
	}
	if req.Local {
		args = append(args, "--local")
	}
	if req.GitopsImage != "" {
		args = append(args, "--gitops-image", req.GitopsImage)
	}
	if req.EditorImage != "" {
		args = append(args, "--editor-image", req.EditorImage)
	}
	if req.GitopsDevSourceDir != "" {
		args = append(args, "--gitops-dev-source-dir", req.GitopsDevSourceDir)
	}
	if req.OauthConfigFile != "" {
		args = append(args, "--oauth-config", req.OauthConfigFile)
	}
	if req.NoOauth {
		args = append(args, "--no-oauth")
	}
	if req.SshPort != "" {
		args = append(args, "--ssh-port", req.SshPort)
	}
	args = append(args, req.Name)

	// Execute workspace init in a goroutine
	go func() {
		// Get server instance
		p.mu.RLock()
		server := p.server
		p.mu.RUnlock()

		if server == nil {
			fmt.Printf("Server instance not available, using CLI fallback for workspace creation\n")
			// Fallback to CLI if server not available
			p.executeWorkspaceInitCLI(req, args)
			return
		}

		fmt.Printf("Using internal server function for workspace creation: %s\n", req.Name)

		// Use internal function with MQTT log writer
		logWriter := NewMQTTLogWriter(p, req.RequestID, "info")

		// Redirect stdout temporarily
		stdoutMutex.Lock()
		oldStdout := os.Stdout
		rPipe, wPipe, err := os.Pipe()
		if err != nil {
			stdoutMutex.Unlock()
			p.publishLog(req.RequestID, "error", fmt.Sprintf("Failed to create pipe: %v", err))
			p.publishResult(req.RequestID, false, "", fmt.Sprintf("Failed to create pipe: %v", err))
			return
		}
		os.Stdout = wPipe
		stdoutMutex.Unlock()

		defer func() {
			stdoutMutex.Lock()
			os.Stdout = oldStdout
			stdoutMutex.Unlock()
			rPipe.Close()
			wPipe.Close()
		}()

		// Read from pipe and publish logs
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 4096)
			var lineBuf strings.Builder
			for {
				n, err := rPipe.Read(buf)
				if n > 0 {
					// Accumulate data in line buffer
					lineBuf.Write(buf[:n])

					// Process complete lines
					content := lineBuf.String()
					lines := strings.Split(content, "\n")

					// Keep incomplete line in buffer
					lineBuf.Reset()
					if len(lines) > 1 {
						// Last element might be incomplete
						lineBuf.WriteString(lines[len(lines)-1])
					}

					// Process complete lines
					for i := 0; i < len(lines)-1; i++ {
						line := strings.TrimSpace(lines[i])
						if line != "" {
							// Write to log writer which publishes to MQTT
							if _, writeErr := logWriter.Write([]byte(line + "\n")); writeErr != nil {
								fmt.Printf("Error writing to MQTT log writer: %v\n", writeErr)
							}
						}
					}
				}
				if err != nil {
					// Process any remaining data in buffer
					remaining := strings.TrimSpace(lineBuf.String())
					if remaining != "" {
						if _, writeErr := logWriter.Write([]byte(remaining + "\n")); writeErr != nil {
							fmt.Printf("Error writing final line to MQTT log writer: %v\n", writeErr)
						}
					}
					if err.Error() != "EOF" {
						fmt.Printf("Error reading from pipe: %v\n", err)
					}
					break
				}
			}
		}()

		// Run workspace init
		err = server.runWorkspaceInit(args)
		wPipe.Close()
		wg.Wait()

		if err != nil {
			p.publishLog(req.RequestID, "error", fmt.Sprintf("Workspace creation failed: %v", err))
			p.publishResult(req.RequestID, false, "", fmt.Sprintf("Workspace creation failed: %v", err))
		} else {
			p.publishLog(req.RequestID, "info", fmt.Sprintf("Workspace '%s' created successfully", req.Name))
			p.publishResult(req.RequestID, true, fmt.Sprintf("Workspace '%s' created successfully", req.Name), "")

			// Small delay to ensure metadata is fully written before syncing list
			time.Sleep(1 * time.Second)

			// Sync updated workspace list to AOC
			if err := syncWorkspaceListToAOC(); err != nil {
				fmt.Printf("Warning: Failed to sync workspace list after creation: %v\n", err)
			} else {
				fmt.Printf("Synced workspace list after creation of '%s'\n", req.Name)
			}
		}
	}()
}

// executeWorkspaceInitCLI is a fallback that uses CLI when server instance is not available
func (p *MQTTPublisher) executeWorkspaceInitCLI(req WorkspaceCreateRequest, args []string) {
	// Build full command args
	fullArgs := []string{"workspace", "init"}
	fullArgs = append(fullArgs, args...)

	// Create a pipe to capture stdout/stderr
	pr, pw, err := os.Pipe()
	if err != nil {
		p.publishLog(req.RequestID, "error", fmt.Sprintf("Failed to create pipe: %v", err))
		p.publishResult(req.RequestID, false, "", fmt.Sprintf("Failed to create pipe: %v", err))
		return
	}
	defer pr.Close()
	defer pw.Close()

	// Create command
	cmd := exec.Command("bitswan", fullArgs...)
	cmd.Stdout = pw
	cmd.Stderr = pw
	cmd.Stdin = os.Stdin

	// Start command
	err = cmd.Start()
	if err != nil {
		p.publishLog(req.RequestID, "error", fmt.Sprintf("Failed to start workspace init: %v", err))
		p.publishResult(req.RequestID, false, "", fmt.Sprintf("Failed to start workspace init: %v", err))
		pw.Close()
		return
	}

	// Read output line by line and publish as logs
	go func() {
		buf := make([]byte, 4096)
		var lineBuf strings.Builder
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				lineBuf.Write(buf[:n])
				// Process complete lines
				content := lineBuf.String()
				lines := strings.Split(content, "\n")
				// Keep incomplete line in buffer
				lineBuf.Reset()
				if len(lines) > 1 {
					lineBuf.WriteString(lines[len(lines)-1])
				}
				// Publish complete lines
				for i := 0; i < len(lines)-1; i++ {
					line := strings.TrimSpace(lines[i])
					if line != "" {
						p.publishLog(req.RequestID, "info", line)
					}
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Wait for command to complete
	waitErr := cmd.Wait()
	pw.Close()

	if waitErr != nil {
		p.publishLog(req.RequestID, "error", fmt.Sprintf("Workspace creation failed: %v", waitErr))
		p.publishResult(req.RequestID, false, "", fmt.Sprintf("Workspace creation failed: %v", waitErr))
	} else {
		p.publishLog(req.RequestID, "info", fmt.Sprintf("Workspace '%s' created successfully", req.Name))
		p.publishResult(req.RequestID, true, fmt.Sprintf("Workspace '%s' created successfully", req.Name), "")

		// Small delay to ensure metadata is fully written before syncing list
		time.Sleep(1 * time.Second)

		// Sync updated workspace list to AOC
		if err := syncWorkspaceListToAOC(); err != nil {
			fmt.Printf("Warning: Failed to sync workspace list after creation: %v\n", err)
		} else {
			fmt.Printf("Synced workspace list after creation of '%s'\n", req.Name)
		}
	}
}

// handleWorkspaceDelete handles workspace delete requests via MQTT
func (p *MQTTPublisher) handleWorkspaceDelete(client mqtt.Client, msg mqtt.Message) {
	var req WorkspaceDeleteRequest
	if err := json.Unmarshal(msg.Payload(), &req); err != nil {
		p.publishLog(req.RequestID, "error", fmt.Sprintf("Failed to parse delete request: %v", err))
		p.publishResult(req.RequestID, false, "", fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	// ID is required, but we support name for backwards compatibility
	var workspaceName string
	if req.ID != "" {
		// Look up workspace name from ID
		var err error
		workspaceName, err = findWorkspaceNameByID(req.ID)
		if err != nil {
			p.publishLog(req.RequestID, "error", fmt.Sprintf("Failed to find workspace with ID %s: %v", req.ID, err))
			p.publishResult(req.RequestID, false, "", fmt.Sprintf("Workspace with ID %s not found: %v", req.ID, err))
			return
		}
	} else if req.Name != "" {
		// Backwards compatibility: use name if ID not provided
		workspaceName = req.Name
	} else {
		p.publishLog(req.RequestID, "error", "Workspace ID or name is required")
		p.publishResult(req.RequestID, false, "", "Workspace ID or name is required")
		return
	}

	p.publishLog(req.RequestID, "info", fmt.Sprintf("Starting workspace deletion: %s (ID: %s)", workspaceName, req.ID))

	// Execute workspace remove in a goroutine
	go func() {
		// Ensure result is always published, even if there's a panic
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("ERROR: Panic in workspace deletion goroutine for request %s: %v\n", req.RequestID, r)
				p.publishLog(req.RequestID, "error", fmt.Sprintf("Workspace deletion panicked: %v", r))
				p.publishResult(req.RequestID, false, "", fmt.Sprintf("Workspace deletion panicked: %v", r))
			}
		}()

		// Use internal function with MQTT log writer
		logWriter := NewMQTTLogWriter(p, req.RequestID, "info")

		fmt.Printf("Starting workspace deletion for request %s: workspace=%s, id=%s\n", req.RequestID, workspaceName, req.ID)

		// Run workspace remove with MQTT log writer
		err := RunWorkspaceRemove(workspaceName, logWriter)

		fmt.Printf("Workspace deletion completed for request %s: err=%v\n", req.RequestID, err)

		if err != nil {
			fmt.Printf("Publishing failure result for request %s: %v\n", req.RequestID, err)
			p.publishLog(req.RequestID, "error", fmt.Sprintf("Workspace deletion failed: %v", err))
			p.publishResult(req.RequestID, false, "", fmt.Sprintf("Workspace deletion failed: %v", err))
			fmt.Printf("Failure result published for request %s\n", req.RequestID)
		} else {
			fmt.Printf("Publishing success result for request %s\n", req.RequestID)
			// IMPORTANT: Publish result IMMEDIATELY, before any sync operations
			// The frontend is waiting for this result and connections might be lost after sync
			p.publishResult(req.RequestID, true, fmt.Sprintf("Workspace '%s' (ID: %s) deleted successfully", workspaceName, req.ID), "")
			fmt.Printf("Success result published for request %s\n", req.RequestID)
			
			// Now publish the log message (less critical)
			p.publishLog(req.RequestID, "info", fmt.Sprintf("Workspace '%s' (ID: %s) deleted successfully", workspaceName, req.ID))

			// Small delay to ensure workspace directory is fully removed before syncing list
			time.Sleep(500 * time.Millisecond)

			// Sync updated workspace list to AOC (do this last, after result is sent)
			if err := syncWorkspaceListToAOC(); err != nil {
				fmt.Printf("Warning: Failed to sync workspace list after deletion: %v\n", err)
			}
		}
	}()
}

// findWorkspaceNameByID finds the workspace name by looking up the workspace ID in metadata files
func findWorkspaceNameByID(workspaceID string) (string, error) {
	homeDir := os.Getenv("HOME")
	workspacesDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces")

	// Check if workspaces directory exists
	if _, err := os.Stat(workspacesDir); os.IsNotExist(err) {
		return "", fmt.Errorf("workspaces directory does not exist")
	}

	// Iterate through all workspace directories
	files, err := os.ReadDir(workspacesDir)
	if err != nil {
		return "", fmt.Errorf("failed to read workspaces directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			workspaceName := file.Name()
			metadata, err := config.GetWorkspaceMetadata(workspaceName)
			if err != nil {
				// Skip workspaces without metadata
				continue
			}
			if metadata.WorkspaceId != nil && *metadata.WorkspaceId == workspaceID {
				return workspaceName, nil
			}
		}
	}

	return "", fmt.Errorf("workspace with ID %s not found", workspaceID)
}

// publishLog publishes a log message to the logs topic
func (p *MQTTPublisher) publishLog(requestID, level, message string) {
	p.mu.RLock()
	connected := p.connected
	serverInfo := p.serverInfo
	client := p.client
	p.mu.RUnlock()

	if !connected || serverInfo == nil || client == nil {
		// Silently skip if not connected - don't log to avoid infinite loops
		return
	}

	// Double-check client is actually connected (not just our flag)
	if !client.IsConnected() {
		return
	}

	// Use mountpoint-relative topic - EMQX will automatically prepend the mountpoint
	logTopic := "logs"

	logMsg := LogMessage{
		RequestID: requestID,
		Time:      time.Now().UTC().Format(time.RFC3339),
		Level:     level,
		Message:   message,
	}

	payload, err := json.Marshal(logMsg)
	if err != nil {
		// Don't log errors to avoid infinite loops
		return
	}

	// Publish with QoS 1 and non-blocking wait with timeout
	token := client.Publish(logTopic, 1, false, payload)

	// Use WaitTimeout instead of Wait to prevent indefinite blocking
	// If connection is lost, this will timeout quickly
	if !token.WaitTimeout(2 * time.Second) {
		// Timeout - connection might be lost, silently skip
		return
	}

	if token.Error() != nil {
		// Connection error - silently skip to avoid blocking
		return
	}
}

// publishResult publishes the final result message
func (p *MQTTPublisher) publishResult(requestID string, success bool, message, errorMsg string) {
	p.mu.RLock()
	connected := p.connected
	serverInfo := p.serverInfo
	client := p.client
	p.mu.RUnlock()

	if !connected || serverInfo == nil || client == nil {
		fmt.Printf("ERROR: Cannot publish result message for request %s: MQTT not initialized (connected=%v, serverInfo=%v, client=%v)\n", requestID, connected, serverInfo != nil, client != nil)
		return
	}

	// Double-check client is actually connected
	if !client.IsConnected() {
		fmt.Printf("ERROR: Cannot publish result message for request %s: MQTT client not connected\n", requestID)
		return
	}

	// Use mountpoint-relative topic - EMQX will automatically prepend the mountpoint
	logTopic := "logs"

	resultMsg := ResultMessage{
		RequestID: requestID,
		Success:   success,
		Message:   message,
		Error:     errorMsg,
	}

	payload, err := json.Marshal(resultMsg)
	if err != nil {
		fmt.Printf("ERROR: Failed to marshal result message for request %s: %v\n", requestID, err)
		return
	}

	fmt.Printf("Publishing result message for request %s: success=%v, topic=%s\n", requestID, success, logTopic)

	// Publish with QoS 1 and non-blocking wait with timeout
	token := client.Publish(logTopic, 1, false, payload)

	// Use WaitTimeout instead of Wait to prevent indefinite blocking
	if !token.WaitTimeout(5 * time.Second) {
		// Timeout - connection might be lost, log error
		fmt.Printf("ERROR: Timeout publishing result message for request %s: MQTT publish timed out after 5 seconds\n", requestID)
		return
	}

	if token.Error() != nil {
		// Connection error - log it
		fmt.Printf("ERROR: Failed to publish result message for request %s: %v\n", requestID, token.Error())
		return
	}

	fmt.Printf("Successfully published result message for request %s\n", requestID)
}
