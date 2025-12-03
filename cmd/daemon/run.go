package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/spf13/cobra"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemonapi"
)

// WorkspaceInitMessage represents the JSON message for workspace/init topic
type WorkspaceInitMessage struct {
	Name              string `json:"name"`
	Remote            string `json:"remote,omitempty"`
	Branch            string `json:"branch,omitempty"`
	Domain            string `json:"domain,omitempty"`
	EditorImage       string `json:"editor-image,omitempty"`
	GitopsImage       string `json:"gitops-image,omitempty"`
	OauthConfig       string `json:"oauth-config,omitempty"`
	NoOauth           bool   `json:"no-oauth,omitempty"`
	SSHPort           string `json:"ssh-port,omitempty"`
	MkCerts           bool   `json:"mkcerts,omitempty"`
	SetHosts          bool   `json:"set-hosts,omitempty"`
	Local             bool   `json:"local,omitempty"`
	NoIde             bool   `json:"no-ide,omitempty"`
}

// WorkspaceRemoveMessage represents the JSON message for workspace/remove topic
type WorkspaceRemoveMessage struct {
	Name string `json:"name"`
}

// LogMessage represents a log line published to the logs topic
type LogMessage struct {
	Command string `json:"command"`
	Object  string `json:"object"`
	Output  string `json:"output"`
	Status  string `json:"status,omitempty"` // "running", "success", or "failure"
}

func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "__run",
		Short:  "Run the automation server daemon (internal command)",
		Hidden: true, // Hide from help since this is an internal command
		RunE:   runDaemon,
	}
}

func runDaemon(cmd *cobra.Command, args []string) error {
	// Create AOC client to get MQTT credentials
	// NewAOCClient will load the config and settings internally
	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		return fmt.Errorf("failed to create AOC client: %w", err)
	}

	// Get MQTT credentials for the automation server itself
	mqttCreds, err := aocClient.GetAutomationServerMQTTCredentials()
	if err != nil {
		return fmt.Errorf("failed to get MQTT credentials: %w", err)
	}

	// Connect to MQTT
	opts := mqtt.NewClientOptions()
	brokerURL := fmt.Sprintf("tcp://%s:%d", mqttCreds.Broker, mqttCreds.Port)
	opts.AddBroker(brokerURL)
	clientID := fmt.Sprintf("bitswan-automation-server-daemon-%d", time.Now().Unix())
	opts.SetClientID(clientID)
	opts.SetUsername(mqttCreds.Username)
	opts.SetPassword(mqttCreds.Password)
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(5 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetConnectTimeout(10 * time.Second) // Add connection timeout
	opts.SetWriteTimeout(10 * time.Second)
	opts.SetMaxReconnectInterval(30 * time.Second)

	// Add connection callbacks for better logging
	opts.OnConnect = func(client mqtt.Client) {
		fmt.Printf("✓ Successfully connected to MQTT broker at %s\n", brokerURL)
		fmt.Printf("  Client ID: %s\n", clientID)
	}
	opts.OnConnectionLost = func(client mqtt.Client, err error) {
		fmt.Printf("⚠ MQTT connection lost: %v\n", err)
	}
	opts.OnReconnecting = func(client mqtt.Client, opts *mqtt.ClientOptions) {
		fmt.Printf("🔄 Reconnecting to MQTT broker...\n")
	}

	client := mqtt.NewClient(opts)

	fmt.Printf("Connecting to MQTT broker at %s...\n", brokerURL)
	fmt.Printf("  Username: %s\n", mqttCreds.Username)
	fmt.Printf("  Port: %d\n", mqttCreds.Port)
	
	// Connect with timeout
	connectChan := make(chan error, 1)
	go func() {
		token := client.Connect()
		if token.Wait() {
			connectChan <- token.Error()
		} else {
			connectChan <- fmt.Errorf("connection token wait failed")
		}
	}()
	
	select {
	case err := <-connectChan:
		if err != nil {
			return fmt.Errorf("failed to connect to MQTT broker at %s: %w", brokerURL, err)
		}
		fmt.Println("✓ MQTT connection established successfully")
	case <-time.After(15 * time.Second):
		return fmt.Errorf("connection timeout: failed to connect to MQTT broker at %s within 15 seconds", brokerURL)
	}

	// Subscribe to workspace/init topic
	initTopic := "workspace/init"
	fmt.Printf("Subscribing to topic: %s\n", initTopic)
	if token := client.Subscribe(initTopic, 0, handleInitMessage); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", initTopic, token.Error())
	}
	fmt.Printf("✓ Successfully subscribed to %s\n", initTopic)

	// Subscribe to workspace/remove topic
	removeTopic := "workspace/remove"
	fmt.Printf("Subscribing to topic: %s\n", removeTopic)
	if token := client.Subscribe(removeTopic, 0, handleRemoveMessage); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", removeTopic, token.Error())
	}
	fmt.Printf("✓ Successfully subscribed to %s\n", removeTopic)

	// Start REST API server
	cfg := config.NewAutomationServerConfig()
	configDir := cfg.GetConfigPath()
	if configDir != "" {
		// Extract directory from config path
		configDir = filepath.Dir(configDir)
	} else {
		configDir = filepath.Join(os.Getenv("HOME"), ".config", "bitswan")
	}
	
	apiServer, err := daemonapi.NewServer(configDir, 8080)
	if err != nil {
		return fmt.Errorf("failed to create REST API server: %w", err)
	}
	
	// Start REST API server in a goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("Starting REST API server on port 8080...")
		if err := apiServer.Start(); err != nil {
			fmt.Printf("REST API server error: %v\n", err)
		}
	}()
	
	// Give the server a moment to start
	time.Sleep(500 * time.Millisecond)

	fmt.Println("")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("✓ Automation server daemon is ready and listening for commands")
	fmt.Println("  Listening on topics:")
	fmt.Printf("    - %s\n", initTopic)
	fmt.Printf("    - %s\n", removeTopic)
	fmt.Println("  REST API server running on port 8080")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Press Ctrl+C to stop the daemon.")
	<-sigChan

	fmt.Println("Shutting down...")
	apiServer.Stop()
	client.Disconnect(250)
	wg.Wait()
	return nil
}

func handleInitMessage(client mqtt.Client, msg mqtt.Message) {
	fmt.Printf("Received init message on topic %s: %s\n", msg.Topic(), string(msg.Payload()))

	var initMsg WorkspaceInitMessage
	if err := json.Unmarshal(msg.Payload(), &initMsg); err != nil {
		fmt.Printf("Error parsing init message: %v\n", err)
		return
	}

	if initMsg.Name == "" {
		fmt.Println("Error: workspace name is required")
		return
	}

	// Call the bitswan binary to initialize the workspace
	// This avoids import cycles by calling the binary directly
	binaryPath := "/usr/local/bin/bitswan"
	args := []string{"workspace", "init", initMsg.Name}

	if initMsg.Remote != "" {
		args = append(args, "--remote", initMsg.Remote)
	}
	if initMsg.Branch != "" {
		args = append(args, "--branch", initMsg.Branch)
	}
	if initMsg.Domain != "" {
		args = append(args, "--domain", initMsg.Domain)
	}
	if initMsg.EditorImage != "" {
		args = append(args, "--editor-image", initMsg.EditorImage)
	}
	if initMsg.GitopsImage != "" {
		args = append(args, "--gitops-image", initMsg.GitopsImage)
	}
	if initMsg.OauthConfig != "" {
		args = append(args, "--oauth-config", initMsg.OauthConfig)
	}
	if initMsg.NoOauth {
		args = append(args, "--no-oauth")
	}
	if initMsg.SSHPort != "" {
		args = append(args, "--ssh-port", initMsg.SSHPort)
	}
	if initMsg.MkCerts {
		args = append(args, "--mkcerts")
	}
	if initMsg.SetHosts {
		args = append(args, "--set-hosts")
	}
	if initMsg.Local {
		args = append(args, "--local")
	}
	if initMsg.NoIde {
		args = append(args, "--no-ide")
	}

	cmd := exec.Command(binaryPath, args...)
	if err := runCommandWithLogging(client, cmd, "workspace-init", initMsg.Name); err != nil {
		fmt.Printf("Error initializing workspace %s: %v\n", initMsg.Name, err)
		return
	}
}

func handleRemoveMessage(client mqtt.Client, msg mqtt.Message) {
	fmt.Printf("Received remove message on topic %s: %s\n", msg.Topic(), string(msg.Payload()))

	var removeMsg WorkspaceRemoveMessage
	if err := json.Unmarshal(msg.Payload(), &removeMsg); err != nil {
		fmt.Printf("Error parsing remove message: %v\n", err)
		return
	}

	if removeMsg.Name == "" {
		fmt.Println("Error: workspace name is required")
		return
	}

	// Call the bitswan binary to remove the workspace
	// This avoids import cycles by calling the binary directly
	// Use --yes flag to skip confirmation prompts (trust the MQTT message)
	binaryPath := "/usr/local/bin/bitswan"
	cmd := exec.Command(binaryPath, "workspace", "remove", "--yes", removeMsg.Name)
	if err := runCommandWithLogging(client, cmd, "workspace-remove", removeMsg.Name); err != nil {
		fmt.Printf("Error removing workspace %s: %v\n", removeMsg.Name, err)
		return
	}
}

// runCommandWithLogging runs a command and streams its output to the MQTT logs topic
func runCommandWithLogging(client mqtt.Client, cmd *exec.Cmd, commandName, objectName string) error {
	logsTopic := "logs"

	// Create pipes for stdout and stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Function to read and publish lines from a reader
	streamLines := func(reader io.Reader, isStderr bool) {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := scanner.Text()
			// Prefix stderr lines to make them clearly visible
			if isStderr {
				line = "Command stderr: " + line
			}
			logMsg := LogMessage{
				Command: commandName,
				Object:  objectName,
				Output:  line,
				Status:  "running",
			}

			jsonData, err := json.Marshal(logMsg)
			if err != nil {
				fmt.Printf("Error marshaling log message: %v\n", err)
				continue
			}

			token := client.Publish(logsTopic, 0, false, jsonData)
			if token.Wait() && token.Error() != nil {
				fmt.Printf("Error publishing log message: %v\n", token.Error())
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading output: %v\n", err)
		}
	}

	// Stream stdout and stderr concurrently
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		streamLines(stdoutPipe, false)
	}()

	go func() {
		defer wg.Done()
		streamLines(stderrPipe, true)
	}()

	// Wait for all output to be processed
	wg.Wait()

	// Wait for the command to complete and publish final status
	var finalStatus string
	if err := cmd.Wait(); err != nil {
		finalStatus = "failure"
		// Publish failure status message
		logMsg := LogMessage{
			Command: commandName,
			Object:  objectName,
			Output:  fmt.Sprintf("Command failed: %v", err),
			Status:  finalStatus,
		}
		jsonData, err := json.Marshal(logMsg)
		if err == nil {
			token := client.Publish(logsTopic, 0, false, jsonData)
			if token.Wait() && token.Error() != nil {
				fmt.Printf("Error publishing failure status: %v\n", token.Error())
			}
		}
		return fmt.Errorf("command failed: %w", err)
	}

	// Publish success status message
	finalStatus = "success"
	logMsg := LogMessage{
		Command: commandName,
		Object:  objectName,
		Output:  "Command completed successfully",
		Status:  finalStatus,
	}
	jsonData, err := json.Marshal(logMsg)
	if err == nil {
		token := client.Publish(logsTopic, 0, false, jsonData)
		if token.Wait() && token.Error() != nil {
			fmt.Printf("Error publishing success status: %v\n", token.Error())
		}
	}

	return nil
}

