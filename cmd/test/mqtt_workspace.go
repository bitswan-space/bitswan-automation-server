package test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/spf13/cobra"
)

func newMqttWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mqtt-workspace",
		Short: "Test workspace creation and deletion via MQTT",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestMqttWorkspace()
		},
	}

	return cmd
}

func runTestMqttWorkspace() error {
	fmt.Println("=== BitSwan Test Suite: MQTT Workspace ===")
	fmt.Println()

	// Step 1: Get AOC client and automation server info
	fmt.Println("[1/6] Getting AOC client and automation server info...")
	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		return fmt.Errorf("failed to create AOC client: %w", err)
	}

	serverInfo, err := aocClient.GetAutomationServerInfo()
	if err != nil {
		return fmt.Errorf("failed to get automation server info: %w", err)
	}

	fmt.Printf("✓ Automation server ID: %s\n", serverInfo.AutomationServerId)
	fmt.Printf("✓ Organization ID: %s\n", serverInfo.KeycloakOrgId)

	// Step 2: Get MQTT credentials
	fmt.Println("\n[2/6] Getting MQTT credentials...")
	mqttCreds, err := aocClient.GetAutomationServerMQTTCredentials()
	if err != nil {
		return fmt.Errorf("failed to get MQTT credentials: %w", err)
	}

	fmt.Printf("✓ MQTT broker: %s:%d\n", mqttCreds.Broker, mqttCreds.Port)

	// Step 3: Connect to MQTT broker
	fmt.Println("\n[3/6] Connecting to MQTT broker...")

	// Debug: Print raw credentials
	fmt.Printf("  Debug - Raw credentials:\n")
	fmt.Printf("    URL: %s\n", mqttCreds.URL)
	fmt.Printf("    Broker: %s\n", mqttCreds.Broker)
	fmt.Printf("    Port: %d\n", mqttCreds.Port)
	fmt.Printf("    Protocol: %s\n", mqttCreds.Protocol)

	// Always use WSS through ingress for testing
	// Extract host from broker or URL and construct WSS URL
	var brokerURL string
	if mqttCreds.URL != "" {
		brokerURL = mqttCreds.URL
		fmt.Printf("  Using URL from credentials: %s\n", brokerURL)
	} else {
		// Construct from protocol, broker, and port
		protocol := mqttCreds.Protocol
		if protocol == "" {
			protocol = "wss" // Default to WSS
		}
		brokerHost := mqttCreds.Broker
		mqttPort := mqttCreds.Port
		brokerURL = fmt.Sprintf("%s://%s:%d", protocol, brokerHost, mqttPort)
		fmt.Printf("  Constructed URL: %s\n", brokerURL)
	}

	// Normalize to WSS through ingress with /mqtt path
	// For any localhost or bitswan.localhost broker, use WSS through ingress
	if strings.Contains(brokerURL, "localhost") || strings.Contains(brokerURL, "bitswan.localhost") || strings.Contains(brokerURL, "aoc-emqx") {
		fmt.Printf("  Detected localhost/aoc-emqx, normalizing to WSS ingress...\n")
		// Extract hostname - could be from URL or broker field
		var hostname string
		if strings.HasPrefix(brokerURL, "wss://") || strings.HasPrefix(brokerURL, "ws://") ||
			strings.HasPrefix(brokerURL, "tcp://") || strings.HasPrefix(brokerURL, "ssl://") ||
			strings.HasPrefix(brokerURL, "tls://") {
			// Extract from URL
			urlWithoutProtocol := brokerURL
			for _, prefix := range []string{"wss://", "ws://", "tcp://", "ssl://", "tls://"} {
				if strings.HasPrefix(brokerURL, prefix) {
					urlWithoutProtocol = strings.TrimPrefix(brokerURL, prefix)
					break
				}
			}
			fmt.Printf("  URL without protocol: %s\n", urlWithoutProtocol)
			// Get hostname (before : or /)
			if idx := strings.Index(urlWithoutProtocol, ":"); idx > 0 {
				hostname = urlWithoutProtocol[:idx]
			} else if idx := strings.Index(urlWithoutProtocol, "/"); idx > 0 {
				hostname = urlWithoutProtocol[:idx]
			} else {
				hostname = urlWithoutProtocol
			}
		} else {
			// Use broker field directly
			hostname = mqttCreds.Broker
		}
		fmt.Printf("  Extracted hostname: %s\n", hostname)

		// Replace any localhost or aoc-emqx with mqtt.bitswan.localhost for ingress
		if hostname == "aoc-emqx" || strings.Contains(hostname, "localhost") {
			hostname = "mqtt.bitswan.localhost"
			fmt.Printf("  Replaced hostname with: %s\n", hostname)
		}

		// Build WSS URL through ingress with /mqtt path
		brokerURL = "wss://" + hostname + ":443/mqtt"
		fmt.Printf("  Using WSS through ingress: %s\n", brokerURL)
	} else {
		// For non-localhost, ensure /mqtt path is present for WSS
		if strings.HasPrefix(brokerURL, "wss://") && !strings.Contains(brokerURL, "/mqtt") {
			brokerURL = brokerURL + "/mqtt"
		}
	}
	fmt.Printf("  Final URL: %s\n", brokerURL)

	// Debug: Check Caddy and DNS resolution
	fmt.Printf("\n  Debug - Environment checks:\n")

	// Check if we can resolve the hostname
	fmt.Printf("    Checking DNS resolution for mqtt.bitswan.localhost...\n")
	if err := checkDNSResolution("mqtt.bitswan.localhost"); err != nil {
		fmt.Printf("    ⚠️  DNS resolution failed: %v\n", err)
	} else {
		fmt.Printf("    ✓ DNS resolution OK\n")
	}

	// Check Caddy routes (if daemon client is available)
	fmt.Printf("    Checking Caddy routes...\n")
	if err := checkCaddyRoutes(); err != nil {
		fmt.Printf("    ⚠️  Could not check Caddy routes: %v\n", err)
	} else {
		fmt.Printf("    ✓ Caddy routes check completed\n")
	}

	// Check if we can reach the endpoint via HTTPS
	fmt.Printf("    Checking HTTPS connectivity to mqtt.bitswan.localhost:443...\n")
	if err := checkHTTPSConnectivity("mqtt.bitswan.localhost:443"); err != nil {
		fmt.Printf("    ⚠️  HTTPS connectivity failed: %v\n", err)
	} else {
		fmt.Printf("    ✓ HTTPS connectivity OK\n")
	}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(brokerURL)
	opts.SetClientID(fmt.Sprintf("test-client-%d", time.Now().Unix()))
	opts.SetUsername(mqttCreds.Username)
	opts.SetPassword(mqttCreds.Password)
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetCleanSession(true)
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(5 * time.Second)
	opts.SetMaxReconnectInterval(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)

	// Configure TLS for WSS/SSL/TLS connections
	if strings.HasPrefix(brokerURL, "wss://") || strings.HasPrefix(brokerURL, "ssl://") || strings.HasPrefix(brokerURL, "tls://") {
		opts.SetTLSConfig(&tls.Config{
			InsecureSkipVerify: true, // For testing with self-signed certs
		})
	}

	// Set connection handlers for debugging (must be before creating client)
	opts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		fmt.Printf("  Debug - Connection lost: %v\n", err)
	})

	// Variables to track subscription (will be set after initial subscription)
	var logsTopicForReconnect string
	var messageHandlerForReconnect mqtt.MessageHandler

	opts.SetOnConnectHandler(func(client mqtt.Client) {
		fmt.Printf("  Debug - OnConnect callback triggered\n")
		// Re-subscribe to logs topic on reconnect
		if logsTopicForReconnect != "" && messageHandlerForReconnect != nil {
			if token := client.Subscribe(logsTopicForReconnect, 1, messageHandlerForReconnect); token.Wait() && token.Error() != nil {
				fmt.Printf("  Warning: Failed to re-subscribe to logs topic on reconnect: %v\n", token.Error())
			} else {
				fmt.Printf("  Debug - Re-subscribed to logs topic: %s\n", logsTopicForReconnect)
			}
		}
	})

	// Debug: Test WebSocket connection manually before MQTT
	fmt.Printf("\n  Debug - Testing WebSocket connection...\n")
	if strings.HasPrefix(brokerURL, "wss://") {
		if err := testWebSocketConnection(brokerURL); err != nil {
			fmt.Printf("    ⚠️  WebSocket test failed: %v\n", err)
			// Print Docker logs for debugging
			fmt.Printf("\n  Debug - EMQX Docker logs (last 30 lines):\n")
			printDockerLogs("aoc-emqx", 30)
			fmt.Printf("\n  Debug - Caddy Docker logs (last 30 lines):\n")
			printDockerLogs("caddy", 30)
		} else {
			fmt.Printf("    ✓ WebSocket connection test OK\n")
		}
	}

	client := mqtt.NewClient(opts)
	fmt.Printf("  Attempting MQTT connection with timeout 30s...\n")
	token := client.Connect()
	if !token.WaitTimeout(30 * time.Second) {
		// Get more details about the connection state
		fmt.Printf("  Connection timeout after 30s\n")
		fmt.Printf("  Debug - Checking if client is connected: %v\n", client.IsConnected())
		if token.Error() != nil {
			fmt.Printf("  Debug - Token error: %v\n", token.Error())
		}

		// Print Docker logs for debugging
		fmt.Printf("\n  Debug - EMQX Docker logs (last 50 lines):\n")
		printDockerLogs("aoc-emqx", 50)
		fmt.Printf("\n  Debug - Caddy Docker logs (last 50 lines):\n")
		printDockerLogs("caddy", 50)

		return fmt.Errorf("MQTT connection timeout")
	}
	if token.Error() != nil {
		return fmt.Errorf("failed to connect to MQTT broker: %w", token.Error())
	}
	fmt.Println("✓ Connected to MQTT broker")

	// Cleanup function
	defer func() {
		client.Disconnect(250)
	}()

	// Step 4: Subscribe to logs topic
	fmt.Println("\n[4/6] Subscribing to logs topic...")
	// Use mountpoint-relative topics - EMQX will automatically prepend the mountpoint
	// Since the test client uses the same JWT token with the same mountpoint as the daemon,
	// we should use mountpoint-relative topics to match the daemon's subscriptions
	logsTopic := "logs"
	createTopic := "workspace/create"
	deleteTopic := "workspace/delete"

	// Channel to collect log messages
	logMessages := make(chan LogMessage, 100)
	resultMessages := make(chan ResultMessage, 10)

	// Variables to track current request IDs (will be updated)
	var currentRequestID string
	var currentDeleteRequestID string

	// Message handler
	messageHandler := func(client mqtt.Client, msg mqtt.Message) {
		var data map[string]interface{}
		if err := json.Unmarshal(msg.Payload(), &data); err != nil {
			fmt.Printf("Warning: Failed to parse log message: %v\n", err)
			return
		}

		// Check if it's a log message
		if msgRequestID, ok := data["request-id"].(string); ok {
			// Only process messages for the current request
			if msgRequestID != currentRequestID && msgRequestID != currentDeleteRequestID {
				return
			}

			if _, hasTime := data["time"]; hasTime {
				if _, hasLevel := data["level"]; hasLevel {
					if _, hasMessage := data["message"]; hasMessage {
						var logMsg LogMessage
						if err := json.Unmarshal(msg.Payload(), &logMsg); err == nil {
							logMessages <- logMsg
							return
						}
					}
				}
			}

			// Check if it's a result message
			if _, hasSuccess := data["success"]; hasSuccess {
				var resultMsg ResultMessage
				if err := json.Unmarshal(msg.Payload(), &resultMsg); err == nil {
					resultMessages <- resultMsg
					return
				}
			}
		}
	}

	// Store topic and handler for re-subscription on reconnect
	logsTopicForReconnect = logsTopic
	messageHandlerForReconnect = messageHandler

	// Subscribe to logs
	if token := client.Subscribe(logsTopic, 1, messageHandler); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to subscribe to logs topic: %w", token.Error())
	}
	fmt.Printf("✓ Subscribed to logs topic: %s\n", logsTopic)

	// Step 5: Create workspace via MQTT
	fmt.Println("\n[5/6] Creating workspace via MQTT...")
	workspaceName := fmt.Sprintf("test-mqtt-workspace-%d", time.Now().Unix())
	requestID := fmt.Sprintf("create-%d", time.Now().Unix())
	currentRequestID = requestID // Set for message handler

	createRequest := map[string]interface{}{
		"request-id": requestID,
		"name":       workspaceName,
		"local":      true,
		"no-ide":     true,
		"no-oauth":   true,
	}

	requestJSON, err := json.Marshal(createRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal create request: %w", err)
	}

	fmt.Printf("  Publishing to: %s\n", createTopic)
	fmt.Printf("  Workspace name: %s\n", workspaceName)
	fmt.Printf("  Request ID: %s\n", requestID)

	if token := client.Publish(createTopic, 1, false, requestJSON); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to publish create request: %w", token.Error())
	}
	fmt.Println("✓ Create request published")

	// Wait for logs and result
	fmt.Println("  Waiting for workspace creation to complete...")
	var receivedLogs []LogMessage
	var resultMsg *ResultMessage

	// First, wait for initial log message within 5 seconds
	initialTimeout := time.NewTimer(5 * time.Second)
	initialLogReceived := false

	// After initial log, use 5 minute timeout that resets on each log message
	var timeoutTimer *time.Timer
	var timeoutChan <-chan time.Time

	for {
		select {
		case logMsg := <-logMessages:
			if logMsg.RequestID == requestID {
				receivedLogs = append(receivedLogs, logMsg)
				fmt.Printf("  [%s] %s: %s\n", logMsg.Level, logMsg.Time, logMsg.Message)

				// Mark initial log as received and stop initial timeout
				if !initialLogReceived {
					initialLogReceived = true
					initialTimeout.Stop()
					fmt.Println("  Initial log received, continuing to wait for completion...")
				}

				// Reset timeout on each log message
				// Use 10 minutes for workspace creation as it can take a long time (especially pulling Docker images)
				if timeoutTimer != nil {
					timeoutTimer.Stop()
				}
				timeoutTimer = time.NewTimer(10 * time.Minute)
				timeoutChan = timeoutTimer.C
			}
		case result := <-resultMessages:
			if result.RequestID == requestID {
				if timeoutTimer != nil {
					timeoutTimer.Stop()
				}
				initialTimeout.Stop()
				resultMsg = &result
				goto checkResult
			}
		case <-initialTimeout.C:
			if !initialLogReceived {
				return fmt.Errorf("timeout: no initial log message received within 5 seconds - daemon may not be processing the command")
			}
		case <-timeoutChan:
			// This case will only be selected if timeoutChan is not nil
			// (nil channels in select are ignored, so this is safe)
			return fmt.Errorf("timeout waiting for workspace creation result (no log messages received in last 10 minutes)")
		}
	}

checkResult:
	if !resultMsg.Success {
		return fmt.Errorf("workspace creation failed: %s", resultMsg.Error)
	}

	fmt.Println("✓ Workspace created successfully")

	// Verify workspace exists by checking if Docker containers are running
	fmt.Println("  Verifying workspace exists...")
	// Check if the GitOps container for this workspace is running
	projectName := workspaceName + "-site"
	checkCmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", projectName), "--format", "{{.Names}}")
	var output []byte
	output, err = checkCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check workspace containers: %w", err)
	}

	containerNames := strings.TrimSpace(string(output))
	if containerNames == "" {
		return fmt.Errorf("workspace %s containers not found - workspace may not have been created", workspaceName)
	}

	// Check if GitOps container is in the list
	// Container name format: {workspaceName}-site-bitswan-gitops-1
	if !strings.Contains(containerNames, "gitops") {
		return fmt.Errorf("workspace %s GitOps container not found. Found containers: %s", workspaceName, containerNames)
	}
	fmt.Printf("✓ Workspace %s verified (GitOps container is running: %s)\n", workspaceName, containerNames)

	// Step 6: Delete workspace via MQTT
	fmt.Println("\n[6/6] Deleting workspace via MQTT...")
	deleteRequestID := fmt.Sprintf("delete-%d", time.Now().Unix())
	currentDeleteRequestID = deleteRequestID // Set for message handler

	deleteRequest := map[string]interface{}{
		"request-id": deleteRequestID,
		"name":       workspaceName,
	}

	deleteJSON, err := json.Marshal(deleteRequest)
	if err != nil {
		// Try to cleanup manually
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("failed to marshal delete request: %w", err)
	}

	fmt.Printf("  Publishing to: %s\n", deleteTopic)
	fmt.Printf("  Request ID: %s\n", deleteRequestID)

	if token := client.Publish(deleteTopic, 1, false, deleteJSON); token.Wait() && token.Error() != nil {
		// Try to cleanup manually
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("failed to publish delete request: %w", token.Error())
	}
	fmt.Println("✓ Delete request published")

	// Wait for deletion logs and result
	fmt.Println("  Waiting for workspace deletion to complete...")
	receivedLogs = []LogMessage{}
	resultMsg = nil

	// First, wait for initial log message within 5 seconds
	deleteInitialTimeout := time.NewTimer(5 * time.Second)
	deleteInitialLogReceived := false

	// After initial log, use 5 minute timeout that resets on each log message
	var deleteTimeoutTimer *time.Timer
	var deleteTimeoutChan <-chan time.Time

	for {
		select {
		case logMsg := <-logMessages:
			if logMsg.RequestID == deleteRequestID {
				receivedLogs = append(receivedLogs, logMsg)
				fmt.Printf("  [%s] %s: %s\n", logMsg.Level, logMsg.Time, logMsg.Message)

				// Mark initial log as received and stop initial timeout
				if !deleteInitialLogReceived {
					deleteInitialLogReceived = true
					deleteInitialTimeout.Stop()
					fmt.Println("  Initial log received, continuing to wait for completion...")
				}

				// Reset timeout on each log message
				// Use 10 minutes for workspace deletion as it can take a long time
				if deleteTimeoutTimer != nil {
					deleteTimeoutTimer.Stop()
				}
				deleteTimeoutTimer = time.NewTimer(10 * time.Minute)
				deleteTimeoutChan = deleteTimeoutTimer.C
			}
		case result := <-resultMessages:
			if result.RequestID == deleteRequestID {
				if deleteTimeoutTimer != nil {
					deleteTimeoutTimer.Stop()
				}
				deleteInitialTimeout.Stop()
				resultMsg = &result
				goto checkDeleteResult
			}
		case <-deleteInitialTimeout.C:
			if !deleteInitialLogReceived {
				// Try to cleanup manually
				cleanupWorkspace(workspaceName)
				return fmt.Errorf("timeout: no initial log message received within 5 seconds - daemon may not be processing the delete command")
			}
		case <-deleteTimeoutChan:
			// This case will only be selected if deleteTimeoutChan is not nil
			// (nil channels in select are ignored, so this is safe)
			// Try to cleanup manually
			cleanupWorkspace(workspaceName)
			return fmt.Errorf("timeout waiting for workspace deletion result (no log messages received in last 10 minutes)")
		}
	}

checkDeleteResult:
	if !resultMsg.Success {
		// Try to cleanup manually
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("workspace deletion failed: %s", resultMsg.Error)
	}

	fmt.Println("✓ Workspace deleted successfully")

	// Verify workspace is deleted by checking if Docker containers are gone
	fmt.Println("  Verifying workspace is deleted...")
	projectName = workspaceName + "-site"
	checkCmd = exec.Command("docker", "ps", "-a", "--filter", fmt.Sprintf("name=%s", projectName), "--format", "{{.Names}}")
	output, err = checkCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check workspace containers: %w", err)
	}

	containerNames = strings.TrimSpace(string(output))
	if containerNames != "" {
		// Try to cleanup manually
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("workspace %s containers still exist - workspace may not have been deleted", workspaceName)
	}
	fmt.Printf("✓ Workspace %s verified as deleted (containers removed)\n", workspaceName)

	fmt.Println("\n=== Test Passed ===")
	return nil
}

// checkDNSResolution checks if a hostname can be resolved
func checkDNSResolution(hostname string) error {
	_, err := net.LookupHost(hostname)
	return err
}

// checkCaddyRoutes checks if Caddy is running and has the mqtt route
func checkCaddyRoutes() error {
	// Try to connect to Caddy API
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:2019/config/apps/http/servers/srv0/routes")
	if err != nil {
		return fmt.Errorf("could not connect to Caddy API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Caddy API returned status %d", resp.StatusCode)
	}

	var routes []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return fmt.Errorf("could not decode Caddy routes: %w", err)
	}

	// Check if mqtt route exists
	found := false
	for _, route := range routes {
		routeMap, ok := route.(map[string]interface{})
		if !ok {
			continue
		}
		if match, ok := routeMap["match"].([]interface{}); ok && len(match) > 0 {
			if matchMap, ok := match[0].(map[string]interface{}); ok {
				if hosts, ok := matchMap["host"].([]interface{}); ok {
					for _, host := range hosts {
						if hostStr, ok := host.(string); ok && strings.Contains(hostStr, "mqtt") {
							found = true
							fmt.Printf("      Found Caddy route for: %v\n", hosts)
							break
						}
					}
				}
			}
		}
	}

	if !found {
		return fmt.Errorf("no mqtt route found in Caddy")
	}

	return nil
}

// checkHTTPSConnectivity checks if we can establish an HTTPS connection
func checkHTTPSConnectivity(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// testWebSocketConnection tests if we can establish a WebSocket connection
func testWebSocketConnection(url string) error {
	// Parse URL
	urlWithoutProtocol := strings.TrimPrefix(url, "wss://")
	hostPort := urlWithoutProtocol
	path := "/mqtt"
	if idx := strings.Index(urlWithoutProtocol, "/"); idx > 0 {
		hostPort = urlWithoutProtocol[:idx]
		path = urlWithoutProtocol[idx:]
	}

	// For WSS, we need to use TLS
	// Try to connect via TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing with self-signed certs
		ServerName:         strings.Split(hostPort, ":")[0],
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", hostPort, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	// Try to send WebSocket upgrade request over TLS
	host := strings.Split(hostPort, ":")[0]
	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	request := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Protocol: mqtt\r\n"+
		"\r\n", path, host, wsKey)

	if _, err := conn.Write([]byte(request)); err != nil {
		return fmt.Errorf("failed to send WebSocket request: %w", err)
	}

	// Read response (with timeout)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	response := string(buf[:n])
	if !strings.Contains(response, "101") && !strings.Contains(response, "Switching Protocols") {
		return fmt.Errorf("unexpected response: %s", response)
	}

	return nil
}

// printDockerLogs prints the last N lines of Docker logs for a container
func printDockerLogs(containerName string, lines int) {
	cmd := exec.Command("docker", "logs", "--tail", fmt.Sprintf("%d", lines), containerName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("    ⚠️  Could not get Docker logs for %s: %v\n", containerName, err)
		return
	}

	// Print with indentation
	outputStr := string(output)
	for _, line := range strings.Split(outputStr, "\n") {
		if line != "" {
			fmt.Printf("    %s\n", line)
		}
	}
}

// LogMessage represents a log message from MQTT
type LogMessage struct {
	RequestID string `json:"request-id"`
	Time      string `json:"time"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

// ResultMessage represents a result message from MQTT
type ResultMessage struct {
	RequestID string `json:"request-id"`
	Success   bool   `json:"success"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
}
