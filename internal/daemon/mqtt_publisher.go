package daemon

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// MQTTPublisher handles publishing workspace lists to MQTT
type MQTTPublisher struct {
	client              mqtt.Client  // Main client with mountpoint (for receiving commands)
	workspaceListClient mqtt.Client  // Separate client without mountpoint (for publishing workspace lists)
	creds                *aoc.MQTTCredentials
	topic                string
	connected            bool
	workspaceListConnected bool
	mu                   sync.RWMutex
	serverInfo           *aoc.AutomationServerInfo
	server               *Server // Reference to the server for calling internal functions
}

var (
	mqttPublisherInstance *MQTTPublisher
	mqttPublisherOnce     sync.Once
)

// GetMQTTPublisher returns the singleton MQTT publisher instance
func GetMQTTPublisher() *MQTTPublisher {
	mqttPublisherOnce.Do(func() {
		mqttPublisherInstance = &MQTTPublisher{
			connected: false,
		}
	})
	return mqttPublisherInstance
}

// Initialize initializes the MQTT publisher with credentials
func (p *MQTTPublisher) Initialize(creds *aoc.MQTTCredentials, serverInfo *aoc.AutomationServerInfo) error {
	return p.InitializeWithServer(creds, serverInfo, nil)
}

// InitializeWithServer initializes the MQTT publisher with credentials and server reference
func (p *MQTTPublisher) InitializeWithServer(creds *aoc.MQTTCredentials, serverInfo *aoc.AutomationServerInfo, server *Server) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.creds = creds
	p.serverInfo = serverInfo
	p.server = server

	// Validate server info
	if serverInfo == nil {
		return fmt.Errorf("server info is required")
	}

	if serverInfo.KeycloakOrgId == "" {
		return fmt.Errorf("keycloak_org_id is required but not provided in server info")
	}

	// Use mountpoint-relative topic - EMQX will automatically prepend the mountpoint
	p.topic = "workspaces"

	return p.connect()
}

// connect establishes connection to the MQTT broker
func (p *MQTTPublisher) connect() error {
	if p.creds == nil {
		return fmt.Errorf("MQTT credentials not set")
	}

	// Build broker URL using the protocol from credentials
	// If URL is provided, use it directly; otherwise construct from protocol, broker, and port
	var brokerURL string
	if p.creds.URL != "" {
		brokerURL = p.creds.URL
		// Check if we're running in a Docker container
		// If so, replace localhost with host.docker.internal to reach host services
		isInDocker := false
		if _, err := os.Stat("/.dockerenv"); err == nil {
			isInDocker = true
		}

		// For WSS/WS connections through ingress, keep the ingress URL
		// For TCP/SSL/TLS connections, replace localhost with Docker service name for internal communication
		// Also handle direct Docker service names (aoc-emqx) when running in Docker
		if strings.Contains(brokerURL, "localhost") || strings.Contains(brokerURL, "127.0.0.1") || (isInDocker && strings.Contains(brokerURL, "aoc-emqx")) {
			if strings.HasPrefix(brokerURL, "wss://") || strings.HasPrefix(brokerURL, "ws://") {
				// For WebSocket connections, if running in Docker, connect directly to EMQX
				// Since both daemon and EMQX are on the same Docker network, we can use WS (not WSS)
				// to avoid TLS/certificate issues
				if isInDocker {
					// Parse the URL to extract hostname and replace it properly
					parts := strings.Split(brokerURL, "://")
					if len(parts) == 2 {
						hostAndPath := parts[1]
						hostParts := strings.Split(hostAndPath, "/")
						hostPort := hostParts[0]
						hostPortParts := strings.Split(hostPort, ":")
						oldHost := hostPortParts[0]

						// Replace any hostname containing localhost or aoc-emqx with EMQX service name
						if strings.Contains(oldHost, "localhost") || oldHost == "127.0.0.1" || oldHost == "aoc-emqx" {
							// Connect directly to EMQX WebSocket port (8083) on Docker network
							// Use WS instead of WSS since we're on the same network
							newHost := "aoc-emqx:8083"
							fmt.Printf("Docker container detected: connecting directly to EMQX via Docker network (aoc-emqx:8083)\n")

							// Preserve path if present
							if len(hostParts) > 1 {
								newHost = newHost + "/" + strings.Join(hostParts[1:], "/")
							} else {
								// Ensure /mqtt path is present
								newHost = newHost + "/mqtt"
							}
							// Use WS instead of WSS for internal Docker network connection
							brokerURL = "ws://" + newHost
						}
					}
				}
				// Ensure /mqtt path is present for WSS connections
				if strings.HasPrefix(brokerURL, "wss://") && !strings.Contains(brokerURL, "/mqtt") {
					// Add /mqtt path if not present
					if strings.Contains(brokerURL, ":443") {
						brokerURL = strings.Replace(brokerURL, ":443", ":443/mqtt", 1)
					} else {
						brokerURL = brokerURL + "/mqtt"
					}
				}
			} else {
				// For TCP/SSL/TLS connections, if running in Docker and broker is aoc-emqx,
				// convert to WebSocket (WS) for better compatibility
				if isInDocker && (strings.Contains(brokerURL, "aoc-emqx") || p.creds.Broker == "aoc-emqx") {
					// Convert TCP connection to WebSocket for Docker network
					brokerURL = "ws://aoc-emqx:8083/mqtt"
					fmt.Printf("Docker container detected: converting TCP connection to WebSocket (ws://aoc-emqx:8083/mqtt)\n")
				} else {
					// For TCP/SSL/TLS, replace hostname with Docker service name
					protocol := "tcp"
					if strings.HasPrefix(brokerURL, "ssl://") {
						protocol = "ssl"
					} else if strings.HasPrefix(brokerURL, "tls://") {
						protocol = "tls"
					}
					brokerURL = fmt.Sprintf("%s://aoc-emqx:%d", protocol, p.creds.Port)
				}
			}
		}
	} else {
		// Fallback: construct URL from protocol, broker, and port
		protocol := p.creds.Protocol
		if protocol == "" {
			protocol = "tcp" // Default to TCP if not specified
		}
		brokerURL = fmt.Sprintf("%s://%s:%d", protocol, p.creds.Broker, p.creds.Port)
	}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(brokerURL)
	opts.SetClientID(fmt.Sprintf("automation-server-daemon-%d", time.Now().Unix()))
	opts.SetUsername(p.creds.Username)
	opts.SetPassword(p.creds.Password)

	// Connection behavior
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(5 * time.Second)
	opts.SetMaxReconnectInterval(30 * time.Second)
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetCleanSession(true)

	// Configure TLS for WSS/SSL/TLS connections
	// When connecting via Docker network (caddy:443), set ServerName to mqtt.bitswan.localhost
	// so Caddy can route the request correctly via SNI (Server Name Indication)
	if strings.HasPrefix(brokerURL, "wss://") || strings.HasPrefix(brokerURL, "ssl://") || strings.HasPrefix(brokerURL, "tls://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // Skip cert verification for Docker network connections
		}
		// If connecting to caddy directly, set ServerName so Caddy routes correctly
		if strings.Contains(brokerURL, "caddy:") {
			tlsConfig.ServerName = "mqtt.bitswan.localhost"
		}
		opts.SetTLSConfig(tlsConfig)
	}

	// Callbacks
	opts.SetOnConnectHandler(p.onConnect)
	opts.SetConnectionLostHandler(p.onConnectionLost)

	p.client = mqtt.NewClient(opts)

	fmt.Printf("Connecting to MQTT broker: %s\n", brokerURL)
	token := p.client.Connect()

	// Wait for connection with timeout (use the same timeout as SetConnectTimeout)
	if token.WaitTimeout(10 * time.Second) {
		if token.Error() != nil {
			return fmt.Errorf("failed to connect to MQTT broker: %w", token.Error())
		}
		fmt.Printf("Successfully connected to MQTT broker: %s\n", brokerURL)
		p.connected = true
		return nil
	}

	return fmt.Errorf("MQTT connection timed out after 10 seconds")
}

// getDockerGatewayIP gets the Docker gateway IP from the default route
// This is more reliable than host.docker.internal in some CI environments
func getDockerGatewayIP() string {
	// Try ip route first (more reliable)
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err == nil {
		// Parse output like "default via 172.17.0.1 dev eth0"
		fields := strings.Fields(string(output))
		for i, field := range fields {
			if field == "via" && i+1 < len(fields) {
				gatewayIP := fields[i+1]
				// Validate it's an IP address (simple check)
				if strings.Contains(gatewayIP, ".") {
					return gatewayIP
				}
			}
		}
	}

	// Fallback: return empty to use host.docker.internal
	return ""
}

// onConnect handles successful connection to MQTT broker
func (p *MQTTPublisher) onConnect(client mqtt.Client) {
	p.mu.Lock()
	p.connected = true
	p.mu.Unlock()

	fmt.Printf("MQTT publisher connected, ready to publish workspace lists\n")

	// Subscribe to command topics
	// Use mountpoint-relative topics - EMQX will automatically prepend the mountpoint
	createTopic := "workspace/create"
	deleteTopic := "workspace/delete"

	// Set up message handler
	client.Subscribe(createTopic, 1, p.handleWorkspaceCreate)
	client.Subscribe(deleteTopic, 1, p.handleWorkspaceDelete)

	fmt.Printf("Subscribed to workspace command topics: %s, %s\n", createTopic, deleteTopic)

	// Sync workspace list immediately upon connection
	// This ensures the list is synced even if initialization happened before connection was ready
	go func() {
		// Small delay to ensure connection is fully established
		time.Sleep(500 * time.Millisecond)
		if err := syncWorkspaceListToAOC(); err != nil {
			fmt.Printf("Warning: Failed to sync workspace list on connect: %v\n", err)
		}
	}()
}

// onConnectionLost handles connection loss
func (p *MQTTPublisher) onConnectionLost(_ mqtt.Client, err error) {
	p.mu.Lock()
	p.connected = false
	p.mu.Unlock()
	fmt.Printf("MQTT connection lost: %v (will attempt to reconnect)\n", err)
}


// IsConnected returns true if the MQTT publisher is connected
func (p *MQTTPublisher) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connected && p.client != nil && p.client.IsConnected()
}

// Disconnect disconnects from the MQTT broker
func (p *MQTTPublisher) Disconnect() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil && p.client.IsConnected() {
		p.client.Disconnect(250)
		p.connected = false
		fmt.Println("MQTT publisher disconnected")
	}
}
