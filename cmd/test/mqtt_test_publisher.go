package test

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

func newMqttTestPublisherCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mqtt-test-publisher",
		Short: "Test MQTT publisher without mountpoint",
		Long:  "Publishes a test message to workspace list topic without mountpoint to test if Django backend can receive it",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMqttTestPublisher()
		},
	}

	return cmd
}

func runMqttTestPublisher() error {
	fmt.Println("=== MQTT Test Publisher (No Mountpoint) ===")
	fmt.Println()

	// Step 1: Get server info from environment or try AOC client
	fmt.Println("[1/4] Getting automation server info...")
	
	var automationServerID, orgID string
	
	// Try environment variables first
	automationServerID = os.Getenv("AUTOMATION_SERVER_ID")
	orgID = os.Getenv("KEYCLOAK_ORG_ID")
	
	// If not in env, try AOC client
	if automationServerID == "" || orgID == "" {
		aocClient, err := aoc.NewAOCClient()
		if err == nil {
			serverInfo, err := aocClient.GetAutomationServerInfo()
			if err == nil {
				automationServerID = serverInfo.AutomationServerId
				orgID = serverInfo.KeycloakOrgId
			}
		}
	}
	
	// Fallback to default test values if still not found
	if automationServerID == "" {
		automationServerID = "7f520cb1-01ba-4137-bf34-57a199f627bc"
		fmt.Println("WARNING: Using default automation server ID (from logs)")
	}
	if orgID == "" {
		orgID = "94bae209-b04e-4011-a898-1a7b15fe8d2f"
		fmt.Println("WARNING: Using default org ID (from logs)")
	}

	fmt.Printf("✓ Automation server ID: %s\n", automationServerID)
	fmt.Printf("✓ Organization ID: %s\n", orgID)

	// Step 2: Create JWT token without mountpoint (like Django backend)
	fmt.Println("\n[2/4] Creating MQTT JWT token without mountpoint...")
	
	// We need the EMQX JWT secret - get it from environment
	emqxSecret := os.Getenv("EMQX_JWT_SECRET")
	if emqxSecret == "" {
		return fmt.Errorf("EMQX_JWT_SECRET environment variable not set")
	}

	// Create JWT token with blank mountpoint (like Django backend)
	// This matches Django's create_mqtt_token function with mountpoint=""
	exp := time.Now().Add(1000 * 7 * 24 * time.Hour) // ~1000 weeks like Django
	claims := jwt.MapClaims{
		"exp":      exp.Unix(),
		"username": "test-publisher-no-mountpoint",
		"client_attrs": map[string]interface{}{
			"mountpoint": "", // Blank mountpoint like Django backend
		},
	}

	jwtTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtTokenString, err := jwtTokenObj.SignedString([]byte(emqxSecret))
	if err != nil {
		return fmt.Errorf("failed to create JWT token: %w", err)
	}

	fmt.Println("✓ JWT token created (no mountpoint)")

	// Step 3: Connect to MQTT broker
	fmt.Println("\n[3/4] Connecting to MQTT broker (no mountpoint)...")
	
	// Use internal EMQX URL (same as Django backend uses)
	// The Django backend uses EMQX_INTERNAL_URL which is "aoc-emqx:1883"
	// We'll use the same for consistency
	brokerURL := "tcp://aoc-emqx:1883"
	
	// If running from host (not in Docker), we need to use a different approach
	// For now, we'll try aoc-emqx and if that fails, try localhost
	// In practice, this test should be run from within the Docker network
	if _, err := os.Stat("/.dockerenv"); err != nil {
		// Not in Docker - try localhost (if port is exposed)
		// Or we could use docker exec to run the command inside a container
		fmt.Println("WARNING: Not running in Docker, trying localhost:1883")
		fmt.Println("If this fails, run the test from within Docker network")
		brokerURL = "tcp://localhost:1883"
	}
	
	opts := mqtt.NewClientOptions()
	opts.AddBroker(brokerURL)
	opts.SetClientID(fmt.Sprintf("test-publisher-no-mountpoint-%d", time.Now().Unix()))
	opts.SetUsername("test-publisher-no-mountpoint")
	opts.SetPassword(jwtTokenString)
	opts.SetCleanSession(true)
	opts.SetAutoReconnect(true)
	opts.SetConnectTimeout(10 * time.Second)

	client := mqtt.NewClient(opts)
	
	fmt.Printf("Connecting to %s...\n", brokerURL)
	connectToken := client.Connect()
	if !connectToken.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("MQTT connection timeout")
	}
	if connectToken.Error() != nil {
		return fmt.Errorf("failed to connect to MQTT broker: %w", connectToken.Error())
	}
	fmt.Println("✓ Connected to MQTT broker (no mountpoint)")

	// Cleanup
	defer func() {
		client.Disconnect(250)
	}()

	// Step 4: Publish test message
	fmt.Println("\n[4/4] Publishing test message...")
	
	topic := fmt.Sprintf("/orgs/%s/automation-servers/%s/workspaces",
		orgID, automationServerID)
	
	testMessage := map[string]interface{}{
		"workspaces": []map[string]interface{}{
			{"id": "test-workspace-id-123", "name": "test-workspace-from-go-publisher"},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	payload, err := json.Marshal(testMessage)
	if err != nil {
		return fmt.Errorf("failed to marshal test message: %w", err)
	}

	fmt.Printf("Publishing to topic: %s\n", topic)
	fmt.Printf("Payload: %s\n", string(payload))
	
	publishToken := client.Publish(topic, 1, true, payload)
	if !publishToken.WaitTimeout(5 * time.Second) {
		return fmt.Errorf("publish timeout")
	}
	if publishToken.Error() != nil {
		return fmt.Errorf("failed to publish: %w", publishToken.Error())
	}

	fmt.Println("✓ Test message published successfully")
	fmt.Println("\nCheck Django backend logs to see if message was received:")
	fmt.Println("  docker logs aoc-bitswan-backend --since 5s | grep 'MQTT message received'")
	
	return nil
}

