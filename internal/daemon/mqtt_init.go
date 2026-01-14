package daemon

import (
	"fmt"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
)

// initializeMQTTPublisher initializes the MQTT publisher if AOC is configured
// This function is non-blocking and will retry on failure
func initializeMQTTPublisher() error {
	return initializeMQTTPublisherWithServer(nil)
}

// initializeMQTTPublisherWithServer initializes the MQTT publisher with a server reference
func initializeMQTTPublisherWithServer(server *Server) error {
	fmt.Println("MQTT publisher initialization scheduled (will start in 2 seconds)")
	// Run initialization in a goroutine so it doesn't block server startup
	go func() {
		// Give the server a moment to fully start
		time.Sleep(2 * time.Second)
		fmt.Println("Starting MQTT publisher initialization...")
		
		maxRetries := 5
		retryDelay := 5 * time.Second
		
		for attempt := 1; attempt <= maxRetries; attempt++ {
			initialized, err := tryInitializeMQTTPublisher(server)
			if initialized {
				// Successfully initialized!
				return
			}
			
			if err == nil {
				// AOC not configured, no need to retry
				fmt.Println("AOC not configured, MQTT publisher initialization skipped")
				return
			}
			
			if attempt < maxRetries {
				fmt.Printf("MQTT publisher initialization failed (attempt %d/%d): %v. Retrying in %v...\n", 
					attempt, maxRetries, err, retryDelay)
				time.Sleep(retryDelay)
			} else {
				fmt.Printf("MQTT publisher initialization failed after %d attempts: %v. Will retry on next workspace operation.\n", 
					maxRetries, err)
			}
		}
	}()
	
	return nil
}

// tryInitializeMQTTPublisher attempts to initialize the MQTT publisher
// Returns (initialized bool, error)
// initialized=true means it was successfully initialized
// initialized=false, err=nil means AOC is not configured (not an error)
// initialized=false, err!=nil means initialization failed (should retry)
func tryInitializeMQTTPublisher(server *Server) (bool, error) {
	fmt.Println("Attempting to initialize MQTT publisher...")
	
	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		// AOC not configured, skip MQTT publisher initialization
		fmt.Printf("AOC not configured (cannot create AOC client: %v), skipping MQTT publisher initialization\n", err)
		return false, nil // Not an error, just not configured
	}

	fmt.Println("AOC client created, getting automation server info...")
	
	// Get automation server info
	serverInfo, err := aocClient.GetAutomationServerInfo()
	if err != nil {
		// Check if this is an AOC not configured error (empty URL)
		if strings.Contains(err.Error(), "unsupported protocol scheme") {
			fmt.Printf("AOC not configured (empty URL), skipping MQTT publisher initialization\n")
			return false, nil // Not an error, just not configured
		}
		return false, fmt.Errorf("failed to get automation server info: %w", err)
	}

	fmt.Printf("Automation server info retrieved: %s (org: %s)\n", serverInfo.AutomationServerId, serverInfo.KeycloakOrgId)

	// Get MQTT credentials for the automation server
	fmt.Println("Getting MQTT credentials for automation server...")
	mqttCreds, err := aocClient.GetAutomationServerMQTTCredentials()
	if err != nil {
		return false, fmt.Errorf("failed to get MQTT credentials: %w", err)
	}

	fmt.Printf("MQTT credentials retrieved: broker=%s:%d\n", mqttCreds.Broker, mqttCreds.Port)

	// Initialize the publisher with server reference
	publisher := GetMQTTPublisher()
	if err := publisher.InitializeWithServer(mqttCreds, serverInfo, server); err != nil {
		return false, fmt.Errorf("failed to initialize MQTT publisher: %w", err)
	}

	// Publish initial workspace list (will happen automatically on connect, but try here too)
	// Sync initial workspace list to AOC
	if err := syncWorkspaceListToAOC(); err != nil {
		// Don't fail initialization if sync fails - AOC might not be configured
		fmt.Printf("Warning: Failed to sync initial workspace list: %v\n", err)
	} else {
		fmt.Println("Initial workspace list synced successfully")
	}

	fmt.Println("MQTT publisher initialized successfully")
	return true, nil
}

