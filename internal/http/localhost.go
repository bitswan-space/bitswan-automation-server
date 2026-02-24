package http

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
)

// IsLocalhostConnectionError checks if an error is a connection refused to localhost
func IsLocalhostConnectionError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Check for connection refused errors
	if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "connect: connection refused") {
		// Check if it's trying to connect to localhost or any 127.x.x.x address
		if strings.Contains(errStr, "127.") || strings.Contains(errStr, "localhost") {
			return true
		}
	}

	// Check for net.OpError with connection refused
	if opErr, ok := err.(*net.OpError); ok {
		if opErr.Op == "dial" {
			// Check the error itself
			if opErr.Err != nil {
				errErrStr := opErr.Err.Error()
				if strings.Contains(errErrStr, "connection refused") {
					// Check the address
					addr := opErr.Addr
					if addr != nil {
						addrStr := addr.String()
						// Check for any 127.x.x.x address or localhost
						if strings.HasPrefix(addrStr, "127.") || strings.Contains(addrStr, "localhost") {
							return true
						}
					}
				}
			}
		}
	}

	// Also check for DNS errors that might indicate localhost resolution issues
	if strings.Contains(errStr, "no such host") && strings.Contains(errStr, "localhost") {
		return true
	}

	return false
}

// AddDockerNetworkAlias adds a network alias for the given hostname pointing to caddy
func AddDockerNetworkAlias(hostname string) error {
	networkName := "bitswan_network"
	containerName := "caddy"

	// Check if caddy container exists and is running
	checkCmd := exec.Command("docker", "ps", "--filter", "name=^"+containerName+"$", "--format", "{{.Names}}")
	output, err := checkCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check if caddy container exists: %w", err)
	}

	if strings.TrimSpace(string(output)) != containerName {
		return fmt.Errorf("caddy container is not running")
	}

	// Check if container is already connected to the network
	networkCheckCmd := exec.Command("docker", "network", "inspect", networkName, "--format", "{{range .Containers}}{{.Name}} {{end}}")
	networkOutput, err := networkCheckCmd.Output()
	alreadyConnected := err == nil && strings.Contains(string(networkOutput), containerName)

	if alreadyConnected {
		// Container is already connected, check if it has the alias
		// Get network info as JSON to parse aliases
		networkJSONCmd := exec.Command("docker", "network", "inspect", networkName, "--format", "{{json .}}")
		jsonOutput, jsonErr := networkJSONCmd.Output()
		if jsonErr == nil {
			var networkInfo struct {
				Containers map[string]struct {
					Name    string   `json:"Name"`
					Aliases []string `json:"Aliases"`
				} `json:"Containers"`
			}
			if json.Unmarshal(jsonOutput, &networkInfo) == nil {
				// Find caddy container in the network
				for _, container := range networkInfo.Containers {
					if container.Name == containerName {
						// Check if alias already exists
						for _, alias := range container.Aliases {
							if alias == hostname {
								// Alias already exists
								return nil
							}
						}
						// Collect existing aliases
						existingAliases := append([]string{}, container.Aliases...)
						existingAliases = append(existingAliases, hostname)

						// Disconnect first
						disconnectCmd := exec.Command("docker", "network", "disconnect", networkName, containerName)
						if err := disconnectCmd.Run(); err != nil {
							return fmt.Errorf("failed to disconnect caddy from network: %w", err)
						}

						// Reconnect with all aliases (including the new one)
						connectArgs := []string{"network", "connect"}
						for _, alias := range existingAliases {
							connectArgs = append(connectArgs, "--alias", alias)
						}
						connectArgs = append(connectArgs, networkName, containerName)
						connectCmd := exec.Command("docker", connectArgs...)
						output, err = connectCmd.CombinedOutput()
						if err != nil {
							return fmt.Errorf("failed to reconnect with alias: %w, output: %s", err, string(output))
						}
						return nil
					}
				}
			}
		}

		// Fallback: if we can't parse JSON, just disconnect and reconnect with the alias
		disconnectCmd := exec.Command("docker", "network", "disconnect", networkName, containerName)
		_ = disconnectCmd.Run()
	}

	// Connect with the alias (either first time or after disconnect)
	connectCmd := exec.Command("docker", "network", "connect", "--alias", hostname, networkName, containerName)
	output, err = connectCmd.CombinedOutput()
	if err != nil {
		// Check if error is because container is already connected with this alias
		if strings.Contains(string(output), "already exists") || strings.Contains(string(output), "already connected") {
			return nil // Alias already exists, that's fine
		}
		return fmt.Errorf("failed to add network alias: %w, output: %s", err, string(output))
	}

	return nil
}

// RetryWithLocalhostAlias wraps an HTTP request function and automatically retries with Docker network alias
// if the request fails with a localhost connection error.
// The requestFn should perform the HTTP request and return an error.
// Returns the error from the request function (nil on success).
func RetryWithLocalhostAlias(requestURL string, requestFn func() error) error {
	// Try the request first
	err := requestFn()
	if err == nil {
		return nil
	}

	// Check if this is a localhost connection error
	if !IsLocalhostConnectionError(err) {
		return err
	}

	// Parse the URL to get the hostname
	parsedURL, parseErr := url.Parse(requestURL)
	if parseErr != nil {
		return fmt.Errorf("error parsing URL: %w (original error: %v)", parseErr, err)
	}

	hostname := parsedURL.Hostname()
	// Only try to fix if it's a localhost hostname
	if hostname == "localhost" || hostname == "127.0.0.1" || strings.HasSuffix(hostname, ".localhost") {
		// Try to add Docker network alias and retry
		if aliasErr := AddDockerNetworkAlias(hostname); aliasErr != nil {
			// Log but don't fail - the original error is more important
			fmt.Printf("Warning: Failed to add Docker network alias for %s: %v\n", hostname, aliasErr)
		} else {
			// Retry the request
			return requestFn()
		}
	}

	// Return the original error
	return err
}

