package certauthority

import (
	"fmt"
	"os"
	"path/filepath"
)

// GetCACertMountConfig returns volumes and environment variables needed to mount CA certificates
// into Docker containers. It mounts the default certauthorities directory directly without copying files.
func GetCACertMountConfig(trustCA bool) ([]string, []string) {
	var volumes []string
	var envVars []string

	if !trustCA {
		return volumes, envVars
	}

	// Use the default certauthorities directory
	certAuthDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "certauthorities")

	// Resolve the absolute path
	absPath, err := filepath.Abs(certAuthDir)
	if err != nil {
		fmt.Printf("Warning: Failed to resolve CA directory path %s: %v\n", certAuthDir, err)
		return volumes, envVars
	}

	// Check if the directory exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		fmt.Printf("Warning: CA directory does not exist: %s\n", absPath)
		fmt.Printf("  Use 'bitswan ca add <certificate-file>' to add certificates.\n")
		return volumes, envVars
	}

	// Mount the directory directly (read-only)
	volumes = append(volumes, absPath+":/usr/local/share/ca-certificates/custom:ro")
	envVars = append(envVars,
		"UPDATE_CA_CERTIFICATES=true",
		"REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
	)

	return volumes, envVars
}
