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

	// Path inside the (daemon) container — used to actually check if certs exist.
	homeDir := os.Getenv("HOME")
	certAuthDir := filepath.Join(homeDir, ".config", "bitswan", "certauthorities")

	absPath, err := filepath.Abs(certAuthDir)
	if err != nil {
		fmt.Printf("Warning: Failed to resolve CA directory path %s: %v\n", certAuthDir, err)
		return volumes, envVars
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		fmt.Printf("Warning: CA directory does not exist: %s\n", absPath)
		fmt.Printf("  Use 'bitswan ca add <certificate-file>' to add certificates.\n")
		return volumes, envVars
	}

	// Host-side path — used as the docker volume source. When the daemon runs
	// inside a container, HOST_HOME points at the real host home directory.
	hostCertAuthDir := absPath
	if hostHome := os.Getenv("HOST_HOME"); hostHome != "" && hostHome != homeDir {
		hostCertAuthDir = filepath.Join(hostHome, ".config", "bitswan", "certauthorities")
	}

	volumes = append(volumes, hostCertAuthDir+":/usr/local/share/ca-certificates/custom:ro")
	envVars = append(envVars,
		"UPDATE_CA_CERTIFICATES=true",
		"REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
	)

	return volumes, envVars
}
