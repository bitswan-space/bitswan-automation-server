package certauthority

import (
	"fmt"
	"os"
	"path/filepath"
)

// GetCACertMountConfig returns volumes and environment variables needed to mount CA certificates
// into Docker containers. It handles both mounting all certificates ("all") or specific certificates.
func GetCACertMountConfig(trustCA []string, workspacePath string) ([]string, []string) {
	var volumes []string
	var envVars []string

	if len(trustCA) == 0 {
		return volumes, envVars
	}

	certAuthDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "certauthorities")

	// Create a temporary directory structure to hold the certificates
	tempCertDir := filepath.Join(workspacePath, "ca-certs")
	if err := os.MkdirAll(tempCertDir, 0755); err != nil {
		fmt.Printf("Warning: Failed to create ca-certs directory at %s: %v\n", tempCertDir, err)
		return volumes, envVars
	}

	// Check if "all" is specified
	if len(trustCA) > 0 && trustCA[0] == "all" {
		// Check if certauthorities directory exists
		if _, err := os.Stat(certAuthDir); os.IsNotExist(err) {
			fmt.Printf("Warning: Certificate authorities directory does not exist: %s\n", certAuthDir)
			fmt.Printf("  Use 'bitswan ca add <certificate-file>' to add certificates.\n")
			return volumes, envVars
		}

		// Copy all certificates from the certauthorities directory
		entries, err := os.ReadDir(certAuthDir)
		if err != nil {
			fmt.Printf("Warning: Failed to read certificate authorities directory: %v\n", err)
			return volumes, envVars
		}

		copiedCount := 0
		for _, entry := range entries {
			if !entry.IsDir() {
				// Copy the certificate file
				srcPath := filepath.Join(certAuthDir, entry.Name())
				dstPath := filepath.Join(tempCertDir, entry.Name())
				data, err := os.ReadFile(srcPath)
				if err != nil {
					fmt.Printf("Warning: Failed to read certificate file %s: %v\n", entry.Name(), err)
					continue // Skip if we can't read the source file
				}
				if err := os.WriteFile(dstPath, data, 0644); err != nil {
					fmt.Printf("Warning: Failed to write certificate file %s: %v\n", entry.Name(), err)
					continue // Skip if we can't write the destination file
				}
				copiedCount++
			}
		}

		if copiedCount == 0 {
			fmt.Printf("Warning: No certificate files found in %s\n", certAuthDir)
			fmt.Printf("  Use 'bitswan ca add <certificate-file>' to add certificates.\n")
			return volumes, envVars
		}

		fmt.Printf("Copied %d certificate(s) to workspace ca-certs directory\n", copiedCount)
	} else {
		// Copy specified certificates to temp directory
		for _, certName := range trustCA {
			srcPath := filepath.Join(certAuthDir, certName)
			if _, err := os.Stat(srcPath); err == nil {
				// Copy the certificate file
				dstPath := filepath.Join(tempCertDir, certName)
				data, err := os.ReadFile(srcPath)
				if err != nil {
					continue // Skip if we can't read the source file
				}
				if err := os.WriteFile(dstPath, data, 0644); err != nil {
					continue // Skip if we can't write the destination file
				}
			}
		}
	}

	// Mount the workspace ca-certs directory
	volumes = append(volumes, tempCertDir+":/usr/local/share/ca-certificates/custom:ro")
	envVars = append(envVars,
		"UPDATE_CA_CERTIFICATES=true",
		"REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
	)

	return volumes, envVars
}
