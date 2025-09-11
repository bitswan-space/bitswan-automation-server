package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// SSHKeyPair represents a generated SSH key pair
type SSHKeyPair struct {
	PrivateKeyPath string
	PublicKeyPath  string
	PublicKey      string
}

// GenerateSSHKeyPair generates a new ED25519 SSH key pair for a workspace
func GenerateSSHKeyPair(workspacePath string) (*SSHKeyPair, error) {
	// Extract workspace name from the path
	workspaceName := filepath.Base(workspacePath)
	// Create ssh directory in workspace
	sshDir := filepath.Join(workspacePath, "ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create ssh directory: %w", err)
	}

	// Generate ED25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Encode private key to PEM format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Convert to OpenSSH format
	opensshPublicKey, err := convertToOpenSSHFormat(publicKey, workspaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to OpenSSH format: %w", err)
	}

	// Write private key to file
	privateKeyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key to file
	publicKeyPath := filepath.Join(sshDir, "id_ed25519.pub")
	if err := os.WriteFile(publicKeyPath, []byte(opensshPublicKey), 0644); err != nil {
		return nil, fmt.Errorf("failed to write public key: %w", err)
	}

	return &SSHKeyPair{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		PublicKey:      opensshPublicKey,
	}, nil
}

// convertToOpenSSHFormat converts a public key to OpenSSH format
func convertToOpenSSHFormat(publicKey ed25519.PublicKey, workspaceName string) (string, error) {
	// For ED25519, we need to create the OpenSSH format manually
	// The format is: ssh-ed25519 <base64-encoded-key> <comment>
	
	// Convert the public key to bytes
	keyBytes := []byte(publicKey)
	
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	
	// Create the OpenSSH format with workspace name and hostname
	opensshKey := fmt.Sprintf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI%s %s-bitswan-workspace@%s", 
		base64.StdEncoding.EncodeToString(keyBytes), workspaceName, hostname)
	
	return opensshKey, nil
}

// GetSSHPublicKey reads the public key from a workspace
func GetSSHPublicKey(workspacePath string) (string, error) {
	publicKeyPath := filepath.Join(workspacePath, "ssh", "id_ed25519.pub")
	
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read public key: %w", err)
	}
	
	return string(data), nil
}

// SSHKeyExists checks if SSH keys exist for a workspace
func SSHKeyExists(workspacePath string) bool {
	privateKeyPath := filepath.Join(workspacePath, "ssh", "id_ed25519")
	publicKeyPath := filepath.Join(workspacePath, "ssh", "id_ed25519.pub")
	
	_, err1 := os.Stat(privateKeyPath)
	_, err2 := os.Stat(publicKeyPath)
	
	return err1 == nil && err2 == nil
}
