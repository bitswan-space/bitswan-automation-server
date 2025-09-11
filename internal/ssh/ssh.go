package ssh

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// SSHKeyPair represents a generated SSH key pair
type SSHKeyPair struct {
	PrivateKeyPath string
	PublicKeyPath  string
	PublicKey      string
}

// GenerateSSHKeyPair generates a new ED25519 SSH key pair for a workspace using ssh-keygen
func GenerateSSHKeyPair(workspacePath string) (*SSHKeyPair, error) {
	// Extract workspace name from the path
	workspaceName := filepath.Base(workspacePath)
	// Create ssh directory in workspace
	sshDir := filepath.Join(workspacePath, "ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create ssh directory: %w", err)
	}

	// Set up file paths
	privateKeyPath := filepath.Join(sshDir, "id_ed25519")
	publicKeyPath := filepath.Join(sshDir, "id_ed25519.pub")

	// Generate SSH key pair using ssh-keygen
	cmd := exec.Command("ssh-keygen", 
		"-t", "ed25519",
		"-f", privateKeyPath,
		"-C", fmt.Sprintf("%s-bitswan-workspace", workspaceName),
		"-N", "", // No passphrase
	)

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to generate SSH key pair: %w", err)
	}

	// Read the generated public key
	publicKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	return &SSHKeyPair{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		PublicKey:      string(publicKeyData),
	}, nil
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
