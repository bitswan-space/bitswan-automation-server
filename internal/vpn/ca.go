package vpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	caDirName  = "ca"
	caKeyFile  = "ca.key"
	caCertFile = "ca.crt"
	tlsKeyFile = "tls.key"
	tlsCertFile = "tls.crt"
)

// CAManager handles the VPN internal certificate authority.
// It generates a self-signed CA and issues TLS certificates for internal services.
type CAManager struct {
	caDir string // e.g., ~/.config/bitswan/vpn/ca
}

// NewCAManager creates a CA manager for the given VPN base directory.
func NewCAManager(vpnBaseDir string) *CAManager {
	return &CAManager{
		caDir: filepath.Join(vpnBaseDir, caDirName),
	}
}

// IsInitialized returns true if the CA has been generated.
func (ca *CAManager) IsInitialized() bool {
	_, err := os.Stat(filepath.Join(ca.caDir, caCertFile))
	return err == nil
}

// Init generates a new CA keypair and self-signed certificate.
// The CA is valid for 10 years.
func (ca *CAManager) Init(orgName string) error {
	if ca.IsInitialized() {
		return nil // already initialized
	}

	os.MkdirAll(ca.caDir, 0700)

	// Generate CA private key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create self-signed CA certificate
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
			CommonName:   orgName + " VPN CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Write CA private key
	caKeyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA key: %w", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyBytes})
	if err := os.WriteFile(filepath.Join(ca.caDir, caKeyFile), caKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	// Write CA certificate
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(filepath.Join(ca.caDir, caCertFile), caCertPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	return nil
}

// IssueTLSCert generates a TLS certificate signed by this CA for the given hostnames.
// Returns paths to the cert and key files. The cert is valid for 2 years.
func (ca *CAManager) IssueTLSCert(hostnames []string) (certPath, keyPath string, err error) {
	if !ca.IsInitialized() {
		return "", "", fmt.Errorf("CA not initialized")
	}

	// Load CA key
	caKeyPEM, err := os.ReadFile(filepath.Join(ca.caDir, caKeyFile))
	if err != nil {
		return "", "", fmt.Errorf("failed to read CA key: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return "", "", fmt.Errorf("failed to decode CA key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Load CA cert
	caCertPEM, err := os.ReadFile(filepath.Join(ca.caDir, caCertFile))
	if err != nil {
		return "", "", fmt.Errorf("failed to read CA cert: %w", err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return "", "", fmt.Errorf("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse CA cert: %w", err)
	}

	// Generate server key
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create server certificate
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serverTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostnames[0],
		},
		DNSNames:  hostnames,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Write server key
	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal server key: %w", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyBytes})
	keyPath = filepath.Join(ca.caDir, tlsKeyFile)
	if err := os.WriteFile(keyPath, serverKeyPEM, 0600); err != nil {
		return "", "", fmt.Errorf("failed to write server key: %w", err)
	}

	// Write server cert (include CA cert in chain)
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	fullChain := append(serverCertPEM, caCertPEM...)
	certPath = filepath.Join(ca.caDir, tlsCertFile)
	if err := os.WriteFile(certPath, fullChain, 0644); err != nil {
		return "", "", fmt.Errorf("failed to write server cert: %w", err)
	}

	return certPath, keyPath, nil
}

// CACertPath returns the path to the CA certificate file.
func (ca *CAManager) CACertPath() string {
	return filepath.Join(ca.caDir, caCertFile)
}

// CACertPEM returns the PEM-encoded CA certificate content.
func (ca *CAManager) CACertPEM() ([]byte, error) {
	return os.ReadFile(filepath.Join(ca.caDir, caCertFile))
}

// ReissueTLSCert regenerates the TLS cert with updated hostnames.
// Call this when new services are added that need to be in the cert SANs.
func (ca *CAManager) ReissueTLSCert(hostnames []string) (certPath, keyPath string, err error) {
	// Remove existing TLS cert/key
	os.Remove(filepath.Join(ca.caDir, tlsCertFile))
	os.Remove(filepath.Join(ca.caDir, tlsKeyFile))
	return ca.IssueTLSCert(hostnames)
}
