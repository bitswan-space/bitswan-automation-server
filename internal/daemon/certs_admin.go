package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
)

// CertAuthorityEntry is returned by the admin-page cert-authorities endpoint.
// Mirrors CertAuthorityInfo from certauthority.go but with a richer shape:
// we compute not-after so the UI can show expiry-soon warnings.
type CertAuthorityEntry struct {
	Name    string `json:"name"`
	SizeKB  string `json:"size_kb"`
	NotAfter string `json:"not_after,omitempty"`
	Subject  string `json:"subject,omitempty"`
}

// listCertAuthorities walks the CA dir and returns one entry per file.
// Non-PEM files are skipped silently.
func listCertAuthorities() ([]CertAuthorityEntry, error) {
	dir, err := getCertAuthoritiesDir()
	if err != nil {
		return nil, err
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	out := make([]CertAuthorityEntry, 0, len(files))
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
			continue
		}
		info, err := f.Info()
		if err != nil {
			continue
		}
		entry := CertAuthorityEntry{
			Name:   name,
			SizeKB: fmt.Sprintf("%.1f", float64(info.Size())/1024),
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			if block, _ := pem.Decode(data); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					entry.Subject = cert.Subject.String()
					entry.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
				}
			}
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// addCertAuthorityPEM writes a PEM file into the trust-store dir and installs
// it into the daemon's system trust via update-ca-certificates. Validates
// that the content parses as at least one certificate before touching disk.
func addCertAuthorityPEM(name string, pemBytes []byte) error {
	name = strings.TrimSpace(name)
	if strings.ContainsAny(name, "/\\") || name == "" {
		return fmt.Errorf("invalid name")
	}
	if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
		name += ".crt"
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("not a valid PEM file")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("not a valid X.509 certificate: %w", err)
	}

	dir, err := getCertAuthoritiesDir()
	if err != nil {
		return err
	}
	target := filepath.Join(dir, name)
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("a CA named %q already exists — remove it first", name)
	}
	if err := os.WriteFile(target, pemBytes, 0644); err != nil {
		return err
	}
	if err := installCertificateInDaemon(name, target); err != nil {
		fmt.Printf("Warning: installCertificateInDaemon failed: %v\n", err)
	}
	return nil
}

// removeCertAuthorityFile deletes a CA from the trust-store dir and from the
// system trust.
func removeCertAuthorityFile(name string) error {
	if strings.ContainsAny(name, "/\\") || name == "" {
		return fmt.Errorf("invalid name")
	}
	dir, err := getCertAuthoritiesDir()
	if err != nil {
		return err
	}
	target := filepath.Join(dir, name)
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return fmt.Errorf("not found")
	}
	if err := removeCertificateFromDaemon(name); err != nil {
		fmt.Printf("Warning: removeCertificateFromDaemon failed: %v\n", err)
	}
	return os.Remove(target)
}

// HostnameCertEntry is one row in the hostname TLS cert list.
type HostnameCertEntry struct {
	Hostname string `json:"hostname"`
	NotAfter string `json:"not_after,omitempty"`
	Subject  string `json:"subject,omitempty"`
	SANs     []string `json:"sans,omitempty"`
}

// traefikCertsRoot returns the host-side path that Traefik uses for per-host
// TLS certs. It sits under ~/.config/bitswan/traefik/certs/{sanitized-host}/.
func traefikCertsRoot() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "bitswan", "traefik", "certs")
}

// sanitizeHostname mirrors traefikapi.sanitizeHostname (unexported). It's
// lossy (both "." and "-" become "_"), so we can't uniquely reverse it; we
// drop a hostname.txt sidecar in each dir to recover the original.
func sanitizeHostname(hostname string) string {
	s := strings.ReplaceAll(hostname, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "*", "_")
	return s
}

// listHostnameCerts enumerates the per-hostname cert directories Traefik
// knows about. Each directory holds cert, key, and a hostname.txt sidecar
// with the original hostname (which the sanitized dirname can't recover
// unambiguously).
func listHostnameCerts() ([]HostnameCertEntry, error) {
	root := traefikCertsRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []HostnameCertEntry{}, nil
		}
		return nil, err
	}
	out := make([]HostnameCertEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		hostDir := filepath.Join(root, e.Name())
		entry := HostnameCertEntry{Hostname: e.Name()} // fallback to dirname
		if raw, err := os.ReadFile(filepath.Join(hostDir, "hostname.txt")); err == nil {
			entry.Hostname = strings.TrimSpace(string(raw))
		}
		// Parse any cert file we find for subject + expiry.
		files, _ := os.ReadDir(hostDir)
		for _, f := range files {
			if f.IsDir() || f.Name() == "hostname.txt" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(hostDir, f.Name()))
			if err != nil {
				continue
			}
			if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					entry.Subject = cert.Subject.String()
					entry.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
					entry.SANs = cert.DNSNames
					break
				}
			}
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

// installHostnameCert writes a cert + key pair to Traefik's per-hostname cert
// dir, after validating both parse and pair up. Also persists a hostname.txt
// sidecar since the directory-name sanitization is lossy.
func installHostnameCert(hostname string, certPEM, keyPEM []byte) error {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("cert/key pair invalid: %w", err)
	}

	dir := filepath.Join(traefikCertsRoot(), sanitizeHostname(hostname))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "hostname.txt"), []byte(hostname), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), keyPEM, 0600); err != nil {
		return err
	}
	// Tell Traefik about the cert via the API so it picks up without a full restart.
	if err := traefikapi.InstallTLSCerts(hostname, false, dir); err != nil {
		fmt.Printf("Warning: Traefik reload for %s failed: %v\n", hostname, err)
	}
	return nil
}

// removeHostnameCert deletes the per-hostname cert dir.
func removeHostnameCert(hostname string) error {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	dir := filepath.Join(traefikCertsRoot(), sanitizeHostname(hostname))
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("not found")
	}
	return os.RemoveAll(dir)
}
