package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CertAuthorityInfo represents information about a certificate authority
type CertAuthorityInfo struct {
	Name string  `json:"name"`
	Size float64 `json:"size_kb"`
}

// CertAuthorityListResponse represents the response from listing certificate authorities
type CertAuthorityListResponse struct {
	CertAuthorities []CertAuthorityInfo `json:"cert_authorities"`
	Directory       string               `json:"directory"`
}

// CertAuthorityAddRequest represents the request to add a certificate authority
type CertAuthorityAddRequest struct {
	FileName    string `json:"file_name"`
	FileContent string `json:"file_content"` // base64 encoded
}

// CertAuthorityAddResponse represents the response from adding a certificate authority
type CertAuthorityAddResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Location string `json:"location"`
}

// CertAuthorityRemoveResponse represents the response from removing a certificate authority
type CertAuthorityRemoveResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// getCertAuthoritiesDir returns the certificate authorities directory path
func getCertAuthoritiesDir() (string, error) {
	certDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "certauthorities")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create certauthorities directory: %w", err)
	}
	return certDir, nil
}

// handleCertAuthority routes certificate authority-related requests
func (s *Server) handleCertAuthority(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/certauthority")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "" || path == "list":
		s.handleCertAuthorityList(w, r)
	case path == "add":
		s.handleCertAuthorityAdd(w, r)
	case strings.HasPrefix(path, "remove/"):
		certName := strings.TrimPrefix(path, "remove/")
		s.handleCertAuthorityRemove(w, r, certName)
	default:
		writeJSONError(w, "not found", http.StatusNotFound)
	}
}

// handleCertAuthorityList handles GET /certauthority or /certauthority/list
func (s *Server) handleCertAuthorityList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	certDir, err := getCertAuthoritiesDir()
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	files, err := os.ReadDir(certDir)
	if err != nil {
		writeJSONError(w, "failed to read certauthorities directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var certAuthorities []CertAuthorityInfo
	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".crt") || strings.HasSuffix(file.Name(), ".pem")) {
			info, _ := file.Info()
			certAuthorities = append(certAuthorities, CertAuthorityInfo{
				Name: file.Name(),
				Size: float64(info.Size()) / 1024,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(CertAuthorityListResponse{
		CertAuthorities: certAuthorities,
		Directory:       certDir,
	})
}

// handleCertAuthorityAdd handles POST /certauthority/add
func (s *Server) handleCertAuthorityAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CertAuthorityAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.FileName == "" {
		writeJSONError(w, "file_name is required", http.StatusBadRequest)
		return
	}

	if req.FileContent == "" {
		writeJSONError(w, "file_content is required", http.StatusBadRequest)
		return
	}

	// Decode base64 content
	fileContent, err := base64.StdEncoding.DecodeString(req.FileContent)
	if err != nil {
		writeJSONError(w, "invalid file_content: not valid base64: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Ensure filename has proper extension
	targetName := req.FileName
	if !strings.HasSuffix(targetName, ".crt") && !strings.HasSuffix(targetName, ".pem") {
		targetName += ".crt"
	}

	certDir, err := getCertAuthoritiesDir()
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	targetPath := filepath.Join(certDir, targetName)

	// Check if file already exists
	if _, err := os.Stat(targetPath); err == nil {
		writeJSONError(w, "certificate authority '"+targetName+"' already exists", http.StatusBadRequest)
		return
	}

	// Write the certificate file
	if err := os.WriteFile(targetPath, fileContent, 0644); err != nil {
		writeJSONError(w, "failed to write certificate file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Install the certificate in the daemon's system certificate store
	if err := installCertificateInDaemon(targetName, targetPath); err != nil {
		// Log warning but don't fail the request - certificate is still saved
		fmt.Printf("Warning: Failed to install certificate in daemon: %v\n", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(CertAuthorityAddResponse{
		Success:  true,
		Message:  "Certificate authority '" + targetName + "' added successfully",
		Location: targetPath,
	})
}

// handleCertAuthorityRemove handles DELETE /certauthority/remove/{name}
func (s *Server) handleCertAuthorityRemove(w http.ResponseWriter, r *http.Request, certName string) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if certName == "" {
		writeJSONError(w, "certificate name is required", http.StatusBadRequest)
		return
	}

	certDir, err := getCertAuthoritiesDir()
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	certPath := filepath.Join(certDir, certName)

	// Check if file exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		writeJSONError(w, "certificate authority '"+certName+"' not found", http.StatusNotFound)
		return
	}

	// Remove the certificate from the daemon's system certificate store
	if err := removeCertificateFromDaemon(certName); err != nil {
		// Log warning but don't fail the request
		fmt.Printf("Warning: Failed to remove certificate from daemon: %v\n", err)
	}

	// Remove the file
	if err := os.Remove(certPath); err != nil {
		writeJSONError(w, "failed to remove certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(CertAuthorityRemoveResponse{
		Success: true,
		Message: "Certificate authority '" + certName + "' removed successfully",
	})
}

// installCertificateInDaemon installs a certificate in the daemon's system certificate store
func installCertificateInDaemon(certName, certPath string) error {
	// Ensure the target directory exists
	targetDir := "/usr/local/share/ca-certificates"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create ca-certificates directory: %w", err)
	}

	// Determine target filename (must be .crt for update-ca-certificates)
	targetName := certName
	if strings.HasSuffix(targetName, ".pem") {
		targetName = strings.TrimSuffix(targetName, ".pem") + ".crt"
	} else if !strings.HasSuffix(targetName, ".crt") {
		targetName += ".crt"
	}

	targetPath := filepath.Join(targetDir, targetName)

	// Read the certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Write to the system certificate directory
	if err := os.WriteFile(targetPath, certData, 0644); err != nil {
		return fmt.Errorf("failed to write certificate to system directory: %w", err)
	}

	// Update the system CA certificates
	cmd := exec.Command("update-ca-certificates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// update-ca-certificates may return non-zero exit code but still work
		// Check if the output contains success indicators
		outputStr := string(output)
		if !strings.Contains(outputStr, "Updating certificates") && !strings.Contains(outputStr, "done") {
			return fmt.Errorf("update-ca-certificates failed: %v, output: %s", err, outputStr)
		}
	}

	return nil
}

// removeCertificateFromDaemon removes a certificate from the daemon's system certificate store
func removeCertificateFromDaemon(certName string) error {
	// Determine the installed certificate name (may be .crt even if original was .pem)
	targetDir := "/usr/local/share/ca-certificates"
	
	// Try both .crt and .pem variants
	var targetPath string
	if strings.HasSuffix(certName, ".pem") {
		targetPath = filepath.Join(targetDir, strings.TrimSuffix(certName, ".pem")+".crt")
	} else if strings.HasSuffix(certName, ".crt") {
		targetPath = filepath.Join(targetDir, certName)
	} else {
		// Try both extensions
		targetPath = filepath.Join(targetDir, certName+".crt")
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			targetPath = filepath.Join(targetDir, certName+".pem")
		}
	}

	// Remove the certificate file if it exists
	if _, err := os.Stat(targetPath); err == nil {
		if err := os.Remove(targetPath); err != nil {
			return fmt.Errorf("failed to remove certificate from system directory: %w", err)
		}
	}

	// Update the system CA certificates
	cmd := exec.Command("update-ca-certificates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := string(output)
		if !strings.Contains(outputStr, "Updating certificates") && !strings.Contains(outputStr, "done") {
			return fmt.Errorf("update-ca-certificates failed: %v, output: %s", err, outputStr)
		}
	}

	return nil
}

// installAllCertificatesInDaemon installs all certificates from the registry into the daemon
// This should be called when the daemon starts
func installAllCertificatesInDaemon() error {
	certDir, err := getCertAuthoritiesDir()
	if err != nil {
		return fmt.Errorf("failed to get certauthorities directory: %w", err)
	}

	files, err := os.ReadDir(certDir)
	if err != nil {
		// Directory might not exist yet, that's okay
		return nil
	}

	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".crt") || strings.HasSuffix(file.Name(), ".pem")) {
			certPath := filepath.Join(certDir, file.Name())
			if err := installCertificateInDaemon(file.Name(), certPath); err != nil {
				fmt.Printf("Warning: Failed to install certificate %s: %v\n", file.Name(), err)
			}
		}
	}

	return nil
}

