package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

