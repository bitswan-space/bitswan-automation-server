package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/vpn"
)

func vpnManager() *vpn.Manager {
	homeDir, _ := os.UserHomeDir()
	return vpn.NewManager(filepath.Join(homeDir, ".config", "bitswan"))
}

func (s *Server) handleVPNInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Endpoint == "" {
		http.Error(w, "endpoint is required (e.g., vpn.example.com)", http.StatusBadRequest)
		return
	}

	mgr := vpnManager()
	if err := mgr.Init(body.Endpoint); err != nil {
		http.Error(w, fmt.Sprintf("failed to initialize VPN: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":  "initialized",
		"message": "WireGuard VPN initialized. Start the container with 'bitswan vpn start'.",
	})
}

func (s *Server) handleVPNStatus(w http.ResponseWriter, r *http.Request) {
	mgr := vpnManager()
	initialized := mgr.IsInitialized()

	result := map[string]interface{}{
		"enabled":     IsVPNEnabled(),
		"initialized": initialized,
	}

	if initialized {
		pub, _ := mgr.ServerPublicKey()
		users, _ := mgr.ListClients()
		result["server_public_key"] = pub
		result["user_count"] = len(users)
	}

	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleVPNGenerateCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.UserID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	mgr := vpnManager()
	conf, err := mgr.GenerateClient(body.UserID)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate credentials: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.conf", body.UserID))
	w.Write(conf)
}

func (s *Server) handleVPNRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.UserID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	mgr := vpnManager()
	if err := mgr.RevokeClient(body.UserID); err != nil {
		http.Error(w, fmt.Sprintf("failed to revoke: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "revoked", "user_id": body.UserID})
}

func (s *Server) handleVPNListUsers(w http.ResponseWriter, r *http.Request) {
	mgr := vpnManager()
	users, err := mgr.ListClients()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list users: %v", err), http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []vpn.VPNUser{}
	}
	json.NewEncoder(w).Encode(users)
}

func (s *Server) handleVPNMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		CreatedBy string `json:"created_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.CreatedBy == "" {
		body.CreatedBy = "admin"
	}

	store := magicLinkStore()
	token, err := store.Create(body.CreatedBy)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create magic link: %v", err), http.StatusInternalServerError)
		return
	}

	domain := os.Getenv("BITSWAN_GITOPS_DOMAIN")
	claimURL := fmt.Sprintf("https://vpn-admin.%s/vpn-admin/claim/%s", domain, token)

	json.NewEncoder(w).Encode(map[string]string{
		"token":     token,
		"claim_url": claimURL,
		"expires":   "1 hour",
	})
}
