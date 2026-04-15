package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/docker"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/vpn"
)

// dockerComposeUp runs docker compose up -d with the given compose content.
// dockerComposeUp writes the compose content to a file and runs docker compose up -d.
func dockerComposeUp(projectName, composeContent, workDir string) error {
	composePath := filepath.Join(workDir, "docker-compose.yaml")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create dir %s: %w", workDir, err)
	}
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		return fmt.Errorf("failed to write compose file: %w", err)
	}
	cmd := exec.Command("docker", "compose", "-p", projectName, "-f", composePath, "up", "-d")
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

// dockerComposeDown stops and removes containers for a compose project.
func dockerComposeDown(projectName, workDir string) error {
	composePath := filepath.Join(workDir, "docker-compose.yaml")
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		return nil // nothing to tear down
	}
	cmd := exec.Command("docker", "compose", "-p", projectName, "-f", composePath, "down", "--remove-orphans")
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

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
		Endpoint       string `json:"endpoint"`
		InternalDomain string `json:"internal_domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Endpoint == "" {
		http.Error(w, "endpoint is required (e.g., vpn.example.com)", http.StatusBadRequest)
		return
	}

	homeDir, _ := os.UserHomeDir()
	vpnPath := filepath.Join(homeDir, ".config", "bitswan", "vpn")
	vpnTraefikPath := filepath.Join(homeDir, ".config", "bitswan", "traefik-vpn")

	// Docker compose volume mounts need host paths, not daemon container paths.
	// HOST_HOME maps the daemon's /root to the actual host home dir.
	hostHome := os.Getenv("HOST_HOME")
	hostVpnPath := vpnPath
	hostVpnTraefikPath := vpnTraefikPath
	if hostHome != "" {
		hostVpnPath = filepath.Join(hostHome, ".config", "bitswan", "vpn")
		hostVpnTraefikPath = filepath.Join(hostHome, ".config", "bitswan", "traefik-vpn")
	}

	// 1. Initialize WireGuard server config (idempotent — skips if already done)
	mgr := vpnManager()
	if !mgr.IsInitialized() {
		if err := mgr.Init(body.Endpoint); err != nil {
			http.Error(w, fmt.Sprintf("failed to initialize VPN: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// 2. Create bitswan_vpn_network
	docker.EnsureDockerNetwork("bitswan_vpn_network", true)

	// 3. Start WireGuard container
	wgCompose, err := dockercompose.CreateWireGuardDockerComposeFile(hostVpnPath, 51820)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate WireGuard compose: %v", err), http.StatusInternalServerError)
		return
	}
	if err := dockerComposeUp("wireguard", wgCompose, vpnPath); err != nil {
		http.Error(w, fmt.Sprintf("failed to start WireGuard: %v", err), http.StatusInternalServerError)
		return
	}

	// 4. Write VPN Traefik config
	os.MkdirAll(vpnTraefikPath, 0755)
	traefikYml := `entryPoints:
  web:
    address: ":80"
api:
  insecure: true
providers:
  rest:
    insecure: true
`
	os.WriteFile(filepath.Join(vpnTraefikPath, "traefik.yml"), []byte(traefikYml), 0644)

	// 5. Start VPN Traefik container
	vpnTraefikCompose, err := dockercompose.CreateVPNTraefikDockerComposeFile(hostVpnTraefikPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate VPN Traefik compose: %v", err), http.StatusInternalServerError)
		return
	}
	if err := dockerComposeUp("traefik-vpn", vpnTraefikCompose, vpnTraefikPath); err != nil {
		http.Error(w, fmt.Sprintf("failed to start VPN Traefik: %v", err), http.StatusInternalServerError)
		return
	}

	// 6. Write Corefile (locally) and start CoreDNS
	if err := dockercompose.WriteCorefile(vpnPath, ""); err != nil {
		http.Error(w, fmt.Sprintf("failed to write Corefile: %v", err), http.StatusInternalServerError)
		return
	}
	corednsCompose, err := dockercompose.CreateCoreDNSDockerComposeFile(hostVpnPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate CoreDNS compose: %v", err), http.StatusInternalServerError)
		return
	}
	if err := dockerComposeUp("coredns-vpn", corednsCompose, vpnPath); err != nil {
		http.Error(w, fmt.Sprintf("failed to start CoreDNS: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":  "initialized",
		"message": "WireGuard VPN initialized with VPN Traefik and CoreDNS.",
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

func (s *Server) handleVPNDestroy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	homeDir, _ := os.UserHomeDir()
	vpnPath := filepath.Join(homeDir, ".config", "bitswan", "vpn")
	vpnTraefikPath := filepath.Join(homeDir, ".config", "bitswan", "traefik-vpn")

	var errors []string

	// Stop containers
	if err := dockerComposeDown("coredns-vpn", vpnPath); err != nil {
		errors = append(errors, fmt.Sprintf("coredns: %v", err))
	}
	if err := dockerComposeDown("traefik-vpn", vpnTraefikPath); err != nil {
		errors = append(errors, fmt.Sprintf("traefik-vpn: %v", err))
	}
	if err := dockerComposeDown("wireguard", vpnPath); err != nil {
		errors = append(errors, fmt.Sprintf("wireguard: %v", err))
	}

	// Remove config
	os.RemoveAll(vpnPath)
	os.RemoveAll(vpnTraefikPath)

	if len(errors) > 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "partial",
			"message":  "VPN destroyed with some errors",
			"errors":   errors,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":  "destroyed",
		"message": "VPN infrastructure removed. Containers stopped, config deleted.",
	})
}
