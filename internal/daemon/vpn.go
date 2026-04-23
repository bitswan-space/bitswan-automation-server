package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/docker"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
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

	// 2. Initialize VPN certificate authority (for HTTPS on VPN Traefik)
	caMgr := vpn.NewCAManager(vpnPath)
	if err := caMgr.Init("BitSwan"); err != nil {
		http.Error(w, fmt.Sprintf("failed to initialize VPN CA: %v", err), http.StatusInternalServerError)
		return
	}

	// Issue TLS certificate for VPN Traefik (wildcard for all internal services)
	tlsHostnames := []string{
		"*.bswn.internal",
		"bswn.internal",
	}
	// Also add the public domain if available, for VPN-internal routes using public hostnames
	cfg := config.NewAutomationServerConfig()
	serverConfig, _ := cfg.LoadConfig()
	if serverConfig != nil && serverConfig.Domain != "" {
		tlsHostnames = append(tlsHostnames, "*."+serverConfig.Domain, serverConfig.Domain)
	}
	tlsCertPath, tlsKeyPath, err := caMgr.IssueTLSCert(tlsHostnames)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to issue VPN TLS cert: %v", err), http.StatusInternalServerError)
		return
	}

	// Also install the CA cert into the existing cert authority system so
	// gitops and other workspace containers trust internal HTTPS.
	caCertPEM, _ := caMgr.CACertPEM()
	if len(caCertPEM) > 0 {
		certAuthDir, _ := getCertAuthoritiesDir()
		os.WriteFile(filepath.Join(certAuthDir, "bitswan-vpn-ca.crt"), caCertPEM, 0644)
		installCertificateInDaemon("bitswan-vpn-ca.crt", filepath.Join(certAuthDir, "bitswan-vpn-ca.crt"))
	}

	// 3. Create bitswan_vpn_network
	docker.EnsureDockerNetwork("bitswan_vpn_network", true)

	// 4. Start WireGuard container
	wgCompose, err := dockercompose.CreateWireGuardDockerComposeFile(hostVpnPath, 51820)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate WireGuard compose: %v", err), http.StatusInternalServerError)
		return
	}
	if err := dockerComposeUp("wireguard", wgCompose, vpnPath); err != nil {
		http.Error(w, fmt.Sprintf("failed to start WireGuard: %v", err), http.StatusInternalServerError)
		return
	}

	// 5. Write VPN Traefik config with TLS
	os.MkdirAll(vpnTraefikPath, 0755)
	traefikYml := `entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"
tls:
  certificates:
    - certFile: /certs/tls.crt
      keyFile: /certs/tls.key
api:
  insecure: true
providers:
  rest:
    insecure: true
`
	os.WriteFile(filepath.Join(vpnTraefikPath, "traefik.yml"), []byte(traefikYml), 0644)

	// Host path for certs (VPN CA dir)
	hostCaDir := filepath.Join(hostVpnPath, "ca")
	_ = tlsCertPath
	_ = tlsKeyPath

	// 6. Start VPN Traefik container (with TLS certs mounted)
	vpnTraefikCompose, err := dockercompose.CreateVPNTraefikDockerComposeFile(hostVpnTraefikPath, hostCaDir)
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

	// 8. Register VPN admin routes on both ingresses
	// (cfg and serverConfig already loaded above for TLS cert hostnames)
	if serverConfig == nil || serverConfig.Domain == "" {
		http.Error(w, "No domain configured. Register with AOC first or set domain in automation_server_config.toml.", http.StatusBadRequest)
		return
	}
	domain := serverConfig.Domain
	internalDomain := serverConfig.InternalDomain()

	// 9. Set up OAuth for the VPN admin page.
	// Register an "automation-server-admin" workspace with AOC to get a
	// Keycloak client, then start oauth2-proxy in the daemon container.
	vpnAdminOAuthUpstream := "bitswan-automation-server-daemon:8080"
	if err := setupVPNAdminOAuth(domain); err != nil {
		fmt.Printf("Warning: VPN admin OAuth setup failed: %v (falling back to unauthenticated)\n", err)
	} else {
		// oauth2-proxy listens on :9999, upstream to localhost:8080
		vpnAdminOAuthUpstream = "bitswan-automation-server-daemon:9999"
	}

	// External VPN admin: internet-facing, behind OAuth (Keycloak).
	externalAdminReq := IngressAddRouteRequest{
		Hostname:      "vpn-admin." + domain,
		Upstream:      vpnAdminOAuthUpstream,
		IngressTarget: "external",
	}
	if err := addRouteToIngress(externalAdminReq, ""); err != nil {
		fmt.Printf("Warning: failed to register external VPN admin route: %v\n", err)
	}

	// Internal VPN admin: behind VPN, no OAuth needed (direct to daemon).
	internalAdminReq := IngressAddRouteRequest{
		Hostname:      "vpn-admin." + internalDomain,
		Upstream:      "bitswan-automation-server-daemon:8080",
		IngressTarget: "internal",
	}
	if err := addRouteToIngress(internalAdminReq, ""); err != nil {
		fmt.Printf("Warning: failed to register internal VPN admin route: %v\n", err)
	}

	// 8. Start session monitor (iptables LOG → wg show enrichment)
	monitor := vpn.NewSessionMonitor(mgr)
	if err := monitor.Start(); err != nil {
		fmt.Printf("Warning: failed to start session monitor: %v\n", err)
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":  "initialized",
		"message": "WireGuard VPN initialized with VPN Traefik, CoreDNS, and session monitoring.",
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
		devices, _ := mgr.ListDevices()
		result["server_public_key"] = pub
		result["device_count"] = len(devices)
	}

	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleVPNGenerateCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		UserID     string `json:"user_id"`
		DeviceName string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.UserID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}
	if body.DeviceName == "" {
		body.DeviceName = "default"
	}

	mgr := vpnManager()
	conf, err := mgr.GenerateClient(body.UserID, body.DeviceName)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate credentials: %v", err), http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("%s-%s.conf", body.UserID, body.DeviceName)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Write(conf)
}

func (s *Server) handleVPNRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		DeviceID string `json:"device_id"` // "user/device" format
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.DeviceID == "" {
		http.Error(w, "device_id is required (format: user/device)", http.StatusBadRequest)
		return
	}

	mgr := vpnManager()
	if err := mgr.RevokeDevice(body.DeviceID); err != nil {
		http.Error(w, fmt.Sprintf("failed to revoke: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "revoked", "device_id": body.DeviceID})
}

func (s *Server) handleVPNListUsers(w http.ResponseWriter, r *http.Request) {
	mgr := vpnManager()
	devices, err := mgr.ListDevices()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list devices: %v", err), http.StatusInternalServerError)
		return
	}
	if devices == nil {
		devices = []vpn.VPNDevice{}
	}
	json.NewEncoder(w).Encode(devices)
}

func (s *Server) handleVPNSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mgr := vpnManager()
	monitor := vpn.NewSessionMonitor(mgr)

	// Check for ?active=true query param
	if r.URL.Query().Get("active") == "true" {
		active := monitor.GetActiveSessions()
		if active == nil {
			active = []vpn.SessionEvent{}
		}
		json.NewEncoder(w).Encode(active)
		return
	}

	// Return recent session log
	limit := 100
	events, err := monitor.GetSessionLog(limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read session log: %v", err), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []vpn.SessionEvent{}
	}
	json.NewEncoder(w).Encode(events)
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

const adminWorkspaceName = "automation-server-admin"

// setupVPNAdminOAuth registers an "automation-server-admin" workspace with
// AOC to get a Keycloak client, then starts oauth2-proxy in the daemon
// container pointing at localhost:8080 (the daemon's HTTP server).
func setupVPNAdminOAuth(domain string) error {
	// 1. Get or create OAuth config
	oauthCfg, err := oauth.GetOauthConfig(adminWorkspaceName)
	if err != nil {
		// Not cached locally — try to fetch from AOC
		aocClient, aocErr := aoc.NewAOCClient()
		if aocErr != nil {
			return fmt.Errorf("AOC not configured: %w", aocErr)
		}

		// Register the admin "workspace" if it doesn't exist yet.
		// The editor_url points to the VPN admin page — it's just a label
		// used by the AOC to create the Keycloak client.
		vpnAdminURL := fmt.Sprintf("https://vpn-admin.%s/vpn-admin/", domain)
		workspaceID, regErr := aocClient.RegisterWorkspace(adminWorkspaceName, &vpnAdminURL, domain)
		if regErr != nil {
			// May already exist — try fetching OAuth anyway
			fmt.Printf("Warning: admin workspace registration: %v\n", regErr)
		}

		if workspaceID == "" {
			// Try to find it via list
			workspaceList, listErr := aocClient.ListWorkspaces()
			if listErr == nil {
				for _, ws := range workspaceList.Results {
					if ws.Name == adminWorkspaceName {
						workspaceID = ws.Id
						break
					}
				}
			}
		}

		if workspaceID == "" {
			return fmt.Errorf("could not register or find admin workspace in AOC")
		}

		oauthCfg, err = aocClient.GetOAuthConfig(workspaceID)
		if err != nil {
			return fmt.Errorf("failed to get OAuth config from AOC: %w", err)
		}

		// Save for next time
		// Ensure the workspace directory exists
		homeDir := os.Getenv("HOME")
		os.MkdirAll(filepath.Join(homeDir, ".config", "bitswan", "workspaces", adminWorkspaceName), 0755)
		if saveErr := oauth.SaveOauthConfig(adminWorkspaceName, oauthCfg); saveErr != nil {
			fmt.Printf("Warning: failed to save admin OAuth config: %v\n", saveErr)
		}
	}

	// 2. Start oauth2-proxy as a subprocess in this container.
	// It listens on :9999 and proxies to localhost:8080 (daemon docs server).
	redirectURL := fmt.Sprintf("https://vpn-admin.%s/oauth2/callback", domain)

	args := []string{
		"--provider=keycloak-oidc",
		"--http-address=0.0.0.0:9999",
		"--upstream=http://127.0.0.1:8080",
		"--client-id=" + oauthCfg.ClientId,
		"--client-secret=" + oauthCfg.ClientSecret,
		"--cookie-secret=" + oauthCfg.CookieSecret,
		"--oidc-issuer-url=" + oauthCfg.IssuerUrl,
		"--redirect-url=" + redirectURL,
		"--email-domain=*",
		"--scope=openid email profile",
		"--code-challenge-method=S256",
		"--skip-provider-button=true",
		"--pass-user-headers=true",
		"--set-xauthrequest=true",
	}

	if oauthCfg.GroupsClaim != nil {
		args = append(args, "--oidc-groups-claim="+*oauthCfg.GroupsClaim)
	} else {
		args = append(args, "--oidc-groups-claim=group_membership")
	}

	// Check if oauth2-proxy binary exists
	oauth2ProxyPath := "/usr/local/bin/oauth2-proxy"
	if _, err := os.Stat(oauth2ProxyPath); os.IsNotExist(err) {
		return fmt.Errorf("oauth2-proxy binary not found at %s", oauth2ProxyPath)
	}

	cmd := exec.Command(oauth2ProxyPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Prevent env var leaks — oauth2-proxy reads OAUTH2_PROXY_* from env
	cmd.Env = append(os.Environ(), "OAUTH2_PROXY_COOKIE_NAME=_bitswan_vpn_admin")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start oauth2-proxy: %w", err)
	}

	fmt.Printf("oauth2-proxy started for VPN admin (PID %d, listening on :9999)\n", cmd.Process.Pid)

	// Don't wait — let it run in the background
	go func() {
		if err := cmd.Wait(); err != nil {
			fmt.Printf("Warning: oauth2-proxy exited: %v\n", err)
		}
	}()

	return nil
}

