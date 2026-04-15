package vpn

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	VPNSubnet    = "10.8.0.0/24"
	ServerIP     = "10.8.0.1"
	ListenPort   = 51820
	DNSServer    = "10.8.0.1"
	vpnDirName   = "vpn"
	usersDirName = "users"
)

// VPNUser represents a registered VPN user.
type VPNUser struct {
	ID        string `json:"id" yaml:"id"`
	PublicKey string `json:"public_key" yaml:"public_key"`
	IP        string `json:"ip" yaml:"ip"`
}

// Manager handles WireGuard server and client configuration.
type Manager struct {
	baseDir string // ~/.config/bitswan/vpn
	mu      sync.Mutex
}

// NewManager creates a VPN manager rooted at the given base dir.
func NewManager(bitswanConfigDir string) *Manager {
	return &Manager{
		baseDir: filepath.Join(bitswanConfigDir, vpnDirName),
	}
}

// IsInitialized returns true if the VPN server has been set up.
func (m *Manager) IsInitialized() bool {
	_, err := os.Stat(filepath.Join(m.baseDir, "server_private.key"))
	return err == nil
}

// Init generates the server keypair and writes wg0.conf.
func (m *Manager) Init(serverEndpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.IsInitialized() {
		return fmt.Errorf("VPN already initialized")
	}

	os.MkdirAll(m.baseDir, 0700)
	os.MkdirAll(filepath.Join(m.baseDir, usersDirName), 0700)

	// Generate server keypair
	serverPriv, serverPub, err := generateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate server keypair: %w", err)
	}

	if err := os.WriteFile(filepath.Join(m.baseDir, "server_private.key"), []byte(serverPriv), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.baseDir, "server_public.key"), []byte(serverPub), 0644); err != nil {
		return err
	}

	// Write initial server config (no peers yet)
	conf := fmt.Sprintf(`[Interface]
Address = %s/24
ListenPort = %d
PrivateKey = %s
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
`, ServerIP, ListenPort, serverPriv)

	if err := os.WriteFile(filepath.Join(m.baseDir, "wg0.conf"), []byte(conf), 0600); err != nil {
		return err
	}

	// Store server endpoint for client configs
	meta := map[string]string{
		"endpoint":   serverEndpoint,
		"server_pub": serverPub,
	}
	metaBytes, _ := yaml.Marshal(meta)
	if err := os.WriteFile(filepath.Join(m.baseDir, "meta.yaml"), metaBytes, 0644); err != nil {
		return err
	}

	// Write the enabled flag
	return os.WriteFile(filepath.Join(m.baseDir, "enabled"), []byte("true\n"), 0644)
}

// GenerateClient creates a new VPN client and returns the client .conf content.
func (m *Manager) GenerateClient(userID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.IsInitialized() {
		return nil, fmt.Errorf("VPN not initialized")
	}

	userDir := filepath.Join(m.baseDir, usersDirName, userID)
	if _, err := os.Stat(userDir); err == nil {
		return nil, fmt.Errorf("user %s already exists", userID)
	}

	// Read server metadata
	metaBytes, err := os.ReadFile(filepath.Join(m.baseDir, "meta.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to read server metadata: %w", err)
	}
	var meta map[string]string
	yaml.Unmarshal(metaBytes, &meta)
	serverEndpoint := meta["endpoint"]
	serverPub := meta["server_pub"]

	// Generate client keypair
	clientPriv, clientPub, err := generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client keypair: %w", err)
	}

	// Assign next available IP
	clientIP, err := m.nextAvailableIP()
	if err != nil {
		return nil, err
	}

	// Save client info
	os.MkdirAll(userDir, 0700)
	user := VPNUser{
		ID:        userID,
		PublicKey: clientPub,
		IP:        clientIP,
	}
	userBytes, _ := yaml.Marshal(user)
	os.WriteFile(filepath.Join(userDir, "user.yaml"), userBytes, 0644)
	os.WriteFile(filepath.Join(userDir, "private.key"), []byte(clientPriv), 0600)

	// Build client config
	clientConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = %s
PersistentKeepalive = 25
`, clientPriv, clientIP, DNSServer, serverPub, serverEndpoint, ListenPort, VPNSubnet)

	os.WriteFile(filepath.Join(userDir, "client.conf"), []byte(clientConf), 0600)

	// Add peer to server config
	if err := m.addPeerToServerConfig(clientPub, clientIP); err != nil {
		return nil, fmt.Errorf("failed to add peer to server: %w", err)
	}

	return []byte(clientConf), nil
}

// RevokeClient removes a VPN client.
func (m *Manager) RevokeClient(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	userDir := filepath.Join(m.baseDir, usersDirName, userID)
	userFile := filepath.Join(userDir, "user.yaml")

	data, err := os.ReadFile(userFile)
	if err != nil {
		return fmt.Errorf("user %s not found", userID)
	}
	var user VPNUser
	yaml.Unmarshal(data, &user)

	// Remove peer from server config
	if err := m.removePeerFromServerConfig(user.PublicKey); err != nil {
		return err
	}

	// Delete user directory
	return os.RemoveAll(userDir)
}

// ListClients returns all registered VPN users.
func (m *Manager) ListClients() ([]VPNUser, error) {
	usersDir := filepath.Join(m.baseDir, usersDirName)
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var users []VPNUser
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(usersDir, entry.Name(), "user.yaml"))
		if err != nil {
			continue
		}
		var user VPNUser
		yaml.Unmarshal(data, &user)
		users = append(users, user)
	}
	return users, nil
}

// ServerPublicKey returns the server's public key.
func (m *Manager) ServerPublicKey() (string, error) {
	data, err := os.ReadFile(filepath.Join(m.baseDir, "server_public.key"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ReloadServer signals the WireGuard container to reload its config.
func (m *Manager) ReloadServer() error {
	// docker exec wireguard wg syncconf wg0 <(wg-quick strip wg0)
	cmd := exec.Command("docker", "exec", "wireguard", "bash", "-c",
		"wg syncconf wg0 <(wg-quick strip /config/wg0.conf)")
	return cmd.Run()
}

// --- internal helpers ---

func (m *Manager) nextAvailableIP() (string, error) {
	users, _ := m.ListClients()
	used := map[string]bool{ServerIP: true}
	for _, u := range users {
		used[u.IP] = true
	}

	// Assign from 10.8.0.2 to 10.8.0.254
	for i := 2; i < 255; i++ {
		ip := fmt.Sprintf("10.8.0.%d", i)
		if !used[ip] {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no available IP addresses in VPN subnet")
}

func (m *Manager) addPeerToServerConfig(publicKey, ip string) error {
	confPath := filepath.Join(m.baseDir, "wg0.conf")
	f, err := os.OpenFile(confPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	peer := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", publicKey, ip)
	_, err = f.WriteString(peer)
	if err != nil {
		return err
	}

	return m.ReloadServer()
}

func (m *Manager) removePeerFromServerConfig(publicKey string) error {
	confPath := filepath.Join(m.baseDir, "wg0.conf")
	data, err := os.ReadFile(confPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var result []string
	skip := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "[Peer]" {
			skip = false
		}
		if skip {
			continue
		}
		if strings.Contains(line, publicKey) {
			// Remove the [Peer] header we just added
			if len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "[Peer]" {
				result = result[:len(result)-1]
			}
			skip = true
			continue
		}
		result = append(result, line)
	}

	if err := os.WriteFile(confPath, []byte(strings.Join(result, "\n")), 0600); err != nil {
		return err
	}

	return m.ReloadServer()
}

func generateKeyPair() (privateKey, publicKey string, err error) {
	// Try using wg command if available
	privCmd := exec.Command("wg", "genkey")
	privOut, err := privCmd.Output()
	if err == nil {
		priv := strings.TrimSpace(string(privOut))
		pubCmd := exec.Command("wg", "pubkey")
		pubCmd.Stdin = strings.NewReader(priv)
		pubOut, err := pubCmd.Output()
		if err == nil {
			return priv, strings.TrimSpace(string(pubOut)), nil
		}
	}

	// Fallback: generate Curve25519 keypair manually
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", err
	}
	// Clamp private key per Curve25519 spec
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	priv := base64.StdEncoding.EncodeToString(private[:])

	// Compute public key via Curve25519 scalar multiplication
	// For simplicity, shell out to wg pubkey if available, otherwise error
	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(priv)
	pubOut, err := pubCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg command not available for key generation: %w", err)
	}

	return priv, strings.TrimSpace(string(pubOut)), nil
}

// Silence unused import warning
var _ = net.ParseCIDR
