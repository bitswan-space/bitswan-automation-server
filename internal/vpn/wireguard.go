package vpn

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

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

// VPNDevice represents a single device registered to a user.
type VPNDevice struct {
	DeviceID   string `json:"device_id" yaml:"device_id"`     // unique: {user_id}/{device_name}
	UserID     string `json:"user_id" yaml:"user_id"`
	DeviceName string `json:"device_name" yaml:"device_name"` // e.g., "laptop", "phone"
	PublicKey  string `json:"public_key" yaml:"public_key"`
	IP         string `json:"ip" yaml:"ip"`
	IssuedAt   string `json:"issued_at" yaml:"issued_at"`
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

// GenerateClient creates a new VPN device for a user and returns the client .conf content.
// userID: the user (e.g., email or username)
// deviceName: the device label (e.g., "laptop", "phone")
func (m *Manager) GenerateClient(userID, deviceName string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.IsInitialized() {
		return nil, fmt.Errorf("VPN not initialized")
	}

	deviceDir := filepath.Join(m.baseDir, usersDirName, userID, deviceName)
	if _, err := os.Stat(deviceDir); err == nil {
		return nil, fmt.Errorf("device %s/%s already exists", userID, deviceName)
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

	// Save device info
	os.MkdirAll(deviceDir, 0700)
	device := VPNDevice{
		DeviceID:   userID + "/" + deviceName,
		UserID:     userID,
		DeviceName: deviceName,
		PublicKey:  clientPub,
		IP:         clientIP,
		IssuedAt:   fmt.Sprintf("%s", time.Now().UTC().Format(time.RFC3339)),
	}
	deviceBytes, _ := yaml.Marshal(device)
	os.WriteFile(filepath.Join(deviceDir, "device.yaml"), deviceBytes, 0644)
	os.WriteFile(filepath.Join(deviceDir, "private.key"), []byte(clientPriv), 0600)

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

	os.WriteFile(filepath.Join(deviceDir, "client.conf"), []byte(clientConf), 0600)

	// Add peer to server config
	if err := m.addPeerToServerConfig(clientPub, clientIP); err != nil {
		return nil, fmt.Errorf("failed to add peer to server: %w", err)
	}

	return []byte(clientConf), nil
}

// RevokeDevice removes a single VPN device.
// deviceID is "userID/deviceName" (e.g., "admin/laptop").
func (m *Manager) RevokeDevice(deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	deviceDir := filepath.Join(m.baseDir, usersDirName, deviceID)
	deviceFile := filepath.Join(deviceDir, "device.yaml")

	data, err := os.ReadFile(deviceFile)
	if err != nil {
		return fmt.Errorf("device %s not found", deviceID)
	}
	var device VPNDevice
	yaml.Unmarshal(data, &device)

	// Remove peer from server config
	if err := m.removePeerFromServerConfig(device.PublicKey); err != nil {
		return err
	}

	// Delete device directory
	if err := os.RemoveAll(deviceDir); err != nil {
		return err
	}

	// Clean up empty user directory
	userDir := filepath.Dir(deviceDir)
	entries, _ := os.ReadDir(userDir)
	if len(entries) == 0 {
		os.Remove(userDir)
	}

	return nil
}

// ListDevices returns all registered VPN devices across all users.
func (m *Manager) ListDevices() ([]VPNDevice, error) {
	usersDir := filepath.Join(m.baseDir, usersDirName)
	var devices []VPNDevice

	userEntries, err := os.ReadDir(usersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	for _, userEntry := range userEntries {
		if !userEntry.IsDir() {
			continue
		}
		userPath := filepath.Join(usersDir, userEntry.Name())
		deviceEntries, err := os.ReadDir(userPath)
		if err != nil {
			continue
		}
		for _, devEntry := range deviceEntries {
			if !devEntry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(userPath, devEntry.Name(), "device.yaml"))
			if err != nil {
				continue
			}
			var device VPNDevice
			yaml.Unmarshal(data, &device)
			devices = append(devices, device)
		}
	}
	return devices, nil
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
	devices, _ := m.ListDevices()
	used := map[string]bool{ServerIP: true}
	for _, d := range devices {
		used[d.IP] = true
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
	// Pure Go X25519 key generation via crypto/ecdh — no wg binary needed
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	privBytes := key.Bytes()
	pubBytes := key.PublicKey().Bytes()

	return base64.StdEncoding.EncodeToString(privBytes),
		base64.StdEncoding.EncodeToString(pubBytes), nil
}
