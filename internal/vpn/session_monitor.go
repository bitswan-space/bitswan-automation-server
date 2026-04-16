package vpn

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	handshakeTimeout = 3 * time.Minute // no handshake for 3 min = offline
	sessionLogFile   = "sessions.jsonl"
	iptablesPrefix   = "WG-HANDSHAKE: "
)

// SessionEvent represents a single enriched VPN session event.
type SessionEvent struct {
	DeviceID   string `json:"device_id"`
	UserID     string `json:"user_id"`
	DeviceName string `json:"device_name"`
	Event      string `json:"event"` // "handshake", "connected", "disconnected"
	Timestamp  string `json:"timestamp"`
	SourceIP   string `json:"source_ip,omitempty"`
	PublicKey  string `json:"public_key"`
	IP         string `json:"ip"`
	TransferRx int64  `json:"transfer_rx"`
	TransferTx int64  `json:"transfer_tx"`
}

// PeerState tracks the last known state of a WireGuard peer.
type PeerState struct {
	PublicKey      string
	LastHandshake  time.Time
	TransferRx    int64
	TransferTx    int64
	Connected     bool
}

// SessionMonitor watches for WireGuard handshakes via iptables log
// and enriches them with wg show data.
type SessionMonitor struct {
	manager    *Manager
	logPath    string // path to sessions.jsonl
	peerStates map[string]*PeerState // pubkey → state
	mu         sync.Mutex
	stopCh     chan struct{}
}

// NewSessionMonitor creates a monitor that writes to the VPN config dir.
func NewSessionMonitor(manager *Manager) *SessionMonitor {
	return &SessionMonitor{
		manager:    manager,
		logPath:    filepath.Join(manager.baseDir, sessionLogFile),
		peerStates: make(map[string]*PeerState),
		stopCh:     make(chan struct{}),
	}
}

// Start begins monitoring. Call in a goroutine.
// It sets up the iptables rule, tails the kernel log, and enriches events.
func (sm *SessionMonitor) Start() error {
	// Ensure iptables LOG rule exists
	if err := sm.ensureIptablesRule(); err != nil {
		return fmt.Errorf("failed to set up iptables logging: %w", err)
	}

	// Start two goroutines:
	// 1. Tail kernel log for handshake packets → trigger enrichment
	// 2. Periodic disconnect checker (detect peers that went silent)
	go sm.tailKernelLog()
	go sm.disconnectChecker()

	return nil
}

// Stop shuts down the monitor.
func (sm *SessionMonitor) Stop() {
	close(sm.stopCh)
}

// GetActiveSessions returns currently connected devices.
func (sm *SessionMonitor) GetActiveSessions() []SessionEvent {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var active []SessionEvent
	for _, state := range sm.peerStates {
		if !state.Connected {
			continue
		}
		device := sm.lookupDevice(state.PublicKey)
		if device == nil {
			continue
		}
		active = append(active, SessionEvent{
			DeviceID:   device.DeviceID,
			UserID:     device.UserID,
			DeviceName: device.DeviceName,
			Event:      "active",
			Timestamp:  state.LastHandshake.Format(time.RFC3339),
			PublicKey:  state.PublicKey,
			IP:         device.IP,
			TransferRx: state.TransferRx,
			TransferTx: state.TransferTx,
		})
	}
	return active
}

// GetSessionLog returns recent session events from the log file.
func (sm *SessionMonitor) GetSessionLog(limit int) ([]SessionEvent, error) {
	data, err := os.ReadFile(sm.logPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var events []SessionEvent
	for _, line := range lines {
		if line == "" {
			continue
		}
		var event SessionEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		events = append(events, event)
	}

	// Return last N events
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

// --- Internal ---

func (sm *SessionMonitor) ensureIptablesRule() error {
	// Check if rule already exists
	check := exec.Command("docker", "exec", "wireguard",
		"iptables", "-C", "INPUT", "-p", "udp", "--dport", "51820",
		"-j", "LOG", "--log-prefix", iptablesPrefix)
	if check.Run() == nil {
		return nil // already exists
	}

	// Add the rule
	add := exec.Command("docker", "exec", "wireguard",
		"iptables", "-A", "INPUT", "-p", "udp", "--dport", "51820",
		"-j", "LOG", "--log-prefix", iptablesPrefix)
	out, err := add.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

func (sm *SessionMonitor) tailKernelLog() {
	// Tail the kernel log from the wireguard container
	cmd := exec.Command("docker", "exec", "wireguard",
		"tail", "-n", "0", "-F", "/proc/kmsg")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "session monitor: failed to tail kernel log: %v\n", err)
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "session monitor: failed to start tail: %v\n", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-sm.stopCh:
			cmd.Process.Kill()
			return
		default:
		}

		line := scanner.Text()
		if !strings.Contains(line, iptablesPrefix) {
			continue
		}

		// Extract source IP from iptables log line
		sourceIP := extractSourceIP(line)

		// Handshake detected — enrich with wg show
		sm.onHandshakeDetected(sourceIP)
	}
}

func (sm *SessionMonitor) onHandshakeDetected(sourceIP string) {
	// Run wg show to get current peer states
	peers, err := sm.getWgShowDump()
	if err != nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now().UTC()

	for _, peer := range peers {
		existing, ok := sm.peerStates[peer.PublicKey]

		if !ok {
			// New peer
			sm.peerStates[peer.PublicKey] = &PeerState{
				PublicKey:     peer.PublicKey,
				LastHandshake: peer.LastHandshake,
				TransferRx:   peer.TransferRx,
				TransferTx:   peer.TransferTx,
				Connected:    !peer.LastHandshake.IsZero(),
			}
			if !peer.LastHandshake.IsZero() {
				sm.emitEvent(peer.PublicKey, "connected", sourceIP, peer.TransferRx, peer.TransferTx)
			}
			continue
		}

		// Check if handshake timestamp changed (new handshake)
		if peer.LastHandshake.After(existing.LastHandshake) {
			wasConnected := existing.Connected
			existing.LastHandshake = peer.LastHandshake
			existing.TransferRx = peer.TransferRx
			existing.TransferTx = peer.TransferTx
			existing.Connected = true

			if !wasConnected {
				sm.emitEvent(peer.PublicKey, "connected", sourceIP, peer.TransferRx, peer.TransferTx)
			}
			sm.emitEvent(peer.PublicKey, "handshake", sourceIP, peer.TransferRx, peer.TransferTx)
		}

		// Update transfer counters regardless
		existing.TransferRx = peer.TransferRx
		existing.TransferTx = peer.TransferTx
		_ = now
	}
}

func (sm *SessionMonitor) disconnectChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopCh:
			return
		case <-ticker.C:
			sm.checkDisconnects()
		}
	}
}

func (sm *SessionMonitor) checkDisconnects() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now().UTC()
	for pubkey, state := range sm.peerStates {
		if state.Connected && now.Sub(state.LastHandshake) > handshakeTimeout {
			state.Connected = false
			sm.emitEvent(pubkey, "disconnected", "", state.TransferRx, state.TransferTx)
		}
	}
}

func (sm *SessionMonitor) emitEvent(publicKey, event, sourceIP string, rx, tx int64) {
	device := sm.lookupDevice(publicKey)

	sessionEvent := SessionEvent{
		Event:      event,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		SourceIP:   sourceIP,
		PublicKey:  publicKey,
		TransferRx: rx,
		TransferTx: tx,
	}
	if device != nil {
		sessionEvent.DeviceID = device.DeviceID
		sessionEvent.UserID = device.UserID
		sessionEvent.DeviceName = device.DeviceName
		sessionEvent.IP = device.IP
	}

	// Append to JSONL log
	data, _ := json.Marshal(sessionEvent)
	f, err := os.OpenFile(sm.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(data)
	f.WriteString("\n")
}

func (sm *SessionMonitor) lookupDevice(publicKey string) *VPNDevice {
	devices, _ := sm.manager.ListDevices()
	for _, d := range devices {
		if d.PublicKey == publicKey {
			return &d
		}
	}
	return nil
}

// wgPeer represents a peer from `wg show dump` output.
type wgPeer struct {
	PublicKey     string
	LastHandshake time.Time
	TransferRx   int64
	TransferTx   int64
}

func (sm *SessionMonitor) getWgShowDump() ([]wgPeer, error) {
	cmd := exec.Command("docker", "exec", "wireguard", "wg", "show", "wg0", "dump")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var peers []wgPeer
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // skip header (interface line)
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		// Fields: public_key, preshared_key, endpoint, allowed_ips, latest_handshake, transfer_rx, transfer_tx
		var handshakeTime time.Time
		if ts := fields[4]; ts != "0" {
			var epoch int64
			fmt.Sscanf(ts, "%d", &epoch)
			if epoch > 0 {
				handshakeTime = time.Unix(epoch, 0).UTC()
			}
		}
		var rx, tx int64
		fmt.Sscanf(fields[5], "%d", &rx)
		fmt.Sscanf(fields[6], "%d", &tx)

		peers = append(peers, wgPeer{
			PublicKey:     fields[0],
			LastHandshake: handshakeTime,
			TransferRx:   rx,
			TransferTx:   tx,
		})
	}
	return peers, nil
}

func extractSourceIP(logLine string) string {
	// iptables LOG format: ... SRC=1.2.3.4 DST=...
	if idx := strings.Index(logLine, "SRC="); idx >= 0 {
		rest := logLine[idx+4:]
		if end := strings.IndexByte(rest, ' '); end >= 0 {
			return rest[:end]
		}
		return rest
	}
	return ""
}
