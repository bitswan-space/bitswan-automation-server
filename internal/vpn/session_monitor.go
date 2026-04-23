package vpn

import (
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
	Event      string `json:"event"` // "handshake", "connected", "disconnected", "unclassified"
	Classified bool   `json:"classified"` // false = could not match to a known device
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
// Polls wg show dump every 30 seconds to detect connect/disconnect events.
func (sm *SessionMonitor) Start() error {
	// Ensure iptables LOG rule exists (for handshake counting, not tailing)
	sm.ensureIptablesRule()

	// Single goroutine: poll wg show dump, detect state changes, emit events
	go sm.pollLoop()

	return nil
}

func (sm *SessionMonitor) pollLoop() {
	// Initial poll immediately
	sm.pollPeerStates()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sm.stopCh:
			return
		case <-ticker.C:
			sm.pollPeerStates()
		}
	}
}

func (sm *SessionMonitor) pollPeerStates() {
	peers, err := sm.getWgShowDump()
	if err != nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now().UTC()

	for _, peer := range peers {
		existing, ok := sm.peerStates[peer.PublicKey]

		isActive := !peer.LastHandshake.IsZero() && now.Sub(peer.LastHandshake) < handshakeTimeout

		if !ok {
			// New peer
			sm.peerStates[peer.PublicKey] = &PeerState{
				PublicKey:     peer.PublicKey,
				LastHandshake: peer.LastHandshake,
				TransferRx:   peer.TransferRx,
				TransferTx:   peer.TransferTx,
				Connected:    isActive,
			}
			if isActive {
				sm.emitEvent(peer.PublicKey, "connected", "", peer.TransferRx, peer.TransferTx)
			}
			continue
		}

		// Detect state changes
		wasConnected := existing.Connected

		if isActive && !wasConnected {
			// Came online
			existing.Connected = true
			sm.emitEvent(peer.PublicKey, "connected", "", peer.TransferRx, peer.TransferTx)
		} else if !isActive && wasConnected {
			// Went offline
			existing.Connected = false
			sm.emitEvent(peer.PublicKey, "disconnected", "", existing.TransferRx, existing.TransferTx)
		}

		// Update state
		existing.LastHandshake = peer.LastHandshake
		existing.TransferRx = peer.TransferRx
		existing.TransferTx = peer.TransferTx
	}
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

// Removed: tailKernelLog, onHandshakeDetected, disconnectChecker
// Replaced by pollLoop + pollPeerStates which uses wg show dump directly.

func (sm *SessionMonitor) emitEvent(publicKey, event, sourceIP string, rx, tx int64) {
	device := sm.lookupDevice(publicKey)

	sessionEvent := SessionEvent{
		Event:      event,
		Classified: device != nil,
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
