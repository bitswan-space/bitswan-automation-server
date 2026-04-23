package vpn

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	handshakeTimeout = 3 * time.Minute // no handshake for 3 min = offline
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
	PublicKey     string
	LastHandshake time.Time
	TransferRx   int64
	TransferTx   int64
	Connected    bool
}

// SessionMonitor watches for WireGuard handshakes via iptables log
// and enriches them with wg show data.
type SessionMonitor struct {
	manager    *Manager
	store      *SessionStore
	peerStates map[string]*PeerState // pubkey → state
	mu         sync.Mutex
	stopCh     chan struct{}
}

// NewSessionMonitor creates a monitor backed by SQLite in the VPN config dir.
func NewSessionMonitor(manager *Manager) *SessionMonitor {
	store, err := NewSessionStore(manager.baseDir)
	if err != nil {
		fmt.Printf("Warning: failed to open session store: %v\n", err)
	}
	return &SessionMonitor{
		manager:    manager,
		store:      store,
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
	// Seed initial state without emitting events — avoids false "connected"
	// entries on every daemon restart.
	sm.seedInitialState()

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

// seedInitialState loads persisted peer states from SQLite, then reconciles
// with the live wg show dump. No events are emitted — this silently
// establishes the baseline so the first real poll only logs actual changes.
func (sm *SessionMonitor) seedInitialState() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 1. Load last-known states from the database (survives restarts).
	if sm.store != nil {
		saved, err := sm.store.LoadPeerStates()
		if err == nil && len(saved) > 0 {
			sm.peerStates = saved
		}
	}

	// 2. Reconcile with live WireGuard state — update without emitting events.
	peers, err := sm.getWgShowDump()
	if err != nil {
		return
	}

	now := time.Now().UTC()
	for _, peer := range peers {
		isActive := !peer.LastHandshake.IsZero() && now.Sub(peer.LastHandshake) < handshakeTimeout

		existing, ok := sm.peerStates[peer.PublicKey]
		if !ok {
			existing = &PeerState{PublicKey: peer.PublicKey}
			sm.peerStates[peer.PublicKey] = existing
		}

		existing.LastHandshake = peer.LastHandshake
		existing.TransferRx = peer.TransferRx
		existing.TransferTx = peer.TransferTx
		existing.Connected = isActive

		if sm.store != nil {
			sm.store.SavePeerState(existing)
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
			sm.persistPeerState(sm.peerStates[peer.PublicKey])
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

		sm.persistPeerState(existing)
	}
}

// Stop shuts down the polling goroutine and closes the database.
func (sm *SessionMonitor) Stop() {
	close(sm.stopCh)
	if sm.store != nil {
		sm.store.Close()
	}
}

// Close releases the database connection without stopping the poll loop.
// Use for short-lived read-only monitors that were never Start()ed.
func (sm *SessionMonitor) Close() {
	if sm.store != nil {
		sm.store.Close()
	}
}

// GetActiveSessions returns currently connected devices.
// Reads from SQLite so it works even on throwaway read-only monitors.
func (sm *SessionMonitor) GetActiveSessions() []SessionEvent {
	// Try SQLite first (works for read-only monitors without a poll loop).
	if sm.store != nil {
		states, err := sm.store.LoadPeerStates()
		if err == nil {
			var active []SessionEvent
			for _, state := range states {
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
	}

	// Fallback to in-memory state (for the running monitor).
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

// GetSessionLog returns recent session events from the SQLite database.
func (sm *SessionMonitor) GetSessionLog(limit int) ([]SessionEvent, error) {
	if sm.store == nil {
		return nil, nil
	}
	return sm.store.GetRecentEvents(limit)
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

	// Persist to SQLite
	if sm.store != nil {
		if err := sm.store.InsertEvent(sessionEvent); err != nil {
			fmt.Printf("Warning: failed to persist session event: %v\n", err)
		}
	}
}

func (sm *SessionMonitor) persistPeerState(ps *PeerState) {
	if sm.store != nil {
		sm.store.SavePeerState(ps)
	}
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
