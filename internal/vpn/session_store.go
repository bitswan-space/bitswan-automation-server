package vpn

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const sessionDBFile = "sessions.db"

// SessionStore persists VPN session events and peer state in SQLite.
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore opens (or creates) the SQLite database in the VPN config dir.
func NewSessionStore(baseDir string) (*SessionStore, error) {
	os.MkdirAll(baseDir, 0700)
	dbPath := filepath.Join(baseDir, sessionDBFile)

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open session db: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate session db: %w", err)
	}

	return &SessionStore{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS session_events (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id   TEXT    NOT NULL DEFAULT '',
			user_id     TEXT    NOT NULL DEFAULT '',
			device_name TEXT    NOT NULL DEFAULT '',
			event       TEXT    NOT NULL,
			classified  BOOLEAN NOT NULL DEFAULT 0,
			timestamp   TEXT    NOT NULL,
			source_ip   TEXT    NOT NULL DEFAULT '',
			public_key  TEXT    NOT NULL,
			ip          TEXT    NOT NULL DEFAULT '',
			transfer_rx INTEGER NOT NULL DEFAULT 0,
			transfer_tx INTEGER NOT NULL DEFAULT 0
		);

		CREATE INDEX IF NOT EXISTS idx_events_timestamp ON session_events(timestamp);
		CREATE INDEX IF NOT EXISTS idx_events_pubkey    ON session_events(public_key);

		CREATE TABLE IF NOT EXISTS peer_states (
			public_key     TEXT PRIMARY KEY,
			last_handshake TEXT    NOT NULL DEFAULT '',
			transfer_rx    INTEGER NOT NULL DEFAULT 0,
			transfer_tx    INTEGER NOT NULL DEFAULT 0,
			connected      BOOLEAN NOT NULL DEFAULT 0
		);
	`)
	return err
}

// InsertEvent writes a session event to the database.
func (s *SessionStore) InsertEvent(ev SessionEvent) error {
	_, err := s.db.Exec(`
		INSERT INTO session_events
			(device_id, user_id, device_name, event, classified, timestamp, source_ip, public_key, ip, transfer_rx, transfer_tx)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.DeviceID, ev.UserID, ev.DeviceName, ev.Event, ev.Classified,
		ev.Timestamp, ev.SourceIP, ev.PublicKey, ev.IP, ev.TransferRx, ev.TransferTx,
	)
	return err
}

// GetRecentEvents returns the last `limit` session events, oldest first.
func (s *SessionStore) GetRecentEvents(limit int) ([]SessionEvent, error) {
	rows, err := s.db.Query(`
		SELECT device_id, user_id, device_name, event, classified, timestamp,
		       source_ip, public_key, ip, transfer_rx, transfer_tx
		FROM session_events
		ORDER BY id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SessionEvent
	for rows.Next() {
		var ev SessionEvent
		if err := rows.Scan(
			&ev.DeviceID, &ev.UserID, &ev.DeviceName, &ev.Event, &ev.Classified,
			&ev.Timestamp, &ev.SourceIP, &ev.PublicKey, &ev.IP, &ev.TransferRx, &ev.TransferTx,
		); err != nil {
			continue
		}
		events = append(events, ev)
	}

	// Reverse so oldest is first (we queried DESC for LIMIT efficiency)
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events, nil
}

// SavePeerState upserts the current state for a peer.
func (s *SessionStore) SavePeerState(ps *PeerState) error {
	hsStr := ""
	if !ps.LastHandshake.IsZero() {
		hsStr = ps.LastHandshake.Format(time.RFC3339)
	}
	_, err := s.db.Exec(`
		INSERT INTO peer_states (public_key, last_handshake, transfer_rx, transfer_tx, connected)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(public_key) DO UPDATE SET
			last_handshake = excluded.last_handshake,
			transfer_rx    = excluded.transfer_rx,
			transfer_tx    = excluded.transfer_tx,
			connected      = excluded.connected`,
		ps.PublicKey, hsStr, ps.TransferRx, ps.TransferTx, ps.Connected,
	)
	return err
}

// LoadPeerStates reads all persisted peer states from the database.
func (s *SessionStore) LoadPeerStates() (map[string]*PeerState, error) {
	rows, err := s.db.Query(`SELECT public_key, last_handshake, transfer_rx, transfer_tx, connected FROM peer_states`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	states := make(map[string]*PeerState)
	for rows.Next() {
		var ps PeerState
		var hsStr string
		if err := rows.Scan(&ps.PublicKey, &hsStr, &ps.TransferRx, &ps.TransferTx, &ps.Connected); err != nil {
			continue
		}
		if hsStr != "" {
			if t, err := time.Parse(time.RFC3339, hsStr); err == nil {
				ps.LastHandshake = t
			}
		}
		states[ps.PublicKey] = &ps
	}
	return states, nil
}

// Close closes the database.
func (s *SessionStore) Close() error {
	return s.db.Close()
}
