package daemon

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// bailey_store.go owns the daemon's persistent SQLite database at
// ~/.config/bitswan/bailey.db. Today the schema holds MFA state (TOTP
// records, paired devices, the per-server HMAC signing key); future
// server-wide state can land here too.
//
// One file, one bind-mount; survives daemon container restarts because
// the parent ~/.config/bitswan is already a persistent volume.

var (
	baileyDBOnce sync.Once
	baileyDB     *sql.DB
	baileyDBErr  error
)

const baileySchema = `
CREATE TABLE IF NOT EXISTS totp_records (
  email      TEXT PRIMARY KEY COLLATE NOCASE,
  secret     TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id         TEXT PRIMARY KEY,
  email      TEXT NOT NULL COLLATE NOCASE,
  name       TEXT NOT NULL,
  paired_at  TEXT NOT NULL,
  last_seen  TEXT
);
CREATE INDEX IF NOT EXISTS devices_email_idx ON devices(email);

CREATE TABLE IF NOT EXISTS singletons (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
);

-- Per-endpoint ACL. One row per protected hostname; owner is the user
-- who created the endpoint (the workspace creator for editor/gitops,
-- the deployer for automations, the server registrant for bailey-admin).
CREATE TABLE IF NOT EXISTS endpoints (
  hostname     TEXT PRIMARY KEY COLLATE NOCASE,
  owner_email  TEXT NOT NULL COLLATE NOCASE,
  display_name TEXT,
  created_at   TEXT NOT NULL
);

-- Grants attached to an endpoint. principal_type is 'email' or 'group';
-- principal_value is the email address or Keycloak group path. role is
-- 'owner' or 'access'. The endpoint row in endpoints records the
-- original owner directly; additional owners go here.
CREATE TABLE IF NOT EXISTS endpoint_grants (
  endpoint_host  TEXT NOT NULL COLLATE NOCASE,
  principal_type TEXT NOT NULL CHECK (principal_type IN ('email','group')),
  principal_value TEXT NOT NULL COLLATE NOCASE,
  role           TEXT NOT NULL CHECK (role IN ('owner','access')),
  granted_at     TEXT NOT NULL,
  granted_by     TEXT NOT NULL COLLATE NOCASE,
  PRIMARY KEY (endpoint_host, principal_type, principal_value, role),
  FOREIGN KEY (endpoint_host) REFERENCES endpoints(hostname) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS endpoint_grants_host_idx ON endpoint_grants(endpoint_host);

-- Pending access requests from users who hit an endpoint they don't
-- have access to. Owner sees these in the share UI and can approve.
CREATE TABLE IF NOT EXISTS access_requests (
  endpoint_host TEXT NOT NULL COLLATE NOCASE,
  email         TEXT NOT NULL COLLATE NOCASE,
  requested_at  TEXT NOT NULL,
  PRIMARY KEY (endpoint_host, email),
  FOREIGN KEY (endpoint_host) REFERENCES endpoints(hostname) ON DELETE CASCADE
);
`

// baileyDBPath returns the absolute on-disk location of the daemon's
// SQLite database.
func baileyDBPath() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "bailey.db")
}

// openBaileyDB lazily opens (and on first call, creates) the DB.
// Safe to call from multiple goroutines.
func openBaileyDB() (*sql.DB, error) {
	baileyDBOnce.Do(func() {
		if err := os.MkdirAll(filepath.Dir(baileyDBPath()), 0o755); err != nil {
			baileyDBErr = fmt.Errorf("mkdir bailey config dir: %w", err)
			return
		}
		dsn := baileyDBPath() + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			baileyDBErr = fmt.Errorf("open sqlite: %w", err)
			return
		}
		db.SetMaxOpenConns(1)
		if _, err := db.Exec(baileySchema); err != nil {
			db.Close()
			baileyDBErr = fmt.Errorf("apply schema: %w", err)
			return
		}
		baileyDB = db
	})
	return baileyDB, baileyDBErr
}

// --- TOTP record ops ---

func dbLoadTOTP(email string) (*totpRecord, error) {
	db, err := openBaileyDB()
	if err != nil {
		return nil, err
	}
	var rec totpRecord
	row := db.QueryRow(
		`SELECT email, secret, created_at FROM totp_records WHERE email = ? COLLATE NOCASE`, email)
	if err := row.Scan(&rec.Email, &rec.Secret, &rec.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return &rec, nil
}

func dbSaveTOTP(rec *totpRecord) error {
	db, err := openBaileyDB()
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO totp_records(email, secret, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at`,
		rec.Email, rec.Secret, rec.CreatedAt)
	return err
}

func dbDeleteTOTP(email string) error {
	db, err := openBaileyDB()
	if err != nil {
		return err
	}
	_, err = db.Exec(`DELETE FROM totp_records WHERE email = ? COLLATE NOCASE`, email)
	return err
}

// --- Device ops ---

// dbListTOTPEnrolledEmails returns the set of emails with TOTP set up.
func dbListTOTPEnrolledEmails() (map[string]bool, error) {
	db, err := openBaileyDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT email FROM totp_records`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out[strings.ToLower(e)] = true
	}
	return out, rows.Err()
}

// dbListAllDevices returns every paired device on the server,
// ordered first by email and then by paired_at. Used by the admin
// Devices page to render the per-user device tree.
func dbListAllDevices() ([]deviceRecord, error) {
	db, err := openBaileyDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(
		`SELECT email, id, name, paired_at, COALESCE(last_seen, '') FROM devices ORDER BY email COLLATE NOCASE, paired_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []deviceRecord
	for rows.Next() {
		var d deviceRecord
		if err := rows.Scan(&d.Email, &d.ID, &d.Name, &d.PairedAt, &d.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func dbListDevices(email string) ([]deviceRecord, error) {
	db, err := openBaileyDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(
		`SELECT id, name, paired_at, COALESCE(last_seen, '') FROM devices WHERE email = ? COLLATE NOCASE ORDER BY paired_at`,
		email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []deviceRecord
	for rows.Next() {
		var d deviceRecord
		if err := rows.Scan(&d.ID, &d.Name, &d.PairedAt, &d.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func dbAddDevice(email, name string) (*deviceRecord, error) {
	db, err := openBaileyDB()
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, deviceIDLen/2)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	if strings.TrimSpace(name) == "" {
		name = "Device added " + time.Now().UTC().Format("2006-01-02")
	}
	rec := deviceRecord{
		ID:       hex.EncodeToString(idBytes),
		Name:     name,
		PairedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if _, err := db.Exec(
		`INSERT INTO devices(id, email, name, paired_at) VALUES (?, ?, ?, ?)`,
		rec.ID, email, rec.Name, rec.PairedAt); err != nil {
		return nil, err
	}
	return &rec, nil
}

func dbRemoveDevice(email, id string) error {
	db, err := openBaileyDB()
	if err != nil {
		return err
	}
	_, err = db.Exec(`DELETE FROM devices WHERE id = ? AND email = ? COLLATE NOCASE`, id, email)
	return err
}

func dbFindDevice(email, id string) (*deviceRecord, error) {
	db, err := openBaileyDB()
	if err != nil {
		return nil, err
	}
	var d deviceRecord
	row := db.QueryRow(
		`SELECT id, name, paired_at, COALESCE(last_seen, '') FROM devices WHERE id = ? AND email = ? COLLATE NOCASE`,
		id, email)
	if err := row.Scan(&d.ID, &d.Name, &d.PairedAt, &d.LastSeen); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &d, nil
}

func dbTouchDevice(email, id string) {
	db, err := openBaileyDB()
	if err != nil {
		return
	}
	_, _ = db.Exec(`UPDATE devices SET last_seen = ? WHERE id = ? AND email = ? COLLATE NOCASE`,
		time.Now().UTC().Format(time.RFC3339), id, email)
}

func dbAnyDevicesExist() bool {
	db, err := openBaileyDB()
	if err != nil {
		return false
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&n)
	return n > 0
}

// --- Signing key ---

func dbSigningKey() ([]byte, error) {
	db, err := openBaileyDB()
	if err != nil {
		return nil, err
	}
	var key []byte
	row := db.QueryRow(`SELECT value FROM singletons WHERE key = 'signing_key'`)
	if err := row.Scan(&key); err == nil && len(key) >= 32 {
		return key, nil
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	if _, err := db.Exec(
		`INSERT INTO singletons(key, value) VALUES ('signing_key', ?) ON CONFLICT(key) DO NOTHING`,
		buf); err != nil {
		return nil, err
	}
	if err := db.QueryRow(`SELECT value FROM singletons WHERE key = 'signing_key'`).Scan(&key); err != nil {
		return nil, err
	}
	return key, nil
}
