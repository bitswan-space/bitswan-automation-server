package daemon

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CRUD on the server_settings table. Used today for the default
// container images the bailey admin Updates page configures; the
// schema is intentionally generic key/value so future settings don't
// need their own table.

// Well-known setting keys. Centralised here so call sites can't
// silently drift on spelling.
const (
	settingDefaultGitopsImage    = "default_gitops_image"
	settingDefaultDashboardImage = "default_dashboard_image"
)

// dbGetSetting returns ("", nil) when the key is absent — distinguish
// from genuine read errors via the second return value.
func dbGetSetting(key string) (string, error) {
	db, err := openBaileyDB()
	if err != nil {
		return "", err
	}
	var value string
	err = db.QueryRow(`SELECT value FROM server_settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get setting %q: %w", key, err)
	}
	return value, nil
}

// dbSetSetting writes (or replaces) a setting and records who set it.
func dbSetSetting(key, value, updatedBy string) error {
	db, err := openBaileyDB()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec(`INSERT INTO server_settings(key, value, updated_at, updated_by)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at,
			updated_by = excluded.updated_by`,
		key, value, now, updatedBy,
	)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

// dbDeleteSetting removes a key. Used when the admin clears an
// override and wants to fall back to the Docker Hub lookup.
func dbDeleteSetting(key string) error {
	db, err := openBaileyDB()
	if err != nil {
		return err
	}
	_, err = db.Exec(`DELETE FROM server_settings WHERE key = ?`, key)
	if err != nil {
		return fmt.Errorf("delete setting %q: %w", key, err)
	}
	return nil
}

// settingRecord is what /bailey/api/admin/default-images returns for
// each image so the admin UI can show who set it last + when.
type settingRecord struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
}

func dbGetSettingRecord(key string) (*settingRecord, error) {
	db, err := openBaileyDB()
	if err != nil {
		return nil, err
	}
	var rec settingRecord
	rec.Key = key
	err = db.QueryRow(`SELECT value, updated_at, updated_by FROM server_settings WHERE key = ?`, key).
		Scan(&rec.Value, &rec.UpdatedAt, &rec.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get setting record %q: %w", key, err)
	}
	return &rec, nil
}
