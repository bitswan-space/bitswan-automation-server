package daemon

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// Per-user paired-device records. A "device" here is a browser profile
// that the user has explicitly trusted on this automation server.
// Trust is proven by a long-lived HMAC-signed cookie (_bailey_device)
// carrying the device ID; revoking on the server side invalidates the
// cookie on the next request because the gate cross-references the ID
// against the user's on-disk device list.

const (
	deviceCookieName = "_bailey_device"
	deviceCookieAge  = 365 * 24 * time.Hour
	deviceIDLen      = 16 // hex chars; 64 bits of entropy
)

type deviceRecord struct {
	Email    string `json:"email,omitempty"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	PairedAt string `json:"paired_at"`
	LastSeen string `json:"last_seen,omitempty"`
}

// Thin wrappers that route through the SQLite store. Kept as
// separate functions so callers don't have to know about the store.
func anyDevicesExist() bool                                { return dbAnyDevicesExist() }
func listAllDevices() ([]deviceRecord, error)              { return dbListAllDevices() }
func loadDevices(email string) ([]deviceRecord, error)     { return dbListDevices(email) }
func addDevice(email, name string) (*deviceRecord, error)  { return dbAddDevice(email, name) }
func removeDevice(email, id string) error                  { return dbRemoveDevice(email, id) }
func findDevice(email, id string) (*deviceRecord, error)   { return dbFindDevice(email, id) }
func touchDevice(email, id string)                         { dbTouchDevice(email, id) }

// signedDeviceCookie packs (email, device_id, expiry) and HMACs them
// with the per-server signing key so a tampered cookie is rejected.
// Format: base64(email) . device_id . expiryUnix . hex(hmac).
func signedDeviceCookie(email, deviceID string, expiry time.Time) (string, error) {
	key, err := signingKey()
	if err != nil {
		return "", err
	}
	emailEnc := base64.RawURLEncoding.EncodeToString([]byte(email))
	expStr := strconv.FormatInt(expiry.Unix(), 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(emailEnc + "." + deviceID + "." + expStr))
	sig := hex.EncodeToString(mac.Sum(nil))
	return strings.Join([]string{emailEnc, deviceID, expStr, sig}, "."), nil
}

// verifyDeviceCookie returns the device ID + true iff cookieVal is a
// valid signature for email and not expired.
func verifyDeviceCookie(email, cookieVal string) (string, bool) {
	parts := strings.Split(cookieVal, ".")
	if len(parts) != 4 {
		return "", false
	}
	emailEnc, deviceID, expStr, sig := parts[0], parts[1], parts[2], parts[3]
	decoded, err := base64.RawURLEncoding.DecodeString(emailEnc)
	if err != nil || !strings.EqualFold(string(decoded), email) {
		return "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return "", false
	}
	key, err := signingKey()
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(emailEnc + "." + deviceID + "." + expStr))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
		return "", false
	}
	return deviceID, true
}

func setDeviceCookie(w http.ResponseWriter, r *http.Request, email, deviceID string) error {
	expiry := time.Now().Add(deviceCookieAge)
	val, err := signedDeviceCookie(email, deviceID, expiry)
	if err != nil {
		return err
	}
	c := &http.Cookie{
		Name:     deviceCookieName,
		Value:    val,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		// None (not Lax) so the cookie travels with iframe loads
		// inside the bailey chrome wrap. Lax skips iframe subresources,
		// which would make the gate-inside-iframe see no device cookie
		// and bounce to /pending-pair → redirect loop.
		SameSite: http.SameSiteNoneMode,
	}
	if dom := cookieDomainForProtected(); dom != "" {
		c.Domain = dom
	}
	http.SetCookie(w, c)
	return nil
}

func clearDeviceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: deviceCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
}

// cookieDomainForProtected returns ".<protected-domain>" so device
// cookies span every hostname under the operator's public suffix.
// Returns empty when the server has no public domain configured.
func cookieDomainForProtected() string {
	sc, err := config.NewAutomationServerConfig().LoadConfig()
	if err != nil || sc == nil {
		return ""
	}
	d := sc.ProtectedHostnameDomain()
	if d == "" || strings.HasSuffix(d, ".bswn.internal") {
		return ""
	}
	return "." + d
}

func currentDeviceForRequest(r *http.Request, email string) *deviceRecord {
	c, err := r.Cookie(deviceCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	id, ok := verifyDeviceCookie(email, c.Value)
	if !ok {
		return nil
	}
	rec, err := findDevice(email, id)
	if err != nil || rec == nil {
		return nil
	}
	return rec
}

// deviceNameFromRequest builds a default friendly name for a fresh
// device from User-Agent. Best-effort; the user can rename anytime.
func deviceNameFromRequest(r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	browser := "Browser"
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	os := ""
	switch {
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		os = " on macOS"
	case strings.Contains(ua, "Windows"):
		os = " on Windows"
	case strings.Contains(ua, "Linux"):
		os = " on Linux"
	case strings.Contains(ua, "Android"):
		os = " on Android"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		os = " on iOS"
	}
	return fmt.Sprintf("%s%s (%s)", browser, os, time.Now().UTC().Format("2006-01-02"))
}
