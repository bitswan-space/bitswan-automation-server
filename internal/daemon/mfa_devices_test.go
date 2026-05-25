package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Device-cookie verification is the gate that decides whether a
// returning browser bypasses TOTP. The user-facing contract is "trust
// once, forever, until revoked from /bailey/devices" — pinning that
// contract means asserting that a cookie issued years ago still
// verifies as long as the HMAC matches.

// withTmpBaileyDB is shared with other bailey-DB tests in this
// package; declared here so this file compiles on its own. Sets HOME
// to a temp dir so openBaileyDB writes to t.TempDir() instead of
// clobbering the real bailey.db.
func withTmpBaileyDB(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".config", "bitswan"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
}

func TestVerifyDeviceCookie_FreshSignatureRoundTrip(t *testing.T) {
	withTmpBaileyDB(t)
	const email = "alice@example.com"
	const deviceID = "abcdef0123456789"
	val, err := signedDeviceCookie(email, deviceID, time.Now())
	if err != nil {
		t.Fatalf("signedDeviceCookie: %v", err)
	}
	got, ok := verifyDeviceCookie(email, val)
	if !ok {
		t.Fatalf("verifyDeviceCookie returned ok=false for a fresh cookie")
	}
	if got != deviceID {
		t.Errorf("device ID round-trip: got %q want %q", got, deviceID)
	}
}

func TestVerifyDeviceCookie_IssuedYearsAgoStillValid(t *testing.T) {
	// The whole point of dropping the TTL: a cookie issued long ago
	// MUST still verify as long as the HMAC checks out. This is the
	// regression guard against accidentally re-introducing the old
	// time.Now().Unix() >= exp check.
	withTmpBaileyDB(t)
	const email = "alice@example.com"
	const deviceID = "abcdef0123456789"
	old := time.Now().AddDate(-5, 0, 0) // 5 years ago
	val, err := signedDeviceCookie(email, deviceID, old)
	if err != nil {
		t.Fatalf("signedDeviceCookie: %v", err)
	}
	if _, ok := verifyDeviceCookie(email, val); !ok {
		t.Errorf("cookie issued 5 years ago should still verify; trust lives in the device DB, not the cookie")
	}
}

func TestVerifyDeviceCookie_RejectsTamperedSignature(t *testing.T) {
	withTmpBaileyDB(t)
	const email = "alice@example.com"
	const deviceID = "abcdef0123456789"
	val, err := signedDeviceCookie(email, deviceID, time.Now())
	if err != nil {
		t.Fatalf("signedDeviceCookie: %v", err)
	}
	// Flip the last hex char of the signature.
	last := val[len(val)-1]
	if last == 'a' {
		val = val[:len(val)-1] + "b"
	} else {
		val = val[:len(val)-1] + "a"
	}
	if _, ok := verifyDeviceCookie(email, val); ok {
		t.Errorf("tampered signature must NOT verify")
	}
}

func TestVerifyDeviceCookie_RejectsWrongEmail(t *testing.T) {
	withTmpBaileyDB(t)
	val, err := signedDeviceCookie("alice@example.com", "abcdef0123456789", time.Now())
	if err != nil {
		t.Fatalf("signedDeviceCookie: %v", err)
	}
	if _, ok := verifyDeviceCookie("bob@example.com", val); ok {
		t.Errorf("cookie bound to alice must NOT verify for bob")
	}
}
