package daemon

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
)

// Pairing flow: new device shows a 6-digit code, trusted device or
// admin approves it at /2fa-gate/approve, new device's poll mints
// the device cookie. State lives in SQLite (pending_pairs table) so
// the proxy container can hold the live flow while the daemon
// container's admin pages process approvals — both read+write the
// same shared bailey.db file.

type pairingEntry struct {
	Email        string
	Code         string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	ApprovedBy   string
	ApproverInfo string
}

const pairingTTL = 5 * time.Minute

// Keeps mfa_pair.go compileable without removing its sync import
// (it's still used by other handlers in this file).
var _ = sync.Mutex{}

func generatePendingPair(email string) (*pairingEntry, error) {
	if err := dbPurgeExpiredPendingPairs(); err != nil {
		return nil, err
	}
	codeInt, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	e := &pairingEntry{
		Email:     email,
		Code:      fmt.Sprintf("%06d", codeInt.Int64()),
		IssuedAt:  now,
		ExpiresAt: now.Add(pairingTTL),
	}
	if err := dbUpsertPendingPair(e); err != nil {
		return nil, err
	}
	return e, nil
}

func approvePendingPair(email, code, approverEmail string, approverIsAdmin bool) *pairingEntry {
	e, err := dbLoadPendingPairByCode(code)
	if err != nil || e == nil {
		return nil
	}
	if e.Email != email || time.Now().After(e.ExpiresAt) {
		return nil
	}
	e.ApprovedBy = approverEmail
	if approverIsAdmin {
		e.ApproverInfo = approverEmail + " (admin)"
	} else {
		e.ApproverInfo = approverEmail
	}
	if err := dbUpsertPendingPair(e); err != nil {
		return nil
	}
	return e
}

func claimPendingPair(email string) *pairingEntry {
	e, err := dbLoadPendingPairByEmail(email)
	if err != nil || e == nil {
		return nil
	}
	if e.ApprovedBy == "" || time.Now().After(e.ExpiresAt) {
		return nil
	}
	_ = dbDeletePendingPairByEmail(email)
	return e
}

func visiblePendingRequests(approverEmail string, approverIsAdmin bool) []*pairingEntry {
	all, err := dbListPendingPairs()
	if err != nil {
		return nil
	}
	now := time.Now()
	out := []*pairingEntry{}
	for _, e := range all {
		if now.After(e.ExpiresAt) || e.ApprovedBy != "" {
			continue
		}
		if !approverIsAdmin && !strings.EqualFold(e.Email, approverEmail) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func pendingPairHandler(w http.ResponseWriter, r *http.Request, email string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	e, err := generatePendingPair(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, pendingPairHTML(email, e))
}

func pendingPairPollHandler(w http.ResponseWriter, r *http.Request, email string) {
	e := claimPendingPair(email)
	if e == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if _, err := completeNewDevicePairFor(w, r, email, e.ApproverInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// If the poller is an admin, also set the TOTP session cookie.
	// The pair approval came from a browser the same admin had
	// already paired (and that previous pairing required TOTP), so
	// the approver is effectively certifying both factors at once.
	// Without this the new browser would land back at /admin/challenge
	// immediately after redirecting, defeating the point of the
	// "punch a code into a trusted browser" flow.
	if _, groups := identityFromHeaders(r); isAdminGroups(groups) {
		_ = setSessionCookie(w, r, email)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"approved":      true,
		"approver":      e.ApproverInfo,
		"redirect_path": originRedirectPath(r),
	})
}

func approveHandler(w http.ResponseWriter, r *http.Request, approverEmail string) {
	approverIsAdmin := isAdmin(r)
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approveListHTML(approverEmail, approverIsAdmin, "", ""))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		targetEmail := strings.TrimSpace(r.FormValue("email"))
		code := strings.TrimSpace(r.FormValue("code"))
		if targetEmail == "" || code == "" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, approveListHTML(approverEmail, approverIsAdmin, targetEmail, "Both email and code are required."))
			return
		}
		if !strings.EqualFold(targetEmail, approverEmail) && !approverIsAdmin {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, approveListHTML(approverEmail, approverIsAdmin, targetEmail, "Only admins can approve a different user."))
			return
		}
		e := approvePendingPair(targetEmail, code, approverEmail, approverIsAdmin)
		if e == nil {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, approveListHTML(approverEmail, approverIsAdmin, targetEmail, "Code didn't match — ask them to read it back."))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approveListHTML(approverEmail, approverIsAdmin, "", "Approved "+targetEmail+"."))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleApprovePairJSON is the JSON variant of approveHandler. Used by
// the inline "Pair a new browser" form on /bailey/devices so the user
// stays on the page after approving — POSTing to the HTML handler would
// navigate to the full approvals page. Same rules: a non-admin can
// only approve their own pending pair; admins can approve anyone's.
func handleApprovePairJSON(w http.ResponseWriter, r *http.Request, approverEmail string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprint(w, `{"error":"POST required"}`)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	approverIsAdmin := isAdmin(r)
	targetEmail := strings.TrimSpace(r.FormValue("email"))
	code := strings.TrimSpace(r.FormValue("code"))
	if targetEmail == "" || code == "" {
		writeJSONError(w, "email and code required", http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(targetEmail, approverEmail) && !approverIsAdmin {
		writeJSONError(w, "only admins can approve a different user", http.StatusForbidden)
		return
	}
	e := approvePendingPair(targetEmail, code, approverEmail, approverIsAdmin)
	if e == nil {
		writeJSONError(w, "code didn't match", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"approved":%q}`, e.Email)
}

func completeNewDevicePairFor(w http.ResponseWriter, r *http.Request, email, approverInfo string) (*deviceRecord, error) {
	name := deviceNameFromRequest(r)
	if approverInfo != "" {
		name = name + " · approved by " + approverInfo
	}
	rec, err := addDevice(email, name)
	if err != nil {
		return nil, err
	}
	if err := setDeviceCookie(w, r, email, rec.ID); err != nil {
		return nil, err
	}
	return rec, nil
}

func originRedirectPath(r *http.Request) string {
	if c, err := r.Cookie(gateOriginCookie); err == nil && c.Value != "" {
		return c.Value
	}
	return "/"
}

func recoveryHandler(w http.ResponseWriter, r *http.Request, email string) {
	rec, err := loadTOTPRecord(email)
	if err != nil || rec == nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, errorBody(email, "TOTP recovery isn't set up for this account."))
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, recoveryFormHTML(email, ""))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		code := strings.TrimSpace(r.FormValue("code"))
		if !totp.Validate(code, rec.Secret) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, recoveryFormHTML(email, "Code didn't match — try again."))
			return
		}
		if _, err := completeNewDevicePairFor(w, r, email, "self via TOTP recovery"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		originRedirect(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func init() {
	handlePendingPair = pendingPairHandler
	handlePendingPairPoll = pendingPairPollHandler
	handleApprovePair = approveHandler
	handleRecovery = recoveryHandler
}

// --- HTML ---

func pendingPairHTML(email string, e *pairingEntry) string {
	body := fmt.Sprintf(`
<div style="text-align:center;padding:64px 24px;">
  <div style="margin-bottom:32px;">%s</div>
  <div style="font-size:72px;letter-spacing:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:300;color:#18181B;margin:8px 0;">%s</div>
  <p style="color:#71717A;font-size:14px;margin:24px 0 4px;">Read this code to an admin to trust this browser.</p>
  <p style="color:#A1A1AA;font-size:13px;margin:0;" id="status">Waiting for approval…</p>
</div>
<script>
async function poll() {
  try {
    const r = await fetch('%s/pending-pair/poll', {credentials:'same-origin'});
    if (r.status === 200) {
      const d = await r.json();
      document.getElementById('status').textContent = 'Approved. Redirecting…';
      setTimeout(() => { window.location = d.redirect_path || '/'; }, 600);
      return;
    }
  } catch (e) {}
  setTimeout(poll, 2000);
}
poll();
</script>
<meta http-equiv="refresh" content="%d">`,
		bitswanLogoSVG, html.EscapeString(e.Code),
		html.EscapeString(mfaGatePathPrefix), int(pairingTTL.Seconds()))
	_ = email
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Trust device</title>%s<style>%s
body { background:#FAFAFA; }</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}

func approveListHTML(approverEmail string, approverIsAdmin bool, errorForEmail, msgBanner string) string {
	pending := visiblePendingRequests(approverEmail, approverIsAdmin)
	adminBadge := ""
	if approverIsAdmin {
		adminBadge = ` <span style="color:#093DF5;font-weight:600;">(admin)</span>`
	}
	banner := ""
	if msgBanner != "" {
		banner = `<p class="note" style="color:#0a7d24;"><b>` + html.EscapeString(msgBanner) + `</b></p>`
	}
	rows := ""
	if len(pending) == 0 {
		rows = `<p class="note">No pending requests right now. This page auto-refreshes when one comes in.</p>`
	} else {
		var b strings.Builder
		for _, e := range pending {
			rowErr := ""
			if strings.EqualFold(errorForEmail, e.Email) {
				rowErr = `<p class="note" style="color:#b00020;margin:6px 0 0;"><b>Code didn't match — ask them to read it back.</b></p>`
			}
			age := int(time.Since(e.IssuedAt).Seconds())
			ageStr := fmt.Sprintf("%ds ago", age)
			if age >= 60 {
				ageStr = fmt.Sprintf("%dm %ds ago", age/60, age%60)
			}
			fmt.Fprintf(&b, `<div style="border:1px solid #E4E4E7;border-radius:8px;padding:16px;margin:12px 0;background:#fff;">
  <div style="display:flex;justify-content:space-between;align-items:baseline;">
    <div><b>%s</b></div>
    <div class="note">requested %s</div>
  </div>
  <form method="POST" action="%s/approve" style="margin-top:12px;display:flex;gap:8px;align-items:center;">
    <input type="hidden" name="email" value="%s">
    <label style="font-size:13px;color:#3F3F46;">Code shown on their device:</label>
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="off" required style="font-size:18px;letter-spacing:4px;padding:6px 8px;width:120px;">
    <button type="submit" style="background:#093DF5;color:white;border:0;padding:8px 16px;border-radius:4px;font-size:14px;cursor:pointer;">Approve</button>
  </form>
  %s
</div>`,
				html.EscapeString(e.Email), ageStr, html.EscapeString(mfaGatePathPrefix),
				html.EscapeString(e.Email), rowErr)
		}
		rows = b.String()
	}
	scope := "your own"
	if approverIsAdmin {
		scope = "any user's"
	}
	body := fmt.Sprintf(`
<div class="header">%s<h1>Pending device approvals</h1><a href="/bailey/" class="sign-out">← Bailey</a></div>
<div class="card">
  <p>Signed in as <code>%s</code>%s. You can approve %s pending device requests.</p>
  <p class="note">Ask the user to read the 6-digit code shown on their screen, type it below, and click Approve.</p>
  %s%s
</div>
<meta http-equiv="refresh" content="5">`,
		bitswanLogoSVG, html.EscapeString(approverEmail), adminBadge, scope, banner, rows)
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Approve devices</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}

func recoveryFormHTML(email, errMsg string) string {
	errBlock := ""
	if errMsg != "" {
		errBlock = `<p class="note" style="color:#b00020;"><b>` + html.EscapeString(errMsg) + `</b></p>`
	}
	body := fmt.Sprintf(`
<div class="header">%s<h1>Recover with authenticator</h1></div>
<div class="card">
  <p>Signed in as <code>%s</code>. Enter the 6-digit code from your authenticator app:</p>
  %s
  <form method="POST" action="%s/recovery">
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autofocus required style="font-size:18px;letter-spacing:4px;padding:6px 8px;width:120px;">
    <button type="submit" style="background:#093DF5;color:white;border:0;padding:8px 16px;margin-left:8px;border-radius:4px;font-size:14px;cursor:pointer;">Recover</button>
  </form>
</div>`,
		bitswanLogoSVG, html.EscapeString(email), errBlock, html.EscapeString(mfaGatePathPrefix))
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Recovery</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}

func errorBody(email, msg string) string {
	body := fmt.Sprintf(`
<div class="header">%s<h1>Trust device</h1></div>
<div class="card">
  <p style="color:#b00020;"><b>%s</b></p>
  <p>Signed in as <code>%s</code>.</p>
</div>`,
		bitswanLogoSVG, html.EscapeString(msg), html.EscapeString(email))
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Error</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}
