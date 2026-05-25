package daemon

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"html"
	"image/png"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// /2fa-gate/account/* — self-service pages where a signed-in user can
// see their paired devices and (admin only) enrol in TOTP. We keep the
// pages minimal and stitched into the same chrome-and-CSS that the
// bailey uses so they feel like one site.

func accountDevicesHandler(w http.ResponseWriter, r *http.Request, email string) {
	switch r.Method {
	case http.MethodGet:
		devs, _ := loadDevices(email)
		current := currentDeviceForRequest(r, email)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, accountDevicesHTML(email, devs, current))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		action := strings.TrimSpace(r.FormValue("action"))
		id := strings.TrimSpace(r.FormValue("id"))
		switch action {
		case "remove":
			if id == "" {
				http.Error(w, "id required", http.StatusBadRequest)
				return
			}
			if err := removeDevice(email, id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, mfaGatePathPrefix+"/account/devices", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

const accountEnrolCookieName = "_bailey_account_enroll"

// accountTOTPHandler serves /2fa-gate/account/2fa.
//
//   - GET when no record exists: mint a candidate secret in a path-scoped
//     cookie and render the QR + form. Reload preserves the cookie so a
//     refresh doesn't silently invalidate the user's authenticator entry.
//   - GET when a record exists: render the "you're enrolled, here's the
//     disable button" landing.
//   - POST action=enroll: validate the 6-digit code against the cookie's
//     candidate secret, persist the TOTP record, drop the cookie.
//   - POST action=disable: tear down the record (admins only, since
//     non-admin TOTP is the recovery they opted into).
func accountTOTPHandler(w http.ResponseWriter, r *http.Request, email string) {
	admin := isAdmin(r)
	switch r.Method {
	case http.MethodGet:
		rec, _ := loadTOTPRecord(email)
		if rec != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, accountTOTPStatusHTML(email, admin, rec))
			return
		}
		secret := candidateSecretForAccount(w, r, email)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, accountTOTPEnrollHTML(email, secret, ""))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch strings.TrimSpace(r.FormValue("action")) {
		case "enroll":
			c, err := r.Cookie(accountEnrolCookieName)
			if err != nil || c.Value == "" {
				http.Error(w, "enrolment session expired — reload and try again", http.StatusBadRequest)
				return
			}
			code := strings.TrimSpace(r.FormValue("code"))
			if !totp.Validate(code, c.Value) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, accountTOTPEnrollHTML(email, c.Value, "Code didn't match — check your authenticator and try again."))
				return
			}
			if err := saveTOTPRecord(&totpRecord{
				Email:     email,
				Secret:    c.Value,
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: accountEnrolCookieName, Value: "", Path: mfaGatePathPrefix + "/account/2fa", MaxAge: -1})
			http.Redirect(w, r, safeReturnTo(r.FormValue("return_to"), mfaGatePathPrefix+"/account/2fa"), http.StatusSeeOther)
		case "disable":
			if !admin {
				http.Error(w, "admins only", http.StatusForbidden)
				return
			}
			if err := dbDeleteTOTP(email); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, safeReturnTo(r.FormValue("return_to"), mfaGatePathPrefix+"/account/2fa"), http.StatusSeeOther)
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// candidateSecretForAccount returns the candidate TOTP secret to show
// on the enrol page. Reuses the cookie value if one is already set so
// the QR (and the authenticator entry the user just scanned) survive a
// reload. See mfa_totp.go for the same trick on the admin enrol path.
func candidateSecretForAccount(w http.ResponseWriter, r *http.Request, email string) string {
	if c, err := r.Cookie(accountEnrolCookieName); err == nil && c.Value != "" {
		if _, derr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(c.Value); derr == nil {
			return c.Value
		}
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuerName(),
		AccountName: email,
	})
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     accountEnrolCookieName,
		Value:    key.Secret(),
		Path:     mfaGatePathPrefix + "/account/2fa",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteNoneMode,
	})
	return key.Secret()
}

func init() {
	handleAccountDevices = accountDevicesHandler
	handleAccountTOTP = accountTOTPHandler
}

// safeReturnTo restricts open-redirect risk: only allow same-origin
// paths that start with a single '/' (no '//', no scheme). Anything
// else falls back to fallback. Used by the TOTP flow's return_to
// param so the inlined section on /bailey/devices can be redirected
// back there after enrol/disable.
func safeReturnTo(candidate, fallback string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return fallback
	}
	if !strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "//") {
		return fallback
	}
	return candidate
}

// renderTOTPInlineHTML returns just the inner section markup for the
// TOTP enrol / status flow, suitable for splicing into another page
// (specifically the merged /bailey/devices). When called during a GET
// it may set the candidate-secret cookie via w, same as
// accountTOTPHandler does — keep the call site at the route handler
// where (w, r) are in scope, NOT inside vpnInternalPage's render.
//
// returnTo is appended to the form POST as ?return_to=<path> so
// accountTOTPHandler can land the user back on the inlined page
// after enrol/disable instead of the standalone /2fa-gate page.
func renderTOTPInlineHTML(w http.ResponseWriter, r *http.Request, email string, admin bool, returnTo string) string {
	rec, _ := loadTOTPRecord(email)
	if rec != nil {
		return inlineTOTPStatusHTML(email, admin, returnTo)
	}
	secret := candidateSecretForAccount(w, r, email)
	return inlineTOTPEnrollHTML(email, secret, "", returnTo)
}

func inlineTOTPStatusHTML(email string, admin bool, returnTo string) string {
	cta := ""
	if admin {
		rt := ""
		if returnTo != "" {
			rt = fmt.Sprintf(`<input type="hidden" name="return_to" value="%s">`, html.EscapeString(returnTo))
		}
		cta = fmt.Sprintf(`<form method="POST" action="%s/account/2fa" onsubmit="return confirm('Disable TOTP? You will lose authenticator-based recovery.');" style="margin-top:8px;">
  <input type="hidden" name="action" value="disable">
  %s
  <button type="submit" style="color:#b00020;background:none;border:1px solid #b00020;padding:6px 12px;border-radius:4px;cursor:pointer;">Disable TOTP</button>
</form>`, html.EscapeString(mfaGatePathPrefix), rt)
	}
	return fmt.Sprintf(`<p>Your account has TOTP enabled. You can use your authenticator app to recover a device on a fresh browser.</p>%s`, cta)
}

func inlineTOTPEnrollHTML(email, secret, errMsg, returnTo string) string {
	errBlock := ""
	if errMsg != "" {
		errBlock = `<p class="note" style="color:#b00020;"><b>` + html.EscapeString(errMsg) + `</b></p>`
	}
	qrDataURL := ""
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if key, kerr := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuerName(),
		AccountName: email,
		Secret:      raw,
	}); kerr == nil {
		if img, ierr := key.Image(220, 220); ierr == nil {
			var buf bytes.Buffer
			if png.Encode(&buf, img) == nil {
				qrDataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
			}
		}
	}
	rt := ""
	if returnTo != "" {
		rt = fmt.Sprintf(`<input type="hidden" name="return_to" value="%s">`, html.EscapeString(returnTo))
	}
	return fmt.Sprintf(`
<p>Scan with an authenticator app and enter the 6-digit code:</p>
<div style="display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap;">
  <img alt="TOTP QR" src="%s" style="width:220px;height:220px;border:1px solid #eee;">
  <div>
    <p><b>Account:</b> <code>%s</code></p>
    <p><b>Secret:</b> <code style="font-size:14px;letter-spacing:1px;">%s</code></p>
  </div>
</div>
%s
<form method="POST" action="%s/account/2fa" style="margin-top:16px;">
  <input type="hidden" name="action" value="enroll">
  %s
  <label>Code: <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="off" required style="font-size:18px;letter-spacing:4px;padding:6px 8px;width:120px;"></label>
  <button type="submit" style="background:#093DF5;color:white;border:0;padding:8px 16px;margin-left:8px;border-radius:4px;font-size:14px;cursor:pointer;">Enrol</button>
</form>`,
		html.EscapeString(qrDataURL),
		html.EscapeString(email), html.EscapeString(secret),
		errBlock, html.EscapeString(mfaGatePathPrefix), rt)
}

// --- HTML ---

func accountDevicesHTML(email string, devs []deviceRecord, current *deviceRecord) string {
	rows := ""
	if len(devs) == 0 {
		rows = `<p class="note">No devices paired yet.</p>`
	} else {
		var b strings.Builder
		b.WriteString(`<table style="width:100%;border-collapse:collapse;margin:8px 0;">`)
		b.WriteString(`<thead><tr style="text-align:left;border-bottom:1px solid #E4E4E7;"><th style="padding:8px 0;">Device</th><th>Paired</th><th>Last seen</th><th></th></tr></thead><tbody>`)
		for _, d := range devs {
			isCurrent := current != nil && current.ID == d.ID
			label := html.EscapeString(d.Name)
			if isCurrent {
				label += ` <span style="color:#093DF5;font-weight:600;">(this device)</span>`
			}
			fmt.Fprintf(&b, `<tr style="border-bottom:1px solid #F4F4F5;">
  <td style="padding:8px 4px;">%s</td>
  <td style="color:#71717A;">%s</td>
  <td style="color:#71717A;">%s</td>
  <td style="text-align:right;">
    <form method="POST" action="%s/account/devices" style="display:inline;" onsubmit="return confirm('Remove this device?');">
      <input type="hidden" name="action" value="remove">
      <input type="hidden" name="id" value="%s">
      <button type="submit" style="color:#b00020;background:none;border:0;cursor:pointer;font-size:13px;">Remove</button>
    </form>
  </td>
</tr>`,
				label, html.EscapeString(d.PairedAt), html.EscapeString(d.LastSeen),
				html.EscapeString(mfaGatePathPrefix), html.EscapeString(d.ID))
		}
		b.WriteString(`</tbody></table>`)
		rows = b.String()
	}
	body := fmt.Sprintf(`
<div class="header">%s<h1>Paired devices</h1><a href="/bailey/" class="sign-out">← Bailey</a></div>
<div class="card">
  <p>Signed in as <code>%s</code>.</p>
  %s
  <p class="note">To pair another browser, open this server's URL there — it'll show a 6-digit code that you can approve from this device at <code>%s/approve</code>.</p>
</div>`,
		bitswanLogoSVG, html.EscapeString(email), rows, html.EscapeString(mfaGatePathPrefix))
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Paired devices</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}

func accountTOTPStatusHTML(email string, admin bool, rec *totpRecord) string {
	status := `<p>Your account has TOTP enabled. You can use your authenticator app to recover a device on a fresh browser.</p>`
	cta := ""
	if admin {
		cta = fmt.Sprintf(`<form method="POST" action="%s/account/2fa" onsubmit="return confirm('Disable TOTP? You will lose authenticator-based recovery.');">
  <input type="hidden" name="action" value="disable">
  <button type="submit" style="color:#b00020;background:none;border:1px solid #b00020;padding:6px 12px;border-radius:4px;cursor:pointer;">Disable TOTP</button>
</form>`, html.EscapeString(mfaGatePathPrefix))
	}
	_ = rec
	body := fmt.Sprintf(`
<div class="header">%s<h1>Two-factor authentication</h1><a href="/bailey/" class="sign-out">← Bailey</a></div>
<div class="card">
  <p>Signed in as <code>%s</code>.</p>
  %s
  %s
</div>`,
		bitswanLogoSVG, html.EscapeString(email), status, cta)
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>2FA</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}

func accountTOTPEnrollHTML(email, secret, errMsg string) string {
	errBlock := ""
	if errMsg != "" {
		errBlock = `<p class="note" style="color:#b00020;"><b>` + html.EscapeString(errMsg) + `</b></p>`
	}
	qrDataURL := ""
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if key, kerr := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuerName(),
		AccountName: email,
		Secret:      raw,
	}); kerr == nil {
		if img, ierr := key.Image(220, 220); ierr == nil {
			var buf bytes.Buffer
			if png.Encode(&buf, img) == nil {
				qrDataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
			}
		}
	}
	body := fmt.Sprintf(`
<div class="header">%s<h1>Enrol TOTP recovery</h1><a href="/bailey/" class="sign-out">← Bailey</a></div>
<div class="card">
  <p>Signed in as <code>%s</code>. Scan with an authenticator app and enter the 6-digit code:</p>
  <div style="display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap;">
    <img alt="TOTP QR" src="%s" style="width:220px;height:220px;border:1px solid #eee;">
    <div>
      <p><b>Account:</b> <code>%s</code></p>
      <p><b>Secret:</b> <code style="font-size:14px;letter-spacing:1px;">%s</code></p>
    </div>
  </div>
  %s
  <form method="POST" action="%s/account/2fa" style="margin-top:16px;">
    <input type="hidden" name="action" value="enroll">
    <label>Code: <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autofocus required style="font-size:18px;letter-spacing:4px;padding:6px 8px;width:120px;"></label>
    <button type="submit" style="background:#093DF5;color:white;border:0;padding:8px 16px;margin-left:8px;border-radius:4px;font-size:14px;cursor:pointer;">Enrol</button>
  </form>
</div>`,
		bitswanLogoSVG, html.EscapeString(email), html.EscapeString(qrDataURL),
		html.EscapeString(email), html.EscapeString(secret),
		errBlock, html.EscapeString(mfaGatePathPrefix))
	_ = otp.AlgorithmSHA1 // pin package use under refactors
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Enrol TOTP</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}
