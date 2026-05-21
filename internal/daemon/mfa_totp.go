package daemon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"image/png"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP-based second factor for admin-group users.
//
// Identity comes from Keycloak via oauth2-proxy (X-Forwarded-Email +
// X-Forwarded-Groups). The first factor proves "this Keycloak user is
// in the org's admin group"; TOTP proves "this is the human who
// originally enrolled."

const (
	totpIssuerPrefix    = "Bailey"
	cookieMaxAge        = 8 * time.Hour
	twoFactorCookieName = "_bailey_2fa"
	enrollPathSuffix    = "/enroll"
	challengePathSuffix = "/challenge"
)

type totpRecord struct {
	Email     string `json:"email"`
	Secret    string `json:"secret"`
	CreatedAt string `json:"created_at"`
}

func loadTOTPRecord(email string) (*totpRecord, error) { return dbLoadTOTP(email) }
func saveTOTPRecord(rec *totpRecord) error             { return dbSaveTOTP(rec) }
func signingKey() ([]byte, error)                      { return dbSigningKey() }

// signedSessionCookie packs (email, expiry) and HMACs them with the
// per-server signing key. The email is embedded so a cookie minted
// for user A is rejected if oauth2-proxy later forwards user B.
func signedSessionCookie(email string, expiry time.Time) (string, error) {
	key, err := signingKey()
	if err != nil {
		return "", err
	}
	emailEnc := base64.RawURLEncoding.EncodeToString([]byte(email))
	expStr := strconv.FormatInt(expiry.Unix(), 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(emailEnc + "." + expStr))
	sig := hex.EncodeToString(mac.Sum(nil))
	return emailEnc + "." + expStr + "." + sig, nil
}

func verifySessionCookie(email, cookieVal string) bool {
	parts := strings.Split(cookieVal, ".")
	if len(parts) != 3 {
		return false
	}
	emailEnc, expStr, sig := parts[0], parts[1], parts[2]
	decoded, err := base64.RawURLEncoding.DecodeString(emailEnc)
	if err != nil || !strings.EqualFold(string(decoded), email) {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return false
	}
	key, err := signingKey()
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(emailEnc + "." + expStr))
	want := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(want), []byte(sig)) == 1
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, email string) error {
	expiry := time.Now().Add(cookieMaxAge)
	val, err := signedSessionCookie(email, expiry)
	if err != nil {
		return err
	}
	c := &http.Cookie{
		Name:     twoFactorCookieName,
		Value:    val,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		// None so the cookie travels on iframe loads inside the
		// chrome wrap (Lax skips those, causing a loop).
		SameSite: http.SameSiteNoneMode,
	}
	if dom := cookieDomainForProtected(); dom != "" {
		c.Domain = dom
	}
	http.SetCookie(w, c)
	return nil
}

func hasValidSession(r *http.Request, email string) bool {
	c, err := r.Cookie(twoFactorCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return verifySessionCookie(email, c.Value)
}

// totpIssuerName names the entry in the user's authenticator app —
// "Bailey - <server name>" so a user with multiple bailey deployments
// can tell them apart.
func totpIssuerName() string {
	if sc, err := config.NewAutomationServerConfig().LoadConfig(); err == nil && sc != nil {
		if sc.Name != "" {
			return totpIssuerPrefix + " - " + sc.Name
		}
		if sc.Slug != "" {
			return totpIssuerPrefix + " - " + sc.Slug
		}
	}
	return totpIssuerPrefix
}

func totpIssuerForRequest(r *http.Request) string {
	_ = r
	return totpIssuerName()
}

// enrolCookieName returns the candidate-secret cookie name to use
// while enrolment is in progress. Different bases (admin vs the
// self-service /account/2fa flow) carry their own cookie so a user
// who's halfway through one flow doesn't accidentally clobber the
// other — and the test harness can tell them apart on the wire.
func enrolCookieName(basePath string) string {
	if strings.Contains(basePath, "/account") {
		return "_bailey_account_enroll"
	}
	return "_bailey_enroll"
}

// --- Gate handlers ---

// handleTOTPGate routes enrol/challenge GET+POST.
func handleTOTPGate(w http.ResponseWriter, r *http.Request, basePath, email string) {
	isEnroll := strings.HasPrefix(r.URL.Path, basePath+enrollPathSuffix)
	switch r.Method {
	case http.MethodGet:
		if isEnroll {
			handleEnrollGET(w, r, basePath, email)
		} else {
			handleChallengeGET(w, r, basePath, email)
		}
	case http.MethodPost:
		if isEnroll {
			handleEnrollPOST(w, r, basePath, email)
		} else {
			handleChallengePOST(w, r, basePath, email)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleEnrollGET(w http.ResponseWriter, r *http.Request, basePath, email string) {
	if rec, err := loadTOTPRecord(email); err == nil && rec != nil {
		http.Redirect(w, r, basePath+challengePathSuffix, http.StatusSeeOther)
		return
	}
	// Reuse the existing candidate secret if the user already scanned
	// it. Regenerating on every GET would silently invalidate the
	// authenticator entry on a page reload.
	var key *otp.Key
	if c, err := r.Cookie(enrolCookieName(basePath)); err == nil && c.Value != "" {
		// Subtle: key.Secret() is the base32 STRING. Passing it back
		// in GenerateOpts.Secret treats those characters as RAW BYTES
		// and base32-encodes them again — doubling the secret on
		// every reload. Decode back to raw bytes first.
		if raw, derr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(c.Value); derr == nil && len(raw) > 0 {
			key, _ = totp.Generate(totp.GenerateOpts{
				Issuer:      totpIssuerForRequest(r),
				AccountName: email,
				Secret:      raw,
			})
		}
	}
	if key == nil {
		k, err := totp.Generate(totp.GenerateOpts{
			Issuer:      totpIssuerForRequest(r),
			AccountName: email,
		})
		if err != nil {
			http.Error(w, "generate TOTP key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		key = k
	}
	http.SetCookie(w, &http.Cookie{
		Name:     enrolCookieName(basePath),
		Value:    key.Secret(),
		Path:     basePath + enrollPathSuffix,
		MaxAge:   600,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, totpEnrollHTML(email, key.Secret(), basePath, ""))
}

func handleEnrollPOST(w http.ResponseWriter, r *http.Request, basePath, email string) {
	if rec, err := loadTOTPRecord(email); err == nil && rec != nil {
		http.Redirect(w, r, basePath+challengePathSuffix, http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	candidate, err := r.Cookie(enrolCookieName(basePath))
	if err != nil || candidate.Value == "" {
		http.Error(w, "enrolment session expired — start over", http.StatusBadRequest)
		return
	}
	if !totp.Validate(code, candidate.Value) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, totpEnrollHTML(email, candidate.Value, basePath, "Code didn't match — check your authenticator and try again."))
		return
	}
	if err := saveTOTPRecord(&totpRecord{
		Email:     email,
		Secret:    candidate.Value,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: enrolCookieName(basePath), Value: "", Path: basePath + enrollPathSuffix, MaxAge: -1})
	if err := setSessionCookie(w, r, email); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	originRedirect(w, r)
}

func handleChallengeGET(w http.ResponseWriter, r *http.Request, basePath, email string) {
	if rec, err := loadTOTPRecord(email); err != nil || rec == nil {
		http.Redirect(w, r, basePath+enrollPathSuffix, http.StatusSeeOther)
		return
	}
	if hasValidSession(r, email) {
		originRedirect(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, totpChallengeHTML(email, basePath, ""))
}

func handleChallengePOST(w http.ResponseWriter, r *http.Request, basePath, email string) {
	rec, err := loadTOTPRecord(email)
	if err != nil || rec == nil {
		http.Redirect(w, r, basePath+enrollPathSuffix, http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if !totp.Validate(code, rec.Secret) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, totpChallengeHTML(email, basePath, "Code didn't match — try again."))
		return
	}
	if err := setSessionCookie(w, r, email); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	originRedirect(w, r)
}

// totpEnrollHTML renders the QR + secret + form. Re-rendered with the
// same secret on every reload (caller passes it in).
func totpEnrollHTML(email, secret, basePath, errMsg string) string {
	qrDataURL := ""
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuerName(),
		AccountName: email,
		Secret:      raw,
	}); err == nil {
		if img, err := key.Image(220, 220); err == nil {
			var buf bytes.Buffer
			if png.Encode(&buf, img) == nil {
				qrDataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
			}
		}
	}
	errBlock := ""
	if errMsg != "" {
		errBlock = `<p class="note" style="color:#b00020;"><b>` + html.EscapeString(errMsg) + `</b></p>`
	}
	body := fmt.Sprintf(`
<div class="header">%s<h1>Set up second factor</h1></div>
<div class="card">
  <p>Scan this QR with an authenticator app, or type the secret manually:</p>
  <div style="display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap;">
    <img alt="TOTP QR" src="%s" style="width:220px;height:220px;border:1px solid #eee;">
    <div>
      <p><b>Account:</b> <code>%s</code></p>
      <p><b>Secret:</b> <code style="font-size:14px;letter-spacing:1px;">%s</code></p>
    </div>
  </div>
  %s
  <form method="POST" action="%s%s" style="margin-top:16px;">
    <label>Enter the 6-digit code your app shows:
      <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autofocus required style="font-size:18px;letter-spacing:4px;padding:6px 8px;width:120px;">
    </label>
    <button type="submit" style="background:#093DF5;color:white;border:0;padding:8px 16px;margin-left:8px;border-radius:4px;font-size:14px;cursor:pointer;">Verify &amp; finish</button>
  </form>
</div>`,
		bitswanLogoSVG, html.EscapeString(qrDataURL),
		html.EscapeString(email), html.EscapeString(secret),
		errBlock, html.EscapeString(basePath), enrollPathSuffix)
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Set up second factor</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}

func totpChallengeHTML(email, basePath, errMsg string) string {
	errBlock := ""
	if errMsg != "" {
		errBlock = `<p class="note" style="color:#b00020;"><b>` + html.EscapeString(errMsg) + `</b></p>`
	}
	body := fmt.Sprintf(`
<div class="header">%s<h1>Second factor</h1></div>
<div class="card">
  <p>Signed in as <code>%s</code>. Enter the 6-digit code from your authenticator:</p>
  %s
  <form method="POST" action="%s%s">
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autofocus required style="font-size:18px;letter-spacing:4px;padding:6px 8px;width:120px;">
    <button type="submit" style="background:#093DF5;color:white;border:0;padding:8px 16px;margin-left:8px;border-radius:4px;font-size:14px;cursor:pointer;">Continue</button>
  </form>
</div>`,
		bitswanLogoSVG, html.EscapeString(email),
		errBlock, html.EscapeString(basePath), challengePathSuffix)
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Second factor</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}
