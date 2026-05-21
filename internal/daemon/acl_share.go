package daemon

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// /2fa-gate/share/<hostname>: owner-only UI for managing grants on
// a specific endpoint. Lists current grants, lets the owner add new
// email or group grants, remove existing ones, and approve pending
// access requests.
//
// /2fa-gate/request-access/<hostname>: lightweight POST endpoint
// called from the denied page (or share UI) to record a pending
// access request.

func handleShareEndpoint(w http.ResponseWriter, r *http.Request, email string, groups []string) {
	// /2fa-gate/share or /2fa-gate/share/ → index of endpoints the
	// caller can manage. /2fa-gate/share/<hostname> → specific page.
	if r.URL.Path == mfaGatePathPrefix+"/share" || r.URL.Path == mfaGatePathPrefix+"/share/" {
		handleShareIndex(w, r, email, groups)
		return
	}
	host := strings.TrimPrefix(r.URL.Path, mfaGatePathPrefix+"/share/")
	host = strings.TrimRight(host, "/")
	host, _ = url.PathUnescape(host)
	if host == "" {
		handleShareIndex(w, r, email, groups)
		return
	}

	ep, err := getEndpoint(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ep == nil {
		http.Error(w, "no such endpoint: "+host, http.StatusNotFound)
		return
	}
	role, err := roleFor(host, email, groups)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if role != roleOwner {
		http.Error(w, "owners only", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		action := strings.TrimSpace(r.FormValue("action"))
		switch action {
		case "grant":
			pType := strings.TrimSpace(r.FormValue("principal_type"))
			pVal := strings.TrimSpace(r.FormValue("principal_value"))
			roleVal := strings.TrimSpace(r.FormValue("role"))
			if roleVal == "" {
				roleVal = "access"
			}
			if pVal == "" {
				http.Error(w, "principal_value required", http.StatusBadRequest)
				return
			}
			if err := addGrant(host, pType, pVal, roleVal, email); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// If this grant satisfies a pending access request, clear it.
			if pType == "email" {
				_ = removeAccessRequest(host, pVal)
			}
		case "revoke":
			pType := strings.TrimSpace(r.FormValue("principal_type"))
			pVal := strings.TrimSpace(r.FormValue("principal_value"))
			roleVal := strings.TrimSpace(r.FormValue("role"))
			if err := removeGrant(host, pType, pVal, roleVal); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "deny-request":
			target := strings.TrimSpace(r.FormValue("email"))
			if err := removeAccessRequest(host, target); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, mfaGatePathPrefix+"/share/"+url.PathEscape(host), http.StatusSeeOther)
		return
	}

	// GET: render the share page.
	grants, _ := listGrants(host)
	requests, _ := listAccessRequests(host)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, sharePageHTML(ep, grants, requests, email, groups))
}

func handleShareIndex(w http.ResponseWriter, r *http.Request, email string, groups []string) {
	endpoints, _ := listEndpointsWhereUserCanShare(email, groups)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, shareIndexHTML(email, endpoints))
}

// handleRequestAccess records an access request via POST.
// Used by the denied page's "Request access" button.
func handleRequestAccess(w http.ResponseWriter, r *http.Request, email string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	host := strings.TrimPrefix(r.URL.Path, mfaGatePathPrefix+"/request-access/")
	host = strings.TrimRight(host, "/")
	host, _ = url.PathUnescape(host)
	if host == "" {
		http.Error(w, "host required", http.StatusBadRequest)
		return
	}
	if _, err := getEndpoint(host); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := addAccessRequest(host, email); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8">%s<style>%s</style><title>Access requested</title></head><body>
<div class="header">%s<h1>Access requested</h1></div>
<div class="card">
  <p>Your request to access <code>%s</code> has been sent to the endpoint owner.</p>
  <p class="note">They'll see it in their share page. You'll be able to reach the endpoint as soon as they grant access.</p>
</div></body></html>`,
		bitswanFavicon, bitswanPageCSS, bitswanLogoSVG, html.EscapeString(host))
}

// --- HTML ---

func accessDeniedHTML(host string, ep *endpointRecord, email string) string {
	ownerLine := "unknown"
	if ep != nil && ep.OwnerEmail != "" {
		ownerLine = ep.OwnerEmail
	}
	requestPath := mfaGatePathPrefix + "/request-access/" + url.PathEscape(host)
	body := fmt.Sprintf(`
<div class="header">%s<h1>Access required</h1></div>
<div class="card">
  <p>You're signed in as <code>%s</code>, but you don't have access to <code>%s</code>.</p>
  <p class="note">This endpoint is owned by <code>%s</code>. They can grant you access from their share page.</p>
  <form method="POST" action="%s">
    <button type="submit" style="background:#093DF5;color:white;border:0;padding:8px 16px;border-radius:4px;cursor:pointer;font-size:14px;">Request access</button>
  </form>
</div>`,
		bitswanLogoSVG, html.EscapeString(email), html.EscapeString(host),
		html.EscapeString(ownerLine), html.EscapeString(requestPath))
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Access required</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}

func shareIndexHTML(email string, endpoints []endpointRecord) string {
	rows := ""
	if len(endpoints) == 0 {
		rows = `<p class="note">You don't own any endpoints yet. When you create a workspace or deploy an automation, you'll be its owner and can manage sharing here.</p>`
	} else {
		var b strings.Builder
		b.WriteString(`<table style="width:100%;border-collapse:collapse;">`)
		b.WriteString(`<thead><tr style="text-align:left;border-bottom:1px solid #E4E4E7;"><th style="padding:8px 0;">Endpoint</th><th>Created</th><th></th></tr></thead><tbody>`)
		for _, e := range endpoints {
			fmt.Fprintf(&b, `<tr style="border-bottom:1px solid #F4F4F5;">
  <td style="padding:8px 4px;"><b>%s</b><br><span class="note">%s</span></td>
  <td class="note">%s</td>
  <td style="text-align:right;"><a href="%s/share/%s" style="color:#093DF5;text-decoration:none;">Manage sharing →</a></td>
</tr>`,
				html.EscapeString(e.Hostname),
				html.EscapeString(e.DisplayName),
				html.EscapeString(e.CreatedAt),
				html.EscapeString(mfaGatePathPrefix), html.EscapeString(url.PathEscape(e.Hostname)))
		}
		b.WriteString(`</tbody></table>`)
		rows = b.String()
	}
	body := fmt.Sprintf(`
<div class="header">%s<h1>Endpoints you can share</h1><a href="/bailey-admin/" class="sign-out">← Bailey</a></div>
<div class="card">
  <p>Signed in as <code>%s</code>. These are the endpoints where you're an owner — you can grant access, view who has it, and approve pending requests.</p>
  %s
</div>`, bitswanLogoSVG, html.EscapeString(email), rows)
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Share endpoints</title>%s<style>%s</style></head><body>%s</body></html>`,
		bitswanFavicon, bitswanPageCSS, body)
}

func sharePageHTML(ep *endpointRecord, grants []endpointGrant, requests []struct {
	Email       string
	RequestedAt string
}, callerEmail string, callerGroups []string) string {
	// Grants table.
	grantsRows := ""
	{
		var b strings.Builder
		b.WriteString(`<table style="width:100%;border-collapse:collapse;margin:8px 0;">`)
		b.WriteString(`<thead><tr style="text-align:left;border-bottom:1px solid #E4E4E7;"><th style="padding:8px 0;">Principal</th><th>Role</th><th>Granted</th><th></th></tr></thead><tbody>`)
		// Owner row (the original owner is always implied — no revoke).
		fmt.Fprintf(&b, `<tr style="border-bottom:1px solid #F4F4F5;background:#FAFAFA;">
  <td style="padding:8px 4px;"><code>%s</code> <span class="note">(original owner)</span></td>
  <td>owner</td>
  <td class="note">%s</td>
  <td></td>
</tr>`, html.EscapeString(ep.OwnerEmail), html.EscapeString(ep.CreatedAt))
		for _, g := range grants {
			fmt.Fprintf(&b, `<tr style="border-bottom:1px solid #F4F4F5;">
  <td style="padding:8px 4px;"><code>%s</code> <span class="note">(%s)</span></td>
  <td>%s</td>
  <td class="note">%s by %s</td>
  <td style="text-align:right;">
    <form method="POST" style="display:inline;" onsubmit="return confirm('Revoke this grant?');">
      <input type="hidden" name="action" value="revoke">
      <input type="hidden" name="principal_type" value="%s">
      <input type="hidden" name="principal_value" value="%s">
      <input type="hidden" name="role" value="%s">
      <button type="submit" style="background:none;border:0;color:#b00020;cursor:pointer;font-size:13px;">Revoke</button>
    </form>
  </td>
</tr>`,
				html.EscapeString(g.PrincipalValue),
				html.EscapeString(g.PrincipalType),
				html.EscapeString(string(g.Role)),
				html.EscapeString(g.GrantedAt),
				html.EscapeString(g.GrantedBy),
				html.EscapeString(g.PrincipalType),
				html.EscapeString(g.PrincipalValue),
				html.EscapeString(string(g.Role)))
		}
		b.WriteString(`</tbody></table>`)
		grantsRows = b.String()
	}

	// Pending requests block.
	requestsRows := ""
	if len(requests) > 0 {
		var b strings.Builder
		b.WriteString(`<h2>Pending access requests</h2><table style="width:100%;border-collapse:collapse;margin:8px 0;">`)
		b.WriteString(`<thead><tr style="text-align:left;border-bottom:1px solid #E4E4E7;"><th style="padding:8px 0;">User</th><th>Requested</th><th></th></tr></thead><tbody>`)
		for _, req := range requests {
			fmt.Fprintf(&b, `<tr style="border-bottom:1px solid #F4F4F5;">
  <td style="padding:8px 4px;"><code>%s</code></td>
  <td class="note">%s</td>
  <td style="text-align:right;">
    <form method="POST" style="display:inline;">
      <input type="hidden" name="action" value="grant">
      <input type="hidden" name="principal_type" value="email">
      <input type="hidden" name="principal_value" value="%s">
      <input type="hidden" name="role" value="access">
      <button type="submit" style="background:#093DF5;color:white;border:0;padding:4px 10px;border-radius:3px;cursor:pointer;font-size:13px;">Grant access</button>
    </form>
    <form method="POST" style="display:inline;margin-left:6px;">
      <input type="hidden" name="action" value="deny-request">
      <input type="hidden" name="email" value="%s">
      <button type="submit" style="background:none;border:0;color:#b00020;cursor:pointer;font-size:13px;">Deny</button>
    </form>
  </td>
</tr>`,
				html.EscapeString(req.Email), html.EscapeString(req.RequestedAt),
				html.EscapeString(req.Email), html.EscapeString(req.Email))
		}
		b.WriteString(`</tbody></table>`)
		requestsRows = b.String()
	}

	// Group dropdown — populated from caller's own Keycloak groups.
	groupOptions := ""
	for _, g := range callerGroups {
		groupOptions += fmt.Sprintf(`<option value="%s">%s</option>`,
			html.EscapeString(g), html.EscapeString(g))
	}

	// Caller's first-seen time as a heuristic for the form action.
	_ = time.Now() // formatter no-op

	body := fmt.Sprintf(`
<div class="header">%s<h1>Sharing for %s</h1><a href="%s/share" class="sign-out">← All endpoints</a></div>
<div class="card">
  <p>Signed in as <code>%s</code> · original owner: <code>%s</code></p>
  %s
  %s

  <h2>Add a grant</h2>
  <form method="POST" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
    <input type="hidden" name="action" value="grant">
    <select name="principal_type" id="ptype" onchange="document.getElementById('email-input').style.display=this.value==='email'?'inline-block':'none';document.getElementById('group-select').style.display=this.value==='group'?'inline-block':'none';">
      <option value="email">Email</option>
      <option value="group">Group</option>
    </select>
    <input id="email-input" type="email" name="principal_value" placeholder="user@example.com" style="padding:6px 8px;">
    <select id="group-select" name="principal_value" style="display:none;padding:6px 8px;">%s</select>
    <select name="role">
      <option value="access">access</option>
      <option value="owner">owner</option>
    </select>
    <button type="submit" style="background:#093DF5;color:white;border:0;padding:8px 16px;border-radius:4px;cursor:pointer;font-size:14px;">Grant</button>
  </form>
  <p class="note" style="margin-top:8px;">Owners can manage sharing rules and grant further access. Access is read-only over the endpoint.</p>
</div>`,
		bitswanLogoSVG,
		html.EscapeString(ep.Hostname),
		html.EscapeString(mfaGatePathPrefix),
		html.EscapeString(callerEmail),
		html.EscapeString(ep.OwnerEmail),
		requestsRows,
		grantsRows,
		groupOptions,
	)
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>Share %s</title>%s<style>%s</style></head><body>%s</body></html>`,
		html.EscapeString(ep.Hostname), bitswanFavicon, bitswanPageCSS, body)
}
