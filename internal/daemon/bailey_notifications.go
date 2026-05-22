package daemon

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
)

// Notifications combine the things that pull a user back to bailey:
//
//   - Pending device pair requests (admin sees every user's; a non-admin
//     only sees their own pending pair from another browser).
//   - Access requests pinned to endpoints the caller can grant on
//     (i.e. they are an owner of that endpoint).
//
// Anything time-sensitive that needs the user's attention should land
// here so there's one place to look.

type notification struct {
	Kind        string `json:"kind"`              // "pair" | "access"
	Subject     string `json:"subject"`           // requester email
	Hostname    string `json:"hostname,omitempty"` // for "access"
	Code        string `json:"code,omitempty"`     // for "pair"
	RequestedAt string `json:"requested_at,omitempty"`
}

// gatherNotifications returns all notifications visible to caller.
// Deadlock-safe: each query completes before the next starts (we never
// hold a rows handle while making another DB call). See the comment on
// listAllEndpoints — SetMaxOpenConns(1) makes nested queries deadlock.
func gatherNotifications(callerEmail string, callerGroups []string, isAdmin bool) ([]notification, error) {
	var out []notification

	// (1) Pending pair requests — entirely in-memory, no DB at all.
	for _, p := range visiblePendingRequests(callerEmail, isAdmin) {
		out = append(out, notification{
			Kind:        "pair",
			Subject:     p.Email,
			Code:        p.Code,
			RequestedAt: p.IssuedAt.UTC().Format("2006-01-02 15:04 UTC"),
		})
	}

	// (2) Access requests on endpoints the caller can grant on. Two
	// passes: load all access requests first, then for each row decide
	// whether to surface it. Per-row roleFor() is safe because each
	// call opens and closes its own queries.
	reqs, err := listAllAccessRequests()
	if err != nil {
		return out, err
	}
	for _, r := range reqs {
		role, err := roleFor(r.Hostname, callerEmail, callerGroups)
		if err != nil || role != roleOwner {
			continue
		}
		out = append(out, notification{
			Kind:        "access",
			Subject:     r.Email,
			Hostname:    r.Hostname,
			RequestedAt: r.RequestedAt,
		})
	}
	return out, nil
}

func handleNotificationsCount(w http.ResponseWriter, r *http.Request) {
	email, groups := identityFromHeaders(r)
	if email == "" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"count":0}`)
		return
	}
	admin := isAdminGroups(groups)
	ns, _ := gatherNotifications(email, groups, admin)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"count": len(ns)})
}

// notificationsPageHTML renders the inner card content for /bailey/notifications.
// Returns plain HTML; the caller stitches it into the sidebar layout.
func notificationsPageHTML(email string, groups []string, isAdmin bool) string {
	ns, err := gatherNotifications(email, groups, isAdmin)
	if err != nil {
		return fmt.Sprintf(`<div class="card"><p class="note" style="color:#b00020;">Couldn't load notifications: %s</p></div>`, html.EscapeString(err.Error()))
	}
	if len(ns) == 0 {
		return `<div class="card" style="margin-top:0;">
  <p class="note">Nothing waiting for you right now. This page auto-refreshes when something comes in.</p>
</div>
<meta http-equiv="refresh" content="10">`
	}

	var b strings.Builder
	b.WriteString(`<div class="card" style="margin-top:0;"><p class="note">Items that need your attention. Click through to act on them.</p></div>`)
	for _, n := range ns {
		switch n.Kind {
		case "pair":
			fmt.Fprintf(&b, `
<div class="card">
  <h2>Device pairing — %s</h2>
  <p class="note">A browser signed in as <code>%s</code> is waiting to be approved. They should see a 6-digit code on their screen.</p>
  <p style="font-size:13px;color:#3F3F46;">Expected code: <code style="font-size:18px;letter-spacing:2px;background:#F5F5F6;padding:4px 8px;border-radius:4px;">%s</code> <span class="note" style="margin-left:8px;">(only matches if they read this same code to you — never trust a code <i>they</i> tell <i>you</i> blindly)</span></p>
  <p><a href="/bailey/approvals" class="btn" style="text-decoration:none;">Open approvals →</a></p>
</div>`,
				html.EscapeString(n.Subject), html.EscapeString(n.Subject), html.EscapeString(n.Code))
		case "access":
			fmt.Fprintf(&b, `
<div class="card">
  <h2>Access request — %s</h2>
  <p class="note"><code>%s</code> is asking for access to <b>%s</b> (requested %s).</p>
  <p><a href="/2fa-gate/share/%s" class="btn" style="text-decoration:none;">Open share page →</a></p>
</div>`,
				html.EscapeString(n.Hostname),
				html.EscapeString(n.Subject), html.EscapeString(n.Hostname), html.EscapeString(n.RequestedAt),
				html.EscapeString(n.Hostname))
		}
	}
	b.WriteString(`<meta http-equiv="refresh" content="10">`)
	return b.String()
}
