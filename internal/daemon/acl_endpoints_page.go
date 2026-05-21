package daemon

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// Endpoints page in bailey-admin. Shows a map of every protected
// endpoint with its owner + grants. Anyone signed in can open it
// (it's part of the chrome-wrapped bailey-admin), but the JSON API
// filters per caller:
//
//   - server owner (original owner of bailey-admin.<domain>): sees
//     EVERY endpoint, with full ACL detail, in read-only audit mode.
//   - everyone else: sees only the endpoints they're involved with
//     (own, are granted on, or are in a granted group of).
//
// Modifying grants happens through /2fa-gate/share/<host>, which
// continues to enforce owner-only writes.

type endpointListEntry struct {
	Hostname    string          `json:"hostname"`
	OwnerEmail  string          `json:"owner_email"`
	DisplayName string          `json:"display_name"`
	CreatedAt   string          `json:"created_at"`
	CallerRole  string          `json:"caller_role"`     // owner | access | viewer (server owner) | none
	Grants      []endpointGrant `json:"grants,omitempty"` // populated for owner/server-owner views
}

type endpointListing struct {
	CallerEmail   string              `json:"caller_email"`
	IsServerOwner bool                `json:"is_server_owner"`
	Endpoints     []endpointListEntry `json:"endpoints"`
}

// callerIsServerOwner reports whether the caller is the original
// owner of the bailey-admin.<domain> endpoint. Used to gate the
// server-wide audit view.
func callerIsServerOwner(callerEmail string, r *http.Request) (bool, error) {
	host := serverBaileyAdminHost(r)
	if host == "" {
		return false, nil
	}
	ep, err := getEndpoint(host)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if ep == nil {
		return false, nil
	}
	return strings.EqualFold(ep.OwnerEmail, callerEmail), nil
}

// serverBaileyAdminHost returns the hostname of the bailey-admin
// endpoint for this server. Prefers what the caller's request was
// addressed to (so the same daemon can serve multiple bailey-admin
// hosts if needed); falls back to the configured domain.
func serverBaileyAdminHost(r *http.Request) string {
	if r != nil {
		if h := requestEndpointHost(r); isBaileyAdminHost(h) {
			return h
		}
	}
	sc, err := config.NewAutomationServerConfig().LoadConfig()
	if err != nil || sc == nil {
		return ""
	}
	if d := sc.ProtectedHostnameDomain(); d != "" {
		return "bailey-admin." + d
	}
	return ""
}

// buildEndpointListing constructs the JSON used by the endpoints
// page. The result is already filtered per caller — clients render
// it directly.
func buildEndpointListing(callerEmail string, callerGroups []string, r *http.Request) (*endpointListing, error) {
	db, err := openBaileyDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT hostname, owner_email, COALESCE(display_name,''), created_at FROM endpoints ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	serverOwner, err := callerIsServerOwner(callerEmail, r)
	if err != nil {
		return nil, err
	}

	out := &endpointListing{
		CallerEmail:   callerEmail,
		IsServerOwner: serverOwner,
	}
	for rows.Next() {
		var e endpointListEntry
		if err := rows.Scan(&e.Hostname, &e.OwnerEmail, &e.DisplayName, &e.CreatedAt); err != nil {
			return nil, err
		}
		// Resolve caller's role on this endpoint.
		role, err := roleFor(e.Hostname, callerEmail, callerGroups)
		if err != nil {
			return nil, err
		}
		e.CallerRole = string(role)
		if e.CallerRole == "" && serverOwner {
			e.CallerRole = "viewer"
		}
		if e.CallerRole == "" {
			// Caller has no relationship to this endpoint and isn't
			// the server owner — skip from the per-caller view.
			continue
		}
		// Owner and server-owner views include grants. Access-role
		// callers get the bare metadata so they know the endpoint
		// exists but can't enumerate everyone else with access.
		if e.CallerRole == "owner" || e.CallerRole == "viewer" {
			grants, gerr := listGrants(e.Hostname)
			if gerr != nil {
				return nil, gerr
			}
			e.Grants = grants
		}
		out.Endpoints = append(out.Endpoints, e)
	}
	return out, rows.Err()
}
