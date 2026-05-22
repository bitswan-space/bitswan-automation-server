package daemon

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Admin Devices page — server-wide view of every paired device,
// grouped by user, with pending pair requests inline. Replaces the
// old single-purpose Approvals page (which only showed pending
// pairs). All actions are admin-only.

type adminUserDevice struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PairedAt  string `json:"paired_at"`
	LastSeen  string `json:"last_seen"`
	IsCurrent bool   `json:"is_current"`
}

type adminUserRow struct {
	Email         string             `json:"email"`
	TOTPEnrolled  bool               `json:"totp_enrolled"`
	IsServerOwner bool               `json:"is_server_owner"`
	Devices       []adminUserDevice  `json:"devices"`
	PendingPair   *adminPendingPair  `json:"pending_pair,omitempty"`
}

type adminPendingPair struct {
	Code       string `json:"code"`
	IssuedAt   string `json:"issued_at"`
	AgeSeconds int    `json:"age_seconds"`
}

type adminDevicesResponse struct {
	Users []adminUserRow `json:"users"`
	// PendingPairsOrphan: pending pair requests for emails that have
	// no devices yet (i.e. first-time pairers — they won't appear in
	// the per-user rows otherwise).
	PendingPairsOrphan []adminUserRow `json:"pending_pairs_orphan"`
}

func handleAdminDevicesAPI(w http.ResponseWriter, r *http.Request) {
	devs, err := listAllDevices()
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	totpSet, err := dbListTOTPEnrolledEmails()
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	currentDev := currentDeviceForRequest(r, r.Header.Get("X-Forwarded-Email"))
	currentDevID := ""
	if currentDev != nil {
		currentDevID = currentDev.ID
	}
	pending := visiblePendingRequests("", true) // admin == true → all

	// Group devices by lowercase email.
	byEmail := map[string]*adminUserRow{}
	order := []string{} // preserve first-seen order
	for _, d := range devs {
		key := strings.ToLower(d.Email)
		row, ok := byEmail[key]
		if !ok {
			row = &adminUserRow{
				Email:        d.Email,
				TOTPEnrolled: totpSet[key],
			}
			byEmail[key] = row
			order = append(order, key)
		}
		row.Devices = append(row.Devices, adminUserDevice{
			ID:        d.ID,
			Name:      d.Name,
			PairedAt:  d.PairedAt,
			LastSeen:  d.LastSeen,
			IsCurrent: d.ID == currentDevID,
		})
	}
	// Attach pending pair to the matching user row; collect orphans.
	var orphans []adminUserRow
	for _, p := range pending {
		key := strings.ToLower(p.Email)
		pp := &adminPendingPair{
			Code:       p.Code,
			IssuedAt:   p.IssuedAt.UTC().Format(time.RFC3339),
			AgeSeconds: int(time.Since(p.IssuedAt).Seconds()),
		}
		if row, ok := byEmail[key]; ok {
			row.PendingPair = pp
		} else {
			orphans = append(orphans, adminUserRow{
				Email:        p.Email,
				TOTPEnrolled: totpSet[key],
				PendingPair:  pp,
			})
		}
	}

	out := adminDevicesResponse{
		PendingPairsOrphan: orphans,
	}
	for _, k := range order {
		out.Users = append(out.Users, *byEmail[k])
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleAdminDeviceRemoveAPI lets an admin revoke any user's device
// (not just their own — that's what /bailey/api/devices/remove is for).
func handleAdminDeviceRemoveAPI(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	id := strings.TrimSpace(r.FormValue("id"))
	if email == "" || id == "" {
		writeJSONError(w, "email and id required", http.StatusBadRequest)
		return
	}
	if err := removeDevice(email, id); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}
