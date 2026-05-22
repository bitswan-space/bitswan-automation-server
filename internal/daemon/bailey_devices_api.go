package daemon

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Bailey-side JSON endpoints that back the inline Devices and
// Approvals pages. These let the bailey UI render natively (no
// embedded iframe pointing at /2fa-gate/account/*) and update in
// place via fetch + reload.

type baileyDeviceDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PairedAt  string `json:"paired_at"`
	LastSeen  string `json:"last_seen"`
	IsCurrent bool   `json:"is_current"`
}

func handleBaileyDevicesAPI(w http.ResponseWriter, r *http.Request, email string) {
	devs, err := loadDevices(email)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	current := currentDeviceForRequest(r, email)
	out := make([]baileyDeviceDTO, 0, len(devs))
	for _, d := range devs {
		out = append(out, baileyDeviceDTO{
			ID:        d.ID,
			Name:      d.Name,
			PairedAt:  d.PairedAt,
			LastSeen:  d.LastSeen,
			IsCurrent: current != nil && current.ID == d.ID,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"devices": out})
}

func handleBaileyDevicesRemoveAPI(w http.ResponseWriter, r *http.Request, email string) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		writeJSONError(w, "id required", http.StatusBadRequest)
		return
	}
	if err := removeDevice(email, id); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

type baileyApprovalDTO struct {
	Email      string `json:"email"`
	IssuedAt   string `json:"issued_at"`
	AgeSeconds int    `json:"age_seconds"`
}

func handleBaileyApprovalsAPI(w http.ResponseWriter, r *http.Request, email string, isAdmin bool) {
	pending := visiblePendingRequests(email, isAdmin)
	out := make([]baileyApprovalDTO, 0, len(pending))
	for _, p := range pending {
		out = append(out, baileyApprovalDTO{
			Email:      p.Email,
			IssuedAt:   p.IssuedAt.UTC().Format(time.RFC3339),
			AgeSeconds: int(time.Since(p.IssuedAt).Seconds()),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"pending": out})
}
