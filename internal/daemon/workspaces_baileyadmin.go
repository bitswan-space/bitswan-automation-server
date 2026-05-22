package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// /bailey/api/workspaces — open to any authenticated user.
// GET returns workspaces the caller has any ACL relationship with
// (owner, grantee, or in a granted group). POST creates a new
// workspace with the caller as the owner of its editor + gitops
// endpoints.

type accessibleWorkspace struct {
	Name        string `json:"name"`
	EditorURL   string `json:"editor_url"`
	GitopsURL   string `json:"gitops_url"`
	EditorRole  string `json:"editor_role,omitempty"`  // owner | access | none
	GitopsRole  string `json:"gitops_role,omitempty"`
	IsOwner     bool   `json:"is_owner"`
}

type listAccessibleResponse struct {
	CallerEmail string                `json:"caller_email"`
	Workspaces  []accessibleWorkspace `json:"workspaces"`
}

// handleListAccessibleWorkspaces returns the workspaces the caller
// can see. A workspace is visible if the caller has any ACL on its
// editor or gitops endpoint, OR is its owner. Server owners see
// every workspace (audit view).
func handleListAccessibleWorkspaces(w http.ResponseWriter, r *http.Request, email string) {
	_, groups := identityFromHeaders(r)
	sc, _ := config.NewAutomationServerConfig().LoadConfig()
	domain := ""
	if sc != nil {
		domain = sc.ProtectedHostnameDomain()
	}

	// Get the full workspace list from the daemon's perspective,
	// then filter to those the caller has access to.
	full, err := GetWorkspaceList(false, false)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	serverOwner, _ := callerIsServerOwner(email, r)

	out := listAccessibleResponse{CallerEmail: email}
	if full != nil {
		for _, ws := range full.Workspaces {
			name := ws.Name
			editorHost := name + "-editor." + domain
			gitopsHost := name + "-gitops." + domain
			editorRole, _ := roleFor(editorHost, email, groups)
			gitopsRole, _ := roleFor(gitopsHost, email, groups)
			isOwner := editorRole == roleOwner || gitopsRole == roleOwner
			// Visible to: caller with any role on either endpoint, OR
			// the server owner (audit view).
			if editorRole == roleNone && gitopsRole == roleNone && !serverOwner {
				continue
			}
			entry := accessibleWorkspace{
				Name:       name,
				EditorURL:  "https://" + editorHost,
				GitopsURL:  "https://" + gitopsHost,
				EditorRole: string(editorRole),
				GitopsRole: string(gitopsRole),
				IsOwner:    isOwner,
			}
			out.Workspaces = append(out.Workspaces, entry)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

type createWorkspaceRequest struct {
	Name string `json:"name"`
}

// nameRe constrains workspace names to lowercase letters, digits,
// and hyphens — what's safe in a DNS label and docker compose name.
var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,32}$`)

// handleCreateWorkspaceFromBaileyAdmin spawns a workspace init with
// the caller as owner. Streams the daemon's stdout/stderr output as
// it goes so the frontend can show progress; returns JSON with the
// final URL on success.
func (s *Server) handleCreateWorkspaceFromBaileyAdmin(w http.ResponseWriter, r *http.Request, email string) {
	var req createWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if !nameRe.MatchString(name) {
		http.Error(w, `{"error":"name must be lowercase alphanumeric with hyphens, 2-33 chars, starting with a letter"}`, http.StatusBadRequest)
		return
	}
	sc, _ := config.NewAutomationServerConfig().LoadConfig()
	if sc == nil || sc.Domain == "" {
		http.Error(w, `{"error":"server domain is not configured — cannot create workspace"}`, http.StatusBadRequest)
		return
	}

	// Run the workspace-init flow with stdout/stderr captured and
	// forwarded back to the caller as the response body. This
	// mirrors what the CLI sees.
	args := []string{"workspace", "init", name, "--domain", sc.Domain, "--owner", email}
	confirmCh := make(chan struct{}, 1)
	confirmCh <- struct{}{} // pre-fill so any "press enter" prompt unblocks immediately

	w.Header().Set("Content-Type", "application/json")
	if err := s.runWorkspaceInit(args[2:], confirmCh); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	editorURL := fmt.Sprintf("https://%s-editor.%s", name, sc.Domain)
	gitopsURL := fmt.Sprintf("https://%s-gitops.%s", name, sc.Domain)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":         true,
		"name":       name,
		"owner":      email,
		"editor_url": editorURL,
		"gitops_url": gitopsURL,
	})
}
