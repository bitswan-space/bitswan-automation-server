package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

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
// the caller as owner. Streams stdout/stderr from the init pipeline
// back to the caller as NDJSON progress events so the frontend can
// render a live status. Final line carries either {"ok":true,...}
// or {"ok":false,"error":"..."}.
//
// Streaming matters here for two reasons: the init pipeline takes
// 30+ seconds (network create → sub-traefik → docker compose →
// dashboard up), and any oauth2-proxy or browser fetch sitting in
// front of this would otherwise time out before the daemon writes
// its first byte. Emitting a heartbeat line every step keeps the
// connection alive AND gives the operator useful feedback.
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

	// Switch to NDJSON streaming. Frontend reads with a ReadableStream
	// reader, splits on '\n', json.Parse each line. Final line has
	// {"event":"done", ...} (success) or {"event":"error", ...} (fail).
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // tell nginx/oauth2-proxy to disable buffering
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	writeMu := sync.Mutex{}
	writeEvent := func(payload map[string]any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		line, err := json.Marshal(payload)
		if err != nil {
			return
		}
		_, _ = w.Write(append(line, '\n'))
		if flusher != nil {
			flusher.Flush()
		}
	}
	writeEvent(map[string]any{"event": "start", "message": "Starting workspace creation: " + name})

	// Capture os.Stdout + os.Stderr from runWorkspaceInit and emit each
	// line as a "log" event. Two pipes (one per stream) so we don't
	// interleave bytes at the buffer boundary. Tagged streams let the
	// frontend treat stderr differently if it cares.
	args := []string{"workspace", "init", name, "--domain", sc.Domain, "--owner", email}
	confirmCh := make(chan struct{}, 1)
	confirmCh <- struct{}{}

	stdoutMutex.Lock()
	oldStdout := os.Stdout
	rOut, wOut, err := os.Pipe()
	if err != nil {
		stdoutMutex.Unlock()
		writeEvent(map[string]any{"event": "error", "error": "failed to set up stdout pipe: " + err.Error()})
		return
	}
	os.Stdout = wOut
	stdoutMutex.Unlock()

	stderrMutex.Lock()
	oldStderr := os.Stderr
	rErr, wErr, err := os.Pipe()
	if err != nil {
		stderrMutex.Unlock()
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rOut.Close()
		wOut.Close()
		writeEvent(map[string]any{"event": "error", "error": "failed to set up stderr pipe: " + err.Error()})
		return
	}
	os.Stderr = wErr
	stderrMutex.Unlock()

	defer func() {
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rOut.Close()
		wOut.Close()
		stderrMutex.Lock()
		os.Stderr = oldStderr
		stderrMutex.Unlock()
		rErr.Close()
		wErr.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	relay := func(pipe io.Reader, stream string) {
		defer wg.Done()
		buf := make([]byte, 4096)
		var partial []byte
		for {
			n, err := pipe.Read(buf)
			if n > 0 {
				data := append(partial, buf[:n]...)
				lines := strings.Split(string(data), "\n")
				partial = []byte(lines[len(lines)-1])
				for _, line := range lines[:len(lines)-1] {
					if line == "" {
						continue
					}
					writeEvent(map[string]any{"event": "log", "stream": stream, "message": line})
				}
			}
			if err == io.EOF {
				if len(partial) > 0 {
					writeEvent(map[string]any{"event": "log", "stream": stream, "message": string(partial)})
				}
				return
			}
			if err != nil {
				return
			}
		}
	}
	go relay(rOut, "stdout")
	go relay(rErr, "stderr")

	initErr := s.runWorkspaceInit(args[2:], confirmCh)
	// Close writer ends so the relay goroutines see EOF and exit.
	wOut.Close()
	wErr.Close()
	wg.Wait()

	if initErr != nil {
		writeEvent(map[string]any{"event": "error", "error": initErr.Error()})
		return
	}
	gitopsURL := fmt.Sprintf("https://%s-gitops.%s", name, sc.Domain)
	dashboardURL := fmt.Sprintf("https://%s-dashboard.%s", name, sc.Domain)
	writeEvent(map[string]any{
		"event":         "done",
		"name":          name,
		"owner":         email,
		"gitops_url":    gitopsURL,
		"dashboard_url": dashboardURL,
	})
}
