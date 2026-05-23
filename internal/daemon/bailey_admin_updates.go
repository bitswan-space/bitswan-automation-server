package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
)

// Bailey admin /updates endpoints.
//
// Three classes of operation:
//
//   1. Read the configured default images + suggest tags from Docker
//      Hub for the admin UI dropdown.
//      GET /bailey/api/admin/default-images
//
//   2. Write the default images (free-form string — the UI offers a
//      dropdown of suggestions but anything goes, including custom
//      dev tags like bitswan/gitops:bailey-dev).
//      POST /bailey/api/admin/default-images
//        body: {"gitops_image":"...", "dashboard_image":"..."}
//        empty string clears the setting (falls back to Docker Hub
//        latest at next workspace init).
//
//   3. Update a single workspace's running containers in place
//      (pulls new image + recreates the affected service). Owner-only
//      since it disrupts the workspace's deploys.
//      POST /bailey/api/workspaces/<name>/update

// dockerHubTagsResponse is the slice of fields we care about from the
// Docker Hub v2 tags list response. The full payload has many more
// fields but we only need name + last_updated for the dropdown.
type dockerHubTagsResponse struct {
	Results []struct {
		Name        string `json:"name"`
		LastUpdated string `json:"last_updated"`
	} `json:"results"`
}

// imageSettingResponse is one row in the GET /default-images payload.
// suggestions are Docker Hub tags sorted newest-first; current is the
// effective value (server_settings override OR the Docker Hub latest
// fallback that workspace_init would pick).
type imageSettingResponse struct {
	Key         string          `json:"key"`
	Configured  *settingRecord  `json:"configured,omitempty"`
	Effective   string          `json:"effective"`
	Suggestions []dockerHubTag  `json:"suggestions,omitempty"`
}

type dockerHubTag struct {
	Name        string `json:"name"`
	LastUpdated string `json:"last_updated,omitempty"`
}

// fetchDockerHubTags returns up to `max` tags for a repository,
// newest-first. Best-effort: a Docker Hub outage returns nil + the
// error so the caller can render the UI without suggestions but with
// the configured/effective value still visible.
func fetchDockerHubTags(repo string, max int) ([]dockerHubTag, error) {
	url := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/tags/?page_size=%d&ordering=last_updated", repo, max)
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker hub %s: HTTP %d", repo, resp.StatusCode)
	}
	var parsed dockerHubTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	out := make([]dockerHubTag, 0, len(parsed.Results))
	for _, t := range parsed.Results {
		out = append(out, dockerHubTag{Name: t.Name, LastUpdated: t.LastUpdated})
	}
	return out, nil
}

// imageKindToRepo maps the well-known setting key to the Docker Hub
// repository the UI should fetch tag suggestions from. Centralised so
// the same mapping is used by GET (suggestions) and POST (validation
// — currently free-form so we don't reject, but kept for future use).
var imageKindToRepo = map[string]string{
	settingDefaultGitopsImage:    "bitswan/gitops",
	settingDefaultDashboardImage: "bitswan/workspace-dashboard",
}

// handleAdminDefaultImagesGet returns the configured defaults +
// dropdown suggestions for both gitops and dashboard images.
func (s *Server) handleAdminDefaultImagesGet(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for _, key := range []string{settingDefaultGitopsImage, settingDefaultDashboardImage} {
		entry := imageSettingResponse{Key: key}
		if rec, _ := dbGetSettingRecord(key); rec != nil {
			entry.Configured = rec
			entry.Effective = rec.Value
		} else {
			// Fall back to what workspace_init would pick if the admin
			// hadn't set anything — surface it so the UI can show "(default
			// from Docker Hub: <tag>)" instead of just blank.
			switch key {
			case settingDefaultGitopsImage:
				if img, err := dockerhub.ResolveGitopsImage(false); err == nil {
					entry.Effective = img
				}
			case settingDefaultDashboardImage:
				if img, err := dockerhub.ResolveDashboardImage(false); err == nil {
					entry.Effective = img
				}
			}
		}
		if repo, ok := imageKindToRepo[key]; ok {
			if tags, err := fetchDockerHubTags(repo, 20); err == nil {
				entry.Suggestions = tags
			}
		}
		out[key] = entry
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// setDefaultImagesRequest is the POST body. Each field is OPTIONAL:
// missing keys leave the setting alone, empty strings clear it.
type setDefaultImagesRequest struct {
	GitopsImage    *string `json:"gitops_image,omitempty"`
	DashboardImage *string `json:"dashboard_image,omitempty"`
}

// handleAdminDefaultImagesPost persists the admin's chosen image
// strings. No validation: free-form, by design — the admin is
// trusted to set whatever they want (custom tags, private registry
// paths, etc.). Setting an empty string clears the override.
func (s *Server) handleAdminDefaultImagesPost(w http.ResponseWriter, r *http.Request, email string) {
	var req setDefaultImagesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	apply := func(key string, val *string) error {
		if val == nil {
			return nil
		}
		v := strings.TrimSpace(*val)
		if v == "" {
			return dbDeleteSetting(key)
		}
		return dbSetSetting(key, v, email)
	}
	if err := apply(settingDefaultGitopsImage, req.GitopsImage); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if err := apply(settingDefaultDashboardImage, req.DashboardImage); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// handleUpdateWorkspace pulls the current default images + recreates
// the workspace's gitops + dashboard containers in place. Owner-only
// since this restarts running automations. Returns an NDJSON stream
// of progress events identical to the create flow.
func (s *Server) handleUpdateWorkspace(w http.ResponseWriter, r *http.Request, email, workspaceName string) {
	_, groups := identityFromHeaders(r)
	serverOwner, _ := callerIsServerOwner(email, r)
	if !callerOwnsWorkspace(email, groups, serverOwner, workspaceName) {
		http.Error(w, `{"error":"only the workspace owner can update it"}`, http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	writeMu := sync.Mutex{}
	writeEvent := func(payload map[string]any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		line, _ := json.Marshal(payload)
		_, _ = w.Write(append(line, '\n'))
		if flusher != nil {
			flusher.Flush()
		}
	}
	writeEvent(map[string]any{"event": "start", "message": "Updating " + workspaceName + "…"})

	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		homeDir = os.Getenv("HOME")
	}
	deploymentDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName, "deployment")
	if _, err := os.Stat(deploymentDir); os.IsNotExist(err) {
		writeEvent(map[string]any{"event": "error", "error": "workspace deployment directory not found"})
		return
	}

	// Run docker compose pull + up -d on each compose file the workspace
	// owns. The compose files reference image tags, not specific digests,
	// so changing the SHA behind a tag (e.g. by rebuilding bailey-dev)
	// requires a pull to pick up the new manifest before up -d recreates
	// the containers.
	composeUnits := []struct {
		project string
		args    []string
	}{
		{workspaceName + "-site", []string{"-p", workspaceName + "-site"}},
	}
	dashboardCompose := filepath.Join(deploymentDir, "docker-compose-dashboard.yml")
	if _, err := os.Stat(dashboardCompose); err == nil {
		composeUnits = append(composeUnits, struct {
			project string
			args    []string
		}{
			project: workspaceName + "-dashboard",
			args:    []string{"-p", workspaceName + "-dashboard", "-f", "docker-compose-dashboard.yml"},
		})
	}

	pipeAndRun := func(action string, args []string) error {
		cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
		cmd.Dir = deploymentDir
		pr, pw := io.Pipe()
		cmd.Stdout = pw
		cmd.Stderr = pw
		go func() {
			buf := make([]byte, 4096)
			var partial []byte
			for {
				n, err := pr.Read(buf)
				if n > 0 {
					data := append(partial, buf[:n]...)
					lines := strings.Split(string(data), "\n")
					partial = []byte(lines[len(lines)-1])
					for _, line := range lines[:len(lines)-1] {
						if strings.TrimSpace(line) == "" {
							continue
						}
						writeEvent(map[string]any{"event": "log", "stream": action, "message": line})
					}
				}
				if err != nil {
					if len(partial) > 0 {
						writeEvent(map[string]any{"event": "log", "stream": action, "message": string(partial)})
					}
					return
				}
			}
		}()
		err := cmd.Run()
		_ = pw.Close()
		return err
	}

	for _, unit := range composeUnits {
		writeEvent(map[string]any{"event": "log", "stream": "info", "message": "Pulling images for " + unit.project + "…"})
		if err := pipeAndRun("pull", append([]string{}, append(unit.args, "pull")...)); err != nil {
			writeEvent(map[string]any{"event": "log", "stream": "warn", "message": fmt.Sprintf("pull %s failed: %v (continuing — up -d may still recreate from local image)", unit.project, err)})
		}
		writeEvent(map[string]any{"event": "log", "stream": "info", "message": "Recreating containers for " + unit.project + "…"})
		if err := pipeAndRun("up", append([]string{}, append(unit.args, "up", "-d")...)); err != nil {
			writeEvent(map[string]any{"event": "error", "error": fmt.Sprintf("up -d %s failed: %v", unit.project, err)})
			return
		}
	}

	writeEvent(map[string]any{"event": "done", "message": "Workspace updated."})
}
