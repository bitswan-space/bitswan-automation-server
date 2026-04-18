package containermanager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
)

// Proxy is a filtering reverse proxy for the Docker socket.
// It restricts operations to containers belonging to a specific workspace.
type Proxy struct {
	workspaceName  string
	composeProject string
	socketPath     string // path to expose the proxy socket
	dockerSocket   string // path to the real Docker socket
}

// New creates a new container manager proxy.
func New(workspaceName, composeProject, socketPath, dockerSocket string) *Proxy {
	return &Proxy{
		workspaceName:  workspaceName,
		composeProject: composeProject,
		socketPath:     socketPath,
		dockerSocket:   dockerSocket,
	}
}

// ListenAndServe starts the proxy.
func (p *Proxy) ListenAndServe() error {
	// Remove stale socket
	os.Remove(p.socketPath)

	listener, err := net.Listen("unix", p.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.socketPath, err)
	}
	defer listener.Close()

	// Make socket world-accessible (gitops runs as user1000)
	os.Chmod(p.socketPath, 0666)

	// Create reverse proxy to Docker socket
	director := func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = "docker"
	}
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", p.dockerSocket)
		},
	}
	reverseProxy := &httputil.ReverseProxy{
		Director:  director,
		Transport: transport,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p.handleRequest(w, r, reverseProxy)
	})

	server := &http.Server{Handler: mux}
	log.Printf("Container manager proxy started: workspace=%s project=%s socket=%s",
		p.workspaceName, p.composeProject, p.socketPath)
	return server.Serve(listener)
}

func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy) {
	path := r.URL.Path

	// --- BLOCKED OPERATIONS ---

	// Block: create containers (unless from compose for this workspace)
	if r.Method == "POST" && strings.HasSuffix(path, "/containers/create") {
		if !p.isAllowedCreate(r) {
			log.Printf("BLOCKED: container create from %s — %s", r.RemoteAddr, path)
			http.Error(w, `{"message":"container creation not allowed through proxy"}`, http.StatusForbidden)
			return
		}
	}

	// Block: network create/connect/disconnect (prevents network escape)
	if strings.Contains(path, "/networks/") && r.Method != "GET" {
		log.Printf("BLOCKED: network mutation — %s %s", r.Method, path)
		http.Error(w, `{"message":"network operations not allowed through proxy"}`, http.StatusForbidden)
		return
	}

	// Block: volume create with host paths
	if strings.Contains(path, "/volumes/") && r.Method == "POST" {
		log.Printf("BLOCKED: volume creation — %s", path)
		http.Error(w, `{"message":"volume operations not allowed through proxy"}`, http.StatusForbidden)
		return
	}

	// --- FILTERED OPERATIONS ---

	// Filter: container list — inject workspace label filter
	if r.Method == "GET" && (path == "/containers/json" || path == "/v1.44/containers/json" || strings.HasSuffix(path, "/containers/json")) {
		p.injectWorkspaceFilter(r)
	}

	// Filter: events — inject workspace label filter
	if r.Method == "GET" && strings.Contains(path, "/events") {
		p.injectWorkspaceFilter(r)
	}

	// Validate: container-specific operations — check ownership
	// Skip for /containers/create (handled by isAllowedCreate above)
	if p.isContainerOperation(path) && r.Method != "GET" && !strings.HasSuffix(path, "/containers/create") {
		containerID := p.extractContainerID(path)
		if containerID != "" && containerID != "create" && !p.isContainerInWorkspace(containerID) {
			log.Printf("BLOCKED: operation on non-workspace container %s — %s %s",
				containerID, r.Method, path)
			http.Error(w, `{"message":"container does not belong to this workspace"}`, http.StatusForbidden)
			return
		}
	}

	// --- ALLOWED — forward to Docker ---
	proxy.ServeHTTP(w, r)
}

// injectWorkspaceFilter adds a label filter to restrict results to this workspace.
func (p *Proxy) injectWorkspaceFilter(r *http.Request) {
	q := r.URL.Query()
	filtersStr := q.Get("filters")
	var filters map[string][]string
	if filtersStr != "" {
		json.Unmarshal([]byte(filtersStr), &filters)
	}
	if filters == nil {
		filters = make(map[string][]string)
	}

	// Add workspace label filter
	wsFilter := fmt.Sprintf("gitops.workspace=%s", p.workspaceName)
	existing := filters["label"]
	found := false
	for _, f := range existing {
		if f == wsFilter {
			found = true
			break
		}
	}
	if !found {
		filters["label"] = append(existing, wsFilter)
	}

	filtersJSON, _ := json.Marshal(filters)
	q.Set("filters", string(filtersJSON))
	r.URL.RawQuery = q.Encode()
}

// isContainerOperation checks if the path targets a specific container.
func (p *Proxy) isContainerOperation(path string) bool {
	return strings.Contains(path, "/containers/") && !strings.HasSuffix(path, "/containers/json")
}

// extractContainerID extracts the container ID from a Docker API path.
func (p *Proxy) extractContainerID(path string) string {
	// Paths like /containers/{id}/start, /containers/{id}/json, etc.
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "containers" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// isContainerInWorkspace checks if a container belongs to this workspace.
func (p *Proxy) isContainerInWorkspace(containerID string) bool {
	conn, err := net.Dial("unix", p.dockerSocket)
	if err != nil {
		return false
	}
	defer conn.Close()

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://docker/containers/%s/json", containerID), nil)
	resp, err := http.DefaultTransport.(*http.Transport).RoundTrip(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	// Use a direct connection for the ownership check
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", p.dockerSocket)
			},
		},
	}
	checkResp, err := client.Get(fmt.Sprintf("http://docker/containers/%s/json", containerID))
	if err != nil || checkResp.StatusCode != 200 {
		return false
	}
	defer checkResp.Body.Close()

	body, _ := io.ReadAll(checkResp.Body)
	var info struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	json.Unmarshal(body, &info)

	// Check workspace label
	if info.Config.Labels["gitops.workspace"] == p.workspaceName {
		return true
	}

	// Also allow compose project containers (infra services may not have gitops.workspace)
	if info.Config.Labels["com.docker.compose.project"] == p.composeProject {
		return true
	}

	return false
}

// isAllowedCreate checks if a container create request is safe for this workspace.
func (p *Proxy) isAllowedCreate(r *http.Request) bool {
	// Read and re-buffer the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	var createReq struct {
		Labels     map[string]string `json:"Labels"`
		HostConfig struct {
			Binds       []string `json:"Binds"`
			NetworkMode string   `json:"NetworkMode"`
		} `json:"HostConfig"`
	}
	json.Unmarshal(body, &createReq)

	// Allow if the container has this workspace's label or compose project
	wsLabel := createReq.Labels["gitops.workspace"]
	project := createReq.Labels["com.docker.compose.project"]
	if wsLabel != "" && wsLabel != p.workspaceName {
		log.Printf("BLOCKED: create for wrong workspace %s (expected %s)", wsLabel, p.workspaceName)
		return false
	}
	if project != "" && !strings.HasPrefix(project, strings.ToLower(p.workspaceName)) {
		log.Printf("BLOCKED: create for wrong project %s (expected prefix %s)", project, p.workspaceName)
		return false
	}

	// Block dangerous host mounts — check for sensitive path prefixes, not just exact matches
	for _, bind := range createReq.HostConfig.Binds {
		src := strings.Split(bind, ":")[0]
		if src == "/" || src == "/var/run/docker.sock" {
			log.Printf("BLOCKED: dangerous host mount %s", bind)
			return false
		}
		// Block mounts under sensitive directories
		for _, prefix := range []string{"/etc", "/root", "/proc", "/sys", "/dev",
			"/var/run/docker", "/var/run/bitswan"} {
			if src == prefix || strings.HasPrefix(src, prefix+"/") {
				log.Printf("BLOCKED: sensitive host mount %s (matches %s)", bind, prefix)
				return false
			}
		}
	}

	// Block host/none network mode
	mode := createReq.HostConfig.NetworkMode
	if mode == "host" || mode == "none" {
		log.Printf("BLOCKED: network mode %s", mode)
		return false
	}

	// Block dangerous capabilities, privileged mode, and PID/IPC/UTS modes
	var fullReq map[string]interface{}
	json.Unmarshal(body, &fullReq)
	if hc, ok := fullReq["HostConfig"].(map[string]interface{}); ok {
		if priv, ok := hc["Privileged"].(bool); ok && priv {
			log.Printf("BLOCKED: privileged container")
			return false
		}
		// Block host PID/IPC/UTS namespace sharing
		if pidMode, ok := hc["PidMode"].(string); ok && pidMode == "host" {
			log.Printf("BLOCKED: PidMode host")
			return false
		}
		if ipcMode, ok := hc["IpcMode"].(string); ok && ipcMode == "host" {
			log.Printf("BLOCKED: IpcMode host")
			return false
		}
		if utsMode, ok := hc["UTSMode"].(string); ok && utsMode == "host" {
			log.Printf("BLOCKED: UTSMode host")
			return false
		}
		if caps, ok := hc["CapAdd"].([]interface{}); ok {
			for _, cap := range caps {
				capStr, _ := cap.(string)
				if capStr == "ALL" || capStr == "SYS_ADMIN" || capStr == "SYS_PTRACE" ||
					capStr == "SYS_MODULE" || capStr == "DAC_READ_SEARCH" ||
					capStr == "NET_ADMIN" || capStr == "SYS_RAWIO" {
					log.Printf("BLOCKED: dangerous capability %s", capStr)
					return false
				}
			}
		}
	}

	return true
}
