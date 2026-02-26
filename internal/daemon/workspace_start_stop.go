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
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// WorkspaceStartStopRequest represents the request body for start/stop/restart
type WorkspaceStartStopRequest struct {
	Workspace       string `json:"workspace"`
	AutomationsOnly bool   `json:"automations_only"`
}

func (s *Server) handleWorkspaceStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WorkspaceStartStopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace name is required", http.StatusBadRequest)
		return
	}

	s.runStreamingHandler(w, func(writer io.Writer) error {
		return s.runWorkspaceStart(req.Workspace, req.AutomationsOnly, writer)
	})
}

func (s *Server) handleWorkspaceStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WorkspaceStartStopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace name is required", http.StatusBadRequest)
		return
	}

	s.runStreamingHandler(w, func(writer io.Writer) error {
		return s.runWorkspaceStop(req.Workspace, req.AutomationsOnly, writer)
	})
}

func (s *Server) handleWorkspaceRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WorkspaceStartStopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Workspace == "" {
		writeJSONError(w, "workspace name is required", http.StatusBadRequest)
		return
	}

	s.runStreamingHandler(w, func(writer io.Writer) error {
		return s.runWorkspaceRestart(req.Workspace, req.AutomationsOnly, writer)
	})
}

// runStreamingHandler sets up NDJSON streaming with stdout redirection and runs the given function.
func (s *Server) runStreamingHandler(w http.ResponseWriter, fn func(writer io.Writer) error) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	stdoutMutex.Lock()
	oldStdout := os.Stdout
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		stdoutMutex.Unlock()
		WriteLogEntry(w, "error", fmt.Sprintf("Failed to create pipe: %v", err))
		return
	}

	os.Stdout = wPipe
	stdoutMutex.Unlock()

	defer func() {
		stdoutMutex.Lock()
		os.Stdout = oldStdout
		stdoutMutex.Unlock()
		rPipe.Close()
		wPipe.Close()
	}()

	logWriter := NewLogStreamWriter(w, "info")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, readErr := rPipe.Read(buf)
			if n > 0 {
				logWriter.Write(buf[:n])
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				WriteLogEntry(w, "error", fmt.Sprintf("Error reading from pipe: %v", readErr))
				break
			}
		}
	}()

	err = fn(wPipe)
	wPipe.Close()
	wg.Wait()

	if err != nil {
		WriteLogEntry(w, "error", fmt.Sprintf("Operation failed: %v", err))
	}
}

func (s *Server) runWorkspaceStart(workspaceName string, automationsOnly bool, writer io.Writer) error {
	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		homeDir = os.Getenv("HOME")
	}
	deploymentDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName, "deployment")

	if !automationsOnly {
		// 1. Start the GitOps container
		fmt.Fprintln(writer, "Starting GitOps container...")
		projectName := strings.ToLower(workspaceName) + "-site"
		cmd := exec.Command("docker", "compose", "-p", projectName, "up", "-d", "--pull", "missing")
		cmd.Dir = deploymentDir
		cmd.Stdout = writer
		cmd.Stderr = writer
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to start GitOps container: %w", err)
		}
		fmt.Fprintln(writer, "GitOps container started.")

		// 2. Wait for GitOps to become reachable
		fmt.Fprintln(writer, "Waiting for GitOps to become reachable...")
		if err := waitForGitops(metadata, workspaceName, writer); err != nil {
			return fmt.Errorf("GitOps did not become reachable: %w", err)
		}
		fmt.Fprintln(writer, "GitOps is reachable.")

		// 3. Start editor if enabled
		fmt.Fprintln(writer, "Starting editor service...")
		if err := s.startEditorService(workspaceName); err != nil {
			// Non-fatal: editor might not be enabled
			fmt.Fprintf(writer, "Note: Editor service not started: %v\n", err)
		} else {
			fmt.Fprintln(writer, "Editor service started.")
		}
	}

	// 4. Deploy all automations
	fmt.Fprintln(writer, "Deploying automations...")
	if err := deployAutomations(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer); err != nil {
		return fmt.Errorf("failed to deploy automations: %w", err)
	}
	fmt.Fprintln(writer, "Automations deployed successfully.")

	fmt.Fprintln(writer, "Workspace start completed.")
	return nil
}

func (s *Server) runWorkspaceStop(workspaceName string, automationsOnly bool, writer io.Writer) error {
	// 1. Stop all automations (tolerate errors if GitOps is already down)
	fmt.Fprintln(writer, "Stopping automations...")
	automationSet, err := automations.GetAutomations(workspaceName)
	if err != nil {
		fmt.Fprintf(writer, "Warning: Could not retrieve automations: %v. Continuing...\n", err)
	} else {
		for _, a := range automationSet {
			fmt.Fprintf(writer, "Stopping automation %s...\n", a.Name)
			if err := a.Stop(); err != nil {
				fmt.Fprintf(writer, "Warning: Failed to stop automation %s: %v\n", a.Name, err)
			}
		}
		fmt.Fprintln(writer, "Automations stopped.")
	}

	if automationsOnly {
		fmt.Fprintln(writer, "Workspace stop completed (automations only).")
		return nil
	}

	// 2. Stop editor if enabled
	fmt.Fprintln(writer, "Stopping editor service...")
	if err := s.stopEditorService(workspaceName); err != nil {
		fmt.Fprintf(writer, "Note: Editor service not stopped: %v\n", err)
	} else {
		fmt.Fprintln(writer, "Editor service stopped.")
	}

	// 3. Stop the GitOps container
	fmt.Fprintln(writer, "Stopping GitOps container...")
	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		homeDir = os.Getenv("HOME")
	}
	deploymentDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName, "deployment")
	projectName := strings.ToLower(workspaceName) + "-site"
	cmd := exec.Command("docker", "compose", "-p", projectName, "down")
	cmd.Dir = deploymentDir
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop GitOps container: %w", err)
	}
	fmt.Fprintln(writer, "GitOps container stopped.")

	fmt.Fprintln(writer, "Workspace stop completed.")
	return nil
}

func (s *Server) runWorkspaceRestart(workspaceName string, automationsOnly bool, writer io.Writer) error {
	fmt.Fprintln(writer, "Restarting workspace...")

	if err := s.runWorkspaceStop(workspaceName, automationsOnly, writer); err != nil {
		return fmt.Errorf("stop phase failed: %w", err)
	}

	if err := s.runWorkspaceStart(workspaceName, automationsOnly, writer); err != nil {
		return fmt.Errorf("start phase failed: %w", err)
	}

	return nil
}

// waitForGitops polls the GitOps root endpoint until it responds or times out.
func waitForGitops(metadata config.WorkspaceMetadata, workspaceName string, writer io.Writer) error {
	healthURL := metadata.GitopsURL + "/"
	healthURL = automations.TransformURLForDaemon(healthURL, workspaceName)

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(60 * time.Second)

	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", healthURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create health check request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+metadata.GitopsSecret)

		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("timed out after 60s waiting for GitOps to become reachable at %s", metadata.GitopsURL)
}
