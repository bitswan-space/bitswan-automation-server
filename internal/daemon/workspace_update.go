package daemon

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
	"github.com/bitswan-space/bitswan-workspaces/internal/workspace"
)

// runWorkspaceUpdate runs the workspace update logic with stdout already redirected
func (s *Server) runWorkspaceUpdate(args []string) error {
	// Parse flags
	fs := flag.NewFlagSet("workspace-update", flag.ContinueOnError)
	gitopsImage := fs.String("gitops-image", "", "")
	editorImage := fs.String("editor-image", "", "")
	kafkaImage := fs.String("kafka-image", "", "")
	zookeeperImage := fs.String("zookeeper-image", "", "")
	couchdbImage := fs.String("couchdb-image", "", "")
	staging := fs.Bool("staging", false, "")
	trustCA := fs.Bool("trust-ca", false, "")
	devMode := fs.Bool("dev-mode", false, "")
	disableDevMode := fs.Bool("disable-dev-mode", false, "")
	gitopsDevSourceDir := fs.String("gitops-dev-source-dir", "", "")
	editorDevSourceDir := fs.String("editor-dev-source-dir", "", "")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if len(fs.Args()) < 1 {
		return fmt.Errorf("workspace name is required")
	}

	workspaceName := fs.Args()[0]
	// Use HOME directly - inside container this is /root, on host it's the user's home
	// The workspace files are mounted at /root/.config/bitswan in the container
	homeDir := os.Getenv("HOME")
	bitswanPath := filepath.Join(homeDir, ".config", "bitswan") + "/"
	workspacePath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)
	metadataPath := filepath.Join(workspacePath, "metadata.yaml")

	// Handle dev mode settings - update metadata if dev mode flags are provided
	if *devMode || *disableDevMode || *gitopsDevSourceDir != "" || *editorDevSourceDir != "" {
		fmt.Println("Updating dev mode settings...")
		metadata, err := config.GetWorkspaceMetadata(workspaceName)
		if err != nil {
			return fmt.Errorf("failed to read workspace metadata: %w", err)
		}

		if *devMode {
			metadata.DevMode = true
			fmt.Println("Dev mode enabled")
		}
		if *disableDevMode {
			metadata.DevMode = false
			// Clear dev source directories when disabling dev mode
			metadata.GitopsDevSourceDir = nil
			metadata.EditorDevSourceDir = nil
			fmt.Println("Dev mode disabled")
		}
		if *gitopsDevSourceDir != "" {
			metadata.GitopsDevSourceDir = gitopsDevSourceDir
			metadata.DevMode = true
			fmt.Printf("GitOps dev source directory set to: %s\n", *gitopsDevSourceDir)
		}
		if *editorDevSourceDir != "" {
			metadata.EditorDevSourceDir = editorDevSourceDir
			metadata.DevMode = true
			fmt.Printf("Editor dev source directory set to: %s\n", *editorDevSourceDir)
		}

		if err := metadata.SaveToFile(metadataPath); err != nil {
			return fmt.Errorf("failed to save workspace metadata: %w", err)
		}
	}

	// 1. Create or update examples directory
	fmt.Println("Ensuring examples are up to date...")
	err := ensureExamples(bitswanPath, true)
	if err != nil {
		return fmt.Errorf("failed to download examples: %w", err)
	}
	fmt.Println("Examples are up to date!")

	// 2. Update Docker images and docker-compose file
	fmt.Println("Updating Docker images and docker-compose file...")
	if err := workspace.UpdateWorkspaceDeployment(workspaceName, *gitopsImage, *staging, *trustCA); err != nil {
		return fmt.Errorf("failed to update workspace deployment: %w", err)
	}
	fmt.Println("Gitops service restarted!")

	// 3. Update services if they are enabled
	fmt.Println("Checking for enabled services to update...")
	if err := updateServices(workspaceName, *editorImage, *kafkaImage, *zookeeperImage, *couchdbImage, *staging, *trustCA); err != nil {
		fmt.Printf("Warning: some services failed to update: %v\n", err)
	}

	fmt.Printf("Gitops %s updated successfully!\n", workspaceName)
	return nil
}

// updateServices updates all enabled services for the workspace
func updateServices(workspaceName, editorImage, kafkaImage, zookeeperImage, couchdbImage string, staging, trustCA bool) error {
	// Always try to update editor service if enabled
	fmt.Println("Checking editor service...")
	if err := updateEditorService(workspaceName, editorImage, staging, trustCA); err != nil {
		fmt.Printf("Warning: failed to update editor service: %v\n", err)
	} else {
		fmt.Println("Editor service updated successfully!")
	}

	// Always try to update Kafka service if enabled
	fmt.Println("Checking Kafka service...")
	if err := updateKafkaService(workspaceName, kafkaImage, zookeeperImage); err != nil {
		fmt.Printf("Warning: failed to update Kafka service: %v\n", err)
	} else {
		fmt.Println("Kafka service updated successfully!")
	}

	// Always try to update CouchDB service if enabled
	fmt.Println("Checking CouchDB service...")
	if err := updateCouchDBService(workspaceName, couchdbImage); err != nil {
		fmt.Printf("Warning: failed to update CouchDB service: %v\n", err)
	} else {
		fmt.Println("CouchDB service updated successfully!")
	}

	return nil
}

// updateEditorService updates the editor service for a specific workspace
func updateEditorService(workspaceName, editorImage string, staging bool, trustCA bool) error {
	editorService, err := services.NewEditorService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}

	if !editorService.IsEnabled() {
		fmt.Printf("Editor service is not enabled for workspace '%s', skipping update\n", workspaceName)
		return nil
	}

	fmt.Println("Stopping current editor container...")
	if err := editorService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop current editor container: %w", err)
	}

	// Fix permissions before updating (daemon runs as root, so volumes may be root-owned)
	fmt.Println("Fixing volume permissions...")
	if err := fixEditorPermissions(workspaceName); err != nil {
		// Don't continue if permissions fix fails - this will cause container startup issues
		return fmt.Errorf("failed to fix permissions: %w", err)
	}

	// Regenerate the entire docker-compose file to propagate all configuration changes
	// (volumes, environment variables, images, dev mode settings, certificates, etc.) to existing workspaces
	fmt.Println("Regenerating editor docker-compose file...")
	if err := editorService.RegenerateDockerCompose(editorImage, staging, trustCA); err != nil {
		return fmt.Errorf("failed to regenerate editor docker-compose: %w", err)
	}

	fmt.Println("Starting editor container...")
	if err := editorService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start editor container: %w", err)
	}

	fmt.Println("Waiting for editor to be ready...")
	if err := editorService.WaitForEditorReady(); err != nil {
		return fmt.Errorf("editor failed to start properly: %w", err)
	}

	return nil
}

// fixEditorPermissions fixes ownership of editor service volumes
// Uses the host home directory (not the container's /root) since docker-compose runs on the host
func fixEditorPermissions(workspaceName string) error {
	// Get the host home directory from environment variable (set by daemon init)
	homeDir := os.Getenv("HOST_HOME")
	if homeDir == "" {
		// Fallback: if not set, try to detect if we're in container
		containerHome := os.Getenv("HOME")
		if containerHome == "/root" {
			// We're in the daemon container but HOST_HOME not set, use /root (bind mount)
			homeDir = "/root"
		} else {
			// Not in container, use GetRealUserHomeDir to handle sudo cases
			var err error
			homeDir, err = config.GetRealUserHomeDir()
			if err != nil {
				homeDir = os.Getenv("HOME")
			}
		}
	}

	workspacePath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)
	secretsDir := filepath.Join(workspacePath, "secrets")
	coderHomeDir := filepath.Join(workspacePath, "coder-home")
	gitopsWorkspace := filepath.Join(workspacePath, "workspace")

	// We're running as root in the daemon, so no need for sudo
	// Fix permissions on all directories that are mounted into the container
	dirs := []struct {
		name string
		path string
	}{
		{"secrets", secretsDir},
		{"coder-home", coderHomeDir},
		{"workspace", gitopsWorkspace},
	}

	for _, dir := range dirs {
		// Check if directory exists before trying to chown
		if _, err := os.Stat(dir.path); os.IsNotExist(err) {
			// Directory doesn't exist, create it with correct permissions
			if err := os.MkdirAll(dir.path, 0755); err != nil {
				return fmt.Errorf("failed to create %s directory: %w", dir.name, err)
			}
		}

		// Chown the directory and all its contents to 1000:1000
		chownCom := exec.Command("chown", "-R", "1000:1000", dir.path)
		output, err := chownCom.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to chown %s dir (%s): %w, output: %s", dir.name, dir.path, err, string(output))
		}

		// Set permissions: 755 for directories, 644 for files
		// This ensures the coder user (UID 1000) can read/write/execute directories and read/write files
		chmodCom := exec.Command("find", dir.path, "-type", "d", "-exec", "chmod", "755", "{}", "+")
		if output, err := chmodCom.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to chmod directories in %s (%s): %w, output: %s", dir.name, dir.path, err, string(output))
		}

		chmodCom = exec.Command("find", dir.path, "-type", "f", "-exec", "chmod", "644", "{}", "+")
		if output, err := chmodCom.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to chmod files in %s (%s): %w, output: %s", dir.name, dir.path, err, string(output))
		}

		fmt.Printf("Fixed permissions for %s directory\n", dir.name)
	}

	return nil
}

// updateKafkaService updates the Kafka service via the gitops API
func updateKafkaService(workspaceName, kafkaImage, zookeeperImage string) error {
	body := gitopsServiceRequest{
		KafkaImage: kafkaImage,
	}
	return callGitopsService(workspaceName, "kafka", "update", body)
}

// updateCouchDBService updates the CouchDB service via the gitops API
func updateCouchDBService(workspaceName, couchdbImage string) error {
	body := gitopsServiceRequest{
		Image: couchdbImage,
	}
	return callGitopsService(workspaceName, "couchdb", "update", body)
}

// callGitopsService sends a POST request to a gitops service endpoint.
func callGitopsService(workspaceName, serviceType, action string, body interface{}) error {
	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	gitopsPath := fmt.Sprintf("/services/%s/%s", serviceType, action)
	reqURL := fmt.Sprintf("%s%s", metadata.GitopsURL, gitopsPath)
	reqURL = automations.TransformURLForDaemon(reqURL, workspaceName)

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+metadata.GitopsSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request to gitops: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("gitops returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

