package daemon

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

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

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if len(fs.Args()) < 1 {
		return fmt.Errorf("workspace name is required")
	}

	workspaceName := fs.Args()[0]
	// Use HOST_HOME if available (when running in daemon container), otherwise use HOME
	homeDir := os.Getenv("HOST_HOME")
	if homeDir == "" {
		homeDir = os.Getenv("HOME")
	}
	bitswanPath := filepath.Join(homeDir, ".config", "bitswan") + "/"

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

	if trustCA {
		fmt.Println("Updating certificate configuration...")
		if err := editorService.UpdateCertificates(trustCA); err != nil {
			return fmt.Errorf("failed to update certificates: %w", err)
		}
	}

	if editorImage != "" {
		fmt.Printf("Updating Editor service with custom image: %s\n", editorImage)
		if err := editorService.UpdateImage(editorImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		fmt.Println("Updating Editor service to latest version...")
		if err := editorService.UpdateToLatestWithStaging(staging); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
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
	codeserverConfigDir := filepath.Join(workspacePath, "codeserver-config")
	gitopsWorkspace := filepath.Join(workspacePath, "workspace")
	sshDir := filepath.Join(workspacePath, "ssh")

	// We're running as root in the daemon, so no need for sudo
	// Fix permissions on all directories that are mounted into the container
	dirs := []struct {
		name string
		path string
	}{
		{"secrets", secretsDir},
		{"codeserver-config", codeserverConfigDir},
		{"workspace", gitopsWorkspace},
		{"ssh", sshDir},
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

// updateKafkaService updates the Kafka service for a specific workspace
func updateKafkaService(workspaceName, kafkaImage, zookeeperImage string) error {
	kafkaService, err := services.NewKafkaService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}

	if !kafkaService.IsEnabled() {
		fmt.Printf("Kafka service is not enabled for workspace '%s', skipping update\n", workspaceName)
		return nil
	}

	fmt.Println("Stopping current Kafka containers...")
	if err := kafkaService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop current Kafka containers: %w", err)
	}

	if kafkaImage != "" || zookeeperImage != "" {
		bitswanKafkaImage := kafkaImage
		if bitswanKafkaImage == "" {
			bitswanKafkaImage = "bitswan/bitswan-kafka:latest"
		}

		bitswanZookeeperImage := zookeeperImage
		if bitswanZookeeperImage == "" {
			bitswanZookeeperImage = "bitswan/bitswan-zookeeper:latest"
		}

		fmt.Printf("Updating Kafka service with custom images:\n")
		fmt.Printf("  Kafka: %s\n", bitswanKafkaImage)
		fmt.Printf("  Zookeeper: %s\n", bitswanZookeeperImage)

		if err := kafkaService.UpdateImages(bitswanKafkaImage, bitswanZookeeperImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		fmt.Println("Updating Kafka service to latest versions...")
		if err := kafkaService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest versions: %w", err)
		}
	}

	fmt.Println("Starting Kafka containers with new images...")
	if err := kafkaService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start Kafka containers: %w", err)
	}

	return nil
}

// updateCouchDBService updates the CouchDB service for a specific workspace
func updateCouchDBService(workspaceName, couchdbImage string) error {
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	if !couchdbService.IsEnabled() {
		fmt.Printf("CouchDB service is not enabled for workspace '%s', skipping update\n", workspaceName)
		return nil
	}

	fmt.Println("Stopping current CouchDB container...")
	if err := couchdbService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop current CouchDB container: %w", err)
	}

	if couchdbImage != "" {
		fmt.Printf("Updating CouchDB service with custom image: %s\n", couchdbImage)
		if err := couchdbService.UpdateImage(couchdbImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		fmt.Println("Updating CouchDB service to latest version...")
		if err := couchdbService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
	}

	fmt.Println("Starting CouchDB container with new image...")
	if err := couchdbService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start CouchDB container: %w", err)
	}

	return nil
}

