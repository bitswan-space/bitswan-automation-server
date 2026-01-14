package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// Compose represents docker-compose structure for parsing
type Compose struct {
	Services map[string]struct {
		Image string `yaml:"image"`
	} `yaml:"services"`
}

// RunWorkspaceRemove runs the workspace remove logic
func RunWorkspaceRemove(workspaceName string, writer io.Writer) error {
	// Get the real user's home directory (host home, not container home)
	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		// Fallback to HOME if we can't determine the real user
		homeDir = os.Getenv("HOME")
	}
	bitswanPath := filepath.Join(homeDir, ".config", "bitswan")

	// 1. Ask user for confirmation (handled by CLI, but we need to check automations first)
	// Use public URL during deletion since containers may be stopping/stopped
	automationSet, err := automations.GetListAutomationsWithOptions(workspaceName, true)
	var skipAutomationRemoval bool
	if err != nil {
		// Check if this is a WorkspaceMisbehavingError
		var misbehavingErr *automations.WorkspaceMisbehavingError
		if errors.As(err, &misbehavingErr) {
			fmt.Fprintf(writer, "This workspace seems to be misbehaving. Cannot detect which automations are running within it. Would you like to stop it anyway with the risk of leaving some orphaned automations running? [y/N]: ")
			// Note: User confirmation is handled by CLI, so we'll skip for now
			skipAutomationRemoval = true
			automationSet = nil
		} else {
			// For any other error, just skip automation removal and continue
			fmt.Fprintf(writer, "Warning: Cannot connect to workspace to retrieve automations (%v). Continuing with removal process.\n", err)
			skipAutomationRemoval = true
			automationSet = nil
		}
	}

	// 2. Remove the automations from the server
	if !skipAutomationRemoval && len(automationSet) > 0 {
		fmt.Fprintln(writer, "Removing automations...")
		for _, automation := range automationSet {
			err := automation.Remove()
			if err != nil {
				return fmt.Errorf("error removing automation %s: %w", automation.Name, err)
			}
		}
		fmt.Fprintln(writer, "Automations removed successfully.")
	} else if skipAutomationRemoval {
		fmt.Fprintln(writer, "Skipping automation removal due to workspace misbehavior.")
	} else {
		fmt.Fprintln(writer, "No automations to remove.")
	}

	// 3. Remove docker container and volume
	fmt.Fprintln(writer, "Removing docker containers and volumes...")
	workspacesFolder := filepath.Join(bitswanPath, "workspaces")
	dockerComposePath := filepath.Join(workspacesFolder, workspaceName, "deployment")
	// Docker compose project names must be lowercase
	projectName := strings.ToLower(workspaceName) + "-site"
	cmd := exec.Command("docker", "compose", "-p", projectName, "down", "--volumes")
	cmd.Dir = dockerComposePath
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove docker containers and volumes: %w", err)
	}
	fmt.Fprintln(writer, "Docker containers and volumes removed successfully.")

	// 4. Remove images used by docker-compose
	fmt.Fprintln(writer, "Removing images used by docker-compose...")
	dockerComposeFilePath := filepath.Join(dockerComposePath, "docker-compose.yml")
	data, err := os.ReadFile(dockerComposeFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(writer, "Warning: docker-compose.yml not found, skipping image removal")
		} else {
			fmt.Fprintf(writer, "error reading docker-compose file: %v\n", err)
		}
	} else {
		var compose Compose
		err = yaml.Unmarshal(data, &compose)
		if err != nil {
			return fmt.Errorf("error unmarshalling docker-compose file: %w", err)
		}

		for _, service := range compose.Services {
			if service.Image != "" {
				exists, err := checkContainerExists(service.Image)
				if err != nil {
					fmt.Fprintf(writer, "Warning: Error checking if image exists: %v. Continuing with removal.\n", err)
					continue
				}

				if !exists {
					err = deleteDockerImage(service.Image, writer)
					if err != nil {
						// Don't fail the entire removal if image deletion fails (image might not exist)
						fmt.Fprintf(writer, "Warning: Failed to delete docker image %s: %v. Continuing with removal.\n", service.Image, err)
					} else {
						fmt.Fprintf(writer, "Deleted image: %s\n", service.Image)
					}
				} else {
					fmt.Fprintf(writer, "Image %s is still in use by a different container. Skipping deletion.\n", service.Image)
				}
			}
		}
		fmt.Fprintln(writer, "Image removal process completed.")
	}

	// 5. Remove caddy files (before removing workspace folder so metadata is available)
	// Run in background - don't wait for it to complete since it's not critical
	fmt.Fprintln(writer, "Removing caddy files (running in background)...")
	go func() {
		// Run Caddy deletion in background - don't block main deletion process
		caddyapi.DeleteCaddyRecordsWithWriter(workspaceName, writer)
	}()
	// Continue immediately - don't wait for Caddy cleanup

	// 6. Remove the gitops folder
	fmt.Fprintln(writer, "Removing gitops folder...")
	cmd = exec.Command("rm", "-rf", workspaceName)
	cmd.Dir = workspacesFolder
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove gitops folder: %w", err)
	}
	fmt.Fprintln(writer, "GitOps folder removed successfully.")

	// 7. Remove entries from /etc/hosts
	fmt.Fprintln(writer, "Removing entries from /etc/hosts...")
	err = deleteHostsEntry(workspaceName, writer)
	if err != nil {
		return fmt.Errorf("error removing entries from /etc/hosts: %w", err)
	}
	fmt.Fprintln(writer, "Entries removed from /etc/hosts successfully.")

	// Note: Workspace list sync to AOC is done by the MQTT handler AFTER publishing the result
	// This ensures the frontend receives the result before any potential connection issues from sync

	fmt.Fprintln(writer, "Workspace removal completed.")
	return nil
}

func checkContainerExists(imageName string) (bool, error) {
	cmd := exec.Command("docker", "ps", "-a", "--filter", "ancestor="+imageName, "--format", "{{.ID}}")

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return false, err
	}

	// Trim space and check if the output is empty
	output := strings.TrimSpace(out.String())
	return output != "", nil
}

func deleteDockerImage(image string, writer io.Writer) error {
	// First check if the image exists
	cmd := exec.Command("docker", "images", "-q", image)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error checking if image exists: %w", err)
	}

	// If image doesn't exist, return a specific error that we can handle
	imageID := strings.TrimSpace(out.String())
	if imageID == "" {
		return fmt.Errorf("image %s does not exist", image)
	}

	// Image exists, try to delete it
	cmd = exec.Command("docker", "rmi", image)
	cmd.Stdout = writer
	cmd.Stderr = writer
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("error deleting image %s: %w", image, err)
	}
	return nil
}

func deleteHostsEntry(workspaceName string, writer io.Writer) error {
	hostsFilePath := "/etc/hosts"
	input, err := os.ReadFile(hostsFilePath)
	if err != nil {
		fmt.Fprintf(writer, "failed to read /etc/hosts: %v\n", err)
		return nil
	}

	lines := strings.Split(string(input), "\n")
	var outputLines []string

	// Define the entries to be removed
	hostsEntries := []string{
		"127.0.0.1 " + workspaceName + "-gitops.bitswan.local",
		"127.0.0.1 " + workspaceName + "-editor.bitswan.local",
	}

	found := false
	for _, entry := range hostsEntries {
		if exec.Command("grep", "-wq", entry, "/etc/hosts").Run() == nil {
			found = true
			break
		}
	}

	// No entries found to remove
	if !found {
		fmt.Fprintln(writer, "No entries found in /etc/hosts to remove.")
		return nil
	}

	// Filter out the lines that match the entries
	for _, line := range lines {
		shouldRemove := false
		for _, entry := range hostsEntries {
			if strings.Contains(line, entry) {
				shouldRemove = true
				break
			}
		}
		if !shouldRemove {
			outputLines = append(outputLines, line)
		}
	}

	// Write the updated content back to /etc/hosts
	output := strings.Join(outputLines, "\n")
	cmd := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' | tee %s", output, hostsFilePath))
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(writer, "failed to write to /etc/hosts: %v\n", err)
		return nil
	}
	return nil
}
