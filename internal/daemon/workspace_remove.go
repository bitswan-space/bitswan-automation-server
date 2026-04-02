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
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
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

	// 3. Remove GitOps and Editor docker containers and volumes
	fmt.Fprintln(writer, "Removing docker containers and volumes...")
	workspacesFolder := filepath.Join(bitswanPath, "workspaces")
	dockerComposePath := filepath.Join(workspacesFolder, workspaceName, "deployment")
	// Docker compose project names must be lowercase
	projectName := strings.ToLower(workspaceName)

	if _, err := os.Stat(dockerComposePath); os.IsNotExist(err) {
		fmt.Fprintf(writer, "Warning: Deployment directory %s does not exist, skipping docker compose down.\n", dockerComposePath)
		// Still try to remove containers by project name in case they exist
		for _, projSuffix := range []string{"-site", "-editor"} {
			cmd := exec.Command("docker", "compose", "-p", projectName+projSuffix, "down", "--volumes")
			cmd.Stdout = writer
			cmd.Stderr = writer
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(writer, "Warning: Failed to remove containers for project %s%s: %v\n", projectName, projSuffix, err)
			}
		}
	} else {
		composeArgs := [][]string{
			{"-p", projectName + "-site", "down", "--volumes"},
		}
		editorComposePath := filepath.Join(dockerComposePath, "docker-compose-editor.yml")
		if _, err := os.Stat(editorComposePath); err == nil {
			composeArgs = append(composeArgs, []string{"-f", "docker-compose-editor.yml", "-p", projectName + "-editor", "down", "--volumes"})
		}
		for _, args := range composeArgs {
			cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
			cmd.Dir = dockerComposePath
			cmd.Stdout = writer
			cmd.Stderr = writer
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(writer, "Warning: Failed to remove docker containers and volumes (%v): %v\n", args, err)
			}
		}
	}
	fmt.Fprintln(writer, "Docker containers and volumes removed successfully.")

	// 4. Remove images used by docker-compose
	fmt.Fprintln(writer, "Removing images used by docker-compose...")
	composeFiles := []string{"docker-compose.yml"}
	editorComposePath := filepath.Join(dockerComposePath, "docker-compose-editor.yml")
	if _, err := os.Stat(editorComposePath); err == nil {
		composeFiles = append(composeFiles, "docker-compose-editor.yml")
	}
	for _, composeFile := range composeFiles {
		removeImagesFromComposeFile(filepath.Join(dockerComposePath, composeFile), writer)
	}
	fmt.Fprintln(writer, "Image removal process completed.")

	// 5. Remove traefik files (before removing workspace folder so metadata is available)
	// Run in background - don't wait for it to complete since it's not critical
	fmt.Fprintln(writer, "Removing traefik files (running in background)...")
	go func() {
		// Run Traefik deletion in background - don't block main deletion process
		traefikapi.DeleteTraefikRecordsWithWriter(workspaceName, writer)
	}()
	// Continue immediately - don't wait for Traefik cleanup

	// 6. Remove the gitops folder

	workspaceDir := filepath.Join(workspacesFolder, workspaceName)
	if _, err := os.Stat(workspaceDir); os.IsNotExist(err) {
		fmt.Fprintf(writer, "Warning: Workspace directory %s does not exist, nothing to remove.\n", workspaceDir)
	} else {
		fmt.Fprintln(writer, "Removing gitops folder...")
		cmd := exec.Command("rm", "-rf", workspaceName)
		cmd.Dir = workspacesFolder
		cmd.Stdout = writer
		cmd.Stderr = writer
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(writer, "Warning: Failed to remove gitops folder: %v\n", err)
		} else {
			fmt.Fprintln(writer, "GitOps folder removed successfully.")
		}
	}

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

func removeImagesFromComposeFile(composeFilePath string, writer io.Writer) {
	data, err := os.ReadFile(composeFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(writer, "Warning: %s not found, skipping image removal\n", composeFilePath)
		} else {
			fmt.Fprintf(writer, "Warning: error reading %s: %v\n", composeFilePath, err)
		}
		return
	}
	var compose Compose
	if err := yaml.Unmarshal(data, &compose); err != nil {
		fmt.Fprintf(writer, "Warning: error unmarshalling %s: %v\n", composeFilePath, err)
		return
	}
	for _, service := range compose.Services {
		if service.Image == "" {
			continue
		}
		exists, err := checkContainerExists(service.Image)
		if err != nil {
			fmt.Fprintf(writer, "Warning: Error checking if image exists: %v. Continuing with removal.\n", err)
			continue
		}
		if exists {
			fmt.Fprintf(writer, "Image %s is still in use by a different container. Skipping deletion.\n", service.Image)
			continue
		}
		if err := deleteDockerImage(service.Image, writer); err != nil {
			fmt.Fprintf(writer, "Warning: Failed to delete docker image %s: %v. Continuing with removal.\n", service.Image, err)
		} else {
			fmt.Fprintf(writer, "Deleted image: %s\n", service.Image)
		}
	}
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
