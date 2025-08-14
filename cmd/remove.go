package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/spf13/cobra"
)

// Docker compose only desired field
type Compose struct {
	Services map[string]struct {
		Image string `yaml:"image"`
	} `yaml:"services"`
}

// Metadata only desired field
type Metadata struct {
	EditorURL    *string `yaml:"editor-url"`
	GitOpsURL    string  `yaml:"gitops-url"`
	GitOpsSecret string  `yaml:"gitops-secret"`
}

// ANSI color codes for terminal
const (
	reset  = "\033[0m"
	yellow = "\033[33m"
)

func newRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "remove <workspace-name>",
		Short:        "bitswan workspace remove",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceName := args[0]
			err := removeGitops(workspaceName)
			if err != nil {
				return fmt.Errorf("error removing gitops: %w", err)
			}
			return nil
		},
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

// Function to delete a Docker image
func deleteDockerImage(image string) error {
	cmd := exec.Command("docker", "rmi", image) // -f forces deletion
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error deleting image %s: %s", image, out.String())
	}
	fmt.Printf("Deleted image: %s\n", image)
	return nil
}

// Function for deleting entries from /etc/hosts
func deleteHostsEntry(workspaceName string) error {
	hostsFilePath := "/etc/hosts"
	input, err := os.ReadFile(hostsFilePath)
	if err != nil {
		fmt.Printf(yellow+"failed to read /etc/hosts: %v\n"+reset, err)
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
		fmt.Println(yellow + "No entries found in /etc/hosts to remove." + reset)
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
	cmd := exec.Command("sudo", "tee", hostsFilePath)
	cmd.Stdin = strings.NewReader(output)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf(yellow+"failed to write to /etc/hosts with sudo: %v\n"+reset, err)
		return nil
	}
	return nil
}

func removeGitops(workspaceName string) error {
	bitswanPath := os.Getenv("HOME") + "/.config/bitswan/"
	gitopsPath := bitswanPath + "workspaces/" + workspaceName

	// 1. Ask user for confirmation
	var confirm string

	fmt.Println("Automations in this gitops will be removed and cannot be recovered.")

	metadataPath := gitopsPath + "/metadata.yaml"
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("error reading metadata file: %w", err)
	}

	var metadata Metadata
	err = yaml.Unmarshal(data, &metadata)
	if err != nil {
		return fmt.Errorf("error unmarshalling metadata: %w", err)
	}

	// Parse the response
	automationSet, err := automations.GetListAutomations(workspaceName)
	var skipAutomationRemoval bool
	if err != nil {
		// Check if this is a WorkspaceMisbehavingError
		var misbehavingErr *automations.WorkspaceMisbehavingError
		if errors.As(err, &misbehavingErr) {
			fmt.Printf("This workspace seems to be misbehaving. Cannot detect which automations are running within it. Would you like to stop it anyway with the risk of leaving some orphaned automations running? [y/N]: ")
			var continueAnyway string
			fmt.Scanln(&continueAnyway)
			if continueAnyway != "y" && continueAnyway != "yes" {
				fmt.Println("Remove cancelled.")
				return nil
			}
			skipAutomationRemoval = true
			automationSet = nil // Clear the set since we couldn't fetch it
		} else {
			// For any other error (including connection issues, malformed URLs, etc.), 
			// just skip automation removal and continue with the process
			fmt.Printf("Warning: Cannot connect to workspace to retrieve automations (%v). Continuing with removal process.\n", err)
			skipAutomationRemoval = true
			automationSet = nil // Clear the set since we couldn't fetch it
		}
	}

	fmt.Printf("Are you sure you want to remove %s? (yes/no): \n", workspaceName)
	fmt.Scanln(&confirm)
	if confirm != "yes" {
		fmt.Println("Remove cancelled.")
		return nil
	}

	// 2. Remove the automations from the server
	if !skipAutomationRemoval && len(automationSet) > 0 {
		fmt.Println("Removing automations...")
		for _, automation := range automationSet {
			err := automation.Remove()
			if err != nil {
				return fmt.Errorf("error removing automation %s: %w", automation.Name, err)
			}
		}
		fmt.Println("Automations removed successfully.")
	} else if skipAutomationRemoval {
		fmt.Println("Skipping automation removal due to workspace misbehavior.")
	} else {
		fmt.Println("No automations to remove.")
	}

	// 3. Remove docker container and volume
	fmt.Println("Removing docker containers and volumes...")
	workspacesFolder := filepath.Join(bitswanPath, "workspaces")
	dockerComposePath := filepath.Join(workspacesFolder, workspaceName, "deployment")
	projectName := workspaceName + "-site"
	cmd := exec.Command("docker", "compose", "-p", projectName, "down", "--volumes")
	cmd.Dir = dockerComposePath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove docker containers and volumes: %w", err)
	}
	fmt.Println("Docker containers and volumes removed successfully.")

	// 4. Remove images used by docker-compose
	fmt.Println("Removing images used by docker-compose...")
	dockerComposeFilePath := filepath.Join(dockerComposePath, "docker-compose.yml")
	data, err = os.ReadFile(dockerComposeFilePath)
	if err != nil {
		return fmt.Errorf("error reading docker-compose file: %w", err)
	}

	var compose Compose
	err = yaml.Unmarshal(data, &compose)
	if err != nil {
		return fmt.Errorf("error unmarshalling docker-compose file: %w", err)
	}

	for _, service := range compose.Services {
		if service.Image != "" {
			exists, err := checkContainerExists(service.Image)
			if err != nil {
				return fmt.Errorf("error checking if image exists: %w", err)
			}

			if !exists {
				err = deleteDockerImage(service.Image)
				if err != nil {
					return fmt.Errorf("error deleting docker image %s: %w", service.Image, err)
				}
				fmt.Println("Images removed successfully.")
			} else {
				fmt.Printf("Image %s is still in use by a different container. Skipping deletion.\n", service.Image)
			}
		}
	}

	// 5. Remove the gitops folder
	fmt.Println("Removing gitops folder...")
	cmd = exec.Command("rm", "-r", workspaceName)
	cmd.Dir = workspacesFolder
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove gitops folder: %w", err)
	}
	fmt.Println("GitOps folder removed successfully.")

	// 6. Remove caddy files
	fmt.Println("Removing caddy files...")
	err = caddyapi.DeleteCaddyRecords(workspaceName)
	if err != nil {
		return fmt.Errorf("error removing caddy files: %w", err)
	}
	fmt.Println("Caddy files removed successfully.")

	// 7. Remove entries from /etc/hosts
	fmt.Println("Removing entries from /etc/hosts...")
	err = deleteHostsEntry(workspaceName)
	if err != nil {
		return fmt.Errorf("error removing entries from /etc/hosts: %w", err)
	}
	fmt.Println("Entries removed from /etc/hosts successfully.")

	return nil
}
