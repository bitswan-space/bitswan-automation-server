package test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	var noRemove bool
	var gitopsImage string
	var editorImage string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Test workspace update command",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestUpdate(noRemove, gitopsImage, editorImage)
		},
	}

	cmd.Flags().BoolVar(&noRemove, "no-remove", false, "Leave workspace running (skip cleanup)")
	cmd.Flags().StringVar(&gitopsImage, "gitops-image", "", "Custom GitOps image to use for initial setup (default: uses an older tag)")
	cmd.Flags().StringVar(&editorImage, "editor-image", "", "Custom editor image to use for initial setup (default: uses an older tag)")

	return cmd
}

func runTestUpdate(noRemove bool, customGitopsImage, customEditorImage string) error {
	fmt.Println("=== BitSwan Test Suite: Update ===")
	fmt.Println()

	// Ensure we're in a valid directory
	if wd, err := os.Getwd(); err != nil {
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			homeDir = "/tmp"
		}
		if err := os.Chdir(homeDir); err != nil {
			return fmt.Errorf("failed to change to directory: %w", err)
		}
	} else {
		if _, err := os.Stat(wd); err != nil {
			homeDir := os.Getenv("HOME")
			if homeDir == "" {
				homeDir = "/tmp"
			}
			if err := os.Chdir(homeDir); err != nil {
				return fmt.Errorf("failed to change to directory: %w", err)
			}
		}
	}

	// Generate unique workspace name
	workspaceName := fmt.Sprintf("test-update-%d", time.Now().Unix())
	fmt.Printf("Test workspace name: %s\n", workspaceName)

	// Step 1: Get latest versions from DockerHub
	fmt.Println("\n[1/6] Getting latest versions from DockerHub...")
	latestGitopsVersion, err := dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/gitops/tags/")
	if err != nil {
		return fmt.Errorf("failed to get latest gitops version: %w", err)
	}
	latestEditorVersion, err := dockerhub.GetLatestEditorVersion()
	if err != nil {
		return fmt.Errorf("failed to get latest editor version: %w", err)
	}
	fmt.Printf("Latest gitops version: %s\n", latestGitopsVersion)
	fmt.Printf("Latest editor version: %s\n", latestEditorVersion)

	// Step 2: Initialize workspace with custom/older images
	fmt.Println("\n[2/6] Initializing workspace with custom images...")
	client, err := daemon.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create daemon client: %w", err)
	}

	// Use custom images if provided, otherwise use the latest version tag (which will be updated to latest during update)
	initGitopsImage := customGitopsImage
	if initGitopsImage == "" {
		// Use the latest version we just fetched - update will re-fetch and ensure it's still latest
		initGitopsImage = fmt.Sprintf("bitswan/gitops:%s", latestGitopsVersion)
	}
	initEditorImage := customEditorImage
	if initEditorImage == "" {
		// Use the latest version we just fetched - update will re-fetch and ensure it's still latest
		initEditorImage = fmt.Sprintf("bitswan/bitswan-editor:%s", latestEditorVersion)
	}

	initArgs := []string{
		"workspace", "init",
		"--local",
		"--no-oauth",
		"--gitops-image", initGitopsImage,
		"--editor-image", initEditorImage,
	}
	initArgs = append(initArgs, workspaceName)

	if err := client.WorkspaceInit(initArgs); err != nil {
		return fmt.Errorf("failed to initialize workspace: %w", err)
	}
	fmt.Println("✓ Workspace initialized")

	// Step 3: Verify initial images are set correctly
	fmt.Println("\n[3/6] Verifying initial images...")
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return fmt.Errorf("HOME environment variable not set")
	}
	workspacePath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)

	// Check gitops image in docker-compose.yml
	gitopsImage, err := getImageFromCompose(filepath.Join(workspacePath, "deployment", "docker-compose.yml"), "bitswan-gitops")
	if err != nil {
		return fmt.Errorf("failed to get gitops image: %w", err)
	}
	fmt.Printf("Initial gitops image: %s\n", gitopsImage)

	// Check editor image in docker-compose-editor.yml (if it exists)
	editorImage, err := getImageFromCompose(filepath.Join(workspacePath, "deployment", "docker-compose-editor.yml"), "bitswan-editor")
	if err != nil {
		// Editor might not be enabled, that's okay
		fmt.Printf("Editor service not enabled or file not found: %v\n", err)
	} else {
		fmt.Printf("Initial editor image: %s\n", editorImage)
	}

	// Step 4: Run update command
	fmt.Println("\n[4/6] Running update command...")
	updateArgs := []string{
		"workspace", "update",
		workspaceName,
	}

	if err := client.WorkspaceUpdate(updateArgs); err != nil {
		if !noRemove {
			cleanupWorkspace(workspaceName)
		}
		return fmt.Errorf("failed to update workspace: %w", err)
	}
	fmt.Println("✓ Update command completed")

	// Step 5: Verify images were updated to latest
	fmt.Println("\n[5/6] Verifying images were updated to latest...")

	// Re-fetch latest versions after update (in case new versions were published)
	fmt.Println("Re-fetching latest versions from DockerHub...")
	updatedLatestGitopsVersion, err := dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/gitops/tags/")
	if err != nil {
		fmt.Printf("Warning: failed to re-fetch latest gitops version, using previous: %v\n", err)
		updatedLatestGitopsVersion = latestGitopsVersion
	}
	updatedLatestEditorVersion, err := dockerhub.GetLatestEditorVersion()
	if err != nil {
		fmt.Printf("Warning: failed to re-fetch latest editor version, using previous: %v\n", err)
		updatedLatestEditorVersion = latestEditorVersion
	}

	// Check gitops image
	updatedGitopsImage, err := getImageFromCompose(filepath.Join(workspacePath, "deployment", "docker-compose.yml"), "bitswan-gitops")
	if err != nil {
		if !noRemove {
			cleanupWorkspace(workspaceName)
		}
		return fmt.Errorf("failed to get updated gitops image: %w", err)
	}
	fmt.Printf("Updated gitops image: %s\n", updatedGitopsImage)

	expectedGitopsImage := fmt.Sprintf("bitswan/gitops:%s", updatedLatestGitopsVersion)
	if updatedGitopsImage != expectedGitopsImage {
		if !noRemove {
			cleanupWorkspace(workspaceName)
		}
		return fmt.Errorf("gitops image not updated correctly. Expected: %s, Got: %s", expectedGitopsImage, updatedGitopsImage)
	}
	fmt.Println("✓ Gitops image updated to latest")

	// Check editor image (if enabled)
	updatedEditorImage, err := getImageFromCompose(filepath.Join(workspacePath, "deployment", "docker-compose-editor.yml"), "bitswan-editor")
	if err == nil {
		fmt.Printf("Updated editor image: %s\n", updatedEditorImage)
		expectedEditorImage := fmt.Sprintf("bitswan/bitswan-editor:%s", updatedLatestEditorVersion)
		if updatedEditorImage != expectedEditorImage {
			if !noRemove {
				cleanupWorkspace(workspaceName)
			}
			return fmt.Errorf("editor image not updated correctly. Expected: %s, Got: %s", expectedEditorImage, updatedEditorImage)
		}
		fmt.Println("✓ Editor image updated to latest")
	} else {
		fmt.Println("Editor service not enabled, skipping editor image verification")
	}

	if noRemove {
		fmt.Println("\n[6/6] Skipping cleanup (--no-remove flag set)...")
		fmt.Printf("Workspace '%s' is still running\n", workspaceName)
		fmt.Println("\n=== Test Suite: SUCCESS (workspace left running) ===")
		return nil
	}

	// Step 6: Cleanup
	fmt.Println("\n[6/6] Cleaning up...")
	if err := cleanupWorkspace(workspaceName); err != nil {
		return fmt.Errorf("failed to cleanup workspace: %w", err)
	}
	fmt.Println("✓ Workspace removed")

	fmt.Println("\n=== Test Suite: SUCCESS ===")
	return nil
}

// getImageFromCompose reads a docker-compose YAML file and returns the image for a specific service
func getImageFromCompose(composePath, serviceName string) (string, error) {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return "", fmt.Errorf("failed to read docker-compose file: %w", err)
	}

	var compose map[string]interface{}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return "", fmt.Errorf("failed to parse docker-compose file: %w", err)
	}

	services, ok := compose["services"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("services section not found")
	}

	service, ok := services[serviceName].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("service %s not found", serviceName)
	}

	image, ok := service["image"].(string)
	if !ok {
		return "", fmt.Errorf("image not found for service %s", serviceName)
	}

	return image, nil
}

