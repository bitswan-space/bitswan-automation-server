package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/spf13/cobra"
)

func newSelectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "select <workspace>",
		Short: "Select a workspace for activation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			workspace := args[0]
			bitswanDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan")

			// Validate the workspace
			err := checkValidWorkspace(workspace, bitswanDir)
			if err != nil {
				return fmt.Errorf("error: %w", err)
			}

			// Load the configuration manager
f			configManager := config.NewAutomationServerConfig()

			// Update the active workspace
			if err := configManager.SetActiveWorkspace(workspace); err != nil {
				return err
			}

			fmt.Printf("Active workspace set to '%s' in config file.\n", workspace)
			return nil
		},
	}
}

func checkValidWorkspace(workspace string, bitswanDir string) error {
	workspacesDir := filepath.Join(bitswanDir, "workspaces")

	// Check if the workspaces directory exists
	if _, err := os.Stat(workspacesDir); os.IsNotExist(err) {
		return fmt.Errorf("workspaces directory does not exist: %s", workspacesDir)
	}

	// Validate if the provided workspace exists in the workspaces directory
	workspacePath := filepath.Join(workspacesDir, workspace)
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		var availableWorkspaces []string

		// List available workspaces
		files, err := os.ReadDir(workspacesDir)
		if err != nil {
			return fmt.Errorf("failed to read workspaces directory: %v", err)
		}
		for _, file := range files {
			if file.IsDir() {
				availableWorkspaces = append(availableWorkspaces, file.Name())
			}
		}

		return fmt.Errorf("invalid workspace: '%s'.\n\nAvailable workspaces are:\n%s", workspace, strings.Join(availableWorkspaces, ", "))
	}
	return nil
}
