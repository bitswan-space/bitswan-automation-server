package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/cmd/automation"
	"github.com/bitswan-space/bitswan-workspaces/cmd/caddy"
	"github.com/bitswan-space/bitswan-workspaces/cmd/ingress"
	"github.com/spf13/cobra"
)

func newRootCmd(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bitswan",
		Short: "Deploy your Jupyter pipelines with bitswan",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newVersionCmd(version)) // version subcommand
	cmd.AddCommand(newWorkspaceCmd())      // workspace subcommand
	cmd.AddCommand(newRegisterCmd())       // register subcommand
	cmd.AddCommand(ingress.NewIngressCmd()) // ingress subcommand
	cmd.AddCommand(caddy.NewCaddyCmd())    // caddy subcommand (deprecated)

	// Check if the configuration file exists and has an active workspace
	configPath := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "config.toml")
	if _, err := os.Stat(configPath); err == nil {
		// File exists, read and parse it
		configData, err := os.ReadFile(configPath)
		if err == nil {
			if strings.Contains(string(configData), "active_workspace = \"") {
				cmd.AddCommand(automation.NewAutomationCmd())
			}
		}
	}

	// Find and add external commands
	addExternalCommands(cmd)

	return cmd
}

// newWorkspaceCmd creates the workspace subcommand
func newWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage bitswan workspaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	// Add subcommands to workspace
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newUpdateCmd())
	cmd.AddCommand(newRemoveCmd())
	cmd.AddCommand(newSelectCmd())
	cmd.AddCommand(newOpenCmd())
	cmd.AddCommand(newServiceCmd())

	return cmd
}

// addExternalCommands finds and adds external commands from PATH
func addExternalCommands(rootCmd *cobra.Command) {
	// Get PATH environment variable
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return
	}

	// Split PATH into directories
	pathDirs := filepath.SplitList(pathEnv)

	// Track added commands to avoid duplicates
	addedCommands := make(map[string]bool)

	// Check each directory in PATH
	for _, dir := range pathDirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		// Look for bitswan-* executables
		for _, file := range files {
			if strings.HasPrefix(file.Name(), "bitswan-") {
				subcommandName := strings.TrimPrefix(file.Name(), "bitswan-")

				// Skip if already added or is a workspace command
				if addedCommands[subcommandName] ||
					subcommandName == "workspace" ||
					subcommandName == "version" {
					continue
				}

				// Create a command that executes the external binary
				externalCmd := &cobra.Command{
					Use:   subcommandName,
					Short: fmt.Sprintf("External command: %s", subcommandName),
					RunE: func(execPath string) func(cmd *cobra.Command, args []string) error {
						return func(cmd *cobra.Command, args []string) error {
							// Create the external command
							execCmd := exec.Command(execPath, args...)
							execCmd.Stdin = os.Stdin
							execCmd.Stdout = os.Stdout
							execCmd.Stderr = os.Stderr

							// Run the command
							return execCmd.Run()
						}
					}(filepath.Join(dir, file.Name())),
					DisableFlagParsing: true,
				}

				// Add the command to the root command
				rootCmd.AddCommand(externalCmd)
				addedCommands[subcommandName] = true
			}
		}
	}
}

// Execute invokes the command.
func Execute(version string) error {
	if err := newRootCmd(version).Execute(); err != nil {
		return fmt.Errorf("error executing root command: %w", err)
	}

	return nil
}
