package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/cmd/automation"
	"github.com/bitswan-space/bitswan-workspaces/cmd/automationserverdaemon"
	"github.com/bitswan-space/bitswan-workspaces/cmd/caddy"
	"github.com/bitswan-space/bitswan-workspaces/cmd/certauthority"
	"github.com/bitswan-space/bitswan-workspaces/cmd/ingress"
	"github.com/bitswan-space/bitswan-workspaces/cmd/test"
	"github.com/spf13/cobra"
)

// knownExternalCommand contains installation info for commands that may not be installed
type knownExternalCommand struct {
	description    string
	installMessage string
}

// knownExternalCommands maps command names to their installation instructions
var knownExternalCommands = map[string]knownExternalCommand{
	"notebook": {
		description: "Run and manage Jupyter notebook pipelines",
		installMessage: `The 'notebook' command is part of the BitSwan library.

Install BitSwan:
  pip install bitswan

For more information:
  https://github.com/bitswan-space/BitSwan#installation`,
	},
	"on-prem-aoc": {
		description: "Manage on-premises Automation Operation Center",
		installMessage: `The 'on-prem-aoc' command is part of the Automation Operation Center.

This component requires a proprietary license.
Contact BitSwan for licensing information:
  https://bitswan.ai`,
	},
}

func newRootCmd(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bitswan",
		Short: "Deploy your Jupyter pipelines with bitswan",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newVersionCmd(version))                                    // version subcommand
	cmd.AddCommand(newWorkspaceCmd())                                         // workspace subcommand
	cmd.AddCommand(newRegisterCmd())                                          // register subcommand
	cmd.AddCommand(ingress.NewIngressCmd())                                   // ingress subcommand
	cmd.AddCommand(caddy.NewCaddyCmd())                                       // caddy subcommand (deprecated)
	cmd.AddCommand(certauthority.NewCertAuthorityCmd())                       // certificate authority subcommand
	cmd.AddCommand(automationserverdaemon.NewAutomationServerDaemonCmd())     // automation server daemon subcommand
	cmd.AddCommand(automation.NewAutomationCmd())                             // automation subcommand
	cmd.AddCommand(test.NewTestCmd())                                         // _test subcommand (hidden)

	// Set the version for the daemon server
	automationserverdaemon.SetVersion(version)

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
	cmd.AddCommand(newPullAndDeployCmd())
	cmd.AddCommand(newStartCmd())
	cmd.AddCommand(newStopCmd())
	cmd.AddCommand(newRestartCmd())

	return cmd
}

// addExternalCommands finds and adds external commands from PATH
func addExternalCommands(rootCmd *cobra.Command) {
	// Get PATH environment variable
	pathEnv := os.Getenv("PATH")

	// Split PATH into directories
	pathDirs := filepath.SplitList(pathEnv)

	// Track added commands to avoid duplicates
	addedCommands := make(map[string]bool)

	// Check each directory in PATH for bitswan-* executables
	if pathEnv != "" {
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

	// Add placeholder commands for known external commands that aren't installed
	// These provide helpful installation instructions instead of "unknown command" errors
	for cmdName, cmdInfo := range knownExternalCommands {
		if addedCommands[cmdName] {
			// Command is already installed, skip
			continue
		}

		// Create a placeholder command that shows installation instructions
		placeholderCmd := &cobra.Command{
			Use:   cmdName,
			Short: cmdInfo.description + " (not installed)",
			Long:  cmdInfo.description + "\n\nThis command is not currently installed.",
			RunE: func(name string, info knownExternalCommand) func(cmd *cobra.Command, args []string) error {
				return func(cmd *cobra.Command, args []string) error {
					fmt.Fprintf(os.Stderr, "Error: The '%s' command is not installed.\n\n", name)
					fmt.Fprintln(os.Stderr, info.installMessage)
					return fmt.Errorf("command '%s' not installed", name)
				}
			}(cmdName, cmdInfo),
			DisableFlagParsing: true,
		}

		rootCmd.AddCommand(placeholderCmd)
		addedCommands[cmdName] = true
	}
}

// Execute invokes the command.
func Execute(version string) error {
	if err := newRootCmd(version).Execute(); err != nil {
		return fmt.Errorf("error executing root command: %w", err)
	}

	return nil
}
