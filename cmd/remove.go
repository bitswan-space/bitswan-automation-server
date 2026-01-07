package cmd

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "remove <workspace-name> [workspace-name...]",
		Short:        "bitswan workspace remove",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceNames := args

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			// Show warning about automations
			fmt.Println("Automations in these gitops will be removed and cannot be recovered.")
			if len(workspaceNames) == 1 {
				fmt.Printf("Are you sure you want to remove %s? (yes/no): ", workspaceNames[0])
			} else {
				fmt.Printf("Are you sure you want to remove %d workspaces?\n", len(workspaceNames))
				for _, name := range workspaceNames {
					fmt.Printf("  - %s\n", name)
				}
				fmt.Print("Confirm (yes/no): ")
			}
			var confirm string
			fmt.Scanln(&confirm)
			if confirm != "yes" {
				fmt.Println("Remove cancelled.")
				return nil
			}

			// Remove each workspace
			for i, workspaceName := range workspaceNames {
				if len(workspaceNames) > 1 {
					fmt.Printf("\n[%d/%d] Removing %s...\n", i+1, len(workspaceNames), workspaceName)
				}
				if err := client.WorkspaceRemove(workspaceName); err != nil {
					fmt.Fprintf(os.Stderr, "Error removing %s: %v\n", workspaceName, err)
					// Continue with other workspaces even if one fails
					if i < len(workspaceNames)-1 {
						fmt.Println("Continuing with remaining workspaces...")
					}
				}
			}
			return nil
		},
	}
}

