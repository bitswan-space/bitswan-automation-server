package automation

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newStopCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the automation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			automationDeploymentId := args[0]

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if err := client.StopAutomation(automationDeploymentId, workspace); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Automation %s stopped successfully.\n", automationDeploymentId)
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}
