package cmd

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newSelectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "select <workspace>",
		Short: "Select a workspace for activation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			workspace := args[0]

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if err := client.SelectWorkspace(workspace); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Active workspace set to '%s'.\n", workspace)
			return nil
		},
	}
}
