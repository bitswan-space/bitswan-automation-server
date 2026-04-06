package ingress

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the ingress proxy to the latest version",
		Long: `Update the ingress proxy (Traefik or Caddy) to the latest version.

This command:
  1. Exports all existing routes
  2. Stops the current ingress container
  3. Pulls the latest image and regenerates configuration
  4. Restarts the ingress proxy
  5. Re-adds all exported routes

Use this to fix compatibility issues or apply security updates.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			fmt.Println("Updating ingress proxy...")
			if err := client.UpdateIngress(verbose); err != nil {
				fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("Ingress proxy updated successfully.")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}
