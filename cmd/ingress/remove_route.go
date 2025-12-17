package ingress

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newRemoveRouteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove-route <hostname>",
		Short: "Remove a route by hostname",
		Long: `Remove a route that was previously configured for the specified hostname.

Examples:
  bitswan ingress remove-route foo.bar.example.com
  bitswan ingress remove-route api.myapp.com`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname := args[0]

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if err := client.RemoveIngressRoute(hostname); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Removed route: %s\n", hostname)
			return nil
		},
	}

	return cmd
} 