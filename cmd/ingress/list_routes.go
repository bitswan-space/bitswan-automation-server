package ingress

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newListRoutesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-routes",
		Short: "List all configured routes",
		Long: `List all routes currently configured in the ingress proxy.

Examples:
  bitswan ingress list-routes`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			result, err := client.ListIngressRoutes()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if len(result.Routes) == 0 {
				fmt.Println("No routes configured")
				return nil
			}

			fmt.Printf("Found %d route(s):\n\n", len(result.Routes))
			for _, route := range result.Routes {
				fmt.Printf("Route ID: %s\n", route.ID)
				fmt.Printf("  Hostname: %s\n", route.Hostname)
				fmt.Printf("  Upstream: %s\n", route.Upstream)
				fmt.Printf("  Terminal: %t\n\n", route.Terminal)
			}

			return nil
		},
	}

	return cmd
} 