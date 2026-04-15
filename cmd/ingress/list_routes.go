package ingress

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newListRoutesCmd() *cobra.Command {
	var target string

	cmd := &cobra.Command{
		Use:   "list-routes",
		Short: "List all configured routes",
		Long: `List all routes currently configured in the ingress proxy.

When VPN is enabled, use --target to filter by ingress:
  --target external   Show only internet-facing routes
  --target internal   Show only VPN-internal routes
  (no flag)           Show all routes from both ingresses

Examples:
  bitswan ingress list-routes
  bitswan ingress list-routes --target external
  bitswan ingress list-routes --target internal`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			// List external routes
			showExternal := target == "" || target == "external"
			showInternal := target == "" || target == "internal"

			totalRoutes := 0

			if showExternal {
				result, err := client.ListIngressRoutes()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error listing external routes: %v\n", err)
					os.Exit(1)
				}
				if len(result.Routes) > 0 {
					if target == "" {
						fmt.Printf("=== External Ingress (%d routes) ===\n\n", len(result.Routes))
					}
					for _, route := range result.Routes {
						fmt.Printf("  %s → %s\n", route.Hostname, route.Upstream)
					}
					if target == "" {
						fmt.Println()
					}
					totalRoutes += len(result.Routes)
				}
			}

			if showInternal && daemon.IsVPNEnabled() {
				result, err := client.ListVPNIngressRoutes()
				if err != nil {
					// VPN Traefik might not be running
					if target == "internal" {
						fmt.Fprintf(os.Stderr, "Error listing VPN routes: %v\n", err)
						os.Exit(1)
					}
				} else if len(result.Routes) > 0 {
					if target == "" {
						fmt.Printf("=== VPN Ingress (%d routes) ===\n\n", len(result.Routes))
					}
					for _, route := range result.Routes {
						fmt.Printf("  %s → %s\n", route.Hostname, route.Upstream)
					}
					fmt.Println()
					totalRoutes += len(result.Routes)
				}
			}

			if totalRoutes == 0 {
				fmt.Println("No routes configured")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "Filter by ingress: 'external' or 'internal'")

	return cmd
}
