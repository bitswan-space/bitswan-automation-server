package ingress

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
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
			routes, err := caddyapi.ListRoutes()
			if err != nil {
				return fmt.Errorf("failed to list routes: %w", err)
			}

			if len(routes) == 0 {
				fmt.Println("No routes configured")
				return nil
			}

			fmt.Printf("Found %d route(s):\n\n", len(routes))
			for _, route := range routes {
				// Extract hostname from route match
				var hostnames []string
				for _, match := range route.Match {
					hostnames = append(hostnames, match.Host...)
				}

				// Extract upstream from route handle
				var upstreams []string
				for _, handle := range route.Handle {
					if handle.Handler == "subroute" {
						for _, subRoute := range handle.Routes {
							for _, subHandle := range subRoute.Handle {
								if subHandle.Handler == "reverse_proxy" {
									for _, upstream := range subHandle.Upstreams {
										upstreams = append(upstreams, upstream.Dial)
									}
								}
							}
						}
					}
				}

				// Display route information
				if len(hostnames) > 0 && len(upstreams) > 0 {
					fmt.Printf("Route ID: %s\n", route.ID)
					fmt.Printf("  Hostname: %s\n", hostnames[0])
					fmt.Printf("  Upstream: %s\n", upstreams[0])
					fmt.Printf("  Terminal: %t\n\n", route.Terminal)
				}
			}

			return nil
		},
	}

	return cmd
} 