package ingress

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/spf13/cobra"
)

func newAddRouteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add-route <hostname> <upstream>",
		Short: "Add a route mapping hostname to upstream",
		Long: `Add a route that maps a hostname to an upstream server.

Examples:
  bitswan ingress add-route foo.bar.example.com internal-host-name:2904
  bitswan ingress add-route api.myapp.com localhost:8080`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname := args[0]
			upstream := args[1]

			if err := caddyapi.AddRoute(hostname, upstream); err != nil {
				return fmt.Errorf("failed to add route: %w", err)
			}
			return nil
		},
	}

	return cmd
} 