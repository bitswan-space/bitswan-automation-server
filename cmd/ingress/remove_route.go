package ingress

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
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

			if err := caddyapi.RemoveRoute(hostname); err != nil {
				return fmt.Errorf("failed to remove route: %w", err)
			}
			return nil
		},
	}

	return cmd
} 