package ingress

import (
	"fmt"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/spf13/cobra"
)

func newAddRouteCmd() *cobra.Command {
	var mkcert bool

	cmd := &cobra.Command{
		Use:   "add-route <hostname> <upstream>",
		Short: "Add a route mapping hostname to upstream",
		Long: `Add a route that maps a hostname to an upstream server.

Examples:
  bitswan ingress add-route foo.bar.example.com internal-host-name:2904
  bitswan ingress add-route api.myapp.com localhost:8080
  bitswan ingress add-route keycloak.bitswan.localhost aoc-keycloak:8080 --mkcert`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname := args[0]
			upstream := args[1]

			// Generate and install certificates if --mkcert flag is set
			if mkcert {
				// Extract domain from hostname
				parts := strings.Split(hostname, ".")
				if len(parts) < 2 {
					return fmt.Errorf("invalid hostname format: %s (must contain at least one dot)", hostname)
				}
				domain := strings.Join(parts[1:], ".")

				// Generate certificate for the specific hostname
				if err := caddyapi.GenerateAndInstallCertsForHostname(hostname, domain); err != nil {
					return fmt.Errorf("failed to generate and install certificates: %w", err)
				}

				// Install TLS policies for the specific hostname
				// Use "default" as workspace name when none is provided
				if err := caddyapi.InstallTLSCertsForHostname(hostname, domain, "default"); err != nil {
					return fmt.Errorf("failed to install TLS policies: %w", err)
				}
			}

			if err := caddyapi.AddRoute(hostname, upstream); err != nil {
				return fmt.Errorf("failed to add route: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&mkcert, "mkcert", false, "Generate certificates using mkcert for the hostname")

	return cmd
} 