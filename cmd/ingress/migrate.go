package ingress

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newMigrateCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate from Caddy to Traefik",
		Long: `Migrate the ingress proxy from Caddy to Traefik while preserving all routes.

This command:
  1. Exports all existing routes from Caddy
  2. Stops Caddy
  3. Starts Traefik
  4. Re-adds all exported routes to Traefik

Routes are preserved including their hostname-to-upstream mappings.
TLS certificates for non-.localhost domains will use Let's Encrypt via Traefik.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			// Check current ingress type
			ingressType, err := client.GetIngressType()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error checking ingress type: %v\n", err)
				os.Exit(1)
			}

			if ingressType != "caddy" {
				fmt.Fprintf(os.Stderr, "Current ingress is '%s', not 'caddy'. Nothing to migrate.\n", ingressType)
				os.Exit(1)
			}

			fmt.Println("Migrating ingress from Caddy to Traefik...")
			if err := client.MigrateIngress(verbose); err != nil {
				fmt.Fprintf(os.Stderr, "Migration failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("Migration completed successfully.")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}
