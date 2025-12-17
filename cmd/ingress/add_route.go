package ingress

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newAddRouteCmd() *cobra.Command {
	var mkcert bool
	var certsDir string

	cmd := &cobra.Command{
		Use:   "add-route <hostname> <upstream>",
		Short: "Add a route mapping hostname to upstream",
		Long: `Add a route that maps a hostname to an upstream server.

Examples:
  bitswan ingress add-route foo.bar.example.com internal-host-name:2904
  bitswan ingress add-route api.myapp.com localhost:8080
  bitswan ingress add-route keycloak.bitswan.localhost aoc-keycloak:8080 --mkcert
  bitswan ingress add-route secure.example.com backend:8080 --certs-dir /path/to/certs`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname := args[0]
			upstream := args[1]

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			result, err := client.AddIngressRoute(hostname, upstream, mkcert, certsDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().BoolVar(&mkcert, "mkcert", false, "Generate certificates using mkcert for the hostname")
	cmd.Flags().StringVar(&certsDir, "certs-dir", "", "The directory where the certificates are located")

	return cmd
} 