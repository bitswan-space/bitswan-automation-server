package automationserverdaemon

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newApiDocsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "api-docs",
		Short: "Open API documentation in browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if daemon is running
			_, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			// Ensure the docs ingress route is set up
			// Try to set it up if it doesn't exist
			_ = daemon.SetupDocsIngress()

			// Open browser to docs URL
			docsURL := "http://automation-server-daemon-docs.bitswan.localhost"
			fmt.Printf("Opening API documentation at %s...\n", docsURL)

			if err := daemon.OpenBrowser(docsURL); err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to open browser: %v\n", err)
				fmt.Fprintf(os.Stderr, "Please open %s manually in your browser.\n", docsURL)
				os.Exit(1)
			}

			return nil
		},
	}
}

