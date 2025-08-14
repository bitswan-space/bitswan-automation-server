package caddy

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/cmd/ingress"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initializes a Caddy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Print deprecation warning to STDERR
			fmt.Fprintln(os.Stderr, "WARNING: The 'caddy init' command is deprecated and will be removed in a future version. Please use 'ingress init' instead.")
			if err := ingress.InitIngress(verbose); err != nil {
				return fmt.Errorf("failed to initialize Caddy: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}


