package caddy

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewCaddyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "caddy",
		Short: "Manage caddy",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Print deprecation warning to STDERR
			fmt.Fprintln(os.Stderr, "WARNING: The 'caddy' command is deprecated and will be removed in a future version. Please use 'ingress' instead.")
			return cmd.Help()
		},
	}

	cmd.AddCommand(newInitCmd())

	return cmd
}
