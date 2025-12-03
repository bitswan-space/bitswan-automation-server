package daemon

import (
	"github.com/spf13/cobra"
)

// NewDaemonCmd creates the automation-server-daemon command
func NewDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "automation-server-daemon",
		Short: "Manage the automation server daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newRunCmd())

	return cmd
}

