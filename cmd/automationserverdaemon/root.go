package automationserverdaemon

import (
	"github.com/spf13/cobra"
)

func NewAutomationServerDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "automation-server-daemon",
		Short: "Manage the automation server daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newRunCmd())
	cmd.AddCommand(newStatusCmd())

	return cmd
}

