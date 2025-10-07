package automation

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available bitswan workspace automations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.NewAutomationServerConfig()
			workspaceName, err := cfg.GetActiveWorkspace()
			if err != nil {
				return fmt.Errorf("failed to get active workspace from automation server config: %v", err)
			}
			_, err = automations.GetListAutomations(workspaceName)
			if err != nil {
				return fmt.Errorf("failed to list automations: %v", err)
			}
			return nil
		},
	}

	// Add subcommands to workspace

	return cmd
}
