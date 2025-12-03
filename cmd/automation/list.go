package automation

import (
	"github.com/spf13/cobra"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemonapi"
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
				return err
			}
			return daemonapi.ExecuteViaDockerExec("automation", []string{"list"}, workspaceName)
		},
	}

	return cmd
}
