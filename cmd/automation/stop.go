package automation

import (
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemonapi"
	"github.com/spf13/cobra"
)

func newStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the automation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.NewAutomationServerConfig()
			workspaceName, err := cfg.GetActiveWorkspace()
			if err != nil {
				return err
			}
			automationDeploymentId := args[0]
			return daemonapi.ExecuteViaDockerExec("automation", []string{"stop", automationDeploymentId}, workspaceName)
		},
	}

	return cmd
}
