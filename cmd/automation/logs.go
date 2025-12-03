package automation

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemonapi"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Get logs for automation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.NewAutomationServerConfig()
			workspaceName, err := cfg.GetActiveWorkspace()
			if err != nil {
				return err
			}
			automationDeploymentId := args[0]
			
			lines, err := cmd.Flags().GetInt("lines")
			if err != nil {
				return err
			}
			
			argsList := []string{"logs", automationDeploymentId}
			if lines > 0 {
				argsList = append(argsList, "--lines", fmt.Sprintf("%d", lines))
			}
			
			return daemonapi.ExecuteViaDockerExec("automation", argsList, workspaceName)
		},
	}

	cmd.Flags().IntP("lines", "l", 0, "Number of log lines to show (default 0 for all logs)")

	return cmd
}
