package automation

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/spf13/cobra"
)

func newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove the automation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configManager := config.NewAutomationServerConfig()
			workspaceName, err := configManager.GetActiveWorkspace()
			automationDeploymentId := args[0]
			if err != nil {
				return fmt.Errorf("failed to get active workspace from automation server config: %v", err)
			}

			// Create an Automation instance
			automation := automations.Automation{
				DeploymentID: automationDeploymentId,
				Workspace:    workspaceName,
			}

			// Print a message indicating the removal process
			fmt.Printf("Removing automation %s...\n", automationDeploymentId)

			// Call the Remove method on the Automation instance
			err = automation.Remove()
			if err != nil {
				return fmt.Errorf("failed to remove automation: %v", err)
			}
			return nil
		},
	}

	return cmd
}
