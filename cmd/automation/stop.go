package automation

import (
	"fmt"
	"net/http"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/spf13/cobra"
)

func newStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the automation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configManager := config.NewAutomationServerConfig()
			workspaceName, err := configManager.GetActiveWorkspace()
			automationDeploymentId := args[0]
			if err != nil {
				return fmt.Errorf("failed to get active workspace from automation server config: %v", err)
			}

			fmt.Printf("Stopping an automation %s...\n", automationDeploymentId)
			err = stopAutomation(workspaceName, automationDeploymentId)
			if err != nil {
				return fmt.Errorf("failed to stop an automation: %v", err)
			}
			return nil
		},
	}

	return cmd
}

func stopAutomation(workspaceName, automationDeploymentId string) error {
	metadata := config.GetWorkspaceMetadata(workspaceName)
	// Construct the URL for stopping the automation
	url := fmt.Sprintf("%s/automations/%s/stop", metadata.GitOpsURL, automationDeploymentId)

	// Send the request to stop the automation
	resp, err := automations.SendAutomationRequest("POST", url, metadata.GitOpsSecret)
	if err != nil {
		return fmt.Errorf("failed to send request to stop automation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to stop automation, status code: %d", resp.StatusCode)
	}

	fmt.Printf("Automation %s stopped successfully.\n", automationDeploymentId)
	return nil
}
