package automation

import (
	"fmt"
	"net/http"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/spf13/cobra"
)

func newStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the automation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.NewAutomationServerConfig()
			workspaceName, err := cfg.GetActiveWorkspace()
			automationDeploymentId := args[0]
			if err != nil {
				return fmt.Errorf("failed to get active workspace from automation server config: %v", err)
			}

			fmt.Printf("Starting an automation %s...\n", automationDeploymentId)
			err = startAutomation(workspaceName, automationDeploymentId)
			if err != nil {
				return fmt.Errorf("failed to start an automation: %v", err)
			}
			return nil
		},
	}

	return cmd
}

func startAutomation(workspaceName, automationDeploymentId string) error {
	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}
	// Construct the URL for stopping the automation
	url := fmt.Sprintf("%s/automations/%s/start", metadata.GitopsURL, automationDeploymentId)

	// Send the request to stop the automation
	resp, err := automations.SendAutomationRequest("POST", url, metadata.GitopsSecret)
	if err != nil {
		return fmt.Errorf("failed to send request to start automation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to start automation, status code: %d", resp.StatusCode)
	}
	fmt.Printf("Automation %s started successfully.\n", automationDeploymentId)
	return nil
}
