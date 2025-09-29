package automation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/bitswan-space/bitswan-workspaces/internal/ansi"
	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/spf13/cobra"
)

type AutomationLog struct {
	Status string   `json:"status"`
	Logs   []string `json:"logs"`
}

func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Get logs for automation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configManager := config.NewAutomationServerConfig()
			workspaceName, err := configManager.GetActiveWorkspace()
			automationDeploymentId := args[0]
			if err != nil {
				return fmt.Errorf("failed to get active workspace from automation server config: %v", err)
			}

			lines, err := cmd.Flags().GetInt("lines")
			if err != nil {
				return fmt.Errorf("failed to parse lines flag: %v", err)
			}

			err = getLogsFromAutomation(workspaceName, automationDeploymentId, lines)
			if err != nil {
				return fmt.Errorf("failed to get logs from an automation: %v", err)
			}
			return nil
		},
	}

	cmd.Flags().IntP("lines", "l", 0, "Number of log lines to show (default 0 for all logs)")

	return cmd
}

func getLogsFromAutomation(workspaceName string, automationDeploymentId string, lines int) error {
	metadata := config.GetWorkspaceMetadata(workspaceName)

	fmt.Println("Fetching automations logs...")

	// Create a new GET request
	url := fmt.Sprintf("%s/automations/%s/logs", metadata.GitOpsURL, automationDeploymentId)
	if lines > 0 {
		url += fmt.Sprintf("?lines=%d", lines)
	}
	resp, err := automations.SendAutomationRequest("GET", url, metadata.GitOpsSecret)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get logs from automation: %s", resp.Status)
	}

	var automationLog AutomationLog
	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal([]byte(body), &automationLog)
	if err != nil {
		return fmt.Errorf("error decoding JSON: %w", err)
	}

	fmt.Printf("Automation %s logs fetched successfully.\n", automationDeploymentId)
	fmt.Println("=========================================")
	if automationLog.Status != "success" {
		fmt.Printf("Status: %s\n", ansi.RedCheck)
		fmt.Println("No logs available => check name of the automation or if it is running")
		return nil
	} else {
		fmt.Printf("Status: %s\n", ansi.GreenCheck)
	}
	fmt.Println("Logs:")
	for _, log := range automationLog.Logs {
		fmt.Printf("  %s\n", log)
	}

	return nil
}
