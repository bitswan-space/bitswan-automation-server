package automation

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/ansi"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Get logs for automation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			automationDeploymentId := args[0]

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			lines, err := cmd.Flags().GetInt("lines")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid lines flag: %v\n", err)
				os.Exit(1)
			}

			result, err := client.GetAutomationLogs(automationDeploymentId, lines, workspace)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Automation %s logs fetched successfully.\n", automationDeploymentId)
			fmt.Println("=========================================")

			if result.Status != "success" {
				fmt.Printf("Status: %s\n", ansi.RedCheck)
				fmt.Println("No logs available => check name of the automation or if it is running")
				return nil
			}

			fmt.Printf("Status: %s\n", ansi.GreenCheck)
			fmt.Println("Logs:")
			for _, log := range result.Logs {
				fmt.Printf("  %s\n", log)
			}

			return nil
		},
	}

	cmd.Flags().IntP("lines", "l", 0, "Number of log lines to show (default 0 for all logs)")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}
