package automation

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/bitswan-space/bitswan-workspaces/internal/ansi"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
)

func newListCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available bitswan workspace automations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			result, err := client.ListAutomations(workspace)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("Automations fetched successfully.")
			fmt.Print("The following automations are running in this gitops:\n\n")

			// Print table header
			fmt.Printf("%s%-8s %-20s %-12s %-12s %-8s %-20s %-20s%s\n", ansi.Bold, "RUNNING", "NAME", "STATE", "STATUS", "ACTIVE", "DEPLOYMENT ID", "CREATED AT", ansi.Reset)
			fmt.Println(ansi.Gray + "--------------------------------------------------------------------------------------------------------" + ansi.Reset)

			if len(result.Automations) == 0 {
				fmt.Println(ansi.Gray + "No automations found." + ansi.Reset)
				return nil
			}

			// Print each automation
			for _, a := range result.Automations {
				runningStatus := ansi.RedDot
				if a.State == "running" {
					runningStatus = ansi.GreenDot
				}

				activeStatus := ansi.RedCheck
				if a.Active {
					activeStatus = ansi.GreenCheck
				}

				createdAtFormatted := parseTimestamp(a.CreatedAt)

				name := a.Name
				if len(name) > 20 {
					name = name[:15] + "..."
				}

				deploymentId := a.DeploymentID
				if len(a.DeploymentID) > 20 {
					deploymentId = a.DeploymentID[:15] + "..."
				}

				fmt.Printf("%-16s %-20s %-12s %-12s %-16s %-20s %-20s\n",
					runningStatus, name, a.State, a.Status, activeStatus, deploymentId, createdAtFormatted)
				fmt.Println(ansi.Gray + "--------------------------------------------------------------------------------------------------------" + ansi.Reset)
			}

			fmt.Println(ansi.Yellow + "✔ Running containers are marked with a green dot.\n" + ansi.Reset)

			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

// parseTimestamp parses a custom timestamp format
func parseTimestamp(timestamp string) string {
	layout := "2006-01-02T15:04:05.999999"
	t, err := time.Parse(layout, timestamp)
	if err != nil {
		return "Invalid Date"
	}
	return t.Format("02 Jan 2006 15:04")
}
