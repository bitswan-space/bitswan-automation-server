package automation

import (
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

// validAutomationArgs returns deployment IDs for tab-completion of the
// <deployment-id> positional argument. Once one ID has been provided it
// stops completing (all automation sub-commands take exactly one ID).
func validAutomationArgs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	workspace, _ := cmd.Flags().GetString("workspace")

	client, err := daemon.NewClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	resp, err := client.ListAutomations(workspace)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	ids := make([]string, 0, len(resp.Automations))
	for _, a := range resp.Automations {
		ids = append(ids, a.DeploymentID)
	}
	return ids, cobra.ShellCompDirectiveNoFileComp
}
