package cmd

import (
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

// validWorkspaceArgs is a ValidArgsFunction that completes workspace names
// by querying the daemon. Used by any command that takes a <workspace-name> arg.
func validWorkspaceArgs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	client, err := daemon.NewClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	result, err := client.ListWorkspaces(false, false)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	names := make([]string, 0, len(result.Workspaces))
	for _, w := range result.Workspaces {
		names = append(names, w.Name)
	}

	return names, cobra.ShellCompDirectiveNoFileComp
}
