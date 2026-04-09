package cmd

import (
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

// listWorkspaceNames queries the daemon and returns all workspace names.
func listWorkspaceNames() ([]string, error) {
	client, err := daemon.NewClient()
	if err != nil {
		return nil, err
	}
	result, err := client.ListWorkspaces(false, false)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(result.Workspaces))
	for _, w := range result.Workspaces {
		names = append(names, w.Name)
	}
	return names, nil
}

// validWorkspaceArgs completes a single <workspace-name> positional argument.
// Once one name has been provided it stops completing.
func validWorkspaceArgs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	names, err := listWorkspaceNames()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

// validWorkspaceArgsMulti completes <workspace-name> arguments for commands
// that accept multiple names (e.g. remove), excluding names already on the line.
func validWorkspaceArgsMulti(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	names, err := listWorkspaceNames()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	used := make(map[string]bool, len(args))
	for _, a := range args {
		used[a] = true
	}
	filtered := names[:0]
	for _, n := range names {
		if !used[n] {
			filtered = append(filtered, n)
		}
	}
	return filtered, cobra.ShellCompDirectiveNoFileComp
}
