package cmd

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newPullAndDeployCmd() *cobra.Command {
	var branch string

	cmd := &cobra.Command{
		Use:   "pull-and-deploy [workspace_name]",
		Short: "Pull a specific branch into workspace gitops folder, build all automation images, and deploy them",
		Long:  "Pull a specific branch into workspace gitops folder, build all automation images, and deploy them",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceName := args[0]

			if branch == "" {
				return fmt.Errorf("branch flag is required, use --branch or -b to specify the branch")
			}

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if err := client.PullAndDeploy(workspaceName, branch); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&branch, "branch", "b", "", "Branch name to pull and deploy (required)")

	// Mark branch flag as required
	cmd.MarkFlagRequired("branch")

	return cmd
}
