package cmd

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	var showPasswords bool
	var long bool

	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List available bitswan workspaces",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			result, err := client.ListWorkspaces(long, showPasswords)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Print workspaces
			for _, workspace := range result.Workspaces {
				fmt.Fprintln(cmd.OutOrStdout(), workspace.Name)
				
				if long {
					if workspace.Domain != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "  Workspace Domain: %s\n", workspace.Domain)
					}
					if workspace.EditorURL != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "  Editor URL: %s\n", workspace.EditorURL)
					}
					if workspace.GitopsURL != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "  Gitops URL: %s\n", workspace.GitopsURL)
					}
					if workspace.SSHPublicKey != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "  SSH Public Key: %s\n", workspace.SSHPublicKey)
					}
				}

				if showPasswords {
					if workspace.VSCodePassword != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "  VSCode Password: %s\n", workspace.VSCodePassword)
					}
					if workspace.GitopsSecret != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "  GitOps Secret: %s\n", workspace.GitopsSecret)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&showPasswords, "passwords", false, "Show VSCode server passwords and GitOps secrets")
	cmd.Flags().BoolVarP(&long, "long", "l", false, "Show verbose output")

	return cmd
}
