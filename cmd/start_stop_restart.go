package cmd

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func resolveWorkspaceName(args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	cfg := config.NewAutomationServerConfig()
	ws, err := cfg.GetActiveWorkspace()
	if err != nil {
		return "", fmt.Errorf("no workspace specified and no active workspace set: %w", err)
	}
	return ws, nil
}

func newStartCmd() *cobra.Command {
	var automationsOnly bool

	cmd := &cobra.Command{
		Use:          "start [workspace]",
		Short:        "Start all services in a workspace",
		Long:         "Start the GitOps container, editor service, and deploy all automations in a workspace. If no workspace is specified, the active workspace is used.",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceName, err := resolveWorkspaceName(args)
			if err != nil {
				return err
			}

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if err := client.WorkspaceStart(workspaceName, automationsOnly); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&automationsOnly, "automations", false, "Only start automations and their dependent services (skip GitOps and editor)")

	return cmd
}

func newStopCmd() *cobra.Command {
	var automationsOnly bool

	cmd := &cobra.Command{
		Use:          "stop [workspace]",
		Short:        "Stop all services in a workspace",
		Long:         "Stop all automations, the editor service, and the GitOps container in a workspace. If no workspace is specified, the active workspace is used.",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceName, err := resolveWorkspaceName(args)
			if err != nil {
				return err
			}

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if err := client.WorkspaceStop(workspaceName, automationsOnly); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&automationsOnly, "automations", false, "Only stop automations (skip editor and GitOps)")

	return cmd
}

func newRestartCmd() *cobra.Command {
	var automationsOnly bool

	cmd := &cobra.Command{
		Use:          "restart [workspace]",
		Short:        "Restart all services in a workspace",
		Long:         "Stop and then start all services in a workspace. If no workspace is specified, the active workspace is used.",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceName, err := resolveWorkspaceName(args)
			if err != nil {
				return err
			}

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if err := client.WorkspaceRestart(workspaceName, automationsOnly); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&automationsOnly, "automations", false, "Only restart automations (skip editor and GitOps)")

	return cmd
}
