package test

import (
	"github.com/spf13/cobra"
)

// NewTestCmd creates the hidden _test command
func NewTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "_test",
		Short:  "Internal test suite (hidden)",
		Hidden: true, // Hide from help output
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	// Add subcommands
	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newPullAndDeployCmd())

	return cmd
}

