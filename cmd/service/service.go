package service

import (
	"github.com/spf13/cobra"
)

// NewServiceCmd creates the main service command
func NewServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage workspace services",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	// Add service-specific subcommands
	cmd.AddCommand(NewCouchDBCmd())

	return cmd
} 