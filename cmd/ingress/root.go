package ingress

import "github.com/spf13/cobra"

func NewIngressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ingress",
		Short: "Manage ingress",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newAddRouteCmd())
	cmd.AddCommand(newRemoveRouteCmd())
	cmd.AddCommand(newListRoutesCmd())

	return cmd
} 