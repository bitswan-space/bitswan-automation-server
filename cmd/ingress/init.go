package ingress

import (
	"github.com/bitswan-space/bitswan-workspaces/internal/daemonapi"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initializes an ingress proxy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			argsList := []string{"init"}
			if verbose {
				argsList = append(argsList, "--verbose")
			}
			return daemonapi.ExecuteViaDockerExec("ingress", argsList, "")
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}

// InitIngress is kept for backward compatibility but now calls the REST API
func InitIngress(verbose bool) error {
	argsList := []string{"init"}
	if verbose {
		argsList = append(argsList, "--verbose")
	}
	return daemonapi.ExecuteViaDockerExec("ingress", argsList, "")
}
