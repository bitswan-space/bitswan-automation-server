package certauthority

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemonapi"
	"github.com/spf13/cobra"
)

func NewCertAuthorityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ca",
		Aliases: []string{"certauthority"},
		Short:   "Manage certificate authorities",
		Long:    "Manage certificate authorities that will be trusted by workspace containers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newAddCmd())
	cmd.AddCommand(newRemoveCmd())

	return cmd
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all certificate authorities",
		RunE: func(cmd *cobra.Command, args []string) error {
			return daemonapi.ExecuteViaDockerExec("ca", []string{"list"}, "")
		},
	}
}

func newAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <certificate-file> [name]",
		Short: "Add a certificate authority",
		Long:  "Add a certificate authority. If name is not provided, uses the original filename.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sourcePath := args[0]

			// Check if source file exists
			if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
				return fmt.Errorf("source file does not exist: %s", sourcePath)
			}

			// Build args list - docker_exec.go will read the file
			argsList := []string{"add", sourcePath}
			if len(args) == 2 {
				argsList = append(argsList, args[1])
			}

			return daemonapi.ExecuteViaDockerExec("ca", argsList, "")
		},
	}
}

func newRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <certificate-name>",
		Aliases: []string{"rm"},
		Short:   "Remove a certificate authority",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certName := args[0]
			return daemonapi.ExecuteViaDockerExec("ca", []string{"remove", certName}, "")
		},
	}
}
