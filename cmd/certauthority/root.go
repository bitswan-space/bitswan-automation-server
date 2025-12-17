package certauthority

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
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
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			result, err := client.ListCertAuthorities()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if len(result.CertAuthorities) == 0 {
				fmt.Println("No certificate authorities found.")
				fmt.Printf("Directory: %s\n", result.Directory)
				return nil
			}

			fmt.Println("Certificate Authorities:")
			for _, cert := range result.CertAuthorities {
				fmt.Printf("  - %s (%.2f KB)\n", cert.Name, cert.Size)
			}
			fmt.Printf("\nDirectory: %s\n", result.Directory)
			return nil
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
				fmt.Fprintf(os.Stderr, "Error: source file does not exist: %s\n", sourcePath)
				os.Exit(1)
			}

			// Determine the target filename
			var targetName string
			if len(args) == 2 {
				targetName = args[1]
				// Ensure it has a .crt or .pem extension
				if !strings.HasSuffix(targetName, ".crt") && !strings.HasSuffix(targetName, ".pem") {
					// Preserve original extension if it's .pem, otherwise default to .crt
					if strings.HasSuffix(sourcePath, ".pem") {
						targetName += ".pem"
					} else {
						targetName += ".crt"
					}
				}
			} else {
				targetName = filepath.Base(sourcePath)
			}

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			result, err := client.AddCertAuthority(sourcePath, targetName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("✓ %s\n", result.Message)
			fmt.Printf("  Location: %s\n", result.Location)
			return nil
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

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if err := client.RemoveCertAuthority(certName); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("✓ Certificate authority '%s' removed successfully.\n", certName)
			return nil
		},
	}
}
