package certauthority

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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

func getCertAuthoritiesDir() (string, error) {
	certDir := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "certauthorities")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create certauthorities directory: %w", err)
	}
	return certDir, nil
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all certificate authorities",
		RunE: func(cmd *cobra.Command, args []string) error {
			certDir, err := getCertAuthoritiesDir()
			if err != nil {
				return err
			}

			files, err := os.ReadDir(certDir)
			if err != nil {
				return fmt.Errorf("failed to read certauthorities directory: %w", err)
			}

			if len(files) == 0 {
				fmt.Println("No certificate authorities found.")
				fmt.Printf("Directory: %s\n", certDir)
				return nil
			}

			fmt.Println("Certificate Authorities:")
			count := 0
			for _, file := range files {
				if !file.IsDir() && (strings.HasSuffix(file.Name(), ".crt") || strings.HasSuffix(file.Name(), ".pem")) {
					info, _ := file.Info()
					fmt.Printf("  - %s (%.2f KB)\n", file.Name(), float64(info.Size())/1024)
					count++
				}
			}

			if count == 0 {
				fmt.Println("No certificate authorities found (no .crt or .pem files).")
			}
			fmt.Printf("\nDirectory: %s\n", certDir)
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
				return fmt.Errorf("source file does not exist: %s", sourcePath)
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

			certDir, err := getCertAuthoritiesDir()
			if err != nil {
				return err
			}

			targetPath := filepath.Join(certDir, targetName)

			// Check if file already exists
			if _, err := os.Stat(targetPath); err == nil {
				return fmt.Errorf("certificate authority '%s' already exists", targetName)
			}

			// Copy the certificate file
			sourceFile, err := os.Open(sourcePath)
			if err != nil {
				return fmt.Errorf("failed to open source file: %w", err)
			}
			defer sourceFile.Close()

			targetFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create target file: %w", err)
			}
			defer targetFile.Close()

			if _, err := io.Copy(targetFile, sourceFile); err != nil {
				return fmt.Errorf("failed to copy certificate: %w", err)
			}

			fmt.Printf("✓ Certificate authority '%s' added successfully.\n", targetName)
			fmt.Printf("  Location: %s\n", targetPath)
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

			certDir, err := getCertAuthoritiesDir()
			if err != nil {
				return err
			}

			certPath := filepath.Join(certDir, certName)

			// Check if file exists
			if _, err := os.Stat(certPath); os.IsNotExist(err) {
				return fmt.Errorf("certificate authority '%s' not found", certName)
			}

			// Remove the file
			if err := os.Remove(certPath); err != nil {
				return fmt.Errorf("failed to remove certificate: %w", err)
			}

			fmt.Printf("✓ Certificate authority '%s' removed successfully.\n", certName)
			return nil
		},
	}
}
