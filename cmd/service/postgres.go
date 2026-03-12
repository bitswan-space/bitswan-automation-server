package service

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

// NewPostgresCmd creates the PostgreSQL service command
func NewPostgresCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "postgres",
		Short: "Manage PostgreSQL service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	// Add enable/disable/status subcommands
	cmd.AddCommand(newPostgresEnableCmd())
	cmd.AddCommand(newPostgresDisableCmd())
	cmd.AddCommand(newPostgresStatusCmd())
	cmd.AddCommand(newPostgresStartCmd())
	cmd.AddCommand(newPostgresStopCmd())
	cmd.AddCommand(newPostgresUpdateCmd())
	cmd.AddCommand(newPostgresBackupCmd())
	cmd.AddCommand(newPostgresRestoreCmd())

	return cmd
}

func newPostgresEnableCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable PostgreSQL service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'\n")
					os.Exit(1)
				}
			}

			options := make(map[string]interface{})
			if stage != "" {
				options["stage"] = stage
			}

			result, err := client.EnableService("postgres", workspace, options)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if result != nil && result.Message != "" {
				fmt.Println(result.Message)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newPostgresDisableCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable PostgreSQL service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'\n")
					os.Exit(1)
				}
			}

			result, err := client.DisableService("postgres", workspace, stage)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newPostgresStatusCmd() *cobra.Command {
	var showPasswords bool
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check PostgreSQL service status for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'\n")
					os.Exit(1)
				}
			}

			result, err := client.GetServiceStatus("postgres", workspace, stage, showPasswords)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if statusData, ok := result.Data.(map[string]interface{}); ok {
				if enabled, ok := statusData["enabled"].(bool); ok {
					if enabled {
						fmt.Printf("PostgreSQL service is ENABLED for workspace '%s'\n", workspace)
						if running, ok := statusData["running"].(bool); ok {
							if running {
								fmt.Println("Container status: RUNNING")
							} else {
								fmt.Println("Container status: STOPPED")
							}
						}
					} else {
						fmt.Printf("PostgreSQL service is DISABLED for workspace '%s'\n", workspace)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&showPasswords, "passwords", false, "Show PostgreSQL credentials")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newPostgresStartCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start PostgreSQL container for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'\n")
					os.Exit(1)
				}
			}

			result, err := client.StartService("postgres", workspace, stage)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newPostgresStopCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop PostgreSQL container for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'\n")
					os.Exit(1)
				}
			}

			result, err := client.StopService("postgres", workspace, stage)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newPostgresUpdateCmd() *cobra.Command {
	var postgresImage string
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update PostgreSQL service with new image",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'\n")
					os.Exit(1)
				}
			}

			options := make(map[string]interface{})
			if stage != "" {
				options["stage"] = stage
			}
			if postgresImage != "" {
				options["postgres_image"] = postgresImage
			}

			result, err := client.UpdateService("postgres", workspace, options)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVar(&postgresImage, "postgres-image", "", "Custom image for PostgreSQL")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newPostgresBackupCmd() *cobra.Command {
	var backupPath string
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create a backup of all PostgreSQL databases",
		Long:  "Creates a backup of all databases in PostgreSQL. The backup will be saved as a tarball with automatic date/time naming (format: postgres-backup-YYYYMMDD-HHMMSS.tar.gz) in the specified directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if backupPath == "" {
				fmt.Fprintf(os.Stderr, "Error: backup path is required. Use --path to specify the backup location\n")
				os.Exit(1)
			}

			// Resolve to absolute path so daemon knows the exact host location
			absBackupPath, err := filepath.Abs(backupPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to resolve backup path: %v\n", err)
				os.Exit(1)
			}

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'\n")
					os.Exit(1)
				}
			}

			result, err := client.BackupPostgres(workspace, stage, absBackupPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if result != nil && result.Message != "" {
				fmt.Println(result.Message)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&backupPath, "path", "", "Directory where the backup tarball will be saved (required)")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")
	cmd.MarkFlagRequired("path")

	return cmd
}

func newPostgresRestoreCmd() *cobra.Command {
	var backupPath string
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore PostgreSQL databases from a backup",
		Long:  "Restores PostgreSQL databases from a backup tarball (.tar.gz) or directory. Databases will be created if they don't exist.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if backupPath == "" {
				fmt.Fprintf(os.Stderr, "Error: backup path is required. Use --path to specify the backup location\n")
				os.Exit(1)
			}

			// Resolve to absolute path so daemon knows the exact host location
			absBackupPath, err := filepath.Abs(backupPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to resolve backup path: %v\n", err)
				os.Exit(1)
			}

			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'\n")
					os.Exit(1)
				}
			}

			// Use interactive job API for restore to handle prompts
			err = client.RestorePostgresInteractive(workspace, stage, absBackupPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&backupPath, "path", "", "Path to the backup tarball (.tar.gz) or directory (required)")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")
	cmd.MarkFlagRequired("path")

	return cmd
}
