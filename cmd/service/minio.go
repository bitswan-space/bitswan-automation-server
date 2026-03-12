package service

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

// NewMinioCmd creates the MinIO service command
func NewMinioCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "minio",
		Short: "Manage MinIO service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newMinioEnableCmd())
	cmd.AddCommand(newMinioDisableCmd())
	cmd.AddCommand(newMinioStatusCmd())
	cmd.AddCommand(newMinioStartCmd())
	cmd.AddCommand(newMinioStopCmd())
	cmd.AddCommand(newMinioUpdateCmd())
	cmd.AddCommand(newMinioBackupCmd())
	cmd.AddCommand(newMinioRestoreCmd())

	return cmd
}

func newMinioEnableCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable MinIO service for the workspace",
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

			result, err := client.EnableService("minio", workspace, options)
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

func newMinioDisableCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable MinIO service for the workspace",
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

			result, err := client.DisableService("minio", workspace, stage)
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

func newMinioStatusCmd() *cobra.Command {
	var showPasswords bool
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check MinIO service status for the workspace",
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

			result, err := client.GetServiceStatus("minio", workspace, stage, showPasswords)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if statusData, ok := result.Data.(map[string]interface{}); ok {
				if enabled, ok := statusData["enabled"].(bool); ok {
					if enabled {
						fmt.Printf("MinIO service is ENABLED for workspace '%s'\n", workspace)
						if running, ok := statusData["running"].(bool); ok {
							if running {
								fmt.Println("Container status: RUNNING")
							} else {
								fmt.Println("Container status: STOPPED")
							}
						}
					} else {
						fmt.Printf("MinIO service is DISABLED for workspace '%s'\n", workspace)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&showPasswords, "passwords", false, "Show MinIO credentials")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newMinioStartCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start MinIO container for the workspace",
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

			result, err := client.StartService("minio", workspace, stage)
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

func newMinioStopCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop MinIO container for the workspace",
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

			result, err := client.StopService("minio", workspace, stage)
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

func newMinioUpdateCmd() *cobra.Command {
	var minioImage string
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update MinIO service with new image",
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
			if minioImage != "" {
				options["minio_image"] = minioImage
			}

			result, err := client.UpdateService("minio", workspace, options)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVar(&minioImage, "minio-image", "", "Custom image for MinIO")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newMinioBackupCmd() *cobra.Command {
	var backupPath string
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create a backup of all MinIO buckets",
		Long:  "Creates a backup of all buckets in MinIO. The backup will be saved as a tarball with automatic date/time naming (format: minio-backup-YYYYMMDD-HHMMSS.tar.gz) in the specified directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if backupPath == "" {
				fmt.Fprintf(os.Stderr, "Error: backup path is required. Use --path to specify the backup location\n")
				os.Exit(1)
			}

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

			result, err := client.BackupMinio(workspace, stage, absBackupPath)
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

func newMinioRestoreCmd() *cobra.Command {
	var backupPath string
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore MinIO buckets from a backup",
		Long:  "Restores MinIO buckets from a backup tarball (.tar.gz) or directory. Buckets will be created if they don't exist.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if backupPath == "" {
				fmt.Fprintf(os.Stderr, "Error: backup path is required. Use --path to specify the backup location\n")
				os.Exit(1)
			}

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

			err = client.RestoreMinioInteractive(workspace, stage, absBackupPath)
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
