package service

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

// NewCouchDBCmd creates the CouchDB service command
func NewCouchDBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "couchdb",
		Short: "Manage CouchDB service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	// Add enable/disable/status subcommands
	cmd.AddCommand(newCouchDBEnableCmd())
	cmd.AddCommand(newCouchDBDisableCmd())
	cmd.AddCommand(newCouchDBStatusCmd())
	cmd.AddCommand(newCouchDBStartCmd())
	cmd.AddCommand(newCouchDBStopCmd())
	cmd.AddCommand(newCouchDBUpdateCmd())
	cmd.AddCommand(newCouchDBBackupCmd())
	cmd.AddCommand(newCouchDBRestoreCmd())

	return cmd
}

func newCouchDBEnableCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable CouchDB service for the workspace",
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

			result, err := client.EnableService("couchdb", workspace, options)
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

func newCouchDBDisableCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable CouchDB service for the workspace",
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

			result, err := client.DisableService("couchdb", workspace, stage)
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

func newCouchDBStatusCmd() *cobra.Command {
	var showPasswords bool
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check CouchDB service status for the workspace",
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

			result, err := client.GetServiceStatus("couchdb", workspace, stage, showPasswords)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if statusData, ok := result.Data.(map[string]interface{}); ok {
				if enabled, ok := statusData["enabled"].(bool); ok {
					if enabled {
						fmt.Printf("CouchDB service is ENABLED for workspace '%s'\n", workspace)
						if running, ok := statusData["running"].(bool); ok {
							if running {
								fmt.Println("Container status: RUNNING")
							} else {
								fmt.Println("Container status: STOPPED")
							}
						}
					} else {
						fmt.Printf("CouchDB service is DISABLED for workspace '%s'\n", workspace)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&showPasswords, "passwords", false, "Show CouchDB credentials")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newCouchDBStartCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start CouchDB container for the workspace",
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

			result, err := client.StartService("couchdb", workspace, stage)
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

func newCouchDBStopCmd() *cobra.Command {
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop CouchDB container for the workspace",
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

			result, err := client.StopService("couchdb", workspace, stage)
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

func newCouchDBUpdateCmd() *cobra.Command {
	var couchdbImage string
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update CouchDB service with new image",
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
			if couchdbImage != "" {
				options["couchdb_image"] = couchdbImage
			}

			result, err := client.UpdateService("couchdb", workspace, options)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVar(&couchdbImage, "couchdb-image", "", "Custom image for CouchDB")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	cmd.Flags().StringVar(&stage, "stage", "production", "Service realm stage (dev, staging, production)")

	return cmd
}

func newCouchDBBackupCmd() *cobra.Command {
	var backupPath string
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create a backup of all CouchDB databases",
		Long:  "Creates a backup of all user databases in CouchDB. The backup will be saved as a tarball with automatic date/time naming (format: couchdb-backup-YYYYMMDD-HHMMSS.tar.gz) in the specified directory.",
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

			result, err := client.BackupCouchDB(workspace, stage, absBackupPath)
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

func newCouchDBRestoreCmd() *cobra.Command {
	var backupPath string
	var workspace string
	var stage string

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore CouchDB databases from a backup",
		Long:  "Restores CouchDB databases from a backup tarball (.tar.gz) or directory. Databases will be created if they don't exist.",
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
			err = client.RestoreCouchDBInteractive(workspace, stage, absBackupPath)
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
