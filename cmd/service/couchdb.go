package service

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
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
	return &cobra.Command{
		Use:   "enable",
		Short: "Enable CouchDB service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return enableCouchDBService()
		},
	}
}

func newCouchDBDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Disable CouchDB service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return disableCouchDBService()
		},
	}
}

func newCouchDBStatusCmd() *cobra.Command {
	var showPasswords bool
	
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check CouchDB service status for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return couchDBStatus(showPasswords)
		},
	}
	
	cmd.Flags().BoolVar(&showPasswords, "passwords", false, "Show CouchDB credentials")
	
	return cmd
}

func newCouchDBStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start CouchDB container for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return startCouchDBContainer()
		},
	}
}

func newCouchDBStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop CouchDB container for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return stopCouchDBContainer()
		},
	}
}

func newCouchDBUpdateCmd() *cobra.Command {
	var couchdbImage string
	
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update CouchDB service with new image",
		RunE: func(cmd *cobra.Command, args []string) error {
			return updateCouchDBService(couchdbImage)
		},
	}
	
	cmd.Flags().StringVar(&couchdbImage, "couchdb-image", "", "Custom image for CouchDB")
	
	return cmd
}

func enableCouchDBService() error {
	// Get the active workspace
	cfg := config.NewAutomationServerConfig()
	workspaceName, err := cfg.GetActiveWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create CouchDB service manager
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}
	
	// Check if already enabled
	if couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is already enabled for workspace '%s'", workspaceName)
	}
	
	// Enable the service
	return couchdbService.Enable()
}

func disableCouchDBService() error {
	// Get the active workspace
	cfg := config.NewAutomationServerConfig()
	workspaceName, err := cfg.GetActiveWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create CouchDB service manager
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}
	
	// Check if enabled
	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'", workspaceName)
	}
	
	// Disable the service
	return couchdbService.Disable()
}

func couchDBStatus(showPasswords bool) error {
	// Get the active workspace
	cfg := config.NewAutomationServerConfig()
	workspaceName, err := cfg.GetActiveWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create CouchDB service manager
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}
	
	// Check status
	if couchdbService.IsEnabled() {
		fmt.Printf("CouchDB service is ENABLED for workspace '%s'\n", workspaceName)
		fmt.Println("Files present:")
		fmt.Printf("  - Secrets: %s/secrets/couchdb\n", couchdbService.WorkspacePath)
		fmt.Printf("  - Docker Compose: %s/deployment/docker-compose-couchdb.yml\n", couchdbService.WorkspacePath)
		
		// Check container status
		if couchdbService.IsContainerRunning() {
			fmt.Printf("Container status: RUNNING\n")
		} else {
			fmt.Printf("Container status: STOPPED\n")
		}
		
		// Show access information
		if err := couchdbService.ShowAccessInfo(); err != nil {
			fmt.Printf("Warning: could not show access URLs: %v\n", err)
		}
		
		// Show passwords if requested
		if showPasswords {
			if err := couchdbService.ShowCredentials(); err != nil {
				fmt.Printf("Warning: could not show credentials: %v\n", err)
			}
		}
	} else {
		fmt.Printf("CouchDB service is DISABLED for workspace '%s'\n", workspaceName)
	}
	
	return nil
}

func startCouchDBContainer() error {
	// Get the active workspace
	cfg := config.NewAutomationServerConfig()
	workspaceName, err := cfg.GetActiveWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create CouchDB service manager
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}
	
	// Check if enabled
	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'. Use 'enable' first", workspaceName)
	}
	
	// Check if already running
	if couchdbService.IsContainerRunning() {
		fmt.Printf("CouchDB container is already running for workspace '%s'\n", workspaceName)
		return nil
	}
	
	// Start the container
	return couchdbService.StartContainer()
}

func stopCouchDBContainer() error {
	// Get the active workspace
	cfg := config.NewAutomationServerConfig()
	workspaceName, err := cfg.GetActiveWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create CouchDB service manager
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}
	
	// Check if enabled
	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'", workspaceName)
	}
	
	// Check if running
	if !couchdbService.IsContainerRunning() {
		fmt.Printf("CouchDB container is not running for workspace '%s'\n", workspaceName)
		return nil
	}
	
	// Stop the container
	return couchdbService.StopContainer()
}

func updateCouchDBService(couchdbImage string) error {
	// Get the active workspace
	cfg := config.NewAutomationServerConfig()
	workspaceName, err := cfg.GetActiveWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create CouchDB service manager
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}
	
	// Check if enabled
	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'. Use 'enable' first", workspaceName)
	}
	
	// Stop the current container
	fmt.Println("Stopping current CouchDB container...")
	if err := couchdbService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop current CouchDB container: %w", err)
	}
	
	// Update the service
	if couchdbImage != "" {
		// Use provided custom image
		fmt.Printf("Updating CouchDB service with custom image: %s\n", couchdbImage)
		if err := couchdbService.UpdateImage(couchdbImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		// Update to latest version
		fmt.Println("Updating CouchDB service to latest version...")
		if err := couchdbService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
	}
	
	// Start the container with new image
	fmt.Println("Starting CouchDB container with new image...")
	if err := couchdbService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start CouchDB container: %w", err)
	}
	
	fmt.Println("✅ CouchDB service updated successfully!")
	
	// Show access information
	if err := couchdbService.ShowAccessInfo(); err == nil {
		// Try to get and show credentials
		if err := couchdbService.ShowCredentials(); err == nil {
			fmt.Println("Updated credentials:")
		}
	}
	
	return nil
}

func newCouchDBBackupCmd() *cobra.Command {
	var backupPath string
	
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create a backup of all CouchDB databases",
		Long:  "Creates a backup of all user databases in CouchDB. The backup will be saved as a tarball with automatic date/time naming (format: couchdb-backup-YYYYMMDD-HHMMSS.tar.gz) in the specified directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if backupPath == "" {
				return fmt.Errorf("backup path is required. Use --path to specify the backup location")
			}
			return backupCouchDB(backupPath)
		},
	}
	
	cmd.Flags().StringVar(&backupPath, "path", "", "Directory where the backup tarball will be saved (required)")
	cmd.MarkFlagRequired("path")
	
	return cmd
}

func newCouchDBRestoreCmd() *cobra.Command {
	var backupPath string
	
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore CouchDB databases from a backup",
		Long:  "Restores CouchDB databases from a backup tarball (.tar.gz) or directory. Databases will be created if they don't exist.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if backupPath == "" {
				return fmt.Errorf("backup path is required. Use --path to specify the backup location")
			}
			return restoreCouchDB(backupPath)
		},
	}
	
	cmd.Flags().StringVar(&backupPath, "path", "", "Path to the backup tarball (.tar.gz) or directory (required)")
	cmd.MarkFlagRequired("path")
	
	return cmd
}

func backupCouchDB(backupPath string) error {
	// Get the active workspace
	cfg := config.NewAutomationServerConfig()
	workspaceName, err := cfg.GetActiveWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create CouchDB service manager
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}
	
	// Check if enabled
	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'. Use 'enable' first", workspaceName)
	}
	
	// Perform backup
	return couchdbService.Backup(backupPath)
}

func restoreCouchDB(backupPath string) error {
	// Get the active workspace
	cfg := config.NewAutomationServerConfig()
	workspaceName, err := cfg.GetActiveWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create CouchDB service manager
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}
	
	// Check if enabled
	if !couchdbService.IsEnabled() {
		return fmt.Errorf("CouchDB service is not enabled for workspace '%s'. Use 'enable' first", workspaceName)
	}
	
	// Perform restore
	return couchdbService.Restore(backupPath)
}

 