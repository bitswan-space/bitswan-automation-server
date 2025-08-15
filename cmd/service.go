package cmd

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
	"github.com/spf13/cobra"
)

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage workspace services",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	// Add service-specific subcommands
	cmd.AddCommand(newCouchDBCmd())

	return cmd
}

func newCouchDBCmd() *cobra.Command {
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

func enableCouchDBService() error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
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
	workspaceName, err := config.GetWorkspaceName()
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

func couchDBStatus(showPasswords bool) error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
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

func startCouchDBContainer() error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
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
	workspaceName, err := config.GetWorkspaceName()
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