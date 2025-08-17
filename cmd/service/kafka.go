package service

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
	"github.com/spf13/cobra"
)

// NewKafkaCmd creates the Kafka service command
func NewKafkaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kafka",
		Short: "Manage Kafka service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	// Add enable/disable/status subcommands
	cmd.AddCommand(newKafkaEnableCmd())
	cmd.AddCommand(newKafkaDisableCmd())
	cmd.AddCommand(newKafkaStatusCmd())
	cmd.AddCommand(newKafkaStartCmd())
	cmd.AddCommand(newKafkaStopCmd())

	return cmd
}

func newKafkaEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable",
		Short: "Enable Kafka service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return enableKafkaService()
		},
	}
}

func newKafkaDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Disable Kafka service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return disableKafkaService()
		},
	}
}

func newKafkaStatusCmd() *cobra.Command {
	var showPasswords bool
	
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check Kafka service status for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return kafkaStatus(showPasswords)
		},
	}
	
	cmd.Flags().BoolVar(&showPasswords, "passwords", false, "Show Kafka credentials")
	
	return cmd
}

func newKafkaStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start Kafka containers for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return startKafkaContainer()
		},
	}
}

func newKafkaStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop Kafka containers for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return stopKafkaContainer()
		},
	}
}

func enableKafkaService() error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Kafka service manager
	kafkaService, err := services.NewKafkaService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}
	
	// Check if already enabled
	if kafkaService.IsEnabled() {
		return fmt.Errorf("Kafka service is already enabled for workspace '%s'", workspaceName)
	}
	
	// Enable the service
	return kafkaService.Enable()
}

func disableKafkaService() error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Kafka service manager
	kafkaService, err := services.NewKafkaService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}
	
	// Check if enabled
	if !kafkaService.IsEnabled() {
		return fmt.Errorf("Kafka service is not enabled for workspace '%s'", workspaceName)
	}
	
	// Disable the service
	return kafkaService.Disable()
}

func kafkaStatus(showPasswords bool) error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Kafka service manager
	kafkaService, err := services.NewKafkaService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}
	
	// Check status
	if kafkaService.IsEnabled() {
		fmt.Printf("Kafka service is ENABLED for workspace '%s'\n", workspaceName)
		fmt.Println("Files present:")
		fmt.Printf("  - Secrets: %s/secrets/kafka\n", kafkaService.WorkspacePath)
		fmt.Printf("  - Docker Compose: %s/deployment/docker-compose-kafka.yml\n", kafkaService.WorkspacePath)
		fmt.Printf("  - JAAS Config: %s/deployment/kafka_server_jaas.conf\n", kafkaService.WorkspacePath)
		
		// Check container status
		if kafkaService.IsContainerRunning() {
			fmt.Printf("Container status: RUNNING\n")
		} else {
			fmt.Printf("Container status: STOPPED\n")
		}
		
		// Show access information
		if err := kafkaService.ShowAccessInfo(); err != nil {
			fmt.Printf("Warning: could not show access URLs: %v\n", err)
		}
		
		// Show passwords if requested
		if showPasswords {
			if err := kafkaService.ShowCredentials(); err != nil {
				fmt.Printf("Warning: could not show credentials: %v\n", err)
			}
		}
	} else {
		fmt.Printf("Kafka service is DISABLED for workspace '%s'\n", workspaceName)
	}
	
	return nil
}

func startKafkaContainer() error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Kafka service manager
	kafkaService, err := services.NewKafkaService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}
	
	// Check if enabled
	if !kafkaService.IsEnabled() {
		return fmt.Errorf("Kafka service is not enabled for workspace '%s'. Use 'enable' first", workspaceName)
	}
	
	// Check if already running
	if kafkaService.IsContainerRunning() {
		fmt.Printf("Kafka containers are already running for workspace '%s'\n", workspaceName)
		return nil
	}
	
	// Start the containers
	return kafkaService.StartContainer()
}

func stopKafkaContainer() error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Kafka service manager
	kafkaService, err := services.NewKafkaService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}
	
	// Check if enabled
	if !kafkaService.IsEnabled() {
		return fmt.Errorf("Kafka service is not enabled for workspace '%s'", workspaceName)
	}
	
	// Check if running
	if !kafkaService.IsContainerRunning() {
		fmt.Printf("Kafka containers are not running for workspace '%s'\n", workspaceName)
		return nil
	}
	
	// Stop the containers
	return kafkaService.StopContainer()
} 