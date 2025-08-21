package service

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
	"github.com/spf13/cobra"
)

// NewEditorCmd creates the Editor service command
func NewEditorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "editor",
		Short: "Manage Editor service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	// Add enable/disable/status subcommands
	cmd.AddCommand(newEditorEnableCmd())
	cmd.AddCommand(newEditorDisableCmd())
	cmd.AddCommand(newEditorStatusCmd())
	cmd.AddCommand(newEditorStartCmd())
	cmd.AddCommand(newEditorStopCmd())
	cmd.AddCommand(newEditorUpdateCmd())

	return cmd
}

func newEditorEnableCmd() *cobra.Command {
	var editorImage string
	var oauthConfigFile string
	
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable and start Editor service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return enableEditorService(editorImage, oauthConfigFile)
		},
	}
	
	cmd.Flags().StringVar(&editorImage, "editor-image", "", "Custom image for the editor")
	cmd.Flags().StringVar(&oauthConfigFile, "oauth-config", "", "OAuth config file")
	
	return cmd
}

func newEditorDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Disable Editor service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return disableEditorService()
		},
	}
}

func newEditorStatusCmd() *cobra.Command {
	var showPasswords bool
	
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check Editor service status for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return editorStatus(showPasswords)
		},
	}
	
	cmd.Flags().BoolVar(&showPasswords, "passwords", false, "Show Editor credentials")
	
	return cmd
}

func newEditorStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start Editor container and wait for it to be ready",
		RunE: func(cmd *cobra.Command, args []string) error {
			return startEditorContainer()
		},
	}
}

func newEditorStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop Editor container for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return stopEditorContainer()
		},
	}
}

func newEditorUpdateCmd() *cobra.Command {
	var editorImage string
	
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update Editor service with new image",
		RunE: func(cmd *cobra.Command, args []string) error {
			return updateEditorService(editorImage)
		},
	}
	
	cmd.Flags().StringVar(&editorImage, "editor-image", "", "Custom image for the editor")
	
	return cmd
}

func enableEditorService(editorImage, oauthConfigFile string) error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Editor service manager
	editorService, err := services.NewEditorService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}
	
	// Check if already enabled
	if editorService.IsEnabled() {
		return fmt.Errorf("Editor service is already enabled for workspace '%s'", workspaceName)
	}
	
	// Get metadata to retrieve gitops secret and domain
	metadata, err := editorService.GetMetadata()
	if err != nil {
		return fmt.Errorf("failed to read workspace metadata. Make sure workspace is properly initialized: %w", err)
	}
	
	gitopsSecretToken := metadata.GitopsSecret
	domain := metadata.Domain
	
	// Use provided image or get latest from metadata
	bitswanEditorImage := editorImage
	if bitswanEditorImage == "" {
		// Try to get from metadata or use default
		bitswanEditorImage = "bitswan/bitswan-editor:latest"
	}
	
	// Read OAuth config if provided
	var oauthConfig *oauth.Config
	if oauthConfigFile != "" {
		var err error
		oauthConfig, err = oauth.GetInitOauthConfig(oauthConfigFile)
		if err != nil {
			return fmt.Errorf("failed to get OAuth config: %w", err)
		}
		fmt.Println("OAuth config read successfully!")
	}
	
	// Enable the service
	if err := editorService.Enable(gitopsSecretToken, bitswanEditorImage, domain, oauthConfig); err != nil {
		return err
	}
	
	// Start the editor container
	fmt.Println("Starting editor container...")
	if err := editorService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start editor container: %w", err)
	}
	
	// Wait for editor to be ready
	fmt.Println("Waiting for editor to be ready...")
	if err := editorService.WaitForEditorReady(); err != nil {
		return fmt.Errorf("editor failed to start properly: %w", err)
	}
	
	fmt.Println("✅ Editor service is ready!")
	
	// Show access information
	if err := editorService.ShowAccessInfo(); err == nil {
		// Try to get and show password
		if password, err := editorService.GetEditorPassword(); err == nil {
			fmt.Printf("Editor Password: %s\n", password)
		}
	}
	
	return nil
}

func disableEditorService() error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Editor service manager
	editorService, err := services.NewEditorService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}
	
	// Check if enabled
	if !editorService.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'", workspaceName)
	}
	
	// Disable the service
	return editorService.Disable()
}

func editorStatus(showPasswords bool) error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Editor service manager
	editorService, err := services.NewEditorService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}
	
	// Check status
	if editorService.IsEnabled() {
		fmt.Printf("Editor service is ENABLED for workspace '%s'\n", workspaceName)
		fmt.Println("Files present:")
		fmt.Printf("  - Docker Compose: %s/deployment/docker-compose-editor.yml\n", editorService.WorkspacePath)
		fmt.Printf("  - Config: %s/codeserver-config\n", editorService.WorkspacePath)
		
		// Check container status
		if editorService.IsContainerRunning() {
			fmt.Printf("Container status: RUNNING\n")
		} else {
			fmt.Printf("Container status: STOPPED\n")
		}
		
		// Show access information
		if err := editorService.ShowAccessInfo(); err != nil {
			fmt.Printf("Warning: could not show access URLs: %v\n", err)
		}
		
		// Show passwords if requested
		if showPasswords {
			if err := editorService.ShowCredentials(); err != nil {
				fmt.Printf("Warning: could not show credentials: %v\n", err)
			}
		}
	} else {
		fmt.Printf("Editor service is DISABLED for workspace '%s'\n", workspaceName)
	}
	
	return nil
}

func startEditorContainer() error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Editor service manager
	editorService, err := services.NewEditorService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}
	
	// Check if enabled
	if !editorService.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'. Use 'enable' first", workspaceName)
	}
	
	// Check if already running
	if editorService.IsContainerRunning() {
		fmt.Printf("Editor container is already running for workspace '%s'\n", workspaceName)
		return nil
	}
	
	// Start the container
	fmt.Println("Starting editor container...")
	if err := editorService.StartContainer(); err != nil {
		return err
	}
	
	// Wait for editor to be ready
	fmt.Println("Waiting for editor to be ready...")
	if err := editorService.WaitForEditorReady(); err != nil {
		return fmt.Errorf("editor failed to start properly: %w", err)
	}
	
	fmt.Println("✅ Editor service is ready!")
	
	// Show access information
	if err := editorService.ShowAccessInfo(); err == nil {
		// Try to get and show password
		if password, err := editorService.GetEditorPassword(); err == nil {
			fmt.Printf("Editor Password: %s\n", password)
		}
	}
	
	return nil
}

func stopEditorContainer() error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Editor service manager
	editorService, err := services.NewEditorService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}
	
	// Check if enabled
	if !editorService.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'", workspaceName)
	}
	
	// Check if running
	if !editorService.IsContainerRunning() {
		fmt.Printf("Editor container is not running for workspace '%s'\n", workspaceName)
		return nil
	}
	
	// Stop the container
	return editorService.StopContainer()
}

func updateEditorService(editorImage string) error {
	// Get the active workspace
	workspaceName, err := config.GetWorkspaceName()
	if err != nil {
		return fmt.Errorf("failed to get active workspace: %w", err)
	}
	
	if workspaceName == "" {
		return fmt.Errorf("no active workspace selected. Use 'bitswan workspace select <workspace>' first")
	}
	
	// Create Editor service manager
	editorService, err := services.NewEditorService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}
	
	// Check if enabled
	if !editorService.IsEnabled() {
		return fmt.Errorf("Editor service is not enabled for workspace '%s'. Use 'enable' first", workspaceName)
	}
	
	// Get metadata to verify workspace is properly initialized
	_, err = editorService.GetMetadata()
	if err != nil {
		return fmt.Errorf("failed to read workspace metadata. Make sure workspace is properly initialized: %w", err)
	}
	
	// Stop the current container
	fmt.Println("Stopping current editor container...")
	if err := editorService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop current editor container: %w", err)
	}
	
	// Update the service
	if editorImage != "" {
		// Use provided custom image
		fmt.Printf("Updating Editor service with custom image: %s\n", editorImage)
		if err := editorService.UpdateImage(editorImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		// Update to latest version
		fmt.Println("Updating Editor service to latest version...")
		if err := editorService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
	}
	
	// Start the container with new image
	fmt.Println("Starting editor container with new image...")
	if err := editorService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start editor container: %w", err)
	}
	
	// Wait for editor to be ready
	fmt.Println("Waiting for editor to be ready...")
	if err := editorService.WaitForEditorReady(); err != nil {
		return fmt.Errorf("editor failed to start properly: %w", err)
	}
	
	fmt.Println("✅ Editor service updated successfully!")
	
	// Show access information
	if err := editorService.ShowAccessInfo(); err == nil {
		// Try to get and show password
		if password, err := editorService.GetEditorPassword(); err == nil {
			fmt.Printf("Editor Password: %s\n", password)
		}
	}
	
	return nil
}

 