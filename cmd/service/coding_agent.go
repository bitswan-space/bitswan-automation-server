package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

// NewCodingAgentCmd creates the Coding Agent service command
func NewCodingAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "coding-agent",
		Short: "Manage Coding Agent service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newCodingAgentEnableCmd())
	cmd.AddCommand(newCodingAgentDisableCmd())
	cmd.AddCommand(newCodingAgentStatusCmd())
	cmd.AddCommand(newCodingAgentStartCmd())
	cmd.AddCommand(newCodingAgentStopCmd())
	cmd.AddCommand(newCodingAgentUpdateCmd())
	cmd.AddCommand(newCodingAgentBuildCmd())

	return cmd
}

func newCodingAgentEnableCmd() *cobra.Command {
	var codingAgentImage string
	var workspace string
	var devMode bool
	var sourceDir string

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable and start Coding Agent service for the workspace",
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
			if codingAgentImage != "" {
				options["coding_agent_image"] = codingAgentImage
			}

			if devMode {
				options["dev_mode"] = true
				if sourceDir == "" {
					homeDir := os.Getenv("HOME")
					wsPath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspace)
					sourceDir = filepath.Join(wsPath, "workspace", "AOC", "bitswan-agent")
				}
				options["source_dir"] = sourceDir
			}

			result, err := client.EnableService("coding-agent", workspace, options)
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

	cmd.Flags().StringVar(&codingAgentImage, "coding-agent-image", "", "Custom image for the coding agent")
	cmd.Flags().BoolVar(&devMode, "dev-mode", false, "Mount source files from bitswan-agent for live development")
	cmd.Flags().StringVar(&sourceDir, "source-dir", "", "Path to bitswan-agent source (default: workspace/AOC/bitswan-agent)")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

func newCodingAgentDisableCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable Coding Agent service for the workspace",
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

			result, err := client.DisableService("coding-agent", workspace, "")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

func newCodingAgentStatusCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check Coding Agent service status for the workspace",
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

			result, err := client.GetServiceStatus("coding-agent", workspace, "", false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Format status output
			if statusData, ok := result.Data.(map[string]interface{}); ok {
				if enabled, ok := statusData["enabled"].(bool); ok {
					if enabled {
						fmt.Printf("Coding Agent service is ENABLED for workspace '%s'\n", workspace)
						if running, ok := statusData["running"].(bool); ok {
							if running {
								fmt.Println("Container status: RUNNING")
							} else {
								fmt.Println("Container status: STOPPED")
							}
						}
					} else {
						fmt.Printf("Coding Agent service is DISABLED for workspace '%s'\n", workspace)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

func newCodingAgentStartCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start Coding Agent container",
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

			result, err := client.StartService("coding-agent", workspace, "")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

func newCodingAgentStopCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop Coding Agent container for the workspace",
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

			result, err := client.StopService("coding-agent", workspace, "")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

func newCodingAgentUpdateCmd() *cobra.Command {
	var codingAgentImage string
	var workspace string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update Coding Agent service with a new image",
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
			if codingAgentImage != "" {
				options["coding_agent_image"] = codingAgentImage
			}

			result, err := client.UpdateService("coding-agent", workspace, options)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVar(&codingAgentImage, "coding-agent-image", "", "Custom image for the coding agent")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

func newCodingAgentBuildCmd() *cobra.Command {
	var workspace string
	var sourceDir string

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build coding agent image from local source and restart with dev mode",
		Long: `Builds a Docker image from the bitswan-agent source directory, then
restarts the coding agent container with the new image and dev mode
enabled. Dev mode mounts agent-session-wrapper and AGENTS.md from
the source directory so future changes take effect without rebuilding.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace. Use --workspace or 'bitswan workspace select'\n")
					os.Exit(1)
				}
			}

			if sourceDir == "" {
				homeDir := os.Getenv("HOME")
				wsPath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspace)
				sourceDir = filepath.Join(wsPath, "workspace", "AOC", "bitswan-agent")
			}

			if _, statErr := os.Stat(filepath.Join(sourceDir, "Dockerfile")); os.IsNotExist(statErr) {
				return fmt.Errorf("no Dockerfile found in %s", sourceDir)
			}

			imageTag := fmt.Sprintf("bitswan/coding-agent:%s-local", workspace)
			containerName := fmt.Sprintf("%s-coding-agent", workspace)

			// Build
			fmt.Printf("Building coding agent image from %s...\n", sourceDir)
			buildCmd := exec.Command("docker", "build", "--no-cache", "-t", imageTag, ".")
			buildCmd.Dir = sourceDir
			buildCmd.Stdout = os.Stdout
			buildCmd.Stderr = os.Stderr
			if err := buildCmd.Run(); err != nil {
				return fmt.Errorf("docker build failed: %w", err)
			}

			// Stop old container
			fmt.Printf("Stopping %s...\n", containerName)
			stopCmd := exec.Command("docker", "rm", "-f", containerName)
			stopCmd.Stdout = os.Stdout
			stopCmd.Stderr = os.Stderr
			_ = stopCmd.Run()

			// Re-enable with new image + dev mode
			fmt.Println("Restarting with new image and dev mode...")
			client, err := daemon.NewClient()
			if err != nil {
				return fmt.Errorf("daemon not running: %w", err)
			}
			options := map[string]interface{}{
				"coding_agent_image": imageTag,
				"dev_mode":           true,
				"source_dir":         sourceDir,
			}
			result, err := client.EnableService("coding-agent", workspace, options)
			if err != nil {
				return fmt.Errorf("failed to restart: %w", err)
			}

			if result != nil && result.Message != "" {
				fmt.Println(result.Message)
			}
			fmt.Printf("Image: %s\n", imageTag)
			fmt.Printf("Dev mode: source files mounted from %s\n", sourceDir)
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name")
	cmd.Flags().StringVar(&sourceDir, "source-dir", "", "Source directory (default: workspace/AOC/bitswan-agent)")

	return cmd
}
