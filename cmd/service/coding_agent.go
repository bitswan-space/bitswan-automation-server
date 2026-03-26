package service

import (
	"fmt"
	"os"

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

	// Add enable/disable/status subcommands
	cmd.AddCommand(newCodingAgentEnableCmd())
	cmd.AddCommand(newCodingAgentDisableCmd())
	cmd.AddCommand(newCodingAgentStatusCmd())
	cmd.AddCommand(newCodingAgentStartCmd())
	cmd.AddCommand(newCodingAgentStopCmd())
	cmd.AddCommand(newCodingAgentUpdateCmd())

	return cmd
}

func newCodingAgentEnableCmd() *cobra.Command {
	var codingAgentImage string
	var workspace string

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

			// Get workspace from flag or active config
			if workspace == "" {
				cfg := config.NewAutomationServerConfig()
				workspace, err = cfg.GetActiveWorkspace()
				if err != nil || workspace == "" {
					fmt.Fprintf(os.Stderr, "Error: no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'\n")
					os.Exit(1)
				}
			}

			// Build options map
			options := make(map[string]interface{})
			if codingAgentImage != "" {
				options["coding_agent_image"] = codingAgentImage
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
