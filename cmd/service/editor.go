package service

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
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
	var trustCA bool
	var workspace string

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable and start Editor service for the workspace",
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
			if editorImage != "" {
				options["editor_image"] = editorImage
			}
			if trustCA {
				options["trust_ca"] = true
			}

			// Read OAuth config if provided
			if oauthConfigFile != "" {
				oauthConfig, err := oauth.GetInitOauthConfig(oauthConfigFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: failed to read OAuth config: %v\n", err)
					os.Exit(1)
				}
				// Convert to map for JSON serialization
				oauthJSON, _ := json.Marshal(oauthConfig)
				var oauthMap map[string]interface{}
				json.Unmarshal(oauthJSON, &oauthMap)
				options["oauth_config"] = oauthMap
			}

			result, err := client.EnableService("editor", workspace, options)
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

	cmd.Flags().StringVar(&editorImage, "editor-image", "", "Custom image for the editor")
	cmd.Flags().StringVar(&oauthConfigFile, "oauth-config", "", "OAuth config file")
	cmd.Flags().BoolVar(&trustCA, "trust-ca", false, "Install custom certificates from the default CA certificates directory.")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

func newEditorDisableCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable Editor service for the workspace",
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

			result, err := client.DisableService("editor", workspace, "")
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

func newEditorStatusCmd() *cobra.Command {
	var showPasswords bool
	var workspace string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check Editor service status for the workspace",
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

			result, err := client.GetServiceStatus("editor", workspace, "", showPasswords)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Format status output
			if statusData, ok := result.Data.(map[string]interface{}); ok {
				if enabled, ok := statusData["enabled"].(bool); ok {
					if enabled {
						fmt.Printf("Editor service is ENABLED for workspace '%s'\n", workspace)
						if running, ok := statusData["running"].(bool); ok {
							if running {
								fmt.Println("Container status: RUNNING")
							} else {
								fmt.Println("Container status: STOPPED")
							}
						}
						if showPasswords {
							if password, ok := statusData["password"].(string); ok {
								fmt.Printf("Editor Password: %s\n", password)
							}
						}
					} else {
						fmt.Printf("Editor service is DISABLED for workspace '%s'\n", workspace)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&showPasswords, "passwords", false, "Show Editor credentials")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

func newEditorStartCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start Editor container and wait for it to be ready",
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

			result, err := client.StartService("editor", workspace, "")
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

func newEditorStopCmd() *cobra.Command {
	var workspace string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop Editor container for the workspace",
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

			result, err := client.StopService("editor", workspace, "")
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

func newEditorUpdateCmd() *cobra.Command {
	var editorImage string
	var trustCA bool
	var workspace string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update Editor service with new image and/or certificates",
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
			if editorImage != "" {
				options["editor_image"] = editorImage
			}
			if trustCA {
				options["trust_ca"] = true
			}

			result, err := client.UpdateService("editor", workspace, options)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(result.Message)
			return nil
		},
	}

	cmd.Flags().StringVar(&editorImage, "editor-image", "", "Custom image for the editor")
	cmd.Flags().BoolVar(&trustCA, "trust-ca", false, "Install custom certificates from the default CA certificates directory.")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}
