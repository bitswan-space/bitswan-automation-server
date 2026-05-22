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

// NewDashboardCmd creates the workspace-dashboard service command tree.
// Mirrors NewEditorCmd so the dashboard has the same enable/disable/status/
// start/stop/update lifecycle as the editor.
func NewDashboardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Manage workspace-dashboard service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newDashboardEnableCmd())
	cmd.AddCommand(newDashboardDisableCmd())
	cmd.AddCommand(newDashboardStatusCmd())
	cmd.AddCommand(newDashboardStartCmd())
	cmd.AddCommand(newDashboardStopCmd())
	cmd.AddCommand(newDashboardUpdateCmd())

	return cmd
}

func resolveDashboardWorkspace(workspace *string) error {
	if *workspace != "" {
		return nil
	}
	cfg := config.NewAutomationServerConfig()
	ws, err := cfg.GetActiveWorkspace()
	if err != nil || ws == "" {
		return fmt.Errorf("no active workspace configured. Use --workspace flag or run 'bitswan workspace select <workspace>'")
	}
	*workspace = ws
	return nil
}

func newDashboardEnableCmd() *cobra.Command {
	var dashboardImage string
	var oauthConfigFile string
	var trustCA bool
	var workspace string

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable and start the workspace-dashboard service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			if err := resolveDashboardWorkspace(&workspace); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			options := make(map[string]interface{})
			if dashboardImage != "" {
				options["dashboard_image"] = dashboardImage
			}
			if trustCA {
				options["trust_ca"] = true
			}

			if oauthConfigFile != "" {
				oauthConfig, err := oauth.GetInitOauthConfig(oauthConfigFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: failed to read OAuth config: %v\n", err)
					os.Exit(1)
				}
				oauthJSON, _ := json.Marshal(oauthConfig)
				var oauthMap map[string]interface{}
				_ = json.Unmarshal(oauthJSON, &oauthMap)
				options["oauth_config"] = oauthMap
			}

			result, err := client.EnableService("dashboard", workspace, options)
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

	cmd.Flags().StringVar(&dashboardImage, "dashboard-image", "", "Custom image for the workspace-dashboard")
	cmd.Flags().StringVar(&oauthConfigFile, "oauth-config", "", "OAuth config file")
	cmd.Flags().BoolVar(&trustCA, "trust-ca", false, "Install custom certificates from the default CA certificates directory.")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")

	return cmd
}

func newDashboardDisableCmd() *cobra.Command {
	var workspace string
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable the workspace-dashboard service for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}
			if err := resolveDashboardWorkspace(&workspace); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			result, err := client.DisableService("dashboard", workspace, "")
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

func newDashboardStatusCmd() *cobra.Command {
	var workspace string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check workspace-dashboard service status for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}
			if err := resolveDashboardWorkspace(&workspace); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			result, err := client.GetServiceStatus("dashboard", workspace, "", false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			if result != nil && result.Data != nil {
				out, _ := json.MarshalIndent(result.Data, "", "  ")
				fmt.Println(string(out))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	return cmd
}

func newDashboardStartCmd() *cobra.Command {
	var workspace string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start workspace-dashboard container for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}
			if err := resolveDashboardWorkspace(&workspace); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			result, err := client.StartService("dashboard", workspace, "")
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

func newDashboardStopCmd() *cobra.Command {
	var workspace string
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop workspace-dashboard container for the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}
			if err := resolveDashboardWorkspace(&workspace); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			result, err := client.StopService("dashboard", workspace, "")
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

func newDashboardUpdateCmd() *cobra.Command {
	var dashboardImage string
	var trustCA bool
	var workspace string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update workspace-dashboard service with a new image and/or certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}
			if err := resolveDashboardWorkspace(&workspace); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			options := make(map[string]interface{})
			if dashboardImage != "" {
				options["dashboard_image"] = dashboardImage
			}
			if trustCA {
				options["trust_ca"] = true
			}

			result, err := client.UpdateService("dashboard", workspace, options)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(result.Message)
			return nil
		},
	}
	cmd.Flags().StringVar(&dashboardImage, "dashboard-image", "", "Custom image for the workspace-dashboard")
	cmd.Flags().BoolVar(&trustCA, "trust-ca", false, "Install custom certificates from the default CA certificates directory.")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "Workspace name (uses active workspace if not specified)")
	return cmd
}
