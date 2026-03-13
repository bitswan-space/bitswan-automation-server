package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newDisconnectFromAOCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "disconnect-from-aoc",
		Short:        "Disconnect automation server from AOC",
		Long:         "Disconnect this automation server from its current AOC instance. This removes AOC credentials, OAuth config, and MQTT settings from workspace metadata. Workspaces and their data are preserved.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if actually registered
			cfg := config.NewAutomationServerConfig()
			settings, err := cfg.GetAutomationOperationsCenterSettings()
			if err != nil || settings.AccessToken == "" {
				return fmt.Errorf("this automation server is not registered to any AOC instance")
			}

			fmt.Printf("This automation server is registered to AOC at %s (server ID: %s).\n\n", settings.AOCUrl, settings.AutomationServerId)
			fmt.Println("Disconnecting will:")
			fmt.Println("  - Remove AOC credentials from the server config")
			fmt.Println("  - Remove OAuth config files from all workspaces")
			fmt.Println("  - Clear MQTT connection settings from workspace metadata")
			fmt.Println("  - Disconnect the MQTT connection")
			fmt.Println()
			fmt.Println("Your workspaces and their data will NOT be deleted.")
			fmt.Println()
			fmt.Print("Type 'yes' to confirm: ")

			reader := bufio.NewReader(os.Stdin)
			confirmation, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}

			if strings.TrimSpace(confirmation) != "yes" {
				fmt.Println("Disconnect cancelled.")
				return nil
			}

			fmt.Println()

			client, err := daemon.NewClient()
			if err != nil {
				return fmt.Errorf("failed to create daemon client (daemon may not be running): %w", err)
			}

			if err := client.DisconnectFromAOC(); err != nil {
				return err
			}

			fmt.Println("You can register with a new AOC instance using 'bitswan register'.")

			return nil
		},
	}

	return cmd
}
