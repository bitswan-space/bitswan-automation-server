package automationserverdaemon

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the status of the automation server daemon",
		RunE:  runStatusCmd,
	}
}

func runStatusCmd(cmd *cobra.Command, args []string) error {
	client, err := daemon.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create daemon client: %w", err)
	}

	// First check if daemon is reachable
	if err := client.Ping(); err != nil {
		fmt.Fprintln(os.Stderr, "Automation server daemon is not running")
		fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it")
		return fmt.Errorf("daemon not reachable: %w", err)
	}

	// Get status from daemon
	status, err := client.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get daemon status: %w", err)
	}

	// Display status
	fmt.Println("Automation Server Daemon Status")
	fmt.Println("================================")
	fmt.Printf("Status:     Running\n")
	fmt.Printf("Version:    %s\n", status.Version)
	fmt.Printf("Uptime:     %s\n", status.Uptime)
	fmt.Printf("Started:    %s\n", status.StartTime)

	return nil
}

