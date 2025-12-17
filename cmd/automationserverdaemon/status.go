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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it")
		os.Exit(1)
	}

	// Get status from daemon
	status, err := client.GetStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get daemon status: %v\n", err)
		os.Exit(1)
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

