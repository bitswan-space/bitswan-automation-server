package automationserverdaemon

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update and restart the automation server daemon container with the current binary",
		RunE:  runUpdateCmd,
	}
}

func runUpdateCmd(cmd *cobra.Command, args []string) error {
	// Check if container exists
	checkCmd := exec.Command("docker", "ps", "-a", "--filter", "name=bitswan-automation-server-daemon", "--format", "{{.Names}}")
	output, err := checkCmd.Output()
	if err == nil && len(output) > 0 {
		// Container exists, stop and remove it
		fmt.Println("Stopping existing daemon container...")
		stopCmd := exec.Command("docker", "stop", "bitswan-automation-server-daemon")
		if err := stopCmd.Run(); err != nil {
			return fmt.Errorf("failed to stop existing container: %w", err)
		}

		fmt.Println("Removing existing daemon container...")
		removeCmd := exec.Command("docker", "rm", "bitswan-automation-server-daemon")
		if err := removeCmd.Run(); err != nil {
			return fmt.Errorf("failed to remove existing container: %w", err)
		}
	} else {
		fmt.Println("No existing daemon container found")
	}

	return startDaemonContainer("Starting updated automation server daemon container...", "Automation server daemon updated and started successfully")
}

