package automationserverdaemon

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

// version is set at build time
var version = "dev"

// SetVersion sets the version for the daemon server and configures auto-update
func SetVersion(v string) {
	version = v
	// Set up version check callback so daemon.NewClient() can auto-update
	daemon.SetVersionCheck(v, performUpdate)
}

// performUpdate stops, removes, and restarts the daemon container with the current binary
func performUpdate() error {
	// Check if container exists
	checkCmd := exec.Command("docker", "ps", "-a", "--filter", "name=bitswan-automation-server-daemon", "--format", "{{.Names}}")
	output, err := checkCmd.Output()
	if err == nil && len(output) > 0 {
		// Container exists, stop and remove it
		fmt.Println("Stopping existing daemon container...")
		stopCmd := exec.Command("docker", "stop", "bitswan-automation-server-daemon")
		stopCmd.Stdout = os.Stdout
		stopCmd.Stderr = os.Stderr
		if err := stopCmd.Run(); err != nil {
			return fmt.Errorf("failed to stop existing container: %w", err)
		}

		fmt.Println("Removing existing daemon container...")
		removeCmd := exec.Command("docker", "rm", "bitswan-automation-server-daemon")
		removeCmd.Stdout = os.Stdout
		removeCmd.Stderr = os.Stderr
		if err := removeCmd.Run(); err != nil {
			return fmt.Errorf("failed to remove existing container: %w", err)
		}
	}

	return startDaemonContainer("Starting updated automation server daemon container...", "Automation server daemon updated successfully")
}

func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "__run",
		Short:  "Run the automation server daemon (internal use only)",
		Hidden: true, // Hide from help as this is for internal use
		RunE: func(cmd *cobra.Command, args []string) error {
			server := daemon.NewServer(version)
			return server.Run()
		},
	}
}

