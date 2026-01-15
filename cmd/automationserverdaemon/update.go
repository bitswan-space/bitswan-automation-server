package automationserverdaemon

import (
	"fmt"
	"os/exec"

	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update [tag]",
		Short: "Update and restart the automation server daemon container with the current binary",
		Long:  "Update and restart the automation server daemon container. If [tag] is specified, uses that Docker image tag (e.g., local/automation-server-daemon). Otherwise, fetches the latest release from Docker Hub.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runUpdateCmd,
	}
}

func runUpdateCmd(cmd *cobra.Command, args []string) error {
	var daemonImage string

	// If tag is provided, use it directly; otherwise fetch latest from Docker Hub
	if len(args) > 0 && args[0] != "" {
		daemonImage = args[0]
		fmt.Printf("Using specified image tag: %s\n", daemonImage)
	} else {
		// Fetch latest release from Docker Hub
		fmt.Println("Fetching latest release from Docker Hub...")
		latestVersion, err := dockerhub.GetLatestAutomationServerDaemonRuntimeVersion()
		if err != nil {
			fmt.Printf("Warning: Failed to get latest version from Docker Hub, using 'latest': %v\n", err)
			daemonImage = "bitswan/automation-server-runtime:latest"
		} else {
			daemonImage = fmt.Sprintf("bitswan/automation-server-runtime:%s", latestVersion)
			fmt.Printf("Using latest release: %s\n", daemonImage)
		}
	}

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

	return startDaemonContainer("Starting updated automation server daemon container...", "Automation server daemon updated and started successfully", daemonImage)
}
