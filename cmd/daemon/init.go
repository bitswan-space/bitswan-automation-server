package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize and start the automation server daemon container",
		RunE:  runInitCmd,
	}
}

func runInitCmd(cmd *cobra.Command, args []string) error {
	// Get the current binary path by inspecting the running process
	var binaryPath string
	var err error

	// On Linux, use /proc/self/exe which always points to the actual running binary
	// This is more reliable than os.Executable() which may return a symlink path
	if runtime.GOOS == "linux" {
		procExe := "/proc/self/exe"
		binaryPath, err = os.Readlink(procExe)
		if err != nil {
			// Fallback to os.Executable() if /proc/self/exe is not available
			binaryPath, err = os.Executable()
			if err != nil {
				return fmt.Errorf("failed to get executable path: %w", err)
			}
		}
	} else {
		// On other platforms, use os.Executable()
		binaryPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}
	}

	// Resolve any symlinks to get the actual binary path
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Get absolute path
	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Get the bitswan config directory
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return fmt.Errorf("HOME environment variable is not set")
	}
	bitswanConfig := filepath.Join(homeDir, ".config", "bitswan")
	mkcertDir := filepath.Join(homeDir, ".local", "share", "mkcert")

	// Ensure the config directory exists
	if err := os.MkdirAll(bitswanConfig, 0755); err != nil {
		return fmt.Errorf("failed to create bitswan config directory: %w", err)
	}

	// Ensure mkcert directory exists (create if it doesn't, but it's okay if it doesn't exist)
	// We'll mount it anyway so mkcert can use it if it exists
	_ = os.MkdirAll(mkcertDir, 0755)

	// Check if container already exists
	checkCmd := exec.Command("docker", "ps", "-a", "--filter", "name=bitswan-automation-server-daemon", "--format", "{{.Names}}")
	output, err := checkCmd.Output()
	if err == nil && len(output) > 0 {
		// Container exists, check if it's running
		checkRunningCmd := exec.Command("docker", "ps", "--filter", "name=bitswan-automation-server-daemon", "--format", "{{.Names}}")
		runningOutput, err := checkRunningCmd.Output()
		if err == nil && len(runningOutput) > 0 {
			fmt.Println("Automation server daemon is already running")
			return nil
		}
		// Container exists but is not running, remove it first
		fmt.Println("Removing existing stopped container...")
		removeCmd := exec.Command("docker", "rm", "bitswan-automation-server-daemon")
		if err := removeCmd.Run(); err != nil {
			return fmt.Errorf("failed to remove existing container: %w", err)
		}
	}

	// Launch the daemon container
	// Mount the binary, config directory, docker socket, and mkcert directory
	// Use bitswan_network to allow resolving Docker service names like aoc-emqx
	// Use pre-built image with all tools (git, ssh-keygen, docker-cli, mkcert) pre-installed
	// Set BITSWAN_CADDY_HOST to use 'caddy' hostname instead of 'localhost' when on bitswan_network
	daemonImage := "bitswan/automation-server-daemon:latest"
	dockerCmd := exec.Command("docker", "run",
		"-d",
		"--name", "bitswan-automation-server-daemon",
		"--restart", "unless-stopped",
		"-e", "BITSWAN_CADDY_HOST=caddy:2019",
		"-v", fmt.Sprintf("%s:/usr/local/bin/bitswan:ro", binaryPath),
		"-v", fmt.Sprintf("%s:/root/.config/bitswan", bitswanConfig),
		"-v", fmt.Sprintf("%s:/root/.local/share/mkcert", mkcertDir),
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"--network", "bitswan_network",
		daemonImage,
	)

	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr

	fmt.Println("Starting automation server daemon container...")
	if err := dockerCmd.Run(); err != nil {
		return fmt.Errorf("failed to start daemon container: %w", err)
	}

	fmt.Println("Automation server daemon started successfully")
	return nil
}

