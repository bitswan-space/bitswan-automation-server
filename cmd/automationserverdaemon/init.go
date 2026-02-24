package automationserverdaemon

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/docker"
	"github.com/dchest/uniuri"
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
	// Check if Docker is available
	if !docker.IsDockerAvailable() {
		// Check if we're on Ubuntu LTS
		isUbuntuLTS, codename, err := docker.IsUbuntuLTS()
		if err != nil {
			return fmt.Errorf("failed to check if running on Ubuntu LTS: %w", err)
		}

		if isUbuntuLTS {
			fmt.Printf("Docker is not installed. Detected Ubuntu %s LTS.\n", codename)
			install, err := docker.PromptUser("Would you like to automatically install Docker Engine?")
			if err != nil {
				return fmt.Errorf("failed to get user input: %w", err)
			}

			if install {
				// Check if we need sudo
				if os.Geteuid() != 0 {
					fmt.Println("\nThis operation requires root privileges.")
					fmt.Println("Please run this command with sudo:")
					fmt.Printf("  sudo %s automation-server-daemon init\n", os.Args[0])
					return fmt.Errorf("docker installation requires root privileges")
				}

				if err := docker.InstallDocker(); err != nil {
					return fmt.Errorf("failed to install Docker: %w", err)
				}
			} else {
				return fmt.Errorf("Docker is required but not installed. Please install Docker manually: https://docs.docker.com/engine/install/ubuntu/")
			}
		} else {
			return fmt.Errorf("Docker is required but not found in PATH. Please install Docker: https://docs.docker.com/engine/install/")
		}
	}

	// Generate and save the authentication token to the config file
	cfg := config.NewAutomationServerConfig()
	existingToken, err := cfg.GetLocalServerToken()
	if err != nil || existingToken == "" {
		// Generate a new random token (64 characters)
		token := uniuri.NewLen(64)
		if err := cfg.SetLocalServerToken(token); err != nil {
			return fmt.Errorf("failed to save token to config: %w", err)
		}
		fmt.Println("Generated new authentication token")

		// Set restrictive permissions on the config file (owner read/write only)
		configPath := cfg.GetConfigPath()
		if err := os.Chmod(configPath, 0600); err != nil {
			return fmt.Errorf("failed to set config file permissions: %w", err)
		}
	}

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

	return startDaemonContainer("Starting automation server daemon container...", "Automation server daemon started successfully")
}

// startDaemonContainer sets up and starts the daemon container with the current binary
func startDaemonContainer(startMessage, successMessage string) error {
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

	// Get the real user's home directory (handles sudo correctly)
	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
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

	// Launch the daemon container
	// Mount the binary, config directory, docker socket, and mkcert directory
	// Use bitswan_network to allow resolving Docker service names like caddy
	// Use pre-built image with all tools (git, ssh-keygen, docker-cli, mkcert) pre-installed
	// Set BITSWAN_CADDY_HOST to use 'caddy' hostname instead of 'localhost' when on bitswan_network
	// Mount the bitswan automation server socket directory for IPC
	daemonImage := "bitswan/automation-server-runtime:latest"

	// Create the socket directory on the host if it doesn't exist
	socketDir := "/var/run/bitswan"
	socketPath := filepath.Join(socketDir, "automation-server.sock")

	// Ensure the socket directory exists
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket file if it exists (stale socket from previous run)
	_ = os.Remove(socketPath)

	// Ensure bitswan_network exists before starting the container
	networkName := "bitswan_network"
	networkExists, err := checkNetworkExists(networkName)
	if err != nil {
		return fmt.Errorf("failed to check if network exists: %w", err)
	}

	if !networkExists {
		fmt.Println("Creating BitSwan Docker network...")
		createNetworkCmd := exec.Command("docker", "network", "create", networkName)
		createNetworkCmd.Stdout = os.Stdout
		createNetworkCmd.Stderr = os.Stderr
		if err := createNetworkCmd.Run(); err != nil {
			// Network might have been created by another process, check again
			networkExists, checkErr := checkNetworkExists(networkName)
			if checkErr != nil || !networkExists {
				return fmt.Errorf("failed to create Docker network: %w", err)
			}
			fmt.Println("BitSwan Docker network already exists!")
		} else {
			fmt.Println("BitSwan Docker network created!")
		}
		// Verify the network exists before proceeding (handles race conditions)
		verified := false
		for i := 0; i < 5; i++ {
			networkExists, err := checkNetworkExists(networkName)
			if err == nil && networkExists {
				verified = true
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !verified {
			return fmt.Errorf("network was created but could not be verified: network %s not found", networkName)
		}
	}

	// Final verification right before using the network (handles any edge cases)
	networkExists, err = checkNetworkExists(networkName)
	if err != nil {
		return fmt.Errorf("failed to verify network before starting container: %w", err)
	}
	if !networkExists {
		return fmt.Errorf("network %s does not exist and could not be created", networkName)
	}

	// Set HOST_HOME so the daemon knows the host home directory
	// This is needed when fixing permissions and creating docker-compose files with correct paths
	dockerCmd := exec.Command("docker", "run",
		"-d",
		"--name", "bitswan-automation-server-daemon",
		"--restart", "unless-stopped",
		"--add-host", "host.docker.internal:host-gateway", // Allow container to reach host services
		"-e", "BITSWAN_CADDY_HOST=caddy:2019",
		"-e", fmt.Sprintf("HOST_HOME=%s", homeDir),
		"-v", fmt.Sprintf("%s:/usr/local/bin/bitswan:ro", binaryPath),
		"-v", fmt.Sprintf("%s:/root/.config/bitswan", bitswanConfig),
		"-v", fmt.Sprintf("%s:/root/.local/share/mkcert", mkcertDir),
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-v", fmt.Sprintf("%s:%s", socketDir, socketDir),
		"-v", "/:/host:ro",
		"--network", "bitswan_network",
		daemonImage,
		"/usr/local/bin/bitswan", "automation-server-daemon", "__run",
	)

	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr

	fmt.Println(startMessage)
	if err := dockerCmd.Run(); err != nil {
		return fmt.Errorf("failed to start daemon container: %w", err)
	}

	fmt.Println(successMessage)
	return nil
}

// checkNetworkExists checks if a Docker network exists
func checkNetworkExists(networkName string) (bool, error) {
	cmd := exec.Command("docker", "network", "ls", "--format=json")
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("error running docker command: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")


	for _, line := range lines {
		if line == "" {
			continue
		}
		var network docker.DockerNetwork
		if err := json.Unmarshal([]byte(line), &network); err != nil {
			return false, fmt.Errorf("error parsing JSON: %v", err)
		}

		if network.Name == networkName {
			return true, nil
		}
	}

	return false, nil
}
