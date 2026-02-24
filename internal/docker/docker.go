package docker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/util"
)

type DockerNetwork struct {
	Name string `json:"Name"`
}

// IsDockerAvailable checks if docker command is available in PATH
func IsDockerAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// IsUbuntuLTS checks if the system is running Ubuntu LTS
// Supported LTS versions: 22.04 (Jammy), 24.04 (Noble)
func IsUbuntuLTS() (bool, string, error) {
	if runtime.GOOS != "linux" {
		return false, "", nil
	}

	// Read /etc/os-release
	osReleasePath := "/etc/os-release"
	data, err := os.ReadFile(osReleasePath)
	if err != nil {
		return false, "", fmt.Errorf("failed to read %s: %w", osReleasePath, err)
	}

	var id, versionID string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			versionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}

	if id != "ubuntu" {
		return false, "", nil
	}

	// Check if it's an LTS version
	// Ubuntu 22.04 (Jammy) and 24.04 (Noble) are LTS
	ltsVersions := map[string]string{
		"22.04": "Jammy",
		"24.04": "Noble",
	}

	codename, isLTS := ltsVersions[versionID]
	return isLTS, codename, nil
}

func checkNetworkExists(networkName string) (bool, error) {
	cmd := exec.Command("docker", "network", "ls", "--format=json")
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("error running docker command: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		var network DockerNetwork
		if err := json.Unmarshal([]byte(line), &network); err != nil {
			return false, fmt.Errorf("error parsing JSON: %v", err)
		}

		if network.Name == networkName {
			return true, nil
		}
	}

	return false, nil
}

// EnsureDockerNetwork ensures a Docker network exists, creating it if necessary
func EnsureDockerNetwork(name string, verbose bool) (bool, error) {
	exists, err := checkNetworkExists(name)
	if err != nil {
		return false, fmt.Errorf("error checking network %s: %w", name, err)
	}
	if exists {
		if verbose {
			fmt.Printf("Network called '%s' already exists...\n", name)
		}
		return true, nil
	}
	createDockerNetworkCom := exec.Command("docker", "network", "create", name)
	if verbose {
		fmt.Printf("Creating Docker network '%s'...\n", name)
	}
	if err = util.RunCommandVerbose(createDockerNetworkCom, verbose); err != nil {
		if err.Error() == "exit status 1" {
			if verbose {
				fmt.Printf("Docker network '%s' already exists!\n", name)
			}
		} else {
			fmt.Printf("Failed to create Docker network '%s': %s\n", name, err.Error())
		}
	} else {
		if verbose {
			fmt.Printf("Docker network '%s' created!\n", name)
		}
	}
	return true, nil

}

// PromptUser prompts the user with a yes/no question
func PromptUser(question string) (bool, error) {
	fmt.Print(question + " [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read user input: %w", err)
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes", nil
}

// InstallDocker installs Docker Engine on Ubuntu following the official guide
// https://docs.docker.com/engine/install/ubuntu/
// This function must be run with root privileges (or sudo)
func InstallDocker() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("Docker installation requires root privileges. Please run with sudo")
	}

	fmt.Println("Installing Docker Engine on Ubuntu...")

	// Step 1: Uninstall old versions
	fmt.Println("Removing old Docker packages if any...")
	uninstallCmd := exec.Command("sh", "-c", "apt remove -y $(dpkg --get-selections docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc 2>/dev/null | cut -f1) 2>/dev/null || true")
	uninstallCmd.Stdout = os.Stdout
	uninstallCmd.Stderr = os.Stderr
	_ = uninstallCmd.Run() // Ignore errors, packages might not exist

	// Step 2: Set up Docker's apt repository
	fmt.Println("Setting up Docker's apt repository...")

	// Update package index
	updateCmd := exec.Command("apt", "update")
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr
	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("failed to update package index: %w", err)
	}

	// Install prerequisites
	installPrereqCmd := exec.Command("apt", "install", "-y", "ca-certificates", "curl")
	installPrereqCmd.Stdout = os.Stdout
	installPrereqCmd.Stderr = os.Stderr
	if err := installPrereqCmd.Run(); err != nil {
		return fmt.Errorf("failed to install prerequisites: %w", err)
	}

	// Create keyrings directory
	keyringsDir := "/etc/apt/keyrings"
	mkdirCmd := exec.Command("install", "-m", "0755", "-d", keyringsDir)
	mkdirCmd.Stdout = os.Stdout
	mkdirCmd.Stderr = os.Stderr
	if err := mkdirCmd.Run(); err != nil {
		return fmt.Errorf("failed to create keyrings directory: %w", err)
	}

	// Download and install Docker's GPG key
	downloadKeyCmd := exec.Command("curl", "-fsSL", "https://download.docker.com/linux/ubuntu/gpg", "-o", keyringsDir+"/docker.asc")
	downloadKeyCmd.Stdout = os.Stdout
	downloadKeyCmd.Stderr = os.Stderr
	if err := downloadKeyCmd.Run(); err != nil {
		return fmt.Errorf("failed to download Docker GPG key: %w", err)
	}

	// Set permissions on GPG key
	chmodCmd := exec.Command("chmod", "a+r", keyringsDir+"/docker.asc")
	chmodCmd.Stdout = os.Stdout
	chmodCmd.Stderr = os.Stderr
	if err := chmodCmd.Run(); err != nil {
		return fmt.Errorf("failed to set GPG key permissions: %w", err)
	}

	// Get Ubuntu codename
	getCodenameCmd := exec.Command("sh", "-c", ". /etc/os-release && echo ${UBUNTU_CODENAME:-$VERSION_CODENAME}")
	codenameOutput, err := getCodenameCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get Ubuntu codename: %w", err)
	}
	codename := strings.TrimSpace(string(codenameOutput))

	// Add Docker repository
	repoContent := fmt.Sprintf("Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: %s\nComponents: stable\nSigned-By: %s/docker.asc\n", codename, keyringsDir)
	teeCmd := exec.Command("tee", "/etc/apt/sources.list.d/docker.sources")
	teeCmd.Stdin = strings.NewReader(repoContent)
	teeCmd.Stdout = os.Stdout
	teeCmd.Stderr = os.Stderr
	if err := teeCmd.Run(); err != nil {
		return fmt.Errorf("failed to add Docker repository: %w", err)
	}

	// Update package index again (create new command, cannot reuse after Run())
	updateCmd2 := exec.Command("apt", "update")
	updateCmd2.Stdout = os.Stdout
	updateCmd2.Stderr = os.Stderr
	if err := updateCmd2.Run(); err != nil {
		return fmt.Errorf("failed to update package index after adding repository: %w", err)
	}

	// Step 3: Install Docker packages
	fmt.Println("Installing Docker Engine...")
	installDockerCmd := exec.Command("apt", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin")
	installDockerCmd.Stdout = os.Stdout
	installDockerCmd.Stderr = os.Stderr
	if err := installDockerCmd.Run(); err != nil {
		return fmt.Errorf("failed to install Docker packages: %w", err)
	}

	fmt.Println("Docker Engine has been successfully installed!")
	return nil
}
