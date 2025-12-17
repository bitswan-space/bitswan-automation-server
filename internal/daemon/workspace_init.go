package daemon

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/bitswan-space/bitswan-workspaces/internal/oauth"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
	"github.com/bitswan-space/bitswan-workspaces/internal/ssh"
)

// runWorkspaceInit runs the workspace init logic with stdout already redirected
func (s *Server) runWorkspaceInit(args []string) error {
	// Parse flags
	fs := flag.NewFlagSet("workspace-init", flag.ContinueOnError)
	remoteRepo := fs.String("remote", "", "")
	workspaceBranch := fs.String("branch", "", "")
	domain := fs.String("domain", "", "")
	certsDir := fs.String("certs-dir", "", "")
	verbose := fs.Bool("verbose", false, "")
	mkCerts := fs.Bool("mkcerts", false, "")
	noIde := fs.Bool("no-ide", false, "")
	setHosts := fs.Bool("set-hosts", false, "")
	local := fs.Bool("local", false, "")
	gitopsImage := fs.String("gitops-image", "", "")
	editorImage := fs.String("editor-image", "", "")
	gitopsDevSourceDir := fs.String("gitops-dev-source-dir", "", "")
	oauthConfigFile := fs.String("oauth-config", "", "")
	noOauth := fs.Bool("no-oauth", false, "")
	sshPort := fs.String("ssh-port", "", "")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if len(fs.Args()) < 1 {
		return fmt.Errorf("workspace name is required")
	}

	workspaceName := fs.Args()[0]
	bitswanConfig := os.Getenv("HOME") + "/.config/bitswan/"

	if _, err := os.Stat(bitswanConfig); os.IsNotExist(err) {
		if err := os.MkdirAll(bitswanConfig, 0755); err != nil {
			return fmt.Errorf("failed to create BitSwan config directory: %w", err)
		}
	}

	// Ensure oauth2-proxy binary is available
	if err := oauth.EnsureOAuth2Proxy(bitswanConfig); err != nil {
		fmt.Printf("Warning: Failed to download oauth2-proxy: %v\n", err)
		fmt.Println("OAuth authentication may not work properly without oauth2-proxy")
	}

	// Init bitswan network
	networkName := "bitswan_network"
	exists, err := checkNetworkExists(networkName)
	if err != nil {
		return fmt.Errorf("error checking network: %w", err)
	}

	if exists {
		fmt.Printf("Network '%s' exists\n", networkName)
	} else {
		createDockerNetworkCom := exec.Command("docker", "network", "create", "bitswan_network")
		fmt.Println("Creating BitSwan Docker network...")
		if err := runCommandVerbose(createDockerNetworkCom, *verbose); err != nil {
			if err.Error() == "exit status 1" {
				fmt.Println("BitSwan Docker network already exists!")
			} else {
				fmt.Printf("Failed to create BitSwan Docker network: %s\n", err.Error())
			}
		} else {
			fmt.Println("BitSwan Docker network created!")
		}
	}

	var oauthConfig *oauth.Config
	if *oauthConfigFile != "" {
		oauthConfig, err = oauth.GetInitOauthConfig(*oauthConfigFile)
		if err != nil {
			return fmt.Errorf("failed to get OAuth config: %w", err)
		}
		fmt.Println("OAuth config read successfully!")
	}

	// Init shared Caddy if not exists - call initIngress directly to avoid recursion
	client := &http.Client{
		Timeout: 2 * time.Second,
	}
	resp, err := client.Get("http://localhost:2019")
	caddy_running := true
	if err != nil {
		caddy_running = false
	} else {
		defer resp.Body.Close()
	}

	if !caddy_running {
		if err := initIngress(*verbose); err != nil {
			// Check if error is "caddy already initialized" - that's OK
			if !strings.Contains(err.Error(), "already initialized") {
				return fmt.Errorf("failed to initialize Caddy: %w", err)
			}
		}
		fmt.Println("Ingress proxy is ready!")
	} else {
		fmt.Println("A running instance of Caddy with admin found")
	}

	// Handle --local flag
	if *local && (*setHosts || *mkCerts) {
		return fmt.Errorf("cannot use --local flag with --set-hosts or --mkcerts")
	}

	if *local {
		*setHosts = true
		*mkCerts = true
		if *domain == "" {
			*domain = fmt.Sprintf("bs-%s.localhost", workspaceName)
		}
	}

	// Handle certificate generation and installation
	if *mkCerts {
		if err := caddyapi.GenerateAndInstallCerts(*domain); err != nil {
			return fmt.Errorf("error generating and installing certificates: %w", err)
		}
	} else if *certsDir != "" {
		caddyConfig := bitswanConfig + "caddy"
		if err := caddyapi.InstallCertsFromDir(*certsDir, *domain, caddyConfig); err != nil {
			return fmt.Errorf("error installing certificates from directory: %w", err)
		}
	}

	gitopsConfig := bitswanConfig + "workspaces/" + workspaceName

	if _, err := os.Stat(gitopsConfig); !os.IsNotExist(err) {
		return fmt.Errorf("GitOps with this name was already initialized: %s", workspaceName)
	}

	if err := os.MkdirAll(gitopsConfig, 0755); err != nil {
		return fmt.Errorf("failed to create GitOps directory: %w", err)
	}

	// Initialize Bitswan workspace
	gitopsWorkspace := gitopsConfig + "/workspace"
	if *remoteRepo != "" {
		// Generate SSH key pair for the workspace before cloning
		fmt.Println("Generating SSH key pair for workspace...")
		sshKeyPair, err := ssh.GenerateSSHKeyPair(gitopsConfig)
		if err != nil {
			return fmt.Errorf("failed to generate SSH key pair: %w", err)
		}
		fmt.Printf("SSH key pair generated: %s\n", sshKeyPair.PublicKeyPath)

		// Parse repository URL to get hostname, org, and repo
		repoInfo, err := parseRepositoryURL(*remoteRepo)
		if err != nil {
			return fmt.Errorf("failed to parse repository URL: %w", err)
		}

		// Display the public key and wait for user confirmation
		fmt.Println("\n" + strings.Repeat("=", 60))
		fmt.Println("IMPORTANT: SSH Key Setup Required")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Your SSH public key is:\n\n%s\n", sshKeyPair.PublicKey)
		fmt.Println("\nPlease add this key as a deploy key to your repository:")
		fmt.Printf("Repository: %s/%s\n", repoInfo.Org, repoInfo.Repo)
		fmt.Println("\nSteps:")
		fmt.Println("1. Go to your repository settings")
		fmt.Println("2. Navigate to Deploy keys section")
		fmt.Println("3. Add a new deploy key")
		fmt.Println("4. Paste the public key above")
		fmt.Println("5. Give it a descriptive name (e.g., 'bitswan-workspace')")
		fmt.Println("6. Make sure to check 'Allow write access' if you plan to push changes")
		fmt.Println("\nPress ENTER to continue once you've added the deploy key...")

		// Wait for user input
		var input string
		fmt.Scanln(&input)

		var cloneURL string
		// Clone using SSH key
		cloneURL = fmt.Sprintf("git@%s:%s/%s.git", repoInfo.Hostname, repoInfo.Org, repoInfo.Repo)
		com := exec.Command("git", "clone", cloneURL, gitopsWorkspace) //nolint:gosec

		// Set up SSH command based on whether custom SSH port is specified
		if *sshPort != "" {
			// Create SSH config file for custom port access
			sshConfigPath, err := createSSHConfig(gitopsConfig, workspaceName, repoInfo, *sshPort)
			if err != nil {
				return fmt.Errorf("failed to create SSH config: %w", err)
			}

			// Replace hostname with our SSH config host
			cloneURL = fmt.Sprintf("ssh://git@git-%s/%s/%s.git", workspaceName, repoInfo.Org, repoInfo.Repo)

			// Update the clone command with the new URL
			com = exec.Command("git", "clone", cloneURL, gitopsWorkspace)

			// Set up SSH to use the config file
			com.Env = append(os.Environ(),
				fmt.Sprintf("GIT_SSH_COMMAND=ssh -F %s -o StrictHostKeyChecking=no", sshConfigPath))
		} else {
			// Set up SSH to use the generated key directly
			com.Env = append(os.Environ(),
				fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=no", sshKeyPair.PrivateKeyPath))
		}

		fmt.Println("Cloning remote repository...")
		if err := runCommandVerbose(com, *verbose); err != nil {
			return fmt.Errorf("failed to clone remote repository: %w", err)
		}
		fmt.Println("Remote repository cloned!")

		// Checkout specified branch if provided
		if *workspaceBranch != "" {
			fmt.Printf("Checking out branch '%s'...\n", *workspaceBranch)
			checkoutCom := exec.Command("git", "checkout", *workspaceBranch)
			checkoutCom.Dir = gitopsWorkspace
			if err := runCommandVerbose(checkoutCom, *verbose); err != nil {
				fmt.Printf("Warning: Failed to checkout branch '%s': %v\n", *workspaceBranch, err)
				fmt.Printf("Continuing with the default branch...\n")
			} else {
				fmt.Printf("Successfully checked out branch '%s'!\n", *workspaceBranch)
			}
		}
	} else {
		if err := os.Mkdir(gitopsWorkspace, 0755); err != nil {
			return fmt.Errorf("failed to create GitOps workspace directory %s: %w", gitopsWorkspace, err)
		}
		com := exec.Command("git", "init")
		com.Dir = gitopsWorkspace

		fmt.Println("Initializing git in workspace...")

		if err := runCommandVerbose(com, *verbose); err != nil {
			return fmt.Errorf("failed to init git in workspace: %w", err)
		}

		fmt.Println("Git initialized in workspace!")
	}

	// Add GitOps worktree
	gitopsWorktree := gitopsConfig + "/gitops"
	worktreeAddCom := exec.Command("git", "worktree", "add", "--orphan", "-b", workspaceName, gitopsWorktree)
	worktreeAddCom.Dir = gitopsWorkspace

	fmt.Println("Setting up GitOps worktree...")
	if err := runCommandVerbose(worktreeAddCom, *verbose); err != nil {
		return fmt.Errorf("failed to create GitOps worktree: %w", err)
	}

	// Add repo as safe directory
	safeDirCom := exec.Command("git", "config", "--global", "--add", "safe.directory", gitopsWorktree)
	if err := runCommandVerbose(safeDirCom, *verbose); err != nil {
		return fmt.Errorf("failed to add safe directory: %w", err)
	}

	if *remoteRepo != "" {
		// Create empty commit
		emptyCommitCom := exec.Command("git", "commit", "--allow-empty", "-m", "Initial commit")
		emptyCommitCom.Dir = gitopsWorktree
		if err := runCommandVerbose(emptyCommitCom, *verbose); err != nil {
			return fmt.Errorf("failed to create empty commit: %w", err)
		}

		// Push to remote using SSH key
		setUpstreamCom := exec.Command("git", "push", "-u", "origin", workspaceName)
		setUpstreamCom.Dir = gitopsWorktree

		// Set up SSH command based on whether custom SSH port is specified
		if *sshPort != "" {
			// Parse repository URL to get hostname, org, and repo
			repoInfo, err := parseRepositoryURL(*remoteRepo)
			if err != nil {
				return fmt.Errorf("failed to parse repository URL: %w", err)
			}

			// Create SSH config file for custom port access
			sshConfigPath, err := createSSHConfig(gitopsConfig, workspaceName, repoInfo, *sshPort)
			if err != nil {
				return fmt.Errorf("failed to create SSH config: %w", err)
			}

			// Set up SSH to use the config file
			setUpstreamCom.Env = append(os.Environ(),
				fmt.Sprintf("GIT_SSH_COMMAND=ssh -F %s -o StrictHostKeyChecking=no", sshConfigPath))
		} else {
			// Set up SSH to use the generated key for push operations
			sshKeyPath := filepath.Join(gitopsConfig, "ssh", "id_ed25519")
			setUpstreamCom.Env = append(os.Environ(),
				fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=no", sshKeyPath))
		}

		if err := runCommandVerbose(setUpstreamCom, *verbose); err != nil {
			return fmt.Errorf("failed to set upstream: %w", err)
		}
	}

	fmt.Println("GitOps worktree set up successfully!")

	// Create secrets directory
	secretsDir := gitopsConfig + "/secrets"
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}

	if oauthConfig != nil {
		oauthConfigFile := secretsDir + "/oauth-config.yaml"
		oauthConfigYaml, err := yaml.Marshal(oauthConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal OAuth config: %w", err)
		}
		if err := os.WriteFile(oauthConfigFile, oauthConfigYaml, 0600); err != nil {
			return fmt.Errorf("failed to write oauth config file: %w", err)
		}
	}

	// Generate SSH key pair for the workspace (if not already generated for remote repo)
	if *remoteRepo == "" {
		fmt.Println("Generating SSH key pair for workspace...")
		sshKeyPair, err := ssh.GenerateSSHKeyPair(gitopsConfig)
		if err != nil {
			return fmt.Errorf("failed to generate SSH key pair: %w", err)
		}
		fmt.Printf("SSH key pair generated: %s\n", sshKeyPair.PublicKeyPath)
	}

	// Set hosts to /etc/hosts file
	if *setHosts {
		err := setHostsFile(workspaceName, *domain, *noIde)
		if err != nil {
			fmt.Printf("\033[33m%s\033[0m\n", err)
		}
	}

	imgopsImage := *gitopsImage
	if imgopsImage == "" {
		gitopsLatestVersion, err := dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/gitops/tags/")
		if err != nil {
			return fmt.Errorf("failed to get latest BitSwan GitOps version: %w", err)
		}
		imgopsImage = "bitswan/gitops:" + gitopsLatestVersion
	}

	bitswanEditorImage := *editorImage
	if bitswanEditorImage == "" {
		bitswanEditorLatestVersion, err := dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/bitswan-editor/tags/")
		if err != nil {
			return fmt.Errorf("failed to get latest BitSwan Editor version: %w", err)
		}
		bitswanEditorImage = "bitswan/bitswan-editor:" + bitswanEditorLatestVersion
	}

	fmt.Println("Setting up GitOps deployment...")
	gitopsDeployment := gitopsConfig + "/deployment"
	if err := os.MkdirAll(gitopsDeployment, 0755); err != nil {
		return fmt.Errorf("failed to create deployment directory: %w", err)
	}

	// Install TLS certificates and policies if certificates were provided
	if *mkCerts || *certsDir != "" {
		if err := caddyapi.InstallTLSCerts(workspaceName, *domain); err != nil {
			return fmt.Errorf("failed to install caddy certs: %w", err)
		}
	}

	// Register GitOps service
	if err := caddyapi.RegisterServiceWithCaddy("gitops", workspaceName, *domain, fmt.Sprintf("%s-gitops:8079", workspaceName)); err != nil {
		return fmt.Errorf("failed to register GitOps service: %w", err)
	}

	err = ensureExamples(bitswanConfig, *verbose)
	if err != nil {
		return fmt.Errorf("failed to download examples: %w", err)
	}

	var aocEnvVars []string
	var mqttEnvVars []string
	workspaceId := ""
	fmt.Println("Registering workspace...")

	// Try to create AOC client
	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		fmt.Println("Automation server config not found, skipping workspace registration.")
	} else {
		fmt.Println("Getting automation server token...")
		automationServerToken, err := aocClient.GetAutomationServerToken()
		if err != nil {
			fmt.Println("No automation server token available, skipping workspace registration.")
		} else {
			fmt.Println("Automation server token received successfully!")

			var editorURL *string
			if !*noIde {
				url := fmt.Sprintf("https://%s-editor.%s", workspaceName, *domain)
				editorURL = &url
			}

			workspaceId, err = aocClient.RegisterWorkspace(workspaceName, editorURL)
			if err != nil {
				return fmt.Errorf("failed to register workspace: %w", err)
			}
			fmt.Println("Workspace registered successfully!")

			// Automatically fetch OAuth configuration when AOC is configured
			if !*noOauth {
				fmt.Println("Fetching OAuth configuration from AOC...")
				oauthConfig, err = aocClient.GetOAuthConfig(workspaceId)
				if err != nil {
					return fmt.Errorf("failed to get OAuth config from AOC: %w", err)
				}
				fmt.Println("OAuth configuration fetched successfully!")
			} else {
				fmt.Println("OAuth disabled, using password authentication")
			}

			aocEnvVars = aocClient.GetAOCEnvironmentVariables(workspaceId, automationServerToken)

			fmt.Println("Getting EMQX JWT for workspace...")
			mqttCreds, err := aocClient.GetMQTTCredentials(workspaceId)
			if err != nil {
				return fmt.Errorf("failed to get MQTT credentials: %w", err)
			}
			fmt.Println("EMQX JWT received successfully!")

			mqttEnvVars = aoc.GetMQTTEnvironmentVariables(mqttCreds)
		}
	}

	var oauthEnvVars []string
	if oauthConfig != nil {
		oauthEnvVars = oauth.CreateOAuthEnvVars(oauthConfig, "gitops", workspaceName, *domain)
	}

	config := &dockercompose.DockerComposeConfig{
		GitopsPath:         gitopsConfig,
		WorkspaceName:      workspaceName,
		GitopsImage:        imgopsImage,
		Domain:             *domain,
		MqttEnvVars:        mqttEnvVars,
		AocEnvVars:         aocEnvVars,
		OAuthEnvVars:       oauthEnvVars,
		GitopsDevSourceDir: *gitopsDevSourceDir,
		TrustCA:            true,
	}
	compose, token, err := config.CreateDockerComposeFile()

	if err != nil {
		return fmt.Errorf("failed to create docker-compose file: %w", err)
	}

	dockerComposePath := gitopsDeployment + "/docker-compose.yml"
	if err := os.WriteFile(dockerComposePath, []byte(compose), 0755); err != nil {
		return fmt.Errorf("failed to write docker-compose file: %w", err)
	}

	err = os.Chdir(gitopsDeployment)
	if err != nil {
		return fmt.Errorf("failed to change directory to GitOps deployment: %w", err)
	}

	fmt.Println("GitOps deployment set up successfully!")

	// Save metadata to file
	if err := saveMetadata(gitopsConfig, workspaceName, token, *domain, *noIde, &workspaceId, mqttEnvVars, *gitopsDevSourceDir); err != nil {
		fmt.Printf("Warning: Failed to save metadata: %v\n", err)
	}

	projectName := workspaceName + "-site"
	dockerComposeCom := exec.Command("docker", "compose", "-p", projectName, "up", "-d")

	fmt.Println("Launching BitSwan Workspace services...")
	if err := runCommandVerbose(dockerComposeCom, true); err != nil {
		return fmt.Errorf("failed to start docker-compose: %w", err)
	}

	fmt.Println("BitSwan GitOps initialized successfully!")

	// Setup editor service if not disabled
	if !*noIde {
		fmt.Println("Setting up editor service...")

		// Create editor service
		editorService, err := services.NewEditorService(workspaceName)
		if err != nil {
			return fmt.Errorf("failed to create editor service: %w", err)
		}

		// Enable the editor service
		if err := editorService.Enable(token, bitswanEditorImage, *domain, oauthConfig, true); err != nil {
			return fmt.Errorf("failed to enable editor service: %w", err)
		}

		// Start the editor container
		if err := editorService.StartContainer(); err != nil {
			return fmt.Errorf("failed to start editor container: %w", err)
		}

		fmt.Println("Downloading and installing editor...")

		// Wait for the editor service to be ready by streaming logs
		if err := editorService.WaitForEditorReady(); err != nil {
			return fmt.Errorf("failed to wait for editor to be ready: %w", err)
		}

		fmt.Println("------------BITSWAN EDITOR INFO------------")
		fmt.Printf("Bitswan Editor URL: https://%s-editor.%s\n", workspaceName, *domain)

		if oauthConfig == nil {
			editorPassword, err := editorService.GetEditorPassword()
			if err != nil {
				return fmt.Errorf("failed to get Bitswan Editor password: %w", err)
			}
			fmt.Printf("Bitswan Editor Password: %s\n", editorPassword)
		}
	}

	fmt.Println("------------GITOPS INFO------------")
	fmt.Printf("GitOps ID: %s\n", workspaceName)
	fmt.Printf("GitOps URL: https://%s-gitops.%s\n", workspaceName, *domain)
	fmt.Printf("GitOps Secret: %s\n", token)

	if oauthConfig != nil {
		fmt.Printf("OAuth is enabled for the Editor.\n")
	}

	return nil
}

// Helper functions moved from cmd/init.go

type DockerNetwork struct {
	Name      string `json:"Name"`
	ID        string `json:"ID"`
	CreatedAt string `json:"CreatedAt"`
	Driver    string `json:"Driver"`
	IPv6      string `json:"IPv6"`
	Internal  string `json:"Internal"`
	Labels    string `json:"Labels"`
	Scope     string `json:"Scope"`
}

type RepositoryInfo struct {
	Hostname string
	Org      string
	Repo     string
	IsSSH    bool
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

func ensureExamples(bitswanConfig string, verbose bool) error {
	repoURL := "https://github.com/bitswan-space/BitSwan.git"
	targetDir := filepath.Join(bitswanConfig, "bitswan-src")

	if _, err := os.Stat(filepath.Join(targetDir, ".git")); os.IsNotExist(err) {
		if verbose {
			fmt.Printf("Cloning BitSwan repository to %s\n", targetDir)
		}

		if err := os.MkdirAll(filepath.Dir(targetDir), 0755); err != nil {
			return fmt.Errorf("failed to create parent directory: %w", err)
		}

		cmd := exec.Command("git", "clone", repoURL, targetDir)
		if err := runCommandVerbose(cmd, verbose); err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}

		if verbose {
			fmt.Println("Repository cloned successfully")
		}
	} else {
		if err := updateExamples(bitswanConfig, verbose); err != nil {
			return err
		}
	}

	return nil
}

func updateExamples(bitswanConfig string, verbose bool) error {
	repoPath := filepath.Join(bitswanConfig, "bitswan-src")
	if verbose {
		fmt.Printf("Updating BitSwan repository at %s\n", repoPath)
	}

	cmd := exec.Command("git", "-c", fmt.Sprintf("safe.directory=%s", repoPath), "pull")
	cmd.Dir = repoPath

	if err := runCommandVerbose(cmd, verbose); err != nil {
		return fmt.Errorf("failed to update repository: %w", err)
	}

	if verbose {
		fmt.Println("Repository updated successfully")
	}
	return nil
}

func setHostsFile(workspaceName, domain string, noIde bool) error {
	fmt.Println("Checking if the user has permission to write to /etc/hosts...")
	fileInfo, err := os.Stat("/etc/hosts")
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	if fileInfo.Mode().Perm()&0200 == 0 {
		return fmt.Errorf("user does not have permission to write to /etc/hosts")
	}
	fmt.Println("File /etc/hosts is writable")

	hostsEntries := []string{
		"127.0.0.1 " + workspaceName + "-gitops." + domain,
	}

	if !noIde {
		hostsEntries = append(hostsEntries, "127.0.0.1 "+workspaceName+"-editor."+domain)
	}

	for _, entry := range hostsEntries {
		if exec.Command("grep", "-wq", entry, "/etc/hosts").Run() == nil {
			return fmt.Errorf("hosts already set in /etc/hosts")
		}
	}

	fmt.Println("Adding record to /etc/hosts...")
	for _, entry := range hostsEntries {
		cmdStr := "echo '" + entry + "' | sudo tee -a /etc/hosts"
		addHostsCom := exec.Command("sh", "-c", cmdStr)
		if err := runCommandVerbose(addHostsCom, false); err != nil {
			return fmt.Errorf("unable to write into '/etc/hosts'. \n Please add the records manually")
		}
	}

	fmt.Println("Records added to /etc/hosts successfully!")
	return nil
}

func saveMetadata(gitopsConfig, workspaceName, token, domain string, noIde bool, workspaceId *string, mqttEnvVars []string, gitopsDevSourceDir string) error {
	metadata := config.WorkspaceMetadata{
		Domain:       domain,
		GitopsURL:    fmt.Sprintf("https://%s-gitops.%s", workspaceName, domain),
		GitopsSecret: token,
	}

	if workspaceId != nil {
		metadata.WorkspaceId = workspaceId
	}

	if len(mqttEnvVars) > 0 {
		for _, envVar := range mqttEnvVars {
			key, value, _ := strings.Cut(envVar, "=")
			switch key {
			case "MQTT_USERNAME":
				metadata.MqttUsername = &value
			case "MQTT_PASSWORD":
				metadata.MqttPassword = &value
			case "MQTT_BROKER":
				metadata.MqttBroker = &value
			case "MQTT_PORT":
				port, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Errorf("failed to convert MQTT_PORT: %w", err)
				}
				metadata.MqttPort = &port
			case "MQTT_TOPIC":
				metadata.MqttTopic = &value
			}
		}
	}

	if !noIde {
		editorURL := fmt.Sprintf("https://%s-editor.%s", workspaceName, domain)
		metadata.EditorURL = &editorURL
	}

	if gitopsDevSourceDir != "" {
		metadata.GitopsDevSourceDir = &gitopsDevSourceDir
	}

	metadataPath := filepath.Join(gitopsConfig, "metadata.yaml")
	if err := metadata.SaveToFile(metadataPath); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	return nil
}

func parseRepositoryURL(repoURL string) (*RepositoryInfo, error) {
	repoURL = strings.TrimSpace(repoURL)
	if strings.HasPrefix(repoURL, "git://") {
		url := strings.TrimPrefix(repoURL, "git://")
		url = strings.TrimPrefix(url, "git@")

		parts := strings.SplitN(url, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid git:// URL format: %s", repoURL)
		}

		hostname := parts[0]
		path := parts[1]

		if len(path) > 0 && path[0] >= '0' && path[0] <= '9' {
			slashIndex := strings.Index(path, "/")
			if slashIndex == -1 {
				return nil, fmt.Errorf("invalid git:// URL format - port number without path: %s", repoURL)
			}
			path = path[slashIndex+1:]
		}

		path = strings.TrimSuffix(path, ".git")
		pathParts := strings.Split(path, "/")
		if len(pathParts) != 2 {
			return nil, fmt.Errorf("invalid repository path format: %s", path)
		}

		return &RepositoryInfo{
			Hostname: hostname,
			Org:      pathParts[0],
			Repo:     pathParts[1],
			IsSSH:    true,
		}, nil
	}

	if strings.HasPrefix(repoURL, "git@") {
		url := strings.TrimPrefix(repoURL, "git@")
		lastColonIndex := strings.LastIndex(url, ":")
		if lastColonIndex == -1 {
			return nil, fmt.Errorf("invalid SSH URL format: %s", repoURL)
		}

		hostname := url[:lastColonIndex]
		path := url[lastColonIndex+1:]

		if len(path) > 0 && path[0] >= '0' && path[0] <= '9' {
			slashIndex := strings.Index(path, "/")
			if slashIndex == -1 {
				return nil, fmt.Errorf("invalid SSH URL format - port number without path: %s", repoURL)
			}
			path = path[slashIndex+1:]
		}

		path = strings.TrimSuffix(path, ".git")
		pathParts := strings.Split(path, "/")
		if len(pathParts) != 2 {
			return nil, fmt.Errorf("invalid repository path format: %s", path)
		}

		return &RepositoryInfo{
			Hostname: hostname,
			Org:      pathParts[0],
			Repo:     pathParts[1],
			IsSSH:    true,
		}, nil
	}

	if strings.HasPrefix(repoURL, "https://") {
		url := strings.TrimPrefix(repoURL, "https://")
		url = strings.TrimSuffix(url, ".git")

		parts := strings.Split(url, "/")
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid HTTPS URL format: %s", repoURL)
		}

		hostname := parts[0]
		org := parts[1]
		repo := parts[2]

		return &RepositoryInfo{
			Hostname: hostname,
			Org:      org,
			Repo:     repo,
			IsSSH:    false,
		}, nil
	}

	if strings.Contains(repoURL, "/") && !strings.HasPrefix(repoURL, "git@") && !strings.HasPrefix(repoURL, "git://") && !strings.HasPrefix(repoURL, "https://") {
		slashIndex := strings.Index(repoURL, "/")
		if slashIndex > 0 {
			hostname := repoURL[:slashIndex]
			path := repoURL[slashIndex+1:]

			if colonIndex := strings.LastIndex(hostname, ":"); colonIndex > 0 {
				portPart := hostname[colonIndex+1:]
				isNumeric := true
				for _, c := range portPart {
					if c < '0' || c > '9' {
						isNumeric = false
						break
					}
				}
				if isNumeric {
					hostname = hostname[:colonIndex]
				}
			}

			path = strings.TrimSuffix(path, ".git")
			pathParts := strings.Split(path, "/")
			if len(pathParts) >= 2 {
				return &RepositoryInfo{
					Hostname: hostname,
					Org:      pathParts[0],
					Repo:     pathParts[1],
					IsSSH:    false,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("unsupported URL format: %s", repoURL)
}

func validatePort(portStr string) (int, error) {
	if portStr == "" {
		return 0, fmt.Errorf("port cannot be empty")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port format '%s': %w", portStr, err)
	}

	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d is out of valid range (1-65535)", port)
	}

	return port, nil
}

func createSSHConfig(workspacePath, workspaceName string, repoInfo *RepositoryInfo, port string) (string, error) {
	portNum, err := validatePort(port)
	if err != nil {
		return "", fmt.Errorf("invalid port: %w", err)
	}

	sshDir := filepath.Join(workspacePath, "ssh")
	configPath := filepath.Join(sshDir, "config")

	var sshHostname string
	switch repoInfo.Hostname {
	case "github.com":
		sshHostname = "ssh.github.com"
	case "gitlab.com":
		sshHostname = "gitlab.com"
	default:
		sshHostname = repoInfo.Hostname
	}

	configContent := fmt.Sprintf(`Host git-%s
  HostName %s
  User git
  IdentityFile %s
  IdentitiesOnly yes
  Port %d
  AddKeysToAgent yes
`, workspaceName, sshHostname, filepath.Join(workspacePath, "ssh", "id_ed25519"), portNum)

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write SSH config file: %w", err)
	}

	return configPath, nil
}

