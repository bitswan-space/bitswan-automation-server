package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bitswan-space/bitswan-workspaces/cmd/caddy"
	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/spf13/cobra"
)

type initOptions struct {
	remoteRepo        string
	domain            string
	certsDir          string
	verbose           bool
	mkCerts           bool
	noIde             bool
	setHosts          bool
	local             bool
	gitopsImage       string
	editorImage       string
	gitopsDevSourceDir string
}

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

type MetadataInit struct {
	Domain             string  `yaml:"domain"`
	EditorURL          *string `yaml:"editor-url,omitempty"`
	GitopsURL          string  `yaml:"gitops-url"`
	GitopsSecret       string  `yaml:"gitops-secret"`
	WorkspaceId        *string `yaml:"workspace_id,omitempty"`
	MqttUsername       *int    `yaml:"mqtt_username,omitempty"`
	MqttPassword       *string `yaml:"mqtt_password,omitempty"`
	MqttBroker         *string `yaml:"mqtt_broker,omitempty"`
	MqttPort           *int    `yaml:"mqtt_port,omitempty"`
	MqttTopic          *string `yaml:"mqtt_topic,omitempty"`
	GitopsDevSourceDir *string `yaml:"gitops-dev-source-dir,omitempty"`
}

func defaultInitOptions() *initOptions {
	return &initOptions{}
}

func newInitCmd() *cobra.Command {
	o := defaultInitOptions()

	cmd := &cobra.Command{
		Use:   "init [flags] <workspace-name>",
		Short: "Initializes a new GitOps, Caddy and Bitswan editor",
		Args:  cobra.RangeArgs(1, 2),
		RunE:  o.run,
	}

	cmd.Flags().StringVar(&o.remoteRepo, "remote", "", "The remote repository to clone")
	cmd.Flags().StringVar(&o.domain, "domain", "", "The domain to use for the Caddyfile")
	cmd.Flags().StringVar(&o.certsDir, "certs-dir", "", "The directory where the certificates are located")
	cmd.Flags().BoolVar(&o.noIde, "no-ide", false, "Do not start Bitswan Editor")
	cmd.Flags().BoolVarP(&o.verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&o.mkCerts, "mkcerts", false, "Automatically generate local certificates using the mkcerts utility")
	cmd.Flags().BoolVar(&o.setHosts, "set-hosts", false, "Automatically set hosts to /etc/hosts file")
	cmd.Flags().BoolVar(&o.local, "local", false, "Automatically use flag --set-hosts and --mkcerts. If no domain is set defaults to bs-<workspacename>.localhost")
	cmd.Flags().StringVar(&o.gitopsImage, "gitops-image", "", "Custom image for the gitops")
	cmd.Flags().StringVar(&o.editorImage, "editor-image", "", "Custom image for the editor")
	cmd.Flags().StringVar(&o.gitopsDevSourceDir, "gitops-dev-source-dir", "", "Directory to mount as /src/app in gitops container for development")

	return cmd
}

func checkNetworkExists(networkName string) (bool, error) {
	// Run docker network ls command with JSON format
	cmd := exec.Command("docker", "network", "ls", "--format=json")
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("error running docker command: %v", err)
	}

	// Split output into lines
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	// Process each line
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

func runCommandVerbose(cmd *exec.Cmd, verbose bool) error {
	var stdoutBuf, stderrBuf bytes.Buffer

	if verbose {
		// Set up pipes for real-time streaming
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to create stdout pipe: %w", err)
		}

		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			return fmt.Errorf("failed to create stderr pipe: %w", err)
		}

		// Create multi-writers to both stream and capture output
		stdoutWriter := io.MultiWriter(os.Stdout, &stdoutBuf)
		stderrWriter := io.MultiWriter(os.Stderr, &stderrBuf)

		// Start the command
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start command: %w", err)
		}

		// Copy stdout and stderr in separate goroutines
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(stdoutWriter, stdoutPipe)
		}()

		go func() {
			defer wg.Done()
			io.Copy(stderrWriter, stderrPipe)
		}()

		// Wait for all output to be processed
		wg.Wait()

		// Wait for command to complete
		err = cmd.Wait()
		return err
	} else {
		// Not verbose, just capture output for potential error reporting
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf

		err := cmd.Run()

		// If command failed, print the captured output
		if err != nil {
			if stdoutBuf.Len() > 0 {
				fmt.Println("Command stdout:")
				fmt.Println(stdoutBuf.String())
			}

			if stderrBuf.Len() > 0 {
				fmt.Println("Command stderr:")
				fmt.Println(stderrBuf.String())
			}
		}

		return err
	}
}

// EnsureExamples clones the BitSwan repository if it doesn't exist,
// or updates it if it already exists
func EnsureExamples(bitswanConfig string, verbose bool) error {
	repoURL := "https://github.com/bitswan-space/BitSwan.git"
	targetDir := filepath.Join(bitswanConfig, "bitswan-src")

	// Check if the directory exists and contains a git repository
	if _, err := os.Stat(filepath.Join(targetDir, ".git")); os.IsNotExist(err) {
		// Directory doesn't exist or is not a git repo, clone it
		if verbose {
			fmt.Printf("Cloning BitSwan repository to %s\n", targetDir)
		}

		// Create parent directory if it doesn't exist
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
		// Directory exists and is a git repo, update it
		if err := UpdateExamples(bitswanConfig, verbose); err != nil {
			return err
		}
	}

	return nil
}

// UpdateExamples performs a git pull on the repository
func UpdateExamples(bitswanConfig string, verbose bool) error {

	repoPath := filepath.Join(bitswanConfig, "bitswan-src")
	if verbose {
		fmt.Printf("Updating BitSwan repository at %s\n", repoPath)
	}

	cmd := exec.Command("git", "pull")
	cmd.Dir = repoPath

	if err := runCommandVerbose(cmd, verbose); err != nil {
		return fmt.Errorf("failed to update repository: %w", err)
	}

	if verbose {
		fmt.Println("Repository updated successfully")
	}
	return nil
}

func generateWildcardCerts(domain string) (string, error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "certs-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Store current working directory
	originalDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}

	// Change to temp directory
	if err := os.Chdir(tempDir); err != nil {
		return "", fmt.Errorf("failed to change to temp directory: %w", err)
	}

	// Ensure we change back to original directory when function returns
	defer os.Chdir(originalDir)

	// Generate wildcard certificate
	wildcardDomain := "*." + domain
	cmd := exec.Command("mkcert", wildcardDomain)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Generate file names
	keyFile := fmt.Sprintf("_wildcard.%s-key.pem", domain)
	certFile := fmt.Sprintf("_wildcard.%s.pem", domain)

	// Rename files
	if err := os.Rename(keyFile, "private-key.pem"); err != nil {
		return "", fmt.Errorf("failed to rename key file: %w", err)
	}
	if err := os.Rename(certFile, "full-chain.pem"); err != nil {
		return "", fmt.Errorf("failed to rename cert file: %w", err)
	}

	return tempDir, nil
}

func setHosts(workspaceName string, o *initOptions) error {
	fmt.Println("Checking if the user has permission to write to /etc/hosts...")
	fileInfo, err := os.Stat("/etc/hosts")
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	// Check if the current user can write to the file
	if fileInfo.Mode().Perm()&0200 == 0 {
		return fmt.Errorf("user does not have permission to write to /etc/hosts")
	}
	fmt.Println("File /etc/hosts is writable")

	hostsEntries := []string{
		"127.0.0.1 " + workspaceName + "-gitops." + o.domain,
	}

	if !o.noIde {
		hostsEntries = append(hostsEntries, "127.0.0.1 "+workspaceName+"-editor."+o.domain)
	}

	// Check if the entries already exist in /etc/hosts
	for _, entry := range hostsEntries {
		if exec.Command("grep", "-wq", entry, "/etc/hosts").Run() == nil {
			return fmt.Errorf("hosts already set in /etc/hosts")
		}
	}

	fmt.Println("Adding record to /etc/hosts...")
	for _, entry := range hostsEntries {
		cmdStr := "echo '" + entry + "' | sudo tee -a /etc/hosts"
		addHostsCom := exec.Command("sh", "-c", cmdStr)
		if err := runCommandVerbose(addHostsCom, o.verbose); err != nil {
			return fmt.Errorf("unable to write into '/etc/hosts'. \n Please add the records manually")
		}
	}

	fmt.Println("Records added to /etc/hosts successfully!")
	return nil
}

// After displaying the information, save it to metadata.yaml
func saveMetadata(gitopsConfig, workspaceName, token, domain string, noIde bool, workspaceId *string, mqttEnvVars []string, gitopsDevSourceDir string) error {
	metadata := MetadataInit{
		Domain:       domain,
		GitopsURL:    fmt.Sprintf("https://%s-gitops.%s", workspaceName, domain),
		GitopsSecret: token,
	}

	if workspaceId != nil {
		metadata.WorkspaceId = workspaceId
	}

	// Add MQTT environment variables if they are provided
	if len(mqttEnvVars) > 0 {
		for _, envVar := range mqttEnvVars {
			key, value, _ := strings.Cut(envVar, "=")
			switch key {
			case "MQTT_USERNAME":
				username, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Errorf("failed to convert MQTT_USERNAME: %w", err)
				}
				metadata.MqttUsername = &username
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

	// Add editor URL if IDE is enabled
	if !noIde {
		editorURL := fmt.Sprintf("https://%s-editor.%s", workspaceName, domain)
		metadata.EditorURL = &editorURL
	}

	// Add GitOps dev source directory if provided
	if gitopsDevSourceDir != "" {
		metadata.GitopsDevSourceDir = &gitopsDevSourceDir
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Write to file
	metadataPath := filepath.Join(gitopsConfig, "metadata.yaml")
	if err := os.WriteFile(metadataPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}

	return nil
}

func (o *initOptions) run(cmd *cobra.Command, args []string) error {
	// The first argument is the workspace name
	workspaceName := args[0]
	bitswanConfig := os.Getenv("HOME") + "/.config/bitswan/"

	if _, err := os.Stat(bitswanConfig); os.IsNotExist(err) {
		if err := os.MkdirAll(bitswanConfig, 0755); err != nil {
			return fmt.Errorf("failed to create BitSwan config directory: %w", err)
		}
	}

	// Init bitswan network
	networkName := "bitswan_network"
	exists, err := checkNetworkExists(networkName)
	if err != nil {
		panic(fmt.Errorf("Error checking network: %v\n", err))
	}

	if exists {
		fmt.Printf("Network '%s' exists\n", networkName)
	} else {
		createDockerNetworkCom := exec.Command("docker", "network", "create", "bitswan_network")
		fmt.Println("Creating BitSwan Docker network...")
		if err := runCommandVerbose(createDockerNetworkCom, o.verbose); err != nil {
			if err.Error() == "exit status 1" {
				fmt.Println("BitSwan Docker network already exists!")
			} else {
				fmt.Printf("Failed to create BitSwan Docker network: %s\n", err.Error())
			}
		} else {
			fmt.Println("BitSwan Docker network created!")
		}
	}

	// Init shared Caddy if not exists
	caddyConfig := bitswanConfig + "caddy"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
			fmt.Println("Failed to start Caddy.")
		}
	}()

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
		err = caddy.InitCaddy(o.domain, o.verbose)
		if err != nil {
			return fmt.Errorf("failed to initialize Caddy: %w", err)
		}
	} else {
		fmt.Println("A running instance of Caddy with admin found")
	}

	// Secure that --local flag is not used with --set-hosts or --mkcerts
	if o.local && (o.setHosts || o.mkCerts) {
		panic(fmt.Errorf("Cannot use --local flag with --set-hosts or --mkcerts"))
	}

	if o.local {
		o.setHosts = true
		o.mkCerts = true
		if o.domain == "" {
			o.domain = fmt.Sprintf("bs-%s.localhost", workspaceName)
		}
	}

	inputCertsDir := o.certsDir

	if o.mkCerts {
		certDir, err := generateWildcardCerts(o.domain)
		if err != nil {
			return fmt.Errorf("Error generating certificates: %v\n", err)
		}
		inputCertsDir = certDir
	}

	if inputCertsDir != "" {
		fmt.Println("Installing certs from", inputCertsDir)
		caddyCertsDir := caddyConfig + "/certs"
		if _, err := os.Stat(caddyCertsDir); os.IsNotExist(err) {
			if err := os.MkdirAll(caddyCertsDir, 0755); err != nil {
				return fmt.Errorf("failed to create Caddy certs directory: %w", err)
			}
		}

		certsDir := caddyCertsDir + "/" + o.domain
		if _, err := os.Stat(certsDir); os.IsNotExist(err) {
			if err := os.MkdirAll(certsDir, 0755); err != nil {
				return fmt.Errorf("failed to create certs directory: %w", err)
			}
		}

		certs, err := os.ReadDir(inputCertsDir)
		if err != nil {
			panic(fmt.Errorf("Failed to read certs directory: %w", err))
		}

		for _, cert := range certs {
			if cert.IsDir() {
				continue
			}

			certPath := inputCertsDir + "/" + cert.Name()
			newCertPath := certsDir + "/" + cert.Name()

			bytes, err := os.ReadFile(certPath)
			if err != nil {
				panic(fmt.Errorf("Failed to read cert file: %w", err))
			}

			if err := os.WriteFile(newCertPath, bytes, 0755); err != nil {
				panic(fmt.Errorf("Failed to copy cert file: %w", err))
			}
		}

		fmt.Println("Certs copied successfully!")
	}

	gitopsConfig := bitswanConfig + "workspaces/" + workspaceName

	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
			fmt.Println("Failed to initialize GitOps.")
		}
	}()

	if _, err := os.Stat(gitopsConfig); !os.IsNotExist(err) {
		return fmt.Errorf("GitOps with this name was already initialized: %s", workspaceName)
	}

	if err := os.MkdirAll(gitopsConfig, 0755); err != nil {
		return fmt.Errorf("failed to create GitOps directory: %w", err)
	}

	// Initialize Bitswan workspace
	gitopsWorkspace := gitopsConfig + "/workspace"
	if o.remoteRepo != "" {
		com := exec.Command("git", "clone", o.remoteRepo, gitopsWorkspace) //nolint:gosec

		fmt.Println("Cloning remote repository...")
		if err := runCommandVerbose(com, o.verbose); err != nil {
			panic(fmt.Errorf("Failed to clone remote repository: %w", err))
		}
		fmt.Println("Remote repository cloned!")
	} else {
		if err := os.Mkdir(gitopsWorkspace, 0755); err != nil {
			return fmt.Errorf("failed to create GitOps workspace directory %s: %w", gitopsWorkspace, err)
		}
		com := exec.Command("git", "init")
		com.Dir = gitopsWorkspace

		fmt.Println("Initializing git in workspace...")

		if err := runCommandVerbose(com, o.verbose); err != nil {
			panic(fmt.Errorf("Failed to init git in workspace: %w", err))
		}

		fmt.Println("Git initialized in workspace!")
	}

	// Add GitOps worktree
	gitopsWorktree := gitopsConfig + "/gitops"
	worktreeAddCom := exec.Command("git", "worktree", "add", "--orphan", "-b", workspaceName, gitopsWorktree)
	worktreeAddCom.Dir = gitopsWorkspace

	fmt.Println("Setting up GitOps worktree...")
	if err := runCommandVerbose(worktreeAddCom, o.verbose); err != nil {
		panic(fmt.Errorf("Failed to create GitOps worktree: exit code %w.", err))
	}

	// Add repo as safe directory
	safeDirCom := exec.Command("git", "config", "--global", "--add", "safe.directory", gitopsWorktree)
	if err := runCommandVerbose(safeDirCom, o.verbose); err != nil {
		panic(fmt.Errorf("Failed to add safe directory: %w", err))
	}

	if o.remoteRepo != "" {
		// Create empty commit
		emptyCommitCom := exec.Command("git", "commit", "--allow-empty", "-m", "Initial commit")
		emptyCommitCom.Dir = gitopsWorktree
		if err := runCommandVerbose(emptyCommitCom, o.verbose); err != nil {
			panic(fmt.Errorf("Failed to create empty commit: %w", err))
		}

		// Push to remote
		setUpstreamCom := exec.Command("git", "push", "-u", "origin", workspaceName)
		setUpstreamCom.Dir = gitopsWorktree
		if err := runCommandVerbose(setUpstreamCom, o.verbose); err != nil {
			panic(fmt.Errorf("Failed to set upstream: %w", err))
		}
	}

	fmt.Println("GitOps worktree set up successfully!")

	// Create secrets directory
	secretsDir := gitopsConfig + "/secrets"
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}

	hostOsTmp := runtime.GOOS

	if !o.noIde {
		// Create codeserver config directory
		codeserverConfigDir := gitopsConfig + "/codeserver-config"
		if err := os.MkdirAll(codeserverConfigDir, 0700); err != nil {
			return fmt.Errorf("failed to create codeserver config directory: %w", err)
		}

		if hostOsTmp == "linux" {
			chownCom := exec.Command("sudo", "chown", "-R", "1000:1000", secretsDir)
			if err := runCommandVerbose(chownCom, o.verbose); err != nil {
				return fmt.Errorf("failed to change ownership of secrets folder: %w", err)
			}
			chownCom = exec.Command("sudo", "chown", "-R", "1000:1000", codeserverConfigDir)
			if err := runCommandVerbose(chownCom, o.verbose); err != nil {
				return fmt.Errorf("failed to change ownership of codeserver config folder: %w", err)
			}
			chownCom = exec.Command("sudo", "chown", "-R", "1000:1000", gitopsWorkspace)
			if err := runCommandVerbose(chownCom, o.verbose); err != nil {
				return fmt.Errorf("failed to change ownership of workspace folder: %w", err)
			}
		}
	}

	// Set hosts to /etc/hosts file
	if o.setHosts {
		err := setHosts(workspaceName, o)
		if err != nil {
			fmt.Printf("\033[33m%s\033[0m\n", err)
		}
	}

	gitopsImage := o.gitopsImage
	if gitopsImage == "" {
		gitopsLatestVersion, err := dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/gitops/tags/")
		if err != nil {
			panic(fmt.Errorf("Failed to get latest BitSwan GitOps version: %w", err))
		}
		gitopsImage = "bitswan/gitops:" + gitopsLatestVersion
	}

	bitswanEditorImage := o.editorImage
	if bitswanEditorImage == "" {
		bitswanEditorLatestVersion, err := dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/bitswan-editor/tags/")
		if err != nil {
			panic(fmt.Errorf("Failed to get latest BitSwan Editor version: %w", err))
		}
		bitswanEditorImage = "bitswan/bitswan-editor:" + bitswanEditorLatestVersion
	}

	fmt.Println("Setting up GitOps deployment...")
	gitopsDeployment := gitopsConfig + "/deployment"
	if err := os.MkdirAll(gitopsDeployment, 0755); err != nil {
		return fmt.Errorf("Failed to create deployment directory: %w", err)
	}

	if inputCertsDir != "" {
		if err := caddyapi.InstallTLSCerts(workspaceName, o.domain); err != nil {
			return fmt.Errorf("Failed to install caddy certs %w", err)
		}
	}

	// Register GitOps service
	if err := caddyapi.RegisterServiceWithCaddy("gitops", workspaceName, o.domain, fmt.Sprintf("%s-gitops:8079", workspaceName)); err != nil {
		return fmt.Errorf("failed to register GitOps service: %w", err)
	}

	if err != nil {
		panic(fmt.Errorf("Failed to add Caddy records: %w", err))
	}

	err = EnsureExamples(bitswanConfig, o.verbose)
	if err != nil {
		panic(fmt.Errorf("Failed to download examples: %w", err))
	}

	var aocEnvVars []string
	var mqttEnvVars []string
	workspaceId := ""
	fmt.Println("Registering workspace...")
	// Check if automation_server.yaml exists
	automationServerConfig := filepath.Join(bitswanConfig, "aoc", "automation_server.yaml")
	if _, err := os.Stat(automationServerConfig); !os.IsNotExist(err) {
		// Read automation_server.yaml
		yamlFile, err := os.ReadFile(automationServerConfig)
		if err != nil {
			return fmt.Errorf("failed to read automation_server.yaml: %w", err)
		}

		var automationConfig AutomationServerYaml
		if err := yaml.Unmarshal(yamlFile, &automationConfig); err != nil {
			return fmt.Errorf("failed to unmarshal automation_server.yaml: %w", err)
		}

		fmt.Println("Getting automation server token...")

		resp, err := sendRequest("GET", fmt.Sprintf("%s/api/automation-servers/token", automationConfig.AOCUrl), nil, automationConfig.AccessToken)
		if err != nil {
			return fmt.Errorf("error sending request: %w", err)
		}

		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to get automation server token: %s", resp.Status)
		}

		type AutomationServerTokenResponse struct {
			Token string `json:"token"`
		}

		var automationServerTokenResponse AutomationServerTokenResponse
		body, _ := ioutil.ReadAll(resp.Body)
		err = json.Unmarshal([]byte(body), &automationServerTokenResponse)
		if err != nil {
			return fmt.Errorf("error decoding JSON: %w", err)
		}
		fmt.Println("Automation server token received successfully!")

		payload := map[string]interface{}{
			"name":                 workspaceName,
			"automation_server_id": automationConfig.AutomationServerId,
			"keycloak_org_id":      "00000000-0000-0000-0000-000000000000",
		}

		if !o.noIde {
			payload["editor_url"] = fmt.Sprintf("https://%s-editor.%s", workspaceName, o.domain)
		}

		jsonBytes, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		resp, err = sendRequest("POST", fmt.Sprintf("%s/api/workspaces/", automationConfig.AOCUrl), jsonBytes, automationConfig.AccessToken)
		if err != nil {
			return fmt.Errorf("error sending request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("failed to register workspace: %s", resp.Status)
		}

		type WorkspacePostResponse struct {
			Id                 string `json:"id"`
			Name               string `json:"name"`
			KeycloakOrgId      string `json:"keycloak_org_id"`
			AutomationServerId string `json:"automation_server_id"`
			CreatedAt          string `json:"created_at"`
			UpdatedAt          string `json:"updated_at"`
		}

		var workspacePostResponse WorkspacePostResponse
		body, _ = ioutil.ReadAll(resp.Body)
		err = json.Unmarshal([]byte(body), &workspacePostResponse)
		if err != nil {
			return fmt.Errorf("error decoding JSON: %w", err)
		}

		fmt.Println("Workspace registered successfully!")

		workspaceId = workspacePostResponse.Id

		aocEnvVars = append(aocEnvVars, "BITSWAN_WORKSPACE_ID="+fmt.Sprint(workspacePostResponse.Id))
		aocEnvVars = append(aocEnvVars, "BITSWAN_AOC_URL="+automationConfig.AOCUrl)
		aocEnvVars = append(aocEnvVars, "BITSWAN_AOC_TOKEN="+automationServerTokenResponse.Token)

		fmt.Println("Getting EMQX JWT for workspace...")
		resp, err = sendRequest("GET", fmt.Sprintf("%s/api/workspaces/%s/emqx/jwt", automationConfig.AOCUrl, workspacePostResponse.Id), nil, automationConfig.AccessToken)
		if err != nil {
			return fmt.Errorf("error sending request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to get EMQX JWT: %s", resp.Status)
		}

		type EmqxGetResponse struct {
			Url   string `json:"url"`
			Token string `json:"token"`
		}

		var emqxGetResponse EmqxGetResponse
		body, _ = ioutil.ReadAll(resp.Body)
		err = json.Unmarshal([]byte(body), &emqxGetResponse)
		if err != nil {
			return fmt.Errorf("error decoding JSON: %w", err)
		}

		fmt.Println("EMQX JWT received successfully!")

		urlParts := strings.Split(emqxGetResponse.Url, ":")
		emqxUrl, emqxPort := urlParts[0], urlParts[1]
		mqttEnvVars = append(mqttEnvVars, "MQTT_USERNAME="+fmt.Sprint(workspacePostResponse.Id))
		mqttEnvVars = append(mqttEnvVars, "MQTT_PASSWORD="+emqxGetResponse.Token)
		mqttEnvVars = append(mqttEnvVars, "MQTT_BROKER="+emqxUrl)
		mqttEnvVars = append(mqttEnvVars, "MQTT_PORT="+emqxPort)
		mqttEnvVars = append(mqttEnvVars, "MQTT_TOPIC=/topology")
	} else {
		fmt.Println("Automation server config not found, skipping workspace registration.")
	}

	compose, token, err := dockercompose.CreateDockerComposeFile(
		gitopsConfig,
		workspaceName,
		gitopsImage,
		bitswanEditorImage,
		o.domain,
		o.noIde,
		mqttEnvVars,
		aocEnvVars,
		o.gitopsDevSourceDir,
	)

	if err != nil {
		panic(fmt.Errorf("Failed to create docker-compose file: %w", err))
	}

	dockerComposePath := gitopsDeployment + "/docker-compose.yml"
	if err := os.WriteFile(dockerComposePath, []byte(compose), 0755); err != nil {
		panic(fmt.Errorf("Failed to write docker-compose file: %w", err))
	}

	err = os.Chdir(gitopsDeployment)
	if err != nil {
		panic(fmt.Errorf("Failed to change directory to GitOps deployment: %w", err))
	}

	fmt.Println("GitOps deployment set up successfully!")

	// Save metadata to file
	if err := saveMetadata(gitopsConfig, workspaceName, token, o.domain, o.noIde, &workspaceId, mqttEnvVars, o.gitopsDevSourceDir); err != nil {
		fmt.Printf("Warning: Failed to save metadata: %v\n", err)
	}

	projectName := workspaceName + "-site"
	dockerComposeCom := exec.Command("docker", "compose", "-p", projectName, "up", "-d")

	fmt.Println("Launching BitSwan Workspace services...")
	if err := runCommandVerbose(dockerComposeCom, true); err != nil {
		panic(fmt.Errorf("failed to start docker-compose: %w", err))
	}

	fmt.Println("BitSwan GitOps initialized successfully!")

	// Get Bitswan Editor password from container
	if !o.noIde {
		fmt.Println("Downloading and installing editor...")
		// Register GitOps service
		if err := caddyapi.RegisterServiceWithCaddy("editor", workspaceName, o.domain, fmt.Sprintf("%s-editor:9999", workspaceName)); err != nil {
			return fmt.Errorf("failed to register Editor service with caddy: %w", err)
		}
		// First, wait for the editor service to be ready by streaming logs
		if err := dockercompose.WaitForEditorReady(workspaceName); err != nil {
			panic(fmt.Errorf("failed to wait for editor to be ready: %w", err))
		}
		editorPassword, err := dockercompose.GetEditorPassword(workspaceName)
		if err != nil {
			panic(fmt.Errorf("Failed to get Bitswan Editor password: %w", err))
		}
		fmt.Println("------------BITSWAN EDITOR INFO------------")
		fmt.Printf("Bitswan Editor URL: https://%s-editor.%s\n", workspaceName, o.domain)
		fmt.Printf("Bitswan Editor Password: %s\n", editorPassword)
	}

	fmt.Println("------------GITOPS INFO------------")
	fmt.Printf("GitOps ID: %s\n", workspaceName)
	fmt.Printf("GitOps URL: https://%s-gitops.%s\n", workspaceName, o.domain)
	fmt.Printf("GitOps Secret: %s\n", token)

	return nil
}
