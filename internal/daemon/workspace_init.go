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

	var err error
	if _, err = os.Stat(bitswanConfig); os.IsNotExist(err) {
		if err = os.MkdirAll(bitswanConfig, 0755); err != nil {
			return fmt.Errorf("failed to create BitSwan config directory: %w", err)
		}
	}

	// Ensure oauth2-proxy binary is available
	if err = oauth.EnsureOAuth2Proxy(bitswanConfig); err != nil {
		fmt.Printf("Warning: Failed to download oauth2-proxy: %v\n", err)
		fmt.Println("OAuth authentication may not work properly without oauth2-proxy")
	}

	// Init required networks
	networksToCreate := []string{
		"bitswan_network",
		"bitswan_caddy",
		fmt.Sprintf("bitswan_%s_common", workspaceName),
		fmt.Sprintf("bitswan_%s_dev", workspaceName),
		fmt.Sprintf("bitswan_%s_staging", workspaceName),
		fmt.Sprintf("bitswan_%s_prod", workspaceName),
	}

	for _, networkName := range networksToCreate {
		var exists bool
		exists, err = checkNetworkExists(networkName)
		if err != nil {
			return fmt.Errorf("error checking network %s: %w", networkName, err)
		}

		if exists {
			if *verbose {
				fmt.Printf("Network '%s' exists\n", networkName)
			}
		} else {
			createDockerNetworkCom := exec.Command("docker", "network", "create", networkName)
			if *verbose {
				fmt.Printf("Creating Docker network '%s'...\n", networkName)
			}
			if err = runCommandVerbose(createDockerNetworkCom, *verbose); err != nil {
				if err.Error() == "exit status 1" {
					if *verbose {
						fmt.Printf("Docker network '%s' already exists!\n", networkName)
					}
				} else {
					fmt.Printf("Failed to create Docker network '%s': %s\n", networkName, err.Error())
				}
			} else {
				if *verbose {
					fmt.Printf("Docker network '%s' created!\n", networkName)
				}
			}
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
		_, err := initIngress(*verbose)
		if err != nil {
			return fmt.Errorf("failed to initialize Caddy: %w", err)
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

	// Ensure user1000 exists (create if it doesn't)
	checkUserCmd := exec.Command("id", "-u", "1000")
	if checkUserCmd.Run() != nil {
		// User doesn't exist, create it
		createUserCmd := exec.Command("useradd", "-u", "1000", "-m", "-s", "/bin/sh", "user1000")
		createUserCmd.Run() // Ignore errors, might already exist
	}

	// Ensure the entire path is accessible to user1000 by chowning parent directories
	// Chown /root/.config/bitswan to ensure user1000 can access workspaces
	// Also need to ensure /root is accessible (at least execute permission)
	chownRootCmd := exec.Command("chmod", "755", "/root")
	chownRootCmd.Run() // Ignore errors
	chownRootConfigCmd := exec.Command("chmod", "755", "/root/.config")
	chownRootConfigCmd.Run() // Ignore errors

	bitswanConfigDir := bitswanConfig
	chownBitswanCmd := exec.Command("chown", "-R", "1000:1000", bitswanConfigDir)
	chownBitswanCmd.Run() // Ignore errors, might already be correct

	// Ensure the directory is owned by user1000 from the start
	chownConfigCmd := exec.Command("chown", "-R", "1000:1000", gitopsConfig)
	if err := chownConfigCmd.Run(); err != nil {
		return fmt.Errorf("failed to chown gitops config directory: %w", err)
	}

	// Initialize Bitswan workspace
	gitopsWorkspace := gitopsConfig + "/workspace"
	var localRemoteName string
	var localRemotePath string
	if *remoteRepo != "" {
		// Check if this is a local file path (starts with / or file://)
		isLocalPath := strings.HasPrefix(*remoteRepo, "/") || strings.HasPrefix(*remoteRepo, "file://")

		if isLocalPath {
			// Handle local file path - clone directly without SSH setup
			clonePath := *remoteRepo
			if strings.HasPrefix(clonePath, "file://") {
				clonePath = strings.TrimPrefix(clonePath, "file://")
			}

			fmt.Println("Cloning local repository...")
			// Run git clone as user1000 to ensure the cloned repository is owned by user1000
			// Use su to switch to user1000 for git operations
			// Escape the paths for shell safety
			com := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("git clone %q %q", clonePath, gitopsWorkspace)) //nolint:gosec
			if err := runCommandVerbose(com, *verbose); err != nil {
				return fmt.Errorf("failed to clone local repository: %w", err)
			}
			fmt.Println("Local repository cloned!")

			// For local remotes, we need to mount the repository in the GitOps container
			// so it can fetch from it. Determine the host path and mount name.
			hostHomeDir := os.Getenv("HOST_HOME")

			if strings.HasPrefix(clonePath, "/root/.config/bitswan/workspaces/") {
				// Extract workspace name from path: /root/.config/bitswan/workspaces/<workspace-name>/workspace
				parts := strings.Split(strings.TrimPrefix(clonePath, "/root/.config/bitswan/workspaces/"), "/")
				if len(parts) >= 1 && parts[0] != "" {
					localRemoteName = parts[0]
					// Get the host path for the local repository
					if hostHomeDir != "" {
						localRemotePath = filepath.Join(hostHomeDir, ".config", "bitswan", "workspaces", localRemoteName, "workspace")
						// Store the mount point URL for later (after push)
						// We'll update the remote URL after the push succeeds
						fmt.Printf("Detected workspace repository remote. Will update remote URL after push to: /remote-repos/%s\n", localRemoteName)
					} else {
						fmt.Printf("Warning: HOST_HOME not set, cannot set up local remote mount\n")
					}
				}
			} else {
				// For other local paths, we need to mount them too so GitOps can access them
				// Convert container path to host path if needed
				if hostHomeDir != "" && strings.HasPrefix(clonePath, "/root/.config/bitswan/") {
					// Convert container path to host path
					relativePath := strings.TrimPrefix(clonePath, "/root/.config/bitswan")
					localRemotePath = filepath.Join(hostHomeDir, ".config", "bitswan") + relativePath
					// Use a generic mount point name
					localRemoteName = "remote-repo"
					// Update remote URL to use mount point
					remoteURLForGitOps := filepath.Join("/remote-repos", "remote-repo")
					fmt.Printf("Detected local repository remote. Will update remote URL after push to: %s\n", remoteURLForGitOps)
				} else if strings.HasPrefix(clonePath, "/host/") {
					// Already a /host/ path, use it directly
					localRemotePath = clonePath
					localRemoteName = "remote-repo"
					remoteURLForGitOps := strings.TrimPrefix(clonePath, "/host")
					fmt.Printf("Detected /host/ path remote. Will update remote URL after push to: %s\n", remoteURLForGitOps)
				} else {
					// Absolute path on host, use as-is
					localRemotePath = clonePath
					localRemoteName = "remote-repo"
					remoteURLForGitOps := filepath.Join("/remote-repos", "remote-repo")
					fmt.Printf("Detected local path remote. Will update remote URL after push to: %s\n", remoteURLForGitOps)
				}
			}

			// Checkout specified branch if provided
			if *workspaceBranch != "" {
				fmt.Printf("Checking out branch '%s'...\n", *workspaceBranch)
				// First check if branch exists - run as user1000
				checkBranchCmd := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("cd %s && git rev-parse --verify origin/%s", gitopsWorkspace, *workspaceBranch)) //nolint:gosec
				if checkBranchCmd.Run() == nil {
					// Branch exists in remote, checkout it
					checkoutCom := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("cd %s && git checkout -b %s origin/%s", gitopsWorkspace, *workspaceBranch, *workspaceBranch)) //nolint:gosec
					if err := runCommandVerbose(checkoutCom, *verbose); err != nil {
						// Try just checking out if branch already exists locally
						checkoutCom = exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("cd %s && git checkout %s", gitopsWorkspace, *workspaceBranch)) //nolint:gosec
						if err := runCommandVerbose(checkoutCom, *verbose); err != nil {
							fmt.Printf("Warning: Failed to checkout branch '%s': %v\n", *workspaceBranch, err)
							fmt.Printf("Continuing with the default branch...\n")
						} else {
							fmt.Printf("Successfully checked out branch '%s'!\n", *workspaceBranch)
						}
					} else {
						fmt.Printf("Successfully checked out branch '%s'!\n", *workspaceBranch)
					}
				} else {
					// Branch doesn't exist in remote, it will be created as orphan branch later
					fmt.Printf("Branch '%s' does not exist in remote, will be created as orphan branch\n", *workspaceBranch)
				}
			}
		} else {
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
			// Clone using SSH key as user1000
			cloneURL = fmt.Sprintf("git@%s:%s/%s.git", repoInfo.Hostname, repoInfo.Org, repoInfo.Repo)

			// Build SSH command
			var sshCmd string
			if *sshPort != "" {
				// Create SSH config file for custom port access
				sshConfigPath, err := createSSHConfig(gitopsConfig, workspaceName, repoInfo, *sshPort)
				if err != nil {
					return fmt.Errorf("failed to create SSH config: %w", err)
				}
				// Replace hostname with our SSH config host
				cloneURL = fmt.Sprintf("ssh://git@git-%s/%s/%s.git", workspaceName, repoInfo.Org, repoInfo.Repo)
				sshCmd = fmt.Sprintf("GIT_SSH_COMMAND='ssh -F %s -o StrictHostKeyChecking=no' git clone %s %s", sshConfigPath, cloneURL, gitopsWorkspace)
			} else {
				// Set up SSH to use the generated key directly
				sshCmd = fmt.Sprintf("GIT_SSH_COMMAND='ssh -i %s -o StrictHostKeyChecking=no' git clone %s %s", sshKeyPair.PrivateKeyPath, cloneURL, gitopsWorkspace)
			}

			com := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", sshCmd) //nolint:gosec

			fmt.Println("Cloning remote repository...")
			if err := runCommandVerbose(com, *verbose); err != nil {
				return fmt.Errorf("failed to clone remote repository: %w", err)
			}
			fmt.Println("Remote repository cloned!")

			// Ensure the cloned repository is owned by user1000
			chownCloneCmd := exec.Command("chown", "-R", "1000:1000", gitopsWorkspace)
			chownCloneCmd.Run() // Ignore errors

			// Checkout specified branch if provided
			if *workspaceBranch != "" {
				fmt.Printf("Checking out branch '%s'...\n", *workspaceBranch)
				checkoutCom := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("cd %s && git checkout %s", gitopsWorkspace, *workspaceBranch)) //nolint:gosec
				if err := runCommandVerbose(checkoutCom, *verbose); err != nil {
					fmt.Printf("Warning: Failed to checkout branch '%s': %v\n", *workspaceBranch, err)
					fmt.Printf("Continuing with the default branch...\n")
				} else {
					fmt.Printf("Successfully checked out branch '%s'!\n", *workspaceBranch)
				}
			}
		}
	} else {
		if err := os.MkdirAll(gitopsWorkspace, 0755); err != nil {
			return fmt.Errorf("failed to create GitOps workspace directory %s: %w", gitopsWorkspace, err)
		}
		// Ensure the workspace directory is owned by user1000
		chownWorkspaceCmd := exec.Command("chown", "-R", "1000:1000", gitopsWorkspace)
		if err := chownWorkspaceCmd.Run(); err != nil {
			return fmt.Errorf("failed to chown workspace directory: %w", err)
		}

		// Run git init as user1000 using -C flag to avoid cd issues
		com := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("git -C %s init", gitopsWorkspace)) //nolint:gosec
		fmt.Println("Initializing git in workspace...")

		if err := runCommandVerbose(com, *verbose); err != nil {
			return fmt.Errorf("failed to init git in workspace: %w", err)
		}

		fmt.Println("Git initialized in workspace!")
	}

	// Configure git user globally as user1000 (needed for commits)
	gitConfigGlobalCmd := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", "git config --global user.name 'BitSwan Workspace'") //nolint:gosec
	gitConfigGlobalCmd.Run()                                                                                                         // Ignore errors, might already be set

	gitConfigGlobalCmd = exec.Command("su", "-s", "/bin/sh", "user1000", "-c", "git config --global user.email 'workspace@bitswan.local'") //nolint:gosec
	gitConfigGlobalCmd.Run()                                                                                                               // Ignore errors, might already be set

	// Add GitOps worktree as user1000
	gitopsWorktree := gitopsConfig + "/gitops"
	worktreeAddCom := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("git -C %s worktree add --orphan -b %s %s", gitopsWorkspace, workspaceName, gitopsWorktree)) //nolint:gosec

	fmt.Println("Setting up GitOps worktree...")
	if err := runCommandVerbose(worktreeAddCom, *verbose); err != nil {
		return fmt.Errorf("failed to create GitOps worktree: %w", err)
	}

	if *remoteRepo != "" {
		// Check if this is a local file path
		isLocalPath := strings.HasPrefix(*remoteRepo, "/") || strings.HasPrefix(*remoteRepo, "file://")

		// Create empty commit as user1000
		emptyCommitCom := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("cd %s && git commit --allow-empty -m 'Initial commit'", gitopsWorktree)) //nolint:gosec
		if err := runCommandVerbose(emptyCommitCom, *verbose); err != nil {
			return fmt.Errorf("failed to create empty commit: %w", err)
		}

		if isLocalPath {
			// For local paths, just push directly without SSH setup as user1000
			setUpstreamCom := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("cd %s && git push -u origin %s", gitopsWorktree, workspaceName)) //nolint:gosec
			if err := runCommandVerbose(setUpstreamCom, *verbose); err != nil {
				return fmt.Errorf("failed to set upstream: %w", err)
			}

			// If this is a local remote, update the remote URL to use the mount point
			// after the push succeeds (so GitOps containers can fetch from it)
			if localRemoteName != "" && localRemotePath != "" {
				var remoteURLForGitOps string
				// Determine the mount point path based on the mount name
				// All local remotes are mounted to /remote-repos/<name>
				remoteURLForGitOps = filepath.Join("/remote-repos", localRemoteName)
				fmt.Printf("Updating remote URL to mount point: %s\n", remoteURLForGitOps)
				// Update in both the main workspace repo and the gitops worktree (they share the same remote config)
				// Update in main workspace repo
				updateRemoteCmd := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("cd %s && git remote set-url origin %s", gitopsWorkspace, remoteURLForGitOps)) //nolint:gosec
				if err := runCommandVerbose(updateRemoteCmd, *verbose); err != nil {
					fmt.Printf("Warning: Failed to update remote URL to mount point in main repo: %v\n", err)
				}
				// Also update in gitops worktree explicitly (though they share .git, being explicit helps)
				updateRemoteCmdWorktree := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", fmt.Sprintf("cd %s && git remote set-url origin %s", gitopsWorktree, remoteURLForGitOps)) //nolint:gosec
				if err := runCommandVerbose(updateRemoteCmdWorktree, *verbose); err != nil {
					fmt.Printf("Warning: Failed to update remote URL to mount point in worktree: %v\n", err)
				} else {
					fmt.Printf("Remote URL updated to mount point successfully\n")
				}
			}
		} else {
			// Push to remote using SSH key as user1000
			var sshCmd string
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
				sshCmd = fmt.Sprintf("GIT_SSH_COMMAND='ssh -F %s -o StrictHostKeyChecking=no' cd %s && git push -u origin %s", sshConfigPath, gitopsWorktree, workspaceName)
			} else {
				// Set up SSH to use the generated key for push operations
				sshKeyPath := filepath.Join(gitopsConfig, "ssh", "id_ed25519")
				sshCmd = fmt.Sprintf("GIT_SSH_COMMAND='ssh -i %s -o StrictHostKeyChecking=no' cd %s && git push -u origin %s", sshKeyPath, gitopsWorktree, workspaceName)
			}

			setUpstreamCom := exec.Command("su", "-s", "/bin/sh", "user1000", "-c", sshCmd) //nolint:gosec
			if err := runCommandVerbose(setUpstreamCom, *verbose); err != nil {
				return fmt.Errorf("failed to set upstream: %w", err)
			}
		}
	}

	fmt.Println("GitOps worktree set up successfully!")

	// Fix ownership of gitops worktree to user1000:1000 so the GitOps container can access it
	// The daemon runs as root, but the GitOps container runs as user1000
	// NOTE: We do NOT chown the workspace directory itself, as it may be used as a source
	// for cloning by other workspaces. The daemon (root) needs to be able to clone from it.
	// Only the gitops worktree needs to be owned by user1000 for the GitOps container.
	fmt.Println("Fixing ownership of gitops worktree...")
	chownGitopsCmd := exec.Command("chown", "-R", "1000:1000", gitopsWorktree)
	if err := runCommandVerbose(chownGitopsCmd, *verbose); err != nil {
		return fmt.Errorf("failed to fix ownership of gitops directory: %w", err)
	}
	fmt.Println("Ownership fixed successfully!")

	// Create secrets directory
	secretsDir := gitopsConfig + "/secrets"
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}

	if oauthConfig != nil {
		oauthConfigFile := gitopsConfig + "/oauth-config.yaml"
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

				// Save OAuth config to disk
				if err := oauth.SaveOauthConfig(workspaceName, oauthConfig); err != nil {
					return fmt.Errorf("failed to save OAuth config: %w", err)
				}
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
	var keycloakURL string
	if oauthConfig != nil {
		oauthEnvVars = oauth.CreateOAuthEnvVars(oauthConfig, "gitops", workspaceName, *domain)
		keycloakURL = oauthConfig.IssuerUrl
	}

	// Log local remote info for debugging
	if localRemotePath != "" && localRemoteName != "" {
		fmt.Printf("Configuring local repository mount: %s -> /remote-repos/%s\n", localRemotePath, localRemoteName)
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
		LocalRemotePath:    localRemotePath,
		LocalRemoteName:    localRemoteName,
		KeycloakURL:        keycloakURL,
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

	// Docker compose project names must be lowercase
	projectName := strings.ToLower(workspaceName) + "-site"
	// Use --pull missing to pull images if they don't exist locally (needed for CI)
	dockerComposeCom := exec.Command("docker", "compose", "-p", projectName, "up", "-d", "--pull", "missing")

	fmt.Println("Launching BitSwan Workspace services...")
	if err := runCommandVerbose(dockerComposeCom, true); err != nil {
		return fmt.Errorf("failed to start docker-compose: %w", err)
	}

	fmt.Println("BitSwan GitOps initialized successfully!")

	// Sync updated workspace list to AOC
	if err := syncWorkspaceListToAOC(); err != nil {
		fmt.Printf("Warning: Failed to sync workspace list to AOC: %v\n", err)
	}

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
