package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newPullAndDeployCmd() *cobra.Command {
	var gitopsImage string
	var editorImage string

	cmd := &cobra.Command{
		Use:   "pull-and-deploy",
		Short: "Test pull-and-deploy functionality across two workspaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestPullAndDeploy(gitopsImage, editorImage)
		},
	}

	cmd.Flags().StringVar(&gitopsImage, "gitops-image", "", "Custom GitOps image to use (default: production image)")
	cmd.Flags().StringVar(&editorImage, "editor-image", "", "Custom editor image to use (default: production image)")

	return cmd
}

func runTestPullAndDeploy(gitopsImage, editorImage string) error {
	fmt.Println("=== BitSwan Test Suite: Pull and Deploy ===")
	fmt.Println()

	// Ensure we're in a valid directory
	if wd, err := os.Getwd(); err != nil {
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			homeDir = "/tmp"
		}
		if err := os.Chdir(homeDir); err != nil {
			return fmt.Errorf("failed to change to directory: %w", err)
		}
	} else {
		if _, err := os.Stat(wd); err != nil {
			homeDir := os.Getenv("HOME")
			if homeDir == "" {
				homeDir = "/tmp"
			}
			if err := os.Chdir(homeDir); err != nil {
				return fmt.Errorf("failed to change to directory: %w", err)
			}
		}
	}

	// Generate unique workspace names
	timestamp := time.Now().Unix()
	workspace1Name := fmt.Sprintf("test-workspace-1-%d", timestamp)
	workspace2Name := fmt.Sprintf("test-workspace-2-%d", timestamp)
	fmt.Printf("Workspace 1 name: %s\n", workspace1Name)
	fmt.Printf("Workspace 2 name: %s\n", workspace2Name)

	client, err := daemon.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create daemon client: %w", err)
	}

	// Step 1: Initialize workspace 1
	fmt.Println("\n[1/9] Initializing workspace 1...")
	initArgs1 := []string{
		"workspace", "init",
		"--local",
		"--no-ide",
		"--no-oauth",
	}
	if gitopsImage != "" {
		initArgs1 = append(initArgs1, "--gitops-image", gitopsImage)
	}
	if editorImage != "" {
		initArgs1 = append(initArgs1, "--editor-image", editorImage)
	}
	initArgs1 = append(initArgs1, workspace1Name)

	if err := client.WorkspaceInit(initArgs1); err != nil {
		return fmt.Errorf("failed to initialize workspace 1: %w", err)
	}
	fmt.Println("✓ Workspace 1 initialized")

	// Get workspace 1 metadata
	metadata1, err := config.GetWorkspaceMetadata(workspace1Name)
	if err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("failed to get workspace 1 metadata: %w", err)
	}

	// Wait for gitops service to be ready
	fmt.Println("\n[1.5/9] Waiting for gitops service to be ready...")
	if err := waitForGitopsReady(metadata1.GitopsURL, metadata1.GitopsSecret, workspace1Name); err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("gitops service did not become ready: %w", err)
	}
	fmt.Println("✓ Gitops service ready")

	// Step 2: Deploy FastAPI to workspace 1
	fmt.Println("\n[2/9] Deploying FastAPI to workspace 1...")
	imageHash, err := computeImageDirHash()
	if err != nil {
		fmt.Printf("Warning: could not compute image dir hash: %v (pipelines.conf will not be patched)\n", err)
		imageHash = ""
	}
	zipPath, checksum, err := createFastAPIZip(imageHash)
	if err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("failed to create ZIP: %w", err)
	}
	defer os.Remove(zipPath)

	if err := uploadAsset(metadata1.GitopsURL, metadata1.GitopsSecret, workspace1Name, zipPath, checksum); err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("failed to upload asset: %w", err)
	}

	deploymentID := "test-fastapi"
	imageName := "fastapi"
	imageTag, err := buildAutomationImage(metadata1.GitopsURL, metadata1.GitopsSecret, workspace1Name, imageName, checksum)
	if err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("failed to build image: %w", err)
	}
	if imageTag != "" {
		fmt.Printf("✓ Image built: %s\n", imageTag)
	}

	if err := deployAutomation(metadata1.GitopsURL, metadata1.GitopsSecret, workspace1Name, deploymentID, checksum); err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("failed to deploy automation: %w", err)
	}
	time.Sleep(5 * time.Second)

	endpointURL1, err := waitForDeployment(metadata1.GitopsURL, metadata1.GitopsSecret, workspace1Name, deploymentID)
	if err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("failed to wait for deployment: %w", err)
	}
	if endpointURL1 == "" {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("deployment ready but no endpoint URL found")
	}
	fmt.Printf("✓ FastAPI deployed and running at: %s\n", endpointURL1)

	// Step 3: Verify endpoint on workspace 1
	fmt.Println("\n[3/9] Verifying endpoint on workspace 1...")
	if err := testEndpoint(endpointURL1, workspace1Name); err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("endpoint test failed: %w", err)
	}
	fmt.Println("✓ Endpoint verified on workspace 1")

	// Step 4: Commit to git
	fmt.Println("\n[4/9] Committing deployment to git...")
	// The daemon runs in a container where workspaces are at /root/.config/bitswan
	// But we need to access from the host, so use the host path
	hostHomeDir := os.Getenv("HOME")
	if hostHomeDir == "" {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("HOME environment variable not set")
	}
	
	// For git operations, use host path (workspace is bind-mounted)
	workspace1RepoPath := filepath.Join(hostHomeDir, ".config", "bitswan", "workspaces", workspace1Name, "workspace")
	gitopsWorktree := filepath.Join(hostHomeDir, ".config", "bitswan", "workspaces", workspace1Name, "gitops")
	
	// Verify the gitops worktree exists
	if _, err := os.Stat(gitopsWorktree); os.IsNotExist(err) {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("gitops worktree does not exist: %s", gitopsWorktree)
	}

	// Get the branch name (workspace name) - this is the worktree branch
	branchName := workspace1Name

	// Ensure git config is set globally (needed for commits)
	gitConfigGlobalCmd := exec.Command("git", "config", "--global", "user.name", "Test User")
	gitConfigGlobalCmd.Run() // Ignore errors

	gitConfigGlobalCmd = exec.Command("git", "config", "--global", "user.email", "test@example.com")
	gitConfigGlobalCmd.Run() // Ignore errors

	// Workspace repo should already be owned by user1000 from initialization

	// Also set it in the repo
	gitConfigCmd := exec.Command("git", "config", "user.name", "Test User")
	gitConfigCmd.Dir = workspace1RepoPath
	gitConfigCmd.Run() // Ignore errors

	gitConfigCmd = exec.Command("git", "config", "user.email", "test@example.com")
	gitConfigCmd.Dir = workspace1RepoPath
	gitConfigCmd.Run() // Ignore errors

	// Commit the deployment from the gitops worktree
	// The gitops worktree contains the deployment files
	// Use docker exec to run git commands in the GitOps container where the worktree is mounted at /gitops/gitops
	gitopsContainerName := workspace1Name + "-site-bitswan-gitops-1"
	
	// Ensure ownership is correct in the container (should already be user1000 from initialization)
	chownCmd := exec.Command("docker", "exec", gitopsContainerName, "chown", "-R", "user1000:user1000", "/gitops/gitops")
	chownCmd.Run() // Ignore errors, might already be correct
	
	gitAddCmd := exec.Command("docker", "exec", "-u", "user1000", gitopsContainerName, "git", "-C", "/gitops/gitops", "add", "-A")
	if output, err := gitAddCmd.CombinedOutput(); err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("failed to add files to git: %w (output: %s)", err, string(output))
	}

	gitCommitCmd := exec.Command("docker", "exec", "-u", "user1000", gitopsContainerName, "git", "-C", "/gitops/gitops", "commit", "-m", "Deploy FastAPI for pull-and-deploy test")
	gitCommitCmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test User", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=Test User", "GIT_COMMITTER_EMAIL=test@example.com")
	if err := gitCommitCmd.Run(); err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("failed to commit deployment: %w", err)
	}
	fmt.Println("✓ Deployment committed")

	// Step 5: Initialize workspace 2 with workspace 1's git repo as remote
	fmt.Println("\n[5/9] Initializing workspace 2 with workspace 1's git repo as remote...")
	// The daemon has /host/ mounted and also has /root/.config/bitswan mounted
	// Use container path for cloning (since workspace is mounted there), but we'll update the remote
	// to /host/ path after cloning so GitOps containers can fetch from it
	containerRepoPath := filepath.Join("/root", ".config", "bitswan", "workspaces", workspace1Name, "workspace")
	initArgs2 := []string{
		"workspace", "init",
		"--local",
		"--no-ide",
		"--no-oauth",
		"--remote", containerRepoPath,
		"--branch", branchName,
	}
	if gitopsImage != "" {
		initArgs2 = append(initArgs2, "--gitops-image", gitopsImage)
	}
	if editorImage != "" {
		initArgs2 = append(initArgs2, "--editor-image", editorImage)
	}
	initArgs2 = append(initArgs2, workspace2Name)

	if err := client.WorkspaceInit(initArgs2); err != nil {
		cleanupWorkspace(workspace1Name)
		return fmt.Errorf("failed to initialize workspace 2: %w", err)
	}
	fmt.Println("✓ Workspace 2 initialized with remote configured")

	// Get workspace 2 metadata
	metadata2, err := config.GetWorkspaceMetadata(workspace2Name)
	if err != nil {
		cleanupWorkspace(workspace1Name)
		cleanupWorkspace(workspace2Name)
		return fmt.Errorf("failed to get workspace 2 metadata: %w", err)
	}

	// Debug: Check docker-compose.yml and git remote
	hostHomeDir = os.Getenv("HOME")
	if hostHomeDir == "" {
		cleanupWorkspace(workspace1Name)
		cleanupWorkspace(workspace2Name)
		return fmt.Errorf("HOME environment variable not set")
	}
	
	workspace2DeploymentPath := filepath.Join(hostHomeDir, ".config", "bitswan", "workspaces", workspace2Name, "deployment")
	dockerComposePath := filepath.Join(workspace2DeploymentPath, "docker-compose.yml")
	if composeContent, err := os.ReadFile(dockerComposePath); err == nil {
		fmt.Printf("\n[DEBUG] docker-compose.yml volumes section:\n")
		lines := strings.Split(string(composeContent), "\n")
		inVolumes := false
		for i, line := range lines {
			if strings.Contains(line, "volumes:") {
				inVolumes = true
			}
			if inVolumes {
				if strings.Contains(line, "remote-workspaces") || strings.Contains(line, "- /") || strings.HasPrefix(strings.TrimSpace(line), "-") {
					fmt.Printf("  %s\n", line)
				}
				// Stop after volumes section (empty line followed by non-indented line)
				if strings.TrimSpace(line) == "" && i+1 < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i+1]), "-") && !strings.Contains(lines[i+1], ":") {
					break
				}
			}
		}
	} else {
		fmt.Printf("Warning: Could not read docker-compose.yml: %v\n", err)
	}
	
	workspace2GitopsPath := filepath.Join(hostHomeDir, ".config", "bitswan", "workspaces", workspace2Name, "gitops")
	gitRemoteCmd := exec.Command("git", "remote", "get-url", "origin")
	gitRemoteCmd.Dir = workspace2GitopsPath
	if remoteOutput, err := gitRemoteCmd.Output(); err == nil {
		fmt.Printf("[DEBUG] Git remote URL in gitops worktree (host): %s\n", strings.TrimSpace(string(remoteOutput)))
	} else {
		fmt.Printf("Warning: Could not get git remote URL from host: %v\n", err)
	}
	
	// Also check inside the GitOps container
	containerName := workspace2Name + "-site-bitswan-gitops-1"
	gitRemoteContainerCmd := exec.Command("docker", "exec", containerName, "git", "-C", "/gitops/gitops", "remote", "get-url", "origin")
	if remoteContainerOutput, err := gitRemoteContainerCmd.Output(); err == nil {
		remoteURL := strings.TrimSpace(string(remoteContainerOutput))
		fmt.Printf("[DEBUG] Git remote URL in gitops worktree (container): %s\n", remoteURL)
		// Test if we can access this remote URL directly
		if strings.HasPrefix(remoteURL, "file://") {
			path := strings.TrimPrefix(remoteURL, "file://")
			testRemoteCmd := exec.Command("docker", "exec", containerName, "test", "-d", path)
			if err := testRemoteCmd.Run(); err == nil {
				fmt.Printf("[DEBUG] Remote path exists: %s\n", path)
				testGitCmd := exec.Command("docker", "exec", containerName, "git", "-C", path, "rev-parse", "--git-dir")
				if gitDirOutput, err := testGitCmd.Output(); err == nil {
					fmt.Printf("[DEBUG] Remote path is a valid git repo, git-dir: %s\n", strings.TrimSpace(string(gitDirOutput)))
				} else {
					fmt.Printf("[DEBUG] WARNING: Remote path is NOT a valid git repo: %v\n", err)
				}
			} else {
				fmt.Printf("[DEBUG] WARNING: Remote path does NOT exist: %s\n", path)
			}
		}
	} else {
		fmt.Printf("Warning: Could not get git remote URL from container: %v\n", err)
	}
	
	// Check if the mount point exists in the container
	checkMountCmd := exec.Command("docker", "exec", containerName, "test", "-d", "/remote-repos/"+workspace1Name)
	if err := checkMountCmd.Run(); err == nil {
		fmt.Printf("[DEBUG] Mount point exists in container: /remote-repos/%s\n", workspace1Name)
		// Check if it's a valid git repo
		checkGitRepoCmd := exec.Command("docker", "exec", containerName, "test", "-d", "/remote-repos/"+workspace1Name+"/.git")
		if err := checkGitRepoCmd.Run(); err == nil {
			fmt.Printf("[DEBUG] Mount point is a valid git repository\n")
		} else {
			fmt.Printf("[DEBUG] WARNING: Mount point is NOT a valid git repository\n")
		}
	} else {
		fmt.Printf("[DEBUG] WARNING: Mount point does NOT exist in container: /remote-repos/%s\n", workspace1Name)
	}

	// Wait for gitops service to be ready
	fmt.Println("\n[5.5/9] Waiting for gitops service 2 to be ready...")
	if err := waitForGitopsReady(metadata2.GitopsURL, metadata2.GitopsSecret, workspace2Name); err != nil {
		cleanupWorkspace(workspace1Name)
		cleanupWorkspace(workspace2Name)
		return fmt.Errorf("gitops service 2 did not become ready: %w", err)
	}
	fmt.Println("✓ Gitops service 2 ready")

	// Debug: Test fetch manually in container before pull-and-deploy
	fmt.Println("\n[5.6/9] Testing git fetch manually in container...")
	containerName = workspace2Name + "-site-bitswan-gitops-1"
	
	// First, check what the remote URL actually is
	remoteURLCmd := exec.Command("docker", "exec", containerName, "git", "-C", "/gitops/gitops", "config", "--get", "remote.origin.url")
	if remoteURLOutput, err := remoteURLCmd.Output(); err == nil {
		remoteURL := strings.TrimSpace(string(remoteURLOutput))
		fmt.Printf("[DEBUG] Remote URL in container: %s\n", remoteURL)
		// Test if the remote path exists and is accessible
		testPathCmd := exec.Command("docker", "exec", containerName, "test", "-d", remoteURL)
		if err := testPathCmd.Run(); err == nil {
			fmt.Printf("[DEBUG] Remote path exists: %s\n", remoteURL)
			// Test if it's a git repo
			testGitCmd := exec.Command("docker", "exec", containerName, "git", "-C", remoteURL, "rev-parse", "--git-dir")
			if gitDirOutput, err := testGitCmd.Output(); err == nil {
				fmt.Printf("[DEBUG] Remote path is a valid git repo, git-dir: %s\n", strings.TrimSpace(string(gitDirOutput)))
			} else {
				fmt.Printf("[DEBUG] WARNING: Remote path is NOT a valid git repo: %v\n", err)
			}
		} else {
			fmt.Printf("[DEBUG] WARNING: Remote path does NOT exist: %s\n", remoteURL)
		}
	} else {
		fmt.Printf("[DEBUG] WARNING: Could not get remote URL: %v\n", err)
	}
	
	testFetchCmd := exec.Command("docker", "exec", containerName, "git", "-C", "/gitops/gitops", "fetch", "origin", "--dry-run", "-v")
	if fetchOutput, err := testFetchCmd.CombinedOutput(); err == nil {
		fmt.Printf("[DEBUG] Git fetch dry-run succeeded: %s\n", string(fetchOutput))
	} else {
		fmt.Printf("[DEBUG] Git fetch dry-run failed: %v\nOutput: %s\n", err, string(fetchOutput))
	}
	
	// Also check if the branch exists on the remote
	fmt.Printf("[DEBUG] Checking if branch %s exists on remote...\n", branchName)
	checkBranchCmd := exec.Command("docker", "exec", containerName, "git", "-C", "/gitops/gitops", "ls-remote", "--heads", "origin", branchName)
	if branchOutput, err := checkBranchCmd.CombinedOutput(); err == nil {
		fmt.Printf("[DEBUG] Branch check output: %s\n", string(branchOutput))
	} else {
		fmt.Printf("[DEBUG] Branch check failed: %v\nOutput: %s\n", err, string(branchOutput))
	}

	// Step 6: Use pull-and-deploy on workspace 2
	fmt.Println("\n[6/9] Running pull-and-deploy on workspace 2...")
	if err := client.PullAndDeploy(workspace2Name, branchName); err != nil {
		cleanupWorkspace(workspace1Name)
		cleanupWorkspace(workspace2Name)
		return fmt.Errorf("failed to pull-and-deploy: %w", err)
	}
	fmt.Println("✓ Pull-and-deploy completed")

	// Step 7: Wait for deployment on workspace 2
	fmt.Println("\n[7/9] Waiting for deployment on workspace 2...")
	time.Sleep(10 * time.Second) // Give it time to start building/deploying
	
	endpointURL2, err := waitForDeployment(metadata2.GitopsURL, metadata2.GitopsSecret, workspace2Name, deploymentID)
	if err != nil {
		cleanupWorkspace(workspace1Name)
		cleanupWorkspace(workspace2Name)
		return fmt.Errorf("failed to wait for deployment on workspace 2: %w", err)
	}
	if endpointURL2 == "" {
		cleanupWorkspace(workspace1Name)
		cleanupWorkspace(workspace2Name)
		return fmt.Errorf("deployment ready but no endpoint URL found on workspace 2")
	}
	fmt.Printf("✓ Deployment ready on workspace 2 at: %s\n", endpointURL2)

	// Step 8: Test endpoint on workspace 2
	fmt.Println("\n[8/9] Testing endpoint on workspace 2...")
	if err := testEndpoint(endpointURL2, workspace2Name); err != nil {
		cleanupWorkspace(workspace1Name)
		cleanupWorkspace(workspace2Name)
		return fmt.Errorf("endpoint test failed on workspace 2: %w", err)
	}
	fmt.Println("✓ Endpoint test passed on workspace 2")

	// Step 9: Cleanup
	fmt.Println("\n[9/9] Cleaning up...")
	if err := removeAutomation(metadata1.GitopsURL, metadata1.GitopsSecret, workspace1Name, deploymentID); err != nil {
		fmt.Printf("Warning: Failed to remove automation from workspace 1: %v\n", err)
	}
	if err := removeAutomation(metadata2.GitopsURL, metadata2.GitopsSecret, workspace2Name, deploymentID); err != nil {
		fmt.Printf("Warning: Failed to remove automation from workspace 2: %v\n", err)
	}
	if err := cleanupWorkspace(workspace1Name); err != nil {
		fmt.Printf("Warning: Failed to cleanup workspace 1: %v\n", err)
	}
	if err := cleanupWorkspace(workspace2Name); err != nil {
		return fmt.Errorf("failed to cleanup workspace 2: %w", err)
	}
	fmt.Println("✓ Cleanup completed")

	fmt.Println("\n=== Test Suite: SUCCESS ===")
	return nil
}

