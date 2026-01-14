package test

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/bitswan-space/bitswan-workspaces/internal/httpReq"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var noRemove bool
	var gitopsImage string
	var editorImage string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Test workspace initialization and FastAPI deployment",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestInit(noRemove, gitopsImage, editorImage)
		},
	}

	cmd.Flags().BoolVar(&noRemove, "no-remove", false, "Leave workspace and deployment running (skip cleanup)")
	cmd.Flags().StringVar(&gitopsImage, "gitops-image", "", "Custom GitOps image to use (default: production image)")
	cmd.Flags().StringVar(&editorImage, "editor-image", "", "Custom editor image to use (default: production image)")

	return cmd
}

func runTestInit(noRemove bool, gitopsImage, editorImage string) error {
	fmt.Println("=== BitSwan Test Suite: Init ===")
	fmt.Println()

	// Ensure we're in a valid directory (the daemon will handle its own working directory)
	// We just need to make sure we're not in a deleted directory
	if wd, err := os.Getwd(); err != nil {
		// If we can't get the current directory, try to change to a known good location
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			homeDir = "/tmp"
		}
		if err := os.Chdir(homeDir); err != nil {
			return fmt.Errorf("failed to change to directory: %w", err)
		}
	} else {
		// Verify the directory still exists
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

	// Generate unique workspace name
	workspaceName := fmt.Sprintf("test-workspace-%d", time.Now().Unix())
	fmt.Printf("Test workspace name: %s\n", workspaceName)

	// Step 1: Initialize workspace
	fmt.Println("\n[1/8] Initializing workspace...")
	client, err := daemon.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create daemon client: %w", err)
	}

	// Use local flags for workspace init (no editor, no oauth for faster initialization)
	initArgs := []string{
		"workspace", "init",
		"--local",
		"--no-ide",
		"--no-oauth",
	}
	if gitopsImage != "" {
		initArgs = append(initArgs, "--gitops-image", gitopsImage)
	}
	if editorImage != "" {
		initArgs = append(initArgs, "--editor-image", editorImage)
	}
	initArgs = append(initArgs, workspaceName)

	if err := client.WorkspaceInit(initArgs); err != nil {
		return fmt.Errorf("failed to initialize workspace: %w", err)
	}
	fmt.Println("✓ Workspace initialized")

	// Get workspace metadata
	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	// Wait for gitops service to be ready
	fmt.Println("\n[1.5/7] Waiting for gitops service to be ready...")
	if err := waitForGitopsReady(metadata.GitopsURL, metadata.GitopsSecret, workspaceName); err != nil {
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("gitops service did not become ready: %w", err)
	}
	fmt.Println("✓ Gitops service ready")

	// Step 2: Create ZIP from FastAPI example and calculate checksum
	fmt.Println("\n[2/8] Creating ZIP from FastAPI example...")
	zipPath, checksum, err := createFastAPIZip()
	if err != nil {
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("failed to create ZIP: %w", err)
	}
	defer os.Remove(zipPath)
	fmt.Printf("✓ ZIP created: %s (checksum: %s)\n", zipPath, checksum)

	// Step 3: Upload asset
	fmt.Println("\n[3/8] Uploading asset to gitops...")
	if err := uploadAsset(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, zipPath, checksum); err != nil {
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("failed to upload asset: %w", err)
	}
	fmt.Println("✓ Asset uploaded")

	// Step 3.5: Build image if needed
	fmt.Println("\n[3.5/8] Building automation image...")
	deploymentID := "test-fastapi"
	// Extract image name from pipelines.conf - it expects "fastapi" not "test-fastapi"
	imageName := "fastapi"
	imageTag, err := buildAutomationImage(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, imageName, checksum)
	if err != nil {
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("failed to build image: %w", err)
	}
	if imageTag != "" {
		fmt.Printf("✓ Image built: %s\n", imageTag)
	} else {
		fmt.Println("✓ Image already exists or not needed")
	}

	// Step 4: Deploy automation
	fmt.Println("\n[4/8] Deploying automation...")
	if err := deployAutomation(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, deploymentID, checksum); err != nil {
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("failed to deploy automation: %w", err)
	}
	fmt.Println("✓ Automation deployed")
	// Give deployment a moment to start
	time.Sleep(5 * time.Second)

	// Step 5: Wait for deployment and test endpoint
	fmt.Println("\n[5/8] Waiting for deployment to be ready...")
	endpointURL, err := waitForDeployment(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, deploymentID)
	if err != nil {
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("failed to wait for deployment: %w", err)
	}
	if endpointURL == "" {
		cleanupWorkspace(workspaceName)
		return fmt.Errorf("deployment ready but no endpoint URL found")
	}
	fmt.Printf("✓ Deployment ready at: %s\n", endpointURL)

	fmt.Println("\n[6/8] Testing endpoint...")
	if err := testEndpoint(endpointURL, workspaceName); err != nil {
		if !noRemove {
			cleanupWorkspace(workspaceName)
		}
		return fmt.Errorf("endpoint test failed: %w", err)
	}
	fmt.Println("✓ Endpoint test passed")

	if noRemove {
		fmt.Println("\n[7/8] Skipping cleanup (--no-remove flag set)...")
		fmt.Printf("Workspace '%s' is still running\n", workspaceName)
		fmt.Printf("Endpoint: %s\n", endpointURL)
		fmt.Println("\n=== Test Suite: SUCCESS (workspace left running) ===")
		return nil
	}

	// Step 6: Remove deployment
	fmt.Println("\n[7/8] Cleaning up...")
	if err := removeAutomation(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, deploymentID); err != nil {
		fmt.Printf("Warning: Failed to remove automation: %v\n", err)
	} else {
		fmt.Println("✓ Automation removed")
	}

	// Step 7: Remove workspace
	if err := cleanupWorkspace(workspaceName); err != nil {
		return fmt.Errorf("failed to cleanup workspace: %w", err)
	}
	fmt.Println("✓ Workspace removed")

	fmt.Println("\n=== Test Suite: SUCCESS ===")
	return nil
}

func createFastAPIZip() (string, string, error) {
	// Find the FastAPI example directory in bitswan-src
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return "", "", fmt.Errorf("HOME environment variable not set")
	}
	
	fastAPIDir := filepath.Join(homeDir, ".config", "bitswan", "bitswan-src", "examples", "FastAPI")
	
	// Check if directory exists
	if _, err := os.Stat(fastAPIDir); os.IsNotExist(err) {
		return "", "", fmt.Errorf("FastAPI example directory not found at %s. Ensure workspace init has created bitswan-src", fastAPIDir)
	}

	// First, calculate the git tree hash of the directory
	checksum, err := calculateGitTreeHash(fastAPIDir)
	if err != nil {
		return "", "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	// Create temporary ZIP file
	tmpFile, err := os.CreateTemp("", "fastapi-test-*.zip")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp file: %w", err)
	}
	zipPath := tmpFile.Name()
	tmpFile.Close()

	// Create ZIP file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to create ZIP file: %w", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Walk directory and add files to ZIP
	err = filepath.Walk(fastAPIDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip .git and other hidden files
		if strings.HasPrefix(info.Name(), ".") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Calculate relative path
		relPath, err := filepath.Rel(fastAPIDir, path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Open file
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		// Create file in ZIP
		zipEntry, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		// Copy file content
		_, err = io.Copy(zipEntry, file)
		return err
	})

	if err != nil {
		os.Remove(zipPath)
		return "", "", fmt.Errorf("failed to create ZIP: %w", err)
	}

	return zipPath, checksum, nil
}

// calculateGitTreeHash calculates the git tree hash of a directory
// This implements git's tree object format
func calculateGitTreeHash(dirPath string) (string, error) {
	// Try to use git command if available (most accurate)
	if gitPath, err := exec.LookPath("git"); err == nil {
		cmd := exec.Command(gitPath, "hash-object", "-t", "tree", "--stdin")
		cmd.Dir = dirPath
		
		// Create a temporary git index
		tmpDir, err := os.MkdirTemp("", "git-tree-hash-*")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(tmpDir)
		
		// Copy directory to temp location and use git
		// Actually, let's use a simpler approach: use git hash-object on the directory
		// But git hash-object doesn't work on directories directly
		// So we need to implement it ourselves or use git write-tree
		
		// For now, let's implement a basic version
	}
	
	// Implement git tree hash calculation
	return calculateGitTreeHashRecursive(dirPath)
}

func calculateGitTreeHashRecursive(dirPath string) (string, error) {
	type entry struct {
		mode string
		name string
		hash string
		isDir bool
	}
	
	var entries []entry
	
	// Read directory
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return "", err
	}
	
	// Process each file/directory
	for _, file := range files {
		// Skip .git and hidden files
		if strings.HasPrefix(file.Name(), ".") {
			continue
		}
		
		filePath := filepath.Join(dirPath, file.Name())
		
		if file.IsDir() {
			// Recursively calculate tree hash for subdirectory
			subHash, err := calculateGitTreeHashRecursive(filePath)
			if err != nil {
				return "", err
			}
			entries = append(entries, entry{
				mode: "040000",
				name: file.Name(),
				hash: subHash,
				isDir: true,
			})
		} else {
			// Calculate blob hash for file
			blobHash, err := calculateGitBlobHash(filePath)
			if err != nil {
				return "", err
			}
			
			// Determine file mode (executable or regular)
			info, err := os.Stat(filePath)
			if err != nil {
				return "", err
			}
			mode := "100644" // regular file
			if info.Mode().Perm()&0111 != 0 {
				mode = "100755" // executable
			}
			
			entries = append(entries, entry{
				mode: mode,
				name: file.Name(),
				hash: blobHash,
				isDir: false,
			})
		}
	}
	
	// Sort entries: directories first, then alphabetically
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].isDir != entries[j].isDir {
			return entries[i].isDir // directories first
		}
		return entries[i].name < entries[j].name
	})
	
	// Build tree object: "tree <size>\0<entries>"
	var treeContent []byte
	for _, e := range entries {
		// Each entry: "<mode> <name>\0<20-byte-sha1>"
		hashBytes, err := hex.DecodeString(e.hash)
		if err != nil {
			return "", fmt.Errorf("invalid hash: %w", err)
		}
		
		entryStr := fmt.Sprintf("%s %s\000", e.mode, e.name)
		treeContent = append(treeContent, []byte(entryStr)...)
		treeContent = append(treeContent, hashBytes...)
	}
	
	// Create tree header: "tree <size>\0"
	treeHeader := fmt.Sprintf("tree %d\000", len(treeContent))
	treeObject := append([]byte(treeHeader), treeContent...)
	
	// Calculate SHA1 hash
	hasher := sha1.New()
	hasher.Write(treeObject)
	hash := hex.EncodeToString(hasher.Sum(nil))
	
	return hash, nil
}

func calculateGitBlobHash(filePath string) (string, error) {
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	
	// Create blob: "blob <size>\0<content>"
	blobHeader := fmt.Sprintf("blob %d\000", len(content))
	blob := append([]byte(blobHeader), content...)
	
	// Calculate SHA1 hash
	hasher := sha1.New()
	hasher.Write(blob)
	hash := hex.EncodeToString(hasher.Sum(nil))
	
	return hash, nil
}

func waitForGitopsReady(gitopsURL, secret, workspaceName string) error {
	// Increase timeout for CI environments where services may take longer to start
	maxAttempts := 120 // 4 minutes total (120 * 2 seconds)
	attempt := 0

	// First, wait for container to be running
	// Container name format: {workspaceName}-site-bitswan-gitops-1
	containerName := fmt.Sprintf("%s-site-bitswan-gitops-1", workspaceName)
	fmt.Printf("Waiting for gitops container '%s' to be running...\n", containerName)
	for i := 0; i < 30; i++ { // Wait up to 1 minute for container to start
		cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Status}}")
		output, err := cmd.Output()
		if err == nil && len(output) > 0 && strings.Contains(string(output), "Up") {
			fmt.Printf("Container '%s' is running\n", containerName)
			break
		}
		if i == 29 {
			fmt.Printf("Warning: Container '%s' did not start within 1 minute, continuing anyway...\n", containerName)
		}
		time.Sleep(2 * time.Second)
	}

	for attempt < maxAttempts {
		// Try to get automations list as a health check
		url := fmt.Sprintf("%s/automations", gitopsURL)
		url = automations.TransformURLForDaemon(url, workspaceName)
		req, err := httpReq.NewRequest("GET", url, nil)
		if err != nil {
			time.Sleep(2 * time.Second)
			attempt++
			continue
		}

		req.Header.Set("Authorization", "Bearer "+secret)

		resp, err := httpReq.ExecuteRequestWithLocalhostResolution(req)
		if err != nil {
			// In CI, localhost resolution might fail, so also check container health
			// After container has been running for a while, try to connect via Docker network
			if attempt > 15 { // After 30 seconds, start checking container health and try direct connection
				// Check if container is still running
				checkCmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Status}}")
				statusOutput, statusErr := checkCmd.Output()
				if statusErr == nil && len(statusOutput) > 0 && strings.Contains(string(statusOutput), "Up") {
					// Container is running, try connecting directly via Docker network
					// Use docker exec to curl from within the network
					if attempt > 30 { // After 60 seconds, try direct connection
						// Try to curl from within the container's network
						curlCmd := exec.Command("docker", "exec", containerName, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
							"-H", fmt.Sprintf("Authorization: Bearer %s", secret),
							"http://localhost:8079/automations")
						if curlOutput, curlErr := curlCmd.Output(); curlErr == nil {
							statusCodeStr := strings.TrimSpace(string(curlOutput))
							if statusCodeStr == "200" || statusCodeStr == "404" {
								fmt.Printf("Service is responding directly on port 8079 (status: %s), but Caddy is returning 502\n", statusCodeStr)
								fmt.Printf("This suggests a Caddy routing issue. Checking Caddy logs...\n")
								// Check Caddy logs
								caddyLogsCmd := exec.Command("docker", "logs", "caddy", "--tail", "20")
								if caddyLogs, caddyErr := caddyLogsCmd.Output(); caddyErr == nil {
									fmt.Printf("Recent Caddy logs:\n%s\n", string(caddyLogs))
								}
								// If service is responding directly, assume it's ready despite Caddy issue
								if attempt > 60 {
									fmt.Printf("Service is responding directly after 2+ minutes, assuming ready despite Caddy 502\n")
									return nil
								}
							}
						}
					}
				} else {
					// Container not running - check logs
					if attempt%20 == 0 {
						fmt.Printf("Container may not be running. Checking container status and logs...\n")
						logsCmd := exec.Command("docker", "logs", containerName, "--tail", "30")
						if logsOutput, logsErr := logsCmd.Output(); logsErr == nil {
							fmt.Printf("Container logs (last 30 lines):\n%s\n", string(logsOutput))
						}
					}
				}
			}
			time.Sleep(2 * time.Second)
			attempt++
			continue
		}
		resp.Body.Close()

		// If we get any response (even 200 or 404), the service is up
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
			return nil
		}

		// 502 Bad Gateway means the service is NOT ready - don't treat it as ready
		// Only treat 200/404 as ready, or 401 (auth issue, but service is up)
		if resp.StatusCode == http.StatusBadGateway {
			if attempt%10 == 0 {
				fmt.Printf("Service returned 502 Bad Gateway (attempt %d/%d) - service not ready yet\n", attempt+1, maxAttempts)
				// After many attempts, check if service is actually running but Caddy can't reach it
				if attempt > 60 {
					// Try direct connection to container
					curlCmd := exec.Command("docker", "exec", containerName, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
						"-H", fmt.Sprintf("Authorization: Bearer %s", secret),
						"http://localhost:8079/automations")
					if curlOutput, curlErr := curlCmd.Output(); curlErr == nil {
						statusCodeStr := strings.TrimSpace(string(curlOutput))
						fmt.Printf("Direct container check returned status: %s\n", statusCodeStr)
						if statusCodeStr == "200" || statusCodeStr == "404" {
							fmt.Printf("Service is responding directly but Caddy returns 502 - likely Caddy routing issue\n")
							// Check Caddy configuration
							caddyConfigCmd := exec.Command("curl", "-s", "http://localhost:2019/config/apps/http/servers/srv0/routes")
							if caddyConfig, caddyErr := caddyConfigCmd.Output(); caddyErr == nil {
								fmt.Printf("Caddy routes config:\n%s\n", string(caddyConfig))
							}
						}
					}
				}
			}
			time.Sleep(2 * time.Second)
			attempt++
			continue
		}

		// For other status codes (like 401), log but continue waiting
		// Don't assume service is ready just because we got a response
		if attempt%10 == 0 {
			fmt.Printf("Service returned status %d (attempt %d/%d) - waiting for 200/404\n", resp.StatusCode, attempt+1, maxAttempts)
		}

		time.Sleep(2 * time.Second)
		attempt++
	}

	return fmt.Errorf("gitops service did not become ready within timeout")
}

func uploadAsset(gitopsURL, secret, workspaceName, zipPath, checksum string) error {
	// Open ZIP file
	file, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create multipart form
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Add file
	part, err := writer.CreateFormFile("file", "deployment.zip")
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, file); err != nil {
		return err
	}

	// Add checksum
	if err := writer.WriteField("checksum", checksum); err != nil {
		return err
	}

	writer.Close()

	// Create request
	url := fmt.Sprintf("%s/automations/assets/upload", gitopsURL)
	url = automations.TransformURLForDaemon(url, workspaceName)
	req, err := httpReq.NewRequest("POST", url, &body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+secret)

	// Send request with localhost resolution
	resp, err := httpReq.ExecuteRequestWithLocalhostResolution(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func buildAutomationImage(gitopsURL, secret, workspaceName, imageName, checksum string) (string, error) {
	// Find the FastAPI example directory in bitswan-src
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return "", fmt.Errorf("HOME environment variable not set")
	}
	
	fastAPIDir := filepath.Join(homeDir, ".config", "bitswan", "bitswan-src", "examples", "FastAPI")
	
	// Check if directory exists
	if _, err := os.Stat(fastAPIDir); os.IsNotExist(err) {
		return "", fmt.Errorf("FastAPI example directory not found at %s. Ensure workspace init has created bitswan-src", fastAPIDir)
	}

	imageDir := filepath.Join(fastAPIDir, "image")
	if _, err := os.Stat(imageDir); os.IsNotExist(err) {
		// No image directory, skip image building
		return "", nil
	}

	// Calculate checksum for image directory
	imageChecksum, err := calculateGitTreeHash(imageDir)
	if err != nil {
		return "", fmt.Errorf("failed to calculate image checksum: %w", err)
	}

	// Create ZIP for image
	tmpFile, err := os.CreateTemp("", "fastapi-image-*.zip")
	if err != nil {
		return "", err
	}
	imageZipPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(imageZipPath)

	// Create ZIP from image directory
	zipFile, err := os.Create(imageZipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(imageDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, _ := filepath.Rel(imageDir, path)
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		zipEntry, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}
		_, err = io.Copy(zipEntry, file)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("failed to create image ZIP: %w", err)
	}
	zipWriter.Close()
	zipFile.Close()

	// Upload image
	file, err := os.Open(imageZipPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "image.zip")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, file); err != nil {
		return "", err
	}
	if err := writer.WriteField("checksum", imageChecksum); err != nil {
		return "", err
	}
	writer.Close()

	url := fmt.Sprintf("%s/images/%s", gitopsURL, imageName)
	url = automations.TransformURLForDaemon(url, workspaceName)
	req, err := httpReq.NewRequest("POST", url, &body)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpReq.ExecuteRequestWithLocalhostResolution(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("image build failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response to get image tag
	var buildResponse struct {
		Tag string `json:"tag"`
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(bodyBytes, &buildResponse); err == nil && buildResponse.Tag != "" {
		// Wait for image to be ready
		expectedTag := buildResponse.Tag
		if err := waitForImageReady(gitopsURL, secret, workspaceName, expectedTag); err != nil {
			return "", fmt.Errorf("image build did not complete: %w", err)
		}
		return expectedTag, nil
	}

	return "", nil
}

func waitForImageReady(gitopsURL, secret, workspaceName, expectedTag string) error {
	// Increase timeout for CI environments where image builds may take longer
	// 600 attempts * 2 seconds = 20 minutes
	maxAttempts := 600
	attempt := 0

	fmt.Printf("Waiting for image '%s' to be ready (timeout: %d minutes)...\n", expectedTag, maxAttempts*2/60)

	for attempt < maxAttempts {
		// Use /images/ with trailing slash to avoid 307 redirect that loses Authorization header
		url := fmt.Sprintf("%s/images/", gitopsURL)
		url = automations.TransformURLForDaemon(url, workspaceName)
		req, err := httpReq.NewRequest("GET", url, nil)
		if err != nil {
			if attempt%30 == 0 {
				fmt.Printf("  Error creating request (attempt %d/%d): %v\n", attempt+1, maxAttempts, err)
			}
			time.Sleep(2 * time.Second)
			attempt++
			continue
		}

		req.Header.Set("Authorization", "Bearer "+secret)

		resp, err := httpReq.ExecuteRequestWithLocalhostResolution(req)
		if err != nil {
			if attempt%30 == 0 {
				fmt.Printf("  Error executing request (attempt %d/%d): %v\n", attempt+1, maxAttempts, err)
			}
			time.Sleep(2 * time.Second)
			attempt++
			continue
		}

		if resp.StatusCode == http.StatusOK {
			bodyBytes, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				time.Sleep(2 * time.Second)
				attempt++
				continue
			}

			var images []struct {
				Tag         string `json:"tag"`
				BuildStatus string `json:"build_status"`
			}
			if err := json.Unmarshal(bodyBytes, &images); err == nil {
				found := false
				for _, img := range images {
					if img.Tag == expectedTag {
						found = true
						if img.BuildStatus == "ready" || img.BuildStatus == "" {
							fmt.Printf("  Image '%s' is ready!\n", expectedTag)
							return nil
						}
						if img.BuildStatus == "failed" {
							return fmt.Errorf("image build failed")
						}
						// Still building
						if attempt%10 == 0 {
							fmt.Printf("  Waiting for image build... (attempt %d/%d, status: %s)\n", attempt+1, maxAttempts, img.BuildStatus)
						}
					}
				}
				if !found && attempt%30 == 0 {
					fmt.Printf("  Image '%s' not found in images list yet (attempt %d/%d)\n", expectedTag, attempt+1, maxAttempts)
				}
			}
		} else {
			// Read response body for error details
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if attempt%30 == 0 || resp.StatusCode == 401 {
				fmt.Printf("  Unexpected status code %d (attempt %d/%d)\n", resp.StatusCode, attempt+1, maxAttempts)
				if len(bodyBytes) > 0 {
					fmt.Printf("  Response body: %s\n", string(bodyBytes))
				}
				if resp.StatusCode == 401 {
					fmt.Printf("  Authentication failed - checking gitops container logs...\n")
					// Try to get gitops container logs
					workspaceNameForLogs := workspaceName
					logsCmd := exec.Command("docker", "logs", "--tail", "50", fmt.Sprintf("%s-site-bitswan-gitops-1", workspaceNameForLogs))
					if logsOutput, err := logsCmd.Output(); err == nil {
						fmt.Printf("  Gitops container logs (last 50 lines):\n%s\n", string(logsOutput))
					}
					// Also check the secret being used
					secretPreview := secret
					if len(secret) > 10 {
						secretPreview = secret[:10]
					}
					fmt.Printf("  Using secret from metadata (first 10 chars): %s...\n", secretPreview)
				}
			}
		}

		time.Sleep(2 * time.Second)
		attempt++
	}

	return fmt.Errorf("image did not become ready within timeout")
}

func deployAutomation(gitopsURL, secret, workspaceName, deploymentID, checksum string) error {
	// Create form data
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	writer.WriteField("checksum", checksum)
	writer.WriteField("stage", "dev")
	writer.WriteField("relative_path", "")
	writer.Close()

	// Create request
	url := fmt.Sprintf("%s/automations/%s/deploy", gitopsURL, deploymentID)
	url = automations.TransformURLForDaemon(url, workspaceName)
	req, err := httpReq.NewRequest("POST", url, &body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+secret)

	// Send request with localhost resolution
	resp, err := httpReq.ExecuteRequestWithLocalhostResolution(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		// Try to parse error details
		var errorResp struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(bodyBytes, &errorResp) == nil && errorResp.Detail != "" {
			return fmt.Errorf("deploy failed with status %d: %s", resp.StatusCode, errorResp.Detail)
		}
		return fmt.Errorf("deploy failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func waitForDeployment(gitopsURL, secret, workspaceName, deploymentID string) (string, error) {
	// Increase timeout to 10 minutes (300 attempts * 2 seconds) for CI environments
	// where deployments may take longer to become ready
	maxAttempts := 300
	attempt := 0

	fmt.Printf("Waiting for deployment '%s' to be ready (timeout: %d minutes)...\n", deploymentID, maxAttempts*2/60)

	for attempt < maxAttempts {
		// Get automation status
		// Use /automations/ with trailing slash to avoid 307 redirect that loses Authorization header
		reqURL := fmt.Sprintf("%s/automations/", gitopsURL)
		reqURL = automations.TransformURLForDaemon(reqURL, workspaceName)
		
		// Log the request details
		if attempt%5 == 0 || attempt < 3 {
			fmt.Printf("  [Attempt %d/%d] GET %s\n", attempt+1, maxAttempts, reqURL)
		}
		
		req, err := httpReq.NewRequest("GET", reqURL, nil)
		if err != nil {
			if attempt%5 == 0 || attempt < 3 {
				fmt.Printf("  Error creating request: %v\n", err)
			}
			time.Sleep(2 * time.Second)
			attempt++
			continue
		}

		req.Header.Set("Authorization", "Bearer "+secret)

		resp, err := httpReq.ExecuteRequestWithLocalhostResolution(req)
		if err != nil {
			if attempt%5 == 0 || attempt < 3 {
				fmt.Printf("  Error executing request: %v\n", err)
			}
			time.Sleep(2 * time.Second)
			attempt++
			continue
		}

		// Log response status
		if attempt%5 == 0 || attempt < 3 {
			fmt.Printf("  Response: %d %s\n", resp.StatusCode, resp.Status)
		}

		if resp.StatusCode == http.StatusOK {
			bodyBytes, err := io.ReadAll(resp.Body)
			resp.Body.Close()

			if err != nil {
				if attempt%5 == 0 || attempt < 3 {
					fmt.Printf("  Error reading response body: %v\n", err)
				}
				time.Sleep(2 * time.Second)
				attempt++
				continue
			}

			// Log response body for first few attempts or periodically
			if attempt < 3 || attempt%10 == 0 {
				bodyPreview := string(bodyBytes)
				if len(bodyPreview) > 500 {
					bodyPreview = bodyPreview[:500] + "..."
				}
				fmt.Printf("  Response body: %s\n", bodyPreview)
			}

			// Parse JSON response to find our automation
			var automations []struct {
				DeploymentID  string `json:"deployment_id"`
				State         string `json:"state"`
				EndpointName  string `json:"endpoint_name"`
				AutomationURL string `json:"automation_url"`
			}

			if err := json.Unmarshal(bodyBytes, &automations); err == nil {
				// Find our automation
				found := false
				for _, auto := range automations {
					if auto.DeploymentID == deploymentID {
						found = true
						// Log every attempt when we find the automation
						if attempt%5 == 0 {
							fmt.Printf("  Found automation '%s': state=%s, endpoint_name=%s (attempt %d/%d)\n", deploymentID, auto.State, auto.EndpointName, attempt+1, maxAttempts)
						}
						// Check if it's running
						if auto.State == "running" {
							// Use automation_url if available, otherwise construct from endpoint_name
							endpointURL := auto.AutomationURL
							if endpointURL == "" && auto.EndpointName != "" {
								// Construct URL from gitops URL and endpoint name
								// Format: https://{workspace}-gitops.{domain}/{endpoint_name}
								parsedURL, err := url.Parse(gitopsURL)
								if err == nil {
									endpointURL = fmt.Sprintf("%s://%s/%s", parsedURL.Scheme, parsedURL.Host, auto.EndpointName)
								} else {
									if attempt%10 == 0 {
										fmt.Printf("  Failed to parse gitops URL: %v\n", err)
									}
								}
							}
							if endpointURL != "" {
								fmt.Printf("  Deployment ready! URL: %s\n", endpointURL)
								// Give it a moment to fully start
								time.Sleep(3 * time.Second)
								return endpointURL, nil
							} else {
								// If running but no URL available yet, log and continue waiting
								if attempt%5 == 0 {
									fmt.Printf("  Deployment is running but URL not available (attempt %d/%d, state: %s, endpoint_name: %s, automation_url: %s)\n", attempt+1, maxAttempts, auto.State, auto.EndpointName, auto.AutomationURL)
								}
							}
						} else {
							// If automation exists but isn't running yet, continue waiting
							// (it might be building the image)
							// Log progress every 5 attempts (10 seconds)
							if attempt%5 == 0 {
								fmt.Printf("  Waiting for deployment... (attempt %d/%d, state: %s, endpoint_name: %s)\n", attempt+1, maxAttempts, auto.State, auto.EndpointName)
							}
						}
					}
				}
				// If we didn't find the automation at all, log it more frequently
				if !found {
					if attempt%10 == 0 {
						fmt.Printf("  Automation '%s' not found in list (attempt %d/%d, found %d automations)\n", deploymentID, attempt+1, maxAttempts, len(automations))
					}
				}
				} else {
					// Log parse errors more frequently
					if attempt%10 == 0 {
						fmt.Printf("  Failed to parse automations response (attempt %d/%d): %v\n", attempt+1, maxAttempts, err)
						bodyPreview := string(bodyBytes)
						if len(bodyPreview) > 500 {
							bodyPreview = bodyPreview[:500]
						}
						fmt.Printf("  Response body (first 500 chars): %s\n", bodyPreview)
					}
				}
		} else {
			// Log non-200 responses
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if attempt%5 == 0 || attempt < 3 {
				bodyPreview := string(bodyBytes)
				if len(bodyPreview) > 500 {
					bodyPreview = bodyPreview[:500] + "..."
				}
				fmt.Printf("  Unexpected status code %d: %s\n", resp.StatusCode, bodyPreview)
			}
		}

		time.Sleep(2 * time.Second)
		attempt++
	}

	return "", fmt.Errorf("deployment did not become ready within timeout")
}

func testEndpoint(endpointURL, workspaceName string) error {
	// Test the root endpoint
	// Transform URL for daemon if needed
	url := automations.TransformURLForDaemon(endpointURL, workspaceName)
	req, err := httpReq.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := httpReq.ExecuteRequestWithLocalhostResolution(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Check if response contains expected content (FastAPI returns JSON like {"ok": true})
	bodyStr := string(bodyBytes)
	if !strings.Contains(bodyStr, "ok") && !strings.Contains(bodyStr, "Hello") {
		return fmt.Errorf("unexpected response: %s", bodyStr)
	}

	return nil
}

func removeAutomation(gitopsURL, secret, workspaceName, deploymentID string) error {
	url := fmt.Sprintf("%s/automations/%s", gitopsURL, deploymentID)
	url = automations.TransformURLForDaemon(url, workspaceName)
	req, err := httpReq.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpReq.ExecuteRequestWithLocalhostResolution(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func cleanupWorkspace(workspaceName string) error {
	client, err := daemon.NewClient()
	if err != nil {
		return err
	}

	return client.WorkspaceRemove(workspaceName)
}

