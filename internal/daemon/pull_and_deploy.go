package daemon

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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/httpReq"
)

// PullAndDeployResponse represents the response from the pull-and-deploy endpoint
type PullAndDeployResponse struct {
	Status    string   `json:"status"`
	Message   string   `json:"message"`
	ImageTags []string `json:"image_tags"`
}

// ImageResponse represents a single image from the images endpoint
type ImageResponse struct {
	ID       string `json:"id"`
	Tag      string `json:"tag"`
	Created  string `json:"created"`
	Size     int64  `json:"size"`
	Building bool   `json:"building"`
}

// RunPullAndDeploy runs the pull-and-deploy logic
func RunPullAndDeploy(workspaceName, branchName string, writer io.Writer) error {
	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	// Construct the URL for the pull-and-deploy endpoint
	url := fmt.Sprintf("%s/automations/pull-and-deploy/%s", metadata.GitopsURL, branchName)

	// Transform URL for daemon if needed
	url = automations.TransformURLForDaemon(url, workspaceName)

	// Send the request to pull branch and deploy all automations
	resp, err := automations.SendAutomationRequest("POST", url, metadata.GitopsSecret)
	if err != nil {
		return fmt.Errorf("failed to send request to pull branch and deploy automations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		// "Push failed" is not a fatal error - it's just a warning
		if resp.StatusCode == http.StatusInternalServerError && strings.Contains(bodyStr, "Push failed") {
			fmt.Fprintf(writer, "Warning: Push failed (non-fatal), continuing with pull-and-deploy...\n")
			fmt.Fprintf(writer, "Successfully pulled branch '%s' for '%s' (push warning ignored).\n", branchName, workspaceName)

			// Build any missing images, then deploy
			imageTags, err := buildMissingImages(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer)
			if err != nil {
				return fmt.Errorf("failed to build images: %w", err)
			}
			if len(imageTags) > 0 {
				fmt.Fprintln(writer, "\nMonitoring build progress...")
				if err := monitorImageBuilds(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, imageTags, writer); err != nil {
					return fmt.Errorf("error monitoring image builds: %w", err)
				}
				fmt.Fprintln(writer, "\nAll automation images built successfully!")
			}

			fmt.Fprintln(writer, "\nDeploying automations...")
			if err := deployAutomations(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer); err != nil {
				return fmt.Errorf("failed to deploy automations after pull: %w", err)
			}
			fmt.Fprintln(writer, "Automations deployed successfully!")
			return nil
		}
		return fmt.Errorf("failed to pull branch and deploy automations, status code: %d, response: %s", resp.StatusCode, bodyStr)
	}

	// Parse the response body to get image tags
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var response PullAndDeployResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response JSON: %w", err)
	}

	fmt.Fprintf(writer, "Successfully pulled branch '%s' for '%s'.\n", branchName, workspaceName)

	// Combine image tags from gitops response with any we need to build ourselves
	imageTags := response.ImageTags

	// Scan the gitops worktree for images that need building
	missingTags, err := buildMissingImages(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer)
	if err != nil {
		return fmt.Errorf("failed to build images: %w", err)
	}
	imageTags = append(imageTags, missingTags...)

	// Monitor builds if any images are being built
	if len(imageTags) > 0 {
		fmt.Fprintln(writer, "\nBuilding automation images:")
		for _, tag := range imageTags {
			fmt.Fprintf(writer, "   - %s\n", tag)
		}

		fmt.Fprintln(writer, "\nMonitoring build progress...")
		if err := monitorImageBuilds(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, imageTags, writer); err != nil {
			return fmt.Errorf("error monitoring image builds: %w", err)
		}

		fmt.Fprintln(writer, "\nAll automation images built successfully!")
	} else {
		fmt.Fprintln(writer, "\nNo new automation images to build.")
	}

	// Deploy automations
	fmt.Fprintln(writer, "\nDeploying automations...")
	if err := deployAutomations(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer); err != nil {
		return fmt.Errorf("error deploying automations: %w", err)
	}
	fmt.Fprintln(writer, "Automations deployed successfully!")

	return nil
}

// monitorImageBuilds polls the images endpoint until all builds are complete
func monitorImageBuilds(gitopsURL, gitopsSecret, workspaceName string, imageTags []string, writer io.Writer) error {
	buildingImages := make(map[string]bool)
	for _, tag := range imageTags {
		buildingImages[tag] = true
	}

	pollInterval := 2 * time.Second

	for len(buildingImages) > 0 {
		time.Sleep(pollInterval)

		imagesURL := fmt.Sprintf("%s/images/", gitopsURL)
		imagesURL = automations.TransformURLForDaemon(imagesURL, workspaceName)
		resp, err := automations.SendAutomationRequest("GET", imagesURL, gitopsSecret)
		if err != nil {
			return fmt.Errorf("failed to get images: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return fmt.Errorf("failed to read response body: %w", err)
			}

			var images []ImageResponse
			if err := json.Unmarshal(body, &images); err != nil {
				return fmt.Errorf("failed to parse response JSON: %w", err)
			}

			imageStatus := make(map[string]bool)
			for _, img := range images {
				imageStatus[img.Tag] = img.Building
			}

			for tag := range buildingImages {
				if building, exists := imageStatus[tag]; exists && !building {
					fmt.Fprintf(writer, "  [%s] Build completed\n", tag)
					delete(buildingImages, tag)
				}
			}
		} else {
			resp.Body.Close()
			return fmt.Errorf("failed to get images status: HTTP %d", resp.StatusCode)
		}
	}

	return nil
}

// automationConfig represents the relevant fields from automation.toml
type automationConfig struct {
	Deployment struct {
		Image string `toml:"image"`
	} `toml:"deployment"`
}

// imageRef holds parsed image reference info
type imageRef struct {
	Name string // e.g. "mitchell-backend"
	Tag  string // e.g. "internal/mitchell-backend:sha203384..."
	Hash string // e.g. "203384..."
}

// parseImageRef parses an image string like "internal/mitchell-backend:sha203384..." into components
func parseImageRef(image string) (imageRef, bool) {
	if !strings.HasPrefix(image, "internal/") {
		return imageRef{}, false
	}

	colonIdx := strings.LastIndex(image, ":")
	if colonIdx == -1 {
		return imageRef{}, false
	}

	nameWithPrefix := image[:colonIdx]
	name := strings.TrimPrefix(nameWithPrefix, "internal/")
	tag := image[colonIdx+1:]

	if !strings.HasPrefix(tag, "sha") {
		return imageRef{}, false
	}

	hash := strings.TrimPrefix(tag, "sha")

	return imageRef{
		Name: name,
		Tag:  image,
		Hash: hash,
	}, true
}

// buildMissingImages scans the gitops worktree for automations with image references,
// checks which images are not yet built, and uploads them for building.
// If the server rejects a checksum, the image directory and automation.toml references
// are updated to match the server's computed checksum.
func buildMissingImages(gitopsURL, gitopsSecret, workspaceName string, writer io.Writer) ([]string, error) {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return nil, fmt.Errorf("HOME environment variable not set")
	}
	gitopsPath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName, "gitops")

	// Scan for automation.toml files and collect unique image references
	imageRefs := make(map[string]imageRef) // keyed by hash to deduplicate
	entries, err := os.ReadDir(gitopsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read gitops directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		automationTomlPath := filepath.Join(gitopsPath, entry.Name(), "automation.toml")
		data, err := os.ReadFile(automationTomlPath)
		if err != nil {
			continue
		}

		var cfg automationConfig
		if err := toml.Unmarshal(data, &cfg); err != nil {
			continue
		}

		if cfg.Deployment.Image == "" {
			continue
		}

		ref, ok := parseImageRef(cfg.Deployment.Image)
		if !ok {
			continue
		}

		imageRefs[ref.Hash] = ref
	}

	if len(imageRefs) == 0 {
		return nil, nil
	}

	// Check which images already exist on the gitops service
	existingImages, err := getExistingImageTags(gitopsURL, gitopsSecret, workspaceName)
	if err != nil {
		fmt.Fprintf(writer, "Warning: could not check existing images: %v\n", err)
		existingImages = make(map[string]bool)
	}

	var builtTags []string
	for _, ref := range imageRefs {
		if existingImages[ref.Tag] {
			fmt.Fprintf(writer, "   Image %s already exists, skipping.\n", ref.Tag)
			continue
		}

		// Check if the image source directory exists
		imageSrcDir := filepath.Join(gitopsPath, "images", ref.Hash)
		if _, err := os.Stat(imageSrcDir); os.IsNotExist(err) {
			return nil, fmt.Errorf("image source for hash %s was not found (expected at images/%s)", ref.Hash, ref.Hash)
		}

		fmt.Fprintf(writer, "Uploading image %s for building...\n", ref.Name)
		tag, serverChecksum, err := uploadImageForBuild(gitopsURL, gitopsSecret, workspaceName, ref.Name, imageSrcDir, writer)
		if err != nil {
			return nil, fmt.Errorf("failed to build image %s: %w", ref.Name, err)
		}

		// If the server returned a different checksum, update the worktree
		if serverChecksum != "" && serverChecksum != ref.Hash {
			fmt.Fprintf(writer, "\n*** WARNING: Checksum mismatch for image %s! ***\n", ref.Name)
			fmt.Fprintf(writer, "    Directory hash:  %s\n", ref.Hash)
			fmt.Fprintf(writer, "    Server checksum: %s\n", serverChecksum)
			fmt.Fprintf(writer, "    Updating image directory and automation.toml references to match server checksum.\n\n")

			if err := updateWorktreeChecksums(gitopsPath, ref, serverChecksum); err != nil {
				fmt.Fprintf(writer, "Warning: failed to update worktree checksums: %v\n", err)
			}
		}

		if tag != "" {
			builtTags = append(builtTags, tag)
		}
	}

	return builtTags, nil
}

// getExistingImageTags queries the gitops service for all existing images and returns their tags
func getExistingImageTags(gitopsURL, gitopsSecret, workspaceName string) (map[string]bool, error) {
	imagesURL := fmt.Sprintf("%s/images/", gitopsURL)
	imagesURL = automations.TransformURLForDaemon(imagesURL, workspaceName)

	resp, err := automations.SendAutomationRequest("GET", imagesURL, gitopsSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get images: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("images endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var images []ImageResponse
	if err := json.Unmarshal(body, &images); err != nil {
		return nil, fmt.Errorf("failed to parse images response: %w", err)
	}

	tags := make(map[string]bool)
	for _, img := range images {
		if !img.Building {
			tags[img.Tag] = true
		}
	}

	return tags, nil
}

// createImageZip creates a ZIP archive of the image directory in memory
func createImageZip(imageSrcDir string) (*bytes.Buffer, error) {
	var zipBuf bytes.Buffer
	zipWriter := zip.NewWriter(&zipBuf)

	err := filepath.Walk(imageSrcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, _ := filepath.Rel(imageSrcDir, path)
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
		return nil, err
	}
	zipWriter.Close()
	return &zipBuf, nil
}

// doImageUpload performs the actual HTTP upload of an image ZIP with a given checksum.
// Returns (response body, status code, error).
func doImageUpload(gitopsURL, gitopsSecret, workspaceName, imageName string, zipData []byte, checksum string) ([]byte, int, error) {
	var body bytes.Buffer
	formWriter := multipart.NewWriter(&body)
	part, err := formWriter.CreateFormFile("file", "image.zip")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create form file: %w", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(zipData)); err != nil {
		return nil, 0, fmt.Errorf("failed to write ZIP to form: %w", err)
	}
	if err := formWriter.WriteField("checksum", checksum); err != nil {
		return nil, 0, fmt.Errorf("failed to write checksum field: %w", err)
	}
	formWriter.Close()

	uploadURL := fmt.Sprintf("%s/images/%s", gitopsURL, imageName)
	uploadURL = automations.TransformURLForDaemon(uploadURL, workspaceName)

	req, err := httpReq.NewRequest("POST", uploadURL, &body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create upload request: %w", err)
	}
	req.Header.Set("Content-Type", formWriter.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+gitopsSecret)

	var resp *http.Response
	if os.Getenv("BITSWAN_CADDY_HOST") != "" && !strings.Contains(uploadURL, ".localhost") {
		resp, err = http.DefaultClient.Do(req)
	} else {
		resp, err = httpReq.ExecuteRequestWithLocalhostResolution(req)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to upload image: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// checksumMismatchRegex matches "Expected <hex>, got <hex>" in server error messages
var checksumMismatchRegex = regexp.MustCompile(`Expected\s+([0-9a-f]+),\s+got\s+([0-9a-f]+)`)

// uploadImageForBuild creates a ZIP of the image directory and uploads it to the gitops service.
// On checksum mismatch, it retries with the server's checksum and returns it.
// Returns (imageTag, serverChecksum, error) where serverChecksum is non-empty only if it differed.
func uploadImageForBuild(gitopsURL, gitopsSecret, workspaceName, imageName, imageSrcDir string, writer io.Writer) (string, string, error) {
	checksum, err := calculateGitTreeHash(imageSrcDir)
	if err != nil {
		return "", "", fmt.Errorf("failed to calculate image checksum: %w", err)
	}

	zipBuf, err := createImageZip(imageSrcDir)
	if err != nil {
		return "", "", fmt.Errorf("failed to create image ZIP: %w", err)
	}
	zipData := zipBuf.Bytes()

	// First attempt with our computed checksum
	respBody, statusCode, err := doImageUpload(gitopsURL, gitopsSecret, workspaceName, imageName, zipData, checksum)
	if err != nil {
		return "", "", err
	}

	// If checksum mismatch, parse server's checksum and retry
	if statusCode == http.StatusBadRequest {
		respStr := string(respBody)
		if strings.Contains(respStr, "Checksum verification failed") {
			matches := checksumMismatchRegex.FindStringSubmatch(respStr)
			if len(matches) == 3 {
				serverChecksum := matches[2]
				fmt.Fprintf(writer, "   Checksum mismatch (ours: %s, server: %s), retrying with server checksum...\n", checksum, serverChecksum)

				// Retry with the server's checksum
				respBody, statusCode, err = doImageUpload(gitopsURL, gitopsSecret, workspaceName, imageName, zipData, serverChecksum)
				if err != nil {
					return "", "", err
				}
				if statusCode == http.StatusOK {
					tag := parseUploadResponse(respBody, imageName, writer)
					return tag, serverChecksum, nil
				}
				return "", "", fmt.Errorf("image upload failed on retry with status %d: %s", statusCode, string(respBody))
			}
		}
		return "", "", fmt.Errorf("image upload failed with status %d: %s", statusCode, string(respBody))
	}

	if statusCode != http.StatusOK {
		return "", "", fmt.Errorf("image upload failed with status %d: %s", statusCode, string(respBody))
	}

	tag := parseUploadResponse(respBody, imageName, writer)
	return tag, "", nil
}

// parseUploadResponse extracts the image tag from the upload response
func parseUploadResponse(respBody []byte, imageName string, writer io.Writer) string {
	var buildResponse struct {
		Tag string `json:"tag"`
	}
	if err := json.Unmarshal(respBody, &buildResponse); err == nil && buildResponse.Tag != "" {
		fmt.Fprintf(writer, "   Image %s queued for building (tag: %s)\n", imageName, buildResponse.Tag)
		return buildResponse.Tag
	}
	return ""
}

// updateWorktreeChecksums renames the image directory and updates all automation.toml
// files that reference the old hash to use the new (server) checksum.
func updateWorktreeChecksums(gitopsPath string, ref imageRef, newChecksum string) error {
	oldDirPath := filepath.Join(gitopsPath, "images", ref.Hash)
	newDirPath := filepath.Join(gitopsPath, "images", newChecksum)

	// Rename image directory
	if _, err := os.Stat(oldDirPath); err == nil {
		if err := os.Rename(oldDirPath, newDirPath); err != nil {
			return fmt.Errorf("failed to rename image directory from %s to %s: %w", ref.Hash, newChecksum, err)
		}
	}

	// Update all automation.toml files that reference the old hash
	oldTag := fmt.Sprintf("sha%s", ref.Hash)
	newTag := fmt.Sprintf("sha%s", newChecksum)

	entries, err := os.ReadDir(gitopsPath)
	if err != nil {
		return fmt.Errorf("failed to read gitops directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tomlPath := filepath.Join(gitopsPath, entry.Name(), "automation.toml")
		data, err := os.ReadFile(tomlPath)
		if err != nil {
			continue
		}

		if !strings.Contains(string(data), oldTag) {
			continue
		}

		newData := strings.ReplaceAll(string(data), oldTag, newTag)
		if err := os.WriteFile(tomlPath, []byte(newData), 0644); err != nil {
			return fmt.Errorf("failed to update %s: %w", tomlPath, err)
		}
	}

	return nil
}

// calculateGitTreeHash calculates the git tree hash of a directory.
// This implements the same algorithm as the gitops service uses for checksum verification.
func calculateGitTreeHash(dirPath string) (string, error) {
	return calculateGitTreeHashRecursive(dirPath)
}

func calculateGitTreeHashRecursive(dirPath string) (string, error) {
	type entry struct {
		mode  string
		name  string
		hash  string
		isDir bool
	}

	var entries []entry

	files, err := os.ReadDir(dirPath)
	if err != nil {
		return "", err
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".") {
			continue
		}

		filePath := filepath.Join(dirPath, file.Name())

		if file.IsDir() {
			subHash, err := calculateGitTreeHashRecursive(filePath)
			if err != nil {
				return "", err
			}
			entries = append(entries, entry{
				mode:  "040000",
				name:  file.Name(),
				hash:  subHash,
				isDir: true,
			})
		} else {
			blobHash, err := calculateGitBlobHash(filePath)
			if err != nil {
				return "", err
			}

			info, err := os.Stat(filePath)
			if err != nil {
				return "", err
			}
			mode := "100644"
			if info.Mode().Perm()&0111 != 0 {
				mode = "100755"
			}

			entries = append(entries, entry{
				mode:  mode,
				name:  file.Name(),
				hash:  blobHash,
				isDir: false,
			})
		}
	}

	// Sort entries: directories first, then alphabetically
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].isDir != entries[j].isDir {
			return entries[i].isDir
		}
		return entries[i].name < entries[j].name
	})

	var treeContent []byte
	for _, e := range entries {
		hashBytes, err := hex.DecodeString(e.hash)
		if err != nil {
			return "", fmt.Errorf("invalid hash: %w", err)
		}

		entryStr := fmt.Sprintf("%s %s\000", e.mode, e.name)
		treeContent = append(treeContent, []byte(entryStr)...)
		treeContent = append(treeContent, hashBytes...)
	}

	treeHeader := fmt.Sprintf("tree %d\000", len(treeContent))
	treeObject := append([]byte(treeHeader), treeContent...)

	hasher := sha1.New()
	hasher.Write(treeObject)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func calculateGitBlobHash(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	blobHeader := fmt.Sprintf("blob %d\000", len(content))
	blob := append([]byte(blobHeader), content...)

	hasher := sha1.New()
	hasher.Write(blob)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// deployAutomations calls the deploy endpoint to deploy all automations
func deployAutomations(gitopsURL, gitopsSecret, workspaceName string, writer io.Writer) error {
	deployURL := fmt.Sprintf("%s/automations/deploy", gitopsURL)
	deployURL = automations.TransformURLForDaemon(deployURL, workspaceName)

	resp, err := automations.SendAutomationRequest("POST", deployURL, gitopsSecret)
	if err != nil {
		return fmt.Errorf("failed to send deploy request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to deploy automations, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	return nil
}
