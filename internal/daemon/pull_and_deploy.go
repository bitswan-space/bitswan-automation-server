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
		// The GitOps service may return 500 with "Push failed" but the pull-and-deploy operation can still succeed
		if resp.StatusCode == http.StatusInternalServerError && strings.Contains(bodyStr, "Push failed") {
			fmt.Fprintf(writer, "⚠️  Warning: Push failed (non-fatal), continuing with pull-and-deploy...\n")
			fmt.Fprintf(writer, "✅ Successfully pulled branch '%s' for '%s' (push warning ignored).\n", branchName, workspaceName)

			// Build any missing images, then deploy
			imageTags, err := buildMissingImages(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer)
			if err != nil {
				fmt.Fprintf(writer, "⚠️  Warning: error building images: %v\n", err)
			}
			if len(imageTags) > 0 {
				fmt.Fprintln(writer, "\n🔨 Monitoring build progress...")
				if err := monitorImageBuilds(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, imageTags, writer); err != nil {
					return fmt.Errorf("error monitoring image builds: %w", err)
				}
				fmt.Fprintln(writer, "\n✅ All automation images built successfully!")
			}

			fmt.Fprintln(writer, "\n🚀 Deploying automations...")
			if err := deployAutomations(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer); err != nil {
				return fmt.Errorf("failed to deploy automations after pull: %w", err)
			}
			fmt.Fprintln(writer, "✅ Automations deployed successfully!")
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

	// Display success message
	fmt.Fprintf(writer, "✅ Successfully pulled branch '%s' for '%s'.\n", branchName, workspaceName)

	// Combine image tags from gitops response with any we need to build ourselves
	imageTags := response.ImageTags
	var imageBuildFailed bool

	// Scan the gitops worktree for images that need building
	missingTags, err := buildMissingImages(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer)
	if err != nil {
		fmt.Fprintf(writer, "⚠️  Warning: error building images from worktree: %v\n", err)
		imageBuildFailed = true
	}
	imageTags = append(imageTags, missingTags...)

	// Monitor builds if any images are being built
	if len(imageTags) > 0 {
		fmt.Fprintln(writer, "\n📦 Building automation images:")
		for _, tag := range imageTags {
			fmt.Fprintf(writer, "   • %s\n", tag)
		}

		fmt.Fprintln(writer, "\n🔨 Monitoring build progress...")
		if err := monitorImageBuilds(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, imageTags, writer); err != nil {
			return fmt.Errorf("error monitoring image builds: %w", err)
		}

		fmt.Fprintln(writer, "\n✅ All automation images built successfully!")
	} else if !imageBuildFailed {
		fmt.Fprintln(writer, "\nℹ️  No new automation images to build.")
	}

	if imageBuildFailed {
		return fmt.Errorf("cannot deploy: some required images failed to build")
	}

	// Deploy automations
	fmt.Fprintln(writer, "\n🚀 Deploying automations...")
	if err := deployAutomations(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer); err != nil {
		return fmt.Errorf("error deploying automations: %w", err)
	}
	fmt.Fprintln(writer, "✅ Automations deployed successfully!")

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

		// Get all images to check their building status
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

			// Create a map of tag -> building status for quick lookup
			imageStatus := make(map[string]bool)
			for _, img := range images {
				imageStatus[img.Tag] = img.Building
			}

			// Check each building image
			for tag := range buildingImages {
				// Check if this image is no longer building
				if building, exists := imageStatus[tag]; exists && !building {
					fmt.Fprintf(writer, "  ✅ [%s] Build completed\n", tag)
					delete(buildingImages, tag)
				}
			}
		} else {
			return fmt.Errorf("failed to get images: %w", err)
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
	// Format: "internal/{name}:sha{hash}"
	if !strings.HasPrefix(image, "internal/") {
		return imageRef{}, false
	}

	colonIdx := strings.LastIndex(image, ":")
	if colonIdx == -1 {
		return imageRef{}, false
	}

	nameWithPrefix := image[:colonIdx]                   // "internal/mitchell-backend"
	name := strings.TrimPrefix(nameWithPrefix, "internal/") // "mitchell-backend"
	tag := image[colonIdx+1:]                             // "sha203384..."

	if !strings.HasPrefix(tag, "sha") {
		return imageRef{}, false
	}

	hash := strings.TrimPrefix(tag, "sha") // "203384..."

	return imageRef{
		Name: name,
		Tag:  image,
		Hash: hash,
	}, true
}

// buildMissingImages scans the gitops worktree for automations with image references,
// checks which images are not yet built, and uploads them for building.
func buildMissingImages(gitopsURL, gitopsSecret, workspaceName string, writer io.Writer) ([]string, error) {
	// Get the gitops worktree path
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return nil, fmt.Errorf("HOME environment variable not set")
	}
	gitopsPath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName, "gitops")

	// Scan for automation.toml files and collect unique image references
	imageRefs := make(map[string]imageRef) // keyed by tag to deduplicate
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
			continue // not an automation directory
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

		imageRefs[ref.Tag] = ref
	}

	if len(imageRefs) == 0 {
		return nil, nil
	}

	// Check which images already exist on the gitops service
	existingImages, err := getExistingImageTags(gitopsURL, gitopsSecret, workspaceName)
	if err != nil {
		fmt.Fprintf(writer, "⚠️  Warning: could not check existing images: %v\n", err)
		existingImages = make(map[string]bool)
	}

	// Build missing images
	var builtTags []string
	var failedImages []string
	for _, ref := range imageRefs {
		if existingImages[ref.Tag] {
			fmt.Fprintf(writer, "   ✓ Image %s already exists, skipping.\n", ref.Tag)
			continue
		}

		// Check if the image source directory exists in the worktree
		imageSrcDir := filepath.Join(gitopsPath, "images", ref.Hash)
		if _, err := os.Stat(imageSrcDir); os.IsNotExist(err) {
			fmt.Fprintf(writer, "⚠️  Warning: image source directory not found for %s (expected at images/%s), skipping.\n", ref.Tag, ref.Hash)
			failedImages = append(failedImages, ref.Tag)
			continue
		}

		fmt.Fprintf(writer, "📦 Uploading image %s for building...\n", ref.Tag)
		tag, err := uploadImageForBuild(gitopsURL, gitopsSecret, workspaceName, ref.Name, ref.Hash, imageSrcDir, writer)
		if err != nil {
			fmt.Fprintf(writer, "⚠️  Warning: failed to build image %s: %v\n", ref.Tag, err)
			failedImages = append(failedImages, ref.Tag)
			continue
		}

		if tag != "" {
			builtTags = append(builtTags, tag)
		}
	}

	if len(failedImages) > 0 {
		return builtTags, fmt.Errorf("failed to build %d image(s): %s", len(failedImages), strings.Join(failedImages, ", "))
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

// uploadImageForBuild creates a ZIP of the image directory and uploads it to the gitops service.
// It computes the git tree hash of the directory contents as the checksum.
func uploadImageForBuild(gitopsURL, gitopsSecret, workspaceName, imageName, dirHash, imageSrcDir string, writer io.Writer) (string, error) {
	// Compute the actual git tree hash of the image directory contents
	checksum, err := calculateGitTreeHash(imageSrcDir)
	if err != nil {
		return "", fmt.Errorf("failed to calculate image checksum: %w", err)
	}
	fmt.Fprintf(writer, "   Computed checksum for %s: %s\n", imageName, checksum)

	// Create ZIP in memory
	var zipBuf bytes.Buffer
	zipWriter := zip.NewWriter(&zipBuf)

	err = filepath.Walk(imageSrcDir, func(path string, info os.FileInfo, err error) error {
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
		return "", fmt.Errorf("failed to create image ZIP: %w", err)
	}
	zipWriter.Close()

	// Create multipart form request
	var body bytes.Buffer
	formWriter := multipart.NewWriter(&body)
	part, err := formWriter.CreateFormFile("file", "image.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create form file: %w", err)
	}
	if _, err := io.Copy(part, &zipBuf); err != nil {
		return "", fmt.Errorf("failed to write ZIP to form: %w", err)
	}
	if err := formWriter.WriteField("checksum", checksum); err != nil {
		return "", fmt.Errorf("failed to write checksum field: %w", err)
	}
	formWriter.Close()

	// Upload to gitops service
	uploadURL := fmt.Sprintf("%s/images/%s", gitopsURL, imageName)
	uploadURL = automations.TransformURLForDaemon(uploadURL, workspaceName)

	req, err := httpReq.NewRequest("POST", uploadURL, &body)
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %w", err)
	}
	req.Header.Set("Content-Type", formWriter.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+gitopsSecret)

	// Use appropriate HTTP client based on environment
	var resp *http.Response
	if os.Getenv("BITSWAN_CADDY_HOST") != "" && !strings.Contains(uploadURL, ".localhost") {
		resp, err = http.DefaultClient.Do(req)
	} else {
		resp, err = httpReq.ExecuteRequestWithLocalhostResolution(req)
	}
	if err != nil {
		return "", fmt.Errorf("failed to upload image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("image upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response to get the image tag
	var buildResponse struct {
		Tag string `json:"tag"`
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read upload response: %w", err)
	}
	if err := json.Unmarshal(bodyBytes, &buildResponse); err == nil && buildResponse.Tag != "" {
		fmt.Fprintf(writer, "   ✓ Image %s queued for building (tag: %s)\n", imageName, buildResponse.Tag)
		return buildResponse.Tag, nil
	}

	return "", nil
}

// calculateGitTreeHash computes the git tree hash of a directory,
// matching the algorithm used by the gitops service for checksum verification.
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
		// Skip hidden files (like .git)
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

	// Sort entries: directories first, then alphabetically by name
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].isDir != entries[j].isDir {
			return entries[i].isDir
		}
		return entries[i].name < entries[j].name
	})

	// Build git tree object
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

