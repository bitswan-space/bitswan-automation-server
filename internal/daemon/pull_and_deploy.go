package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
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
func RunPullAndDeploy(workspaceName, branchName string, force, noBuild bool, writer io.Writer) error {
	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	// Construct the URL for the pull-and-deploy endpoint
	url := fmt.Sprintf("%s/automations/pull-and-deploy/%s", metadata.GitopsURL, branchName)
	// Add query parameters if needed
	if force {
		url += "?force=true"
	}
	if noBuild {
		if force {
			url += "&no-build=true"
		} else {
			url += "?no-build=true"
		}
	}

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
			// The pull-and-deploy operation may have still succeeded despite the push failure
			// Try to deploy automations anyway - the fetch and merge likely succeeded
			fmt.Fprintf(writer, "✅ Successfully pulled branch '%s' for '%s' (push warning ignored).\n", branchName, workspaceName)
			// Deploy the automations that were pulled
			if err := deployAutomations(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer); err != nil {
				return fmt.Errorf("failed to deploy automations after pull: %w", err)
			}
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
	fmt.Fprintf(writer, "✅ Successfully pulled branch '%s' and started to build automation images for '%s'.\n", branchName, workspaceName)

	// Display image tags if any
	if len(response.ImageTags) > 0 {
		fmt.Fprintln(writer, "\n📦 Building automation images:")
		for _, tag := range response.ImageTags {
			fmt.Fprintf(writer, "   • %s\n", tag)
		}

		// Monitor build progress
		fmt.Fprintln(writer, "\n🔨 Monitoring build progress...")
		if err := monitorImageBuilds(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, response.ImageTags, writer); err != nil {
			return fmt.Errorf("error monitoring image builds: %w", err)
		}

		fmt.Fprintln(writer, "\n✅ All automation images built successfully!")

		// Deploy the automations
		fmt.Fprintln(writer, "\n🚀 Deploying automations...")
		if err := deployAutomations(metadata.GitopsURL, metadata.GitopsSecret, workspaceName, writer); err != nil {
			return fmt.Errorf("error deploying automations: %w", err)
		}

		fmt.Fprintln(writer, "✅ Automations deployed successfully!")
	} else {
		fmt.Fprintln(writer, "\nℹ️  No new automation images were built.")
	}

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

