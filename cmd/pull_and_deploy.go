package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/spf13/cobra"
)

// PullAndDeployResponse represents the response from the pull-and-deploy endpoint
type PullAndDeployResponse struct {
	Status    string   `json:"status"`
	Message   string   `json:"message"`
	ImageTags []string `json:"image_tags"`
}

// ImageLogsResponse represents the response from the image logs endpoint
type ImageLogsResponse struct {
	ImageTag string   `json:"image_tag"`
	Logs     []string `json:"logs"`
}

// ImageResponse represents a single image from the images endpoint
type ImageResponse struct {
	ID      string `json:"id"`
	Tag     string `json:"tag"`
	Created string `json:"created"`
	Size    int64  `json:"size"`
	Building bool  `json:"building"`
}

func newPullAndDeployCmd() *cobra.Command {
	var branch string
	var force bool
	var noBuild bool

	cmd := &cobra.Command{
		Use:   "pull-and-deploy [workspace_name]",
		Short: "Pull a specific branch into workspace gitops folder, build all automation images, and deploy them",
		Long:  "Pull a specific branch into workspace gitops folder, build all automation images, and deploy them",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceName := args[0]

			if branch == "" {
				return fmt.Errorf("branch flag is required, use --branch or -b to specify the branch")
			}

			fmt.Printf("Pulling branch '%s' and deploying all automations for workspace '%s'...\n", branch, workspaceName)
			err := pullAndDeploy(workspaceName, branch, force, noBuild)
			if err != nil {
				return fmt.Errorf("failed to pull branch and deploy automations: %v", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&branch, "branch", "b", "", "Branch name to pull and deploy (required)")
	cmd.Flags().BoolVar(&force, "force", false, "Force rebuild of all automation images even if they exist")
	cmd.Flags().BoolVar(&noBuild, "no-build", false, "Skip building automation images, only pull and deploy existing images")

	// Mark branch flag as required
	cmd.MarkFlagRequired("branch")

	return cmd
}

func pullAndDeploy(workspaceName, branchName string, force, noBuild bool) error {
	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}
	// Construct the URL for the pull-and-deploy endpoint with query parameters
	url := fmt.Sprintf("%s/automations/pull-and-deploy/%s", metadata.GitopsURL, branchName)

	// Send the request to pull branch and deploy all automations
	resp, err := automations.SendAutomationRequest("POST", url, metadata.GitopsSecret)
	if err != nil {
		return fmt.Errorf("failed to send request to pull branch and deploy automations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to pull branch and deploy automations, status code: %d", resp.StatusCode)
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
	fmt.Printf("✅ Successfully pulled branch '%s' and started to build automation images for '%s'.\n", branchName, workspaceName)

	// Display image tags if any
	if len(response.ImageTags) > 0 {
		fmt.Println("\n📦 Building automation images:")
		for _, tag := range response.ImageTags {
			fmt.Printf("   • %s\n", tag)
		}

		// Monitor build progress
		fmt.Println("\n🔨 Monitoring build progress...")
		if err := monitorImageBuilds(metadata.GitopsURL, metadata.GitopsSecret, response.ImageTags); err != nil {
			return fmt.Errorf("error monitoring image builds: %w", err)
		}

		fmt.Println("\n✅ All automation images built successfully!")

		// Deploy the automations
		fmt.Println("\n🚀 Deploying automations...")
		if err := deployAutomations(metadata.GitopsURL, metadata.GitopsSecret); err != nil {
			return fmt.Errorf("error deploying automations: %w", err)
		}

		fmt.Println("✅ Automations deployed successfully!")
	} else {
		fmt.Println("\nℹ️  No new automation images were built.")
	}

	return nil
}

// monitorImageBuilds polls the images endpoint until all builds are complete
func monitorImageBuilds(gitopsURL, gitopsSecret string, imageTags []string) error {
	buildingImages := make(map[string]bool)
	for _, tag := range imageTags {
		buildingImages[tag] = true
	}

	pollInterval := 2 * time.Second

	for len(buildingImages) > 0 {
		time.Sleep(pollInterval)

		// Get all images to check their building status
		imagesURL := fmt.Sprintf("%s/images/", gitopsURL)
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
					fmt.Printf("  ✅ [%s] Build completed\n", tag)
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
func deployAutomations(gitopsURL, gitopsSecret string) error {
	deployURL := fmt.Sprintf("%s/automations/deploy", gitopsURL)

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
