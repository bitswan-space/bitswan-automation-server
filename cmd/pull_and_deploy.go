package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// monitorImageBuilds polls the image logs endpoint until all builds are complete
func monitorImageBuilds(gitopsURL, gitopsSecret string, imageTags []string) error {
	buildingImages := make(map[string]bool)
	for _, tag := range imageTags {
		buildingImages[tag] = true
	}

	lastLogLines := make(map[string]int) // Track how many lines we've already shown
	pollInterval := 2 * time.Second
	maxRetries := 300 // 10 minutes max (300 * 2 seconds)
	retries := 0

	for len(buildingImages) > 0 && retries < maxRetries {
		retries++
		time.Sleep(pollInterval)

		for tag := range buildingImages {
			// Get logs for this image
			logsURL := fmt.Sprintf("%s/automations/images/%s/logs?lines=1000", gitopsURL, tag)
			resp, err := automations.SendAutomationRequest("GET", logsURL, gitopsSecret)
			if err != nil {
				// Image might not have started building yet, continue
				continue
			}

			if resp.StatusCode == http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}

				var logsResp ImageLogsResponse
				if err := json.Unmarshal(body, &logsResp); err != nil {
					continue
				}

				// Display new log lines
				startLine := lastLogLines[tag]
				if startLine < len(logsResp.Logs) {
					for i := startLine; i < len(logsResp.Logs); i++ {
						logLine := strings.TrimSpace(logsResp.Logs[i])
						if logLine != "" {
							fmt.Printf("  [%s] %s\n", tag, logLine)
						}
					}
					lastLogLines[tag] = len(logsResp.Logs)

					// Check if build is complete by looking for success/completion indicators
					// or checking if the log file no longer has .building extension
					for _, line := range logsResp.Logs {
						if strings.Contains(line, "Successfully built") ||
							strings.Contains(line, "Successfully tagged") ||
							strings.Contains(line, "Build complete") {
							fmt.Printf("  ✅ [%s] Build completed\n", tag)
							delete(buildingImages, tag)
							break
						}
						if strings.Contains(line, "ERROR") || strings.Contains(line, "Build failed") {
							fmt.Printf("  ❌ [%s] Build failed\n", tag)
							delete(buildingImages, tag)
							break
						}
					}
				}
			} else if resp.StatusCode == http.StatusNotFound {
				resp.Body.Close()
				// Log file might have been moved from .building to final name
				// Try one more time, if still 404, consider it done
				time.Sleep(500 * time.Millisecond)
				resp2, err := automations.SendAutomationRequest("GET", logsURL, gitopsSecret)
				if err == nil {
					if resp2.StatusCode == http.StatusNotFound {
						// Build is complete (log file exists without .building)
						fmt.Printf("  ✅ [%s] Build completed\n", tag)
						delete(buildingImages, tag)
					}
					resp2.Body.Close()
				}
			} else {
				resp.Body.Close()
			}
		}
	}

	if retries >= maxRetries {
		return fmt.Errorf("timeout waiting for image builds to complete")
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
