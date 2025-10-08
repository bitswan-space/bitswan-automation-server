	package cmd

	import (
		"fmt"
		"net/http"

		"github.com/bitswan-space/bitswan-workspaces/internal/automations"
		"github.com/bitswan-space/bitswan-workspaces/internal/config"
		"github.com/spf13/cobra"
	)

	func newPullAndDeployCmd() *cobra.Command {
		var branch string
		var force bool
		var noBuild bool

		cmd := &cobra.Command{
			Use:   "pull-and-deploy [workspace_name]",
			Short: "Pull a specific branch into workspace gitops folder, build all automation images, and deploy them",
			Long:  "Pull a specific branch into workspace gitops folder, build all automation images, and deploy them",
			Args: cobra.ExactArgs(1),
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
		metadata := config.GetWorkspaceMetadata(workspaceName)
		// Construct the URL for the pull-and-deploy endpoint with query parameters
		url := fmt.Sprintf("%s/automations/pull-and-deploy/%s", metadata.GitopsURL, branchName)

		// Add query parameters if needed
		if force || noBuild {
			params := []string{}
			if force {
				params = append(params, "force=true")
			}
			if noBuild {
				params = append(params, "no_build=true")
			}
			if len(params) > 0 {
				url += "?" + params[0]
				for i := 1; i < len(params); i++ {
					url += "&" + params[i]
				}
			}
		}

		// Send the request to pull branch and deploy all automations
		resp, err := automations.SendAutomationRequest("POST", url, metadata.GitopsSecret)
		if err != nil {
			return fmt.Errorf("failed to send request to pull branch and deploy automations: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to pull branch and deploy automations, status code: %d", resp.StatusCode)
		}

		fmt.Printf("Successfully pulled branch '%s' and deployed all automations for workspace '%s'.\n", branchName, workspaceName)
		return nil
	}
