package cmd

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/commands"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
	"github.com/bitswan-space/bitswan-workspaces/internal/workspace"
	"github.com/spf13/cobra"
)

type updateOptions struct {
	gitopsImage    string
	editorImage    string
	kafkaImage     string
	zookeeperImage string
	couchdbImage   string
	staging        bool
	trustCA        bool
}

func newUpdateCmd() *cobra.Command {
	o := &updateOptions{}
	cmd := &cobra.Command{
		Use:          "update <workspace-name>",
		Short:        "bitswan workspace update",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceName := args[0]
			fmt.Printf("Updating Gitops: %s...\n", workspaceName)
			err := updateGitops(workspaceName, o)
			if err != nil {
				return fmt.Errorf("error updating workspace: %w", err)
			}
			fmt.Printf("Gitops %s updated successfully!\n", workspaceName)
			return nil
		},
	}

	cmd.Flags().StringVar(&o.gitopsImage, "gitops-image", "", "Custom image for the gitops")
	cmd.Flags().StringVar(&o.editorImage, "editor-image", "", "Custom image for the editor")
	cmd.Flags().StringVar(&o.kafkaImage, "kafka-image", "", "Custom image for Kafka")
	cmd.Flags().StringVar(&o.zookeeperImage, "zookeeper-image", "", "Custom image for Zookeeper")
	cmd.Flags().StringVar(&o.couchdbImage, "couchdb-image", "", "Custom image for CouchDB")
	cmd.Flags().BoolVar(&o.staging, "staging", false, "Use staging images for editor and gitops")
	cmd.Flags().BoolVar(&o.trustCA, "trust-ca", false, "Install custom certificates from the default CA certificates directory.")

	return cmd
}

// updateServices updates all enabled services for the workspace
func updateServices(workspaceName string, o *updateOptions) error {
	// Always try to update editor service if enabled
	fmt.Println("Checking editor service...")
	if err := updateEditorService(workspaceName, o.editorImage, o.staging, o.trustCA); err != nil {
		fmt.Printf("Warning: failed to update editor service: %v\n", err)
	} else {
		fmt.Println("Editor service updated successfully!")
	}

	// Always try to update Kafka service if enabled
	fmt.Println("Checking Kafka service...")
	if err := updateKafkaService(workspaceName, o.kafkaImage, o.zookeeperImage); err != nil {
		fmt.Printf("Warning: failed to update Kafka service: %v\n", err)
	} else {
		fmt.Println("Kafka service updated successfully!")
	}

	// Always try to update CouchDB service if enabled
	fmt.Println("Checking CouchDB service...")
	if err := updateCouchDBService(workspaceName, o.couchdbImage); err != nil {
		fmt.Printf("Warning: failed to update CouchDB service: %v\n", err)
	} else {
		fmt.Println("CouchDB service updated successfully!")
	}

	return nil
}

// updateEditorService updates the editor service for a specific workspace
func updateEditorService(workspaceName, editorImage string, staging bool, trustCA bool) error {
	// Create Editor service manager
	editorService, err := services.NewEditorService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Editor service: %w", err)
	}

	// Check if enabled
	if !editorService.IsEnabled() {
		fmt.Printf("Editor service is not enabled for workspace '%s', skipping update\n", workspaceName)
		return nil
	}

	// Stop the current container
	fmt.Println("Stopping current editor container...")
	if err := editorService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop current editor container: %w", err)
	}

	// Update certificates if specified
	if trustCA {
		fmt.Println("Updating certificate configuration...")
		if err := editorService.UpdateCertificates(trustCA); err != nil {
			return fmt.Errorf("failed to update certificates: %w", err)
		}
	}

	// Update the service image
	if editorImage != "" {
		// Use provided custom image
		fmt.Printf("Updating Editor service with custom image: %s\n", editorImage)
		if err := editorService.UpdateImage(editorImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		// Update to latest version
		fmt.Println("Updating Editor service to latest version...")
		if err := editorService.UpdateToLatestWithStaging(staging); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
	}

	// Start the container with new image
	fmt.Println("Starting editor container...")
	if err := editorService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start editor container: %w", err)
	}

	// Wait for editor to be ready
	fmt.Println("Waiting for editor to be ready...")
	if err := editorService.WaitForEditorReady(); err != nil {
		return fmt.Errorf("editor failed to start properly: %w", err)
	}

	return nil
}

// updateKafkaService updates the Kafka service for a specific workspace
func updateKafkaService(workspaceName, kafkaImage, zookeeperImage string) error {
	// Create Kafka service manager
	kafkaService, err := services.NewKafkaService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create Kafka service: %w", err)
	}

	// Check if enabled
	if !kafkaService.IsEnabled() {
		fmt.Printf("Kafka service is not enabled for workspace '%s', skipping update\n", workspaceName)
		return nil
	}

	// Stop the current containers
	fmt.Println("Stopping current Kafka containers...")
	if err := kafkaService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop current Kafka containers: %w", err)
	}

	// Update the service
	if kafkaImage != "" || zookeeperImage != "" {
		// Use provided custom images
		bitswanKafkaImage := kafkaImage
		if bitswanKafkaImage == "" {
			// For now, use latest when no custom image provided
			bitswanKafkaImage = "bitswan/bitswan-kafka:latest"
		}

		bitswanZookeeperImage := zookeeperImage
		if bitswanZookeeperImage == "" {
			// For now, use latest when no custom image provided
			bitswanZookeeperImage = "bitswan/bitswan-zookeeper:latest"
		}

		fmt.Printf("Updating Kafka service with custom images:\n")
		fmt.Printf("  Kafka: %s\n", bitswanKafkaImage)
		fmt.Printf("  Zookeeper: %s\n", bitswanZookeeperImage)

		if err := kafkaService.UpdateImages(bitswanKafkaImage, bitswanZookeeperImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		// Update to latest versions
		fmt.Println("Updating Kafka service to latest versions...")
		if err := kafkaService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest versions: %w", err)
		}
	}

	// Start the containers with new images
	fmt.Println("Starting Kafka containers with new images...")
	if err := kafkaService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start Kafka containers: %w", err)
	}

	return nil
}

// updateCouchDBService updates the CouchDB service for a specific workspace
func updateCouchDBService(workspaceName, couchdbImage string) error {
	// Create CouchDB service manager
	couchdbService, err := services.NewCouchDBService(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to create CouchDB service: %w", err)
	}

	// Check if enabled
	if !couchdbService.IsEnabled() {
		fmt.Printf("CouchDB service is not enabled for workspace '%s', skipping update\n", workspaceName)
		return nil
	}

	// Stop the current container
	fmt.Println("Stopping current CouchDB container...")
	if err := couchdbService.StopContainer(); err != nil {
		return fmt.Errorf("failed to stop current CouchDB container: %w", err)
	}

	// Update the service
	if couchdbImage != "" {
		// Use provided custom image
		fmt.Printf("Updating CouchDB service with custom image: %s\n", couchdbImage)
		if err := couchdbService.UpdateImage(couchdbImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		// Update to latest version
		fmt.Println("Updating CouchDB service to latest version...")
		if err := couchdbService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
	}

	// Start the container with new image
	fmt.Println("Starting CouchDB container with new image...")
	if err := couchdbService.StartContainer(); err != nil {
		return fmt.Errorf("failed to start CouchDB container: %w", err)
	}

	return nil
}

func updateGitops(workspaceName string, o *updateOptions) error {
	bitswanPath := os.Getenv("HOME") + "/.config/bitswan/"

	// 1. Create or update examples directory
	fmt.Println("Ensuring examples are up to date...")
	err := commands.EnsureExamples(bitswanPath, true)
	if err != nil {
		return fmt.Errorf("failed to download examples: %w", err)
	}
	fmt.Println("Examples are up to date!")

	// 2. Update Docker images and docker-compose file
	fmt.Println("Updating Docker images and docker-compose file...")
	if err := workspace.UpdateWorkspaceDeployment(workspaceName, o.gitopsImage, o.staging, o.trustCA); err != nil {
		return fmt.Errorf("failed to update workspace deployment: %w", err)
	}
	fmt.Println("Gitops service restarted!")

	// 4. Update services if they are enabled
	fmt.Println("Checking for enabled services to update...")
	if err := updateServices(workspaceName, o); err != nil {
		fmt.Printf("Warning: some services failed to update: %v\n", err)
	}

	return nil
}
