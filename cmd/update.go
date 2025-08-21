package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/bitswan-space/bitswan-workspaces/internal/services"
	"github.com/spf13/cobra"
)

type updateOptions struct {
	gitopsImage     string
	editorImage     string
	kafkaImage      string
	zookeeperImage  string
	couchdbImage    string
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

	return cmd
}

// updateServices updates all enabled services for the workspace
func updateServices(workspaceName string, o *updateOptions) error {
	// Always try to update editor service if enabled
	fmt.Println("Checking editor service...")
	if err := updateEditorService(workspaceName, o.editorImage); err != nil {
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
func updateEditorService(workspaceName, editorImage string) error {
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
	
	// Update the service
	if editorImage != "" {
		// Use provided custom image
		fmt.Printf("Updating Editor service with custom image: %s\n", editorImage)
		if err := editorService.UpdateImage(editorImage); err != nil {
			return fmt.Errorf("failed to update docker-compose file: %w", err)
		}
	} else {
		// Update to latest version
		fmt.Println("Updating Editor service to latest version...")
		if err := editorService.UpdateToLatest(); err != nil {
			return fmt.Errorf("failed to update to latest version: %w", err)
		}
	}
	
	// Start the container with new image
	fmt.Println("Starting editor container with new image...")
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

	repoPath := filepath.Join(bitswanPath, "bitswan-src")
	// 1. Create or update examples directory
	fmt.Println("Ensuring examples are up to date...")
	err := EnsureExamples(repoPath, true)
	if err != nil {
		return fmt.Errorf("failed to download examples: %w", err)
	}
	fmt.Println("Examples are up to date!")

	// 2. Update Docker images and docker-compose file
	fmt.Println("Updating Docker images and docker-compose file...")
	gitopsImage := o.gitopsImage
	if gitopsImage == "" {
		gitopsLatestVersion, err := dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/gitops/tags/")
		if err != nil {
			panic(fmt.Errorf("failed to get latest BitSwan GitOps version: %w", err))
		}
		gitopsImage = "bitswan/gitops:" + gitopsLatestVersion
	}



	gitopsConfig := filepath.Join(bitswanPath, "workspaces/", workspaceName)

	// Get the domain from the file `~/.config/bitswan/<workspace-name>/deployment/domain`
	dataPath := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "workspaces", workspaceName, "metadata.yaml")

	data, err := os.ReadFile(dataPath)
	if err != nil {
		return fmt.Errorf("failed to read metadata.yaml: %w", err)
	}

	// Config represents the structure of the YAML file
	var metadata MetadataInit
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal metadata.yaml: %w", err)
	}

	var mqttEnvVars []string
	// Check if mqtt data are in the metadata
	if metadata.MqttUsername != nil {
		mqttEnvVars = append(mqttEnvVars, "MQTT_USERNAME="+fmt.Sprint(metadata.MqttUsername))
		mqttEnvVars = append(mqttEnvVars, "MQTT_PASSWORD="+fmt.Sprint(metadata.MqttPassword))
		mqttEnvVars = append(mqttEnvVars, "MQTT_BROKER="+fmt.Sprint(metadata.MqttBroker))
		mqttEnvVars = append(mqttEnvVars, "MQTT_PORT="+fmt.Sprint(metadata.MqttPort))
		mqttEnvVars = append(mqttEnvVars, "MQTT_TOPIC="+fmt.Sprint(metadata.MqttTopic))
	}

	bitswanConfig := os.Getenv("HOME") + "/.config/bitswan/"
	automationServerConfig := filepath.Join(bitswanConfig, "aoc", "automation_server.yaml")
	var aocEnvVars []string
	if _, err := os.Stat(automationServerConfig); !os.IsNotExist(err) {
		// Read automation_server.yaml
		yamlFile, err := os.ReadFile(automationServerConfig)
		if err != nil {
			return fmt.Errorf("failed to read automation_server.yaml: %w", err)
		}

		var automationConfig AutomationServerYaml
		if err := yaml.Unmarshal(yamlFile, &automationConfig); err != nil {
			return fmt.Errorf("failed to unmarshal automation_server.yaml: %w", err)
		}

		fmt.Println("Getting automation server token...")

		resp, err := sendRequest("GET", fmt.Sprintf("%s/api/automation-servers/token", automationConfig.AOCUrl), nil, automationConfig.AccessToken)
		if err != nil {
			return fmt.Errorf("error sending request: %w", err)
		}

		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to get automation server token: %s", resp.Status)
		}

		type AutomationServerTokenResponse struct {
			Token string `json:"token"`
		}

		var automationServerTokenResponse AutomationServerTokenResponse
		body, _ := ioutil.ReadAll(resp.Body)
		err = json.Unmarshal([]byte(body), &automationServerTokenResponse)
		if err != nil {
			return fmt.Errorf("error decoding JSON: %w", err)
		}
		fmt.Println("Automation server token received successfully!")

		aocEnvVars = append(aocEnvVars, "BITSWAN_WORKSPACE_ID="+*metadata.WorkspaceId)
		aocEnvVars = append(aocEnvVars, "BITSWAN_AOC_URL="+automationConfig.AOCUrl)
		aocEnvVars = append(aocEnvVars, "BITSWAN_AOC_TOKEN="+automationServerTokenResponse.Token)
	}


	// Rewrite the docker-compose file
	var gitopsDevSourceDir string
	if metadata.GitopsDevSourceDir != nil {
		gitopsDevSourceDir = *metadata.GitopsDevSourceDir
	}

	compose, _, err := dockercompose.CreateDockerComposeFile(gitopsConfig, workspaceName, gitopsImage, metadata.Domain, mqttEnvVars, aocEnvVars, gitopsDevSourceDir)
	if err != nil {
		panic(fmt.Errorf("failed to create docker-compose file: %w", err))
	}

	dockerComposeFilePath := filepath.Join(gitopsConfig, "deployment", "/docker-compose.yml")
	if err := os.WriteFile(dockerComposeFilePath, []byte(compose), 0755); err != nil {
		panic(fmt.Errorf("failed to write docker-compose file: %w", err))
	}

	// 3. Restart gitops service
	fmt.Println("Restarting gitops service...")
	dockerComposePath := filepath.Join(gitopsConfig, "deployment")

	projectName := workspaceName + "-site"
	commands := [][]string{
		{"docker", "compose", "down"},
		{"docker", "compose", "-p", projectName, "up", "-d", "--remove-orphans"},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dockerComposePath
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute %v: %w", args, err)
		}
	}
	fmt.Println("Gitops service restarted!")

	// 4. Update services if they are enabled
	fmt.Println("Checking for enabled services to update...")
	if err := updateServices(workspaceName, o); err != nil {
		fmt.Printf("Warning: some services failed to update: %v\n", err)
	}

	return nil
}
