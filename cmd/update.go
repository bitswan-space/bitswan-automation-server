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
	"github.com/spf13/cobra"
)

type updateOptions struct {
	gitopsImage string
	editorImage string
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

	return cmd
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

	bitswanEditorImage := o.editorImage
	if o.editorImage == "" {
		bitswanEditorLatestVersion, err := dockerhub.GetLatestDockerHubVersion("https://hub.docker.com/v2/repositories/bitswan/bitswan-editor/tags/")
		if err != nil {
			panic(fmt.Errorf("failed to get latest BitSwan Editor version: %w", err))
		}
		bitswanEditorImage = "bitswan/bitswan-editor:" + bitswanEditorLatestVersion
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
	noIde := metadata.EditorURL == nil
	var gitopsDevSourceDir string
	if metadata.GitopsDevSourceDir != nil {
		gitopsDevSourceDir = *metadata.GitopsDevSourceDir
	}
	compose, _, err := dockercompose.CreateDockerComposeFile(gitopsConfig, workspaceName, gitopsImage, bitswanEditorImage, metadata.Domain, noIde, mqttEnvVars, aocEnvVars, gitopsDevSourceDir)
	if err != nil {
		panic(fmt.Errorf("failed to create docker-compose file: %w", err))
	}

	dockerComposeFilePath := filepath.Join(gitopsConfig, "deployment", "/docker-compose.yml")
	if err := os.WriteFile(dockerComposeFilePath, []byte(compose), 0755); err != nil {
		panic(fmt.Errorf("failed to write docker-compose file: %w", err))
	}

	// 3. Restart gitops and editor services
	fmt.Println("Restarting services...")
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
	fmt.Println("Services restarted!")

	return nil
}
