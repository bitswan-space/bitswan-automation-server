package config

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v2"
)

// WorkspaceMetadata represents the unified workspace metadata structure
type WorkspaceMetadata struct {
	Domain             string  `yaml:"domain"`
	EditorURL          *string `yaml:"editor-url,omitempty"`
	GitopsURL          string  `yaml:"gitops-url"`
	GitopsSecret       string  `yaml:"gitops-secret"`
	WorkspaceId        *string `yaml:"workspace_id,omitempty"`
	MqttUsername       *string `yaml:"mqtt_username,omitempty"`
	MqttPassword       *string `yaml:"mqtt_password,omitempty"`
	MqttBroker         *string `yaml:"mqtt_broker,omitempty"`
	MqttPort           *int    `yaml:"mqtt_port,omitempty"`
	MqttTopic          *string `yaml:"mqtt_topic,omitempty"`
	GitopsDevSourceDir *string `yaml:"gitops-dev-source-dir,omitempty"`
}

func GetWorkspaceMetadata(workspaceName string) (WorkspaceMetadata, error) {
	metadataPath := os.Getenv("HOME") + "/.config/bitswan/" + "workspaces/" + workspaceName + "/metadata.yaml"

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return WorkspaceMetadata{}, fmt.Errorf("failed to read metadata file: %w", err)
	}

	var metadata WorkspaceMetadata
	err = yaml.Unmarshal(data, &metadata)
	if err != nil {
		return WorkspaceMetadata{}, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return metadata, nil
}

// SaveToFile saves the WorkspaceMetadata to a YAML file at the specified path
func (wm *WorkspaceMetadata) SaveToFile(filePath string) error {
	// Marshal to YAML
	yamlData, err := yaml.Marshal(wm)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}

	return nil
}
