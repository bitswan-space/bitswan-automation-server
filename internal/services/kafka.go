package services

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/dchest/uniuri"
	"gopkg.in/yaml.v3"
)

// KafkaService manages Kafka service deployment for workspaces
type KafkaService struct {
	WorkspaceName string
	WorkspacePath string
}

// NewKafkaService creates a new Kafka service manager
func NewKafkaService(workspaceName string) (*KafkaService, error) {
	workspacePath := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "workspaces", workspaceName)
	
	// Check if workspace exists
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace '%s' does not exist", workspaceName)
	}
	
	return &KafkaService{
		WorkspaceName: workspaceName,
		WorkspacePath: workspacePath,
	}, nil
}

// KafkaSecrets represents the secrets for Kafka
type KafkaSecrets struct {
	KafkaAdminPassword   string
	KafkaUIPassword      string
}

// GenerateSecrets creates new secrets for Kafka
func (k *KafkaService) GenerateSecrets() *KafkaSecrets {
	return &KafkaSecrets{
		KafkaAdminPassword: uniuri.NewLen(32),
		KafkaUIPassword:    uniuri.NewLen(32),
	}
}

// generateClusterID creates a random cluster ID for Kafka
func (k *KafkaService) generateClusterID() (string, error) {
	// Generate 16 random bytes
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random cluster ID: %w", err)
	}
	
	// Encode to base64 and remove padding to match Kafka format
	clusterID := base64.StdEncoding.EncodeToString(bytes)
	clusterID = strings.TrimRight(clusterID, "=")
	
	return clusterID, nil
}

// SaveSecrets saves Kafka secrets to the workspace secrets directory
func (k *KafkaService) SaveSecrets(secrets *KafkaSecrets) error {
	secretsDir := filepath.Join(k.WorkspacePath, "secrets")
	
	// Ensure secrets directory exists
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}
	
	// Create hostname for Kafka container
	kafkaHost := fmt.Sprintf("%s__kafka", k.WorkspaceName)
	
	// Create JAAS config strings
	jaasConfig := fmt.Sprintf("org.apache.kafka.common.security.plain.PlainLoginModule required username=\"admin\" password=\"%s\" user_admin=\"%s\";", 
		secrets.KafkaAdminPassword, secrets.KafkaAdminPassword)
	
	// Create secrets map for better readability
	secretsMap := map[string]string{
		"KAFKA_ADMIN_PASSWORD":     secrets.KafkaAdminPassword,
		"KAFKA_UI_PASSWORD":        secrets.KafkaUIPassword,
		"KAFKA_HOSTNAME":               kafkaHost,
		"KAFKA_LISTENER_NAME_SASL_PLAINTEXT_PLAIN_SASL_JAAS_CONFIG": "'" + jaasConfig + "'",
		"SPRING_SECURITY_USER_PASSWORD":                            secrets.KafkaUIPassword,
		"KAFKA_CLUSTERS_0_PROPERTIES_SASL_JAAS_CONFIG":             "'" + jaasConfig + "'",
	}
	
	// Build the secrets content
	var secretsContent strings.Builder
	for key, value := range secretsMap {
		secretsContent.WriteString(fmt.Sprintf("%s=%s\n", key, value))
	}
	
	secretsFile := filepath.Join(secretsDir, "kafka")
	if err := os.WriteFile(secretsFile, []byte(secretsContent.String()), 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}
	
	fmt.Printf("Kafka secrets saved to: %s\n", secretsFile)
	return nil
}



// CreateJAASConfig creates the Kafka server JAAS configuration file
func (k *KafkaService) CreateJAASConfig(secrets *KafkaSecrets) error {
	deploymentDir := filepath.Join(k.WorkspacePath, "deployment")
	
	// Ensure deployment directory exists
	if err := os.MkdirAll(deploymentDir, 0755); err != nil {
		return fmt.Errorf("failed to create deployment directory: %w", err)
	}
	
	jaasContent := fmt.Sprintf(`KafkaServer {
   org.apache.kafka.common.security.plain.PlainLoginModule required
   username="admin"
   password="%s"
   user_admin="%s";
};

Client {
   org.apache.kafka.common.security.plain.PlainLoginModule required
   username="admin"
   password="%s"
   user_admin="%s";
};
`, secrets.KafkaAdminPassword, secrets.KafkaAdminPassword, secrets.KafkaAdminPassword, secrets.KafkaAdminPassword)

	jaasFile := filepath.Join(deploymentDir, "kafka_server_jaas.conf")
	if err := os.WriteFile(jaasFile, []byte(jaasContent), 0644); err != nil {
		return fmt.Errorf("failed to write JAAS config file: %w", err)
	}
	
	fmt.Printf("Kafka JAAS config saved to: %s\n", jaasFile)
	return nil
}

// CreateDockerCompose generates a docker-compose.yml file for Kafka
func (k *KafkaService) CreateDockerCompose() (string, error) {
	secretsPath := filepath.Join(k.WorkspacePath, "secrets", "kafka")
	containerName := fmt.Sprintf("%s__kafka", k.WorkspaceName)
	uiContainerName := fmt.Sprintf("%s__kafka-ui", k.WorkspaceName)
	volumeName := fmt.Sprintf("%s-kafka-data", k.WorkspaceName)
	
	// Generate a random cluster ID
	clusterID, err := k.generateClusterID()
	if err != nil {
		return "", err
	}
	
	// Construct the docker-compose data structure
	dockerCompose := map[string]interface{}{
		"version": "3",
		"services": map[string]interface{}{
			"kafka-ui": map[string]interface{}{
				"container_name": uiContainerName,
				"restart":        "always",
				"image":          "provectuslabs/kafka-ui:latest",
				"environment": map[string]interface{}{
					"DYNAMIC_CONFIG_ENABLED":                            "true",
					"AUTH_TYPE":                                         "LOGIN_FORM",
					"SPRING_SECURITY_USER_NAME":                         "admin",
					"SERVER_SERVLET_CONTEXTPATH":                        "/kafka",
					"KAFKA_CLUSTERS_0_NAME":                             "local-cluster",
					"KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS":                 containerName + ":9092",
					"KAFKA_CLUSTERS_0_PROPERTIES_SECURITY_PROTOCOL":     "SASL_PLAINTEXT",
					"KAFKA_CLUSTERS_0_PROPERTIES_SASL_MECHANISM":        "PLAIN",
				},
				"env_file": []string{secretsPath},
				"networks": []string{"bitswan_network"},
			},
			"kafka": map[string]interface{}{
				"image":          "confluentinc/cp-kafka:7.5.0",
				"container_name": containerName,
				"environment": map[string]interface{}{
					"KAFKA_NODE_ID":                                     1,
					"KAFKA_PROCESS_ROLES":                               "broker,controller",
					"KAFKA_CONTROLLER_QUORUM_VOTERS":                    "1@" + containerName + ":9094",
					"KAFKA_CONTROLLER_LISTENER_NAMES":                   "CONTROLLER",
					"KAFKA_LISTENERS":                                   "SASL_PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9094",
					"KAFKA_ADVERTISED_LISTENERS":                        "SASL_PLAINTEXT://" + containerName + ":9092",
					"KAFKA_LISTENER_SECURITY_PROTOCOL_MAP":              "CONTROLLER:PLAINTEXT,SASL_PLAINTEXT:SASL_PLAINTEXT",
					"KAFKA_INTER_BROKER_LISTENER_NAME":                  "SASL_PLAINTEXT",
					"KAFKA_SASL_ENABLED_MECHANISMS":                     "PLAIN",
					"KAFKA_SASL_MECHANISM_INTER_BROKER_PROTOCOL":        "PLAIN",
					"KAFKA_OPTS":                                        "-Djava.security.auth.login.config=/etc/kafka/kafka_server_jaas.conf",
					"KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR":            1,
					"KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR":    1,
					"KAFKA_TRANSACTION_STATE_LOG_MIN_ISR":               1,
					"KAFKA_AUTO_CREATE_TOPICS_ENABLE":                   "true",
					"CLUSTER_ID":                                        clusterID,
				},
				"volumes": []string{
					volumeName + ":/var/lib/kafka/data",
					"./kafka_server_jaas.conf:/etc/kafka/kafka_server_jaas.conf",
				},
				"env_file": []string{secretsPath},
				"restart":  "unless-stopped",
				"networks": []string{"bitswan_network"},
			},
		},
		"volumes": map[string]interface{}{
			volumeName: nil,
		},
		"networks": map[string]interface{}{
			"bitswan_network": map[string]interface{}{
				"external": true,
			},
		},
	}
	
	var buf bytes.Buffer
	
	// Serialize the docker-compose data structure to YAML
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("failed to encode docker-compose data structure: %w", err)
	}
	
	return buf.String(), nil
}

// SaveDockerCompose saves the docker-compose.yml file to the deployment directory
func (k *KafkaService) SaveDockerCompose(composeContent string) error {
	deploymentDir := filepath.Join(k.WorkspacePath, "deployment")
	
	// Ensure deployment directory exists
	if err := os.MkdirAll(deploymentDir, 0755); err != nil {
		return fmt.Errorf("failed to create deployment directory: %w", err)
	}
	
	composeFile := filepath.Join(deploymentDir, "docker-compose-kafka.yml")
	if err := os.WriteFile(composeFile, []byte(composeContent), 0644); err != nil {
		return fmt.Errorf("failed to write docker-compose file: %w", err)
	}
	
	fmt.Printf("Kafka docker-compose file saved to: %s\n", composeFile)
	return nil
}

// Enable enables the Kafka service for the workspace
func (k *KafkaService) Enable() error {
	fmt.Printf("Enabling Kafka service for workspace '%s'\n", k.WorkspaceName)
	
	// Generate secrets
	secrets := k.GenerateSecrets()
	if err := k.SaveSecrets(secrets); err != nil {
		return fmt.Errorf("failed to save secrets: %w", err)
	}
	
	// Create JAAS config file
	if err := k.CreateJAASConfig(secrets); err != nil {
		return fmt.Errorf("failed to create JAAS config: %w", err)
	}
	
	// Create docker-compose file
	composeContent, err := k.CreateDockerCompose()
	if err != nil {
		return fmt.Errorf("failed to create docker-compose content: %w", err)
	}
	
	if err := k.SaveDockerCompose(composeContent); err != nil {
		return fmt.Errorf("failed to save docker-compose file: %w", err)
	}
	
	// Start the Kafka containers using docker-compose
	if err := k.StartContainer(); err != nil {
		return fmt.Errorf("failed to start Kafka containers: %w", err)
	}
	
	// Register Kafka UI with Caddy
	if err := k.RegisterWithCaddy(); err != nil {
		return fmt.Errorf("failed to register with Caddy: %w", err)
	}
	
	fmt.Println("Kafka service enabled successfully!")
	fmt.Printf("Kafka Admin Password: %s\n", secrets.KafkaAdminPassword)
	fmt.Printf("Kafka UI Password: %s\n", secrets.KafkaUIPassword)
	
	// Show access URLs
	if err := k.ShowAccessInfo(); err != nil {
		fmt.Printf("Warning: could not show access URLs: %v\n", err)
	}
	
	return nil
}

// Disable disables the Kafka service for the workspace
func (k *KafkaService) Disable() error {
	fmt.Printf("Disabling Kafka service for workspace '%s'\n", k.WorkspaceName)
	
	// Stop and remove the Kafka containers
	if err := k.StopContainer(); err != nil {
		fmt.Printf("Warning: failed to stop Kafka containers: %v\n", err)
	}
	
	// Unregister from Caddy
	if err := k.UnregisterFromCaddy(); err != nil {
		fmt.Printf("Warning: failed to unregister from Caddy: %v\n", err)
	}
	
	// Remove secrets file
	secretsFile := filepath.Join(k.WorkspacePath, "secrets", "kafka")
	if err := os.Remove(secretsFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove secrets file: %w", err)
	}
	
	// Remove deployment files
	deploymentDir := filepath.Join(k.WorkspacePath, "deployment")
	files := []string{
		"docker-compose-kafka.yml",
		"kafka_server_jaas.conf",
	}
	
	for _, file := range files {
		filePath := filepath.Join(deploymentDir, file)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("Warning: failed to remove %s: %v\n", file, err)
		}
	}
	
	fmt.Println("Kafka service disabled successfully!")
	
	return nil
}

// IsEnabled checks if Kafka service is enabled for the workspace
func (k *KafkaService) IsEnabled() bool {
	secretsFile := filepath.Join(k.WorkspacePath, "secrets", "kafka")
	composeFile := filepath.Join(k.WorkspacePath, "deployment", "docker-compose-kafka.yml")
	
	_, secretsExists := os.Stat(secretsFile)
	_, composeExists := os.Stat(composeFile)
	
	return secretsExists == nil && composeExists == nil
}

// RegisterWithCaddy registers the Kafka UI service with Caddy
func (k *KafkaService) RegisterWithCaddy() error {
	// Get workspace metadata to get the domain
	metadata, err := k.getWorkspaceMetadata()
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}
	
	if metadata.Domain == "" {
		return fmt.Errorf("no domain configured for workspace '%s'", k.WorkspaceName)
	}
	
	// Create hostname in the format: workspacename--kafka.domain
	hostname := fmt.Sprintf("%s--kafka.%s", k.WorkspaceName, metadata.Domain)
	
	// Register with Caddy using the Kafka UI container name as upstream
	upstream := fmt.Sprintf("%s__kafka-ui:8080", k.WorkspaceName)
	
	if err := caddyapi.AddRoute(hostname, upstream); err != nil {
		return fmt.Errorf("failed to register Kafka UI route: %w", err)
	}
	
	fmt.Printf("Registered Kafka UI with Caddy: %s -> %s\n", hostname, upstream)
	return nil
}

// UnregisterFromCaddy removes the Kafka UI service from Caddy
func (k *KafkaService) UnregisterFromCaddy() error {
	// Get workspace metadata to get the domain
	metadata, err := k.getWorkspaceMetadata()
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}
	
	if metadata.Domain == "" {
		return fmt.Errorf("no domain configured for workspace '%s'", k.WorkspaceName)
	}
	
	// Create hostname in the format: workspacename--kafka.domain
	hostname := fmt.Sprintf("%s--kafka.%s", k.WorkspaceName, metadata.Domain)
	
	if err := caddyapi.RemoveRoute(hostname); err != nil {
		return fmt.Errorf("failed to unregister Kafka UI route: %w", err)
	}
	
	fmt.Printf("Unregistered Kafka UI from Caddy: %s\n", hostname)
	return nil
}

// getWorkspaceMetadata retrieves workspace metadata
func (k *KafkaService) getWorkspaceMetadata() (*config.WorkspaceMetadata, error) {
	metadata, err := config.GetWorkspaceMetadata(k.WorkspaceName)
	if err != nil {
		return nil, err
	}
	return &metadata, nil
}

// ShowAccessInfo displays access information for the Kafka service
func (k *KafkaService) ShowAccessInfo() error {
	metadata, err := k.getWorkspaceMetadata()
	if err != nil {
		return err
	}
	
	fmt.Println("\nKafka Access Information:")
	
	if metadata.Domain != "" {
		hostname := fmt.Sprintf("%s--kafka.%s", k.WorkspaceName, metadata.Domain)
		fmt.Printf("  Kafka UI:   https://%s/kafka\n", hostname)
		fmt.Printf("  Username:   admin\n")
	} else {
		fmt.Printf("  No domain configured - web access not available\n")
	}
	
	fmt.Printf("  Kafka broker: %s--kafka:9092 (SASL_PLAINTEXT)\n", k.WorkspaceName)
	fmt.Printf("  SASL username: admin\n")
	
	return nil
}

// StartContainer starts the Kafka containers using docker-compose
func (k *KafkaService) StartContainer() error {
	deploymentDir := filepath.Join(k.WorkspacePath, "deployment")
	composeFile := filepath.Join(deploymentDir, "docker-compose-kafka.yml")
	
	// Check if docker-compose file exists
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		return fmt.Errorf("docker-compose file not found: %s", composeFile)
	}
	
	projectName := fmt.Sprintf("%s-kafka", k.WorkspaceName)
	
	fmt.Printf("Starting Kafka containers (project: %s)...\n", projectName)
	
	// Run docker-compose up -d
	cmd := exec.Command("docker", "compose", "-f", composeFile, "-p", projectName, "up", "-d")
	cmd.Dir = deploymentDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start Kafka containers: %w\nOutput: %s", err, string(output))
	}
	
	fmt.Printf("Kafka containers started successfully!\n")
	return nil
}

// StopContainer stops and removes the Kafka containers
func (k *KafkaService) StopContainer() error {
	deploymentDir := filepath.Join(k.WorkspacePath, "deployment")
	composeFile := filepath.Join(deploymentDir, "docker-compose-kafka.yml")
	
	projectName := fmt.Sprintf("%s-kafka", k.WorkspaceName)
	
	fmt.Printf("Stopping Kafka containers (project: %s)...\n", projectName)
	
	// Run docker-compose down
	cmd := exec.Command("docker", "compose", "-f", composeFile, "-p", projectName, "down")
	cmd.Dir = deploymentDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop Kafka containers: %w\nOutput: %s", err, string(output))
	}
	
	fmt.Printf("Kafka containers stopped successfully!\n")
	return nil
}

// IsContainerRunning checks if the Kafka containers are currently running
func (k *KafkaService) IsContainerRunning() bool {
	containerName := fmt.Sprintf("%s__kafka", k.WorkspaceName)
	
	cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return string(output) != ""
}

// ShowCredentials displays the Kafka credentials from the secrets file
func (k *KafkaService) ShowCredentials() error {
	secretsFile := filepath.Join(k.WorkspacePath, "secrets", "kafka")
	
	// Read the secrets file
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		return fmt.Errorf("failed to read secrets file: %w", err)
	}
	
	fmt.Println("\nKafka Credentials:")
	
	// Parse and display the credentials
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		if strings.HasPrefix(line, "KAFKA_ADMIN_PASSWORD=") {
			password := strings.TrimPrefix(line, "KAFKA_ADMIN_PASSWORD=")
			fmt.Printf("  Kafka Admin Password: %s\n", password)
		} else if strings.HasPrefix(line, "KAFKA_UI_PASSWORD=") {
			password := strings.TrimPrefix(line, "KAFKA_UI_PASSWORD=")
			fmt.Printf("  Kafka UI Password: %s\n", password)
		} else if strings.HasPrefix(line, "KAFKA_HOST=") {
			host := strings.TrimPrefix(line, "KAFKA_HOST=")
			fmt.Printf("  Kafka Host: %s\n", host)
		}
	}
	
	return nil
}

// UpdateImages updates the docker-compose-kafka.yml file with new images
func (k *KafkaService) UpdateImages(kafkaImage, zookeeperImage string) error {
	if kafkaImage == "" && zookeeperImage == "" {
		return nil
	}

	if kafkaImage == "" || zookeeperImage == "" {
		return fmt.Errorf("Both kafkaImage and zookeeperImage are required")
	}

	// Read the current docker-compose-kafka.yml file
	composePath := filepath.Join(k.WorkspacePath, "deployment", "docker-compose-kafka.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose-kafka.yml: %w", err)
	}
	
	// Parse the YAML
	var compose map[string]interface{}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return fmt.Errorf("failed to parse docker-compose-kafka.yml: %w", err)
	}
	
	// Update the images in the services
	if services, ok := compose["services"].(map[string]interface{}); ok {
		// Update Kafka image
		if kafkaService, ok := services["kafka"].(map[string]interface{}); ok {
			kafkaService["image"] = kafkaImage
		} else {
			return fmt.Errorf("kafka service not found in docker-compose-kafka.yml")
		}
		
		// Update Zookeeper image
		if zookeeperService, ok := services["zookeeper"].(map[string]interface{}); ok {
			zookeeperService["image"] = zookeeperImage
		} else {
			return fmt.Errorf("zookeeper service not found in docker-compose-kafka.yml")
		}
	} else {
		return fmt.Errorf("services section not found in docker-compose-kafka.yml")
	}
	
	// Write the updated file back
	updatedData, err := yaml.Marshal(compose)
	if err != nil {
		return fmt.Errorf("failed to marshal updated docker-compose: %w", err)
	}
	
	if err := os.WriteFile(composePath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write updated docker-compose-kafka.yml: %w", err)
	}
	
	return nil
}

func (k *KafkaService) UpdateToLatest() error {
	return k.UpdateImages("", "")
}

// getLatestKafkaVersion gets the latest Kafka version from DockerHub
func (k *KafkaService) getLatestKafkaVersion() (string, error) {
	return dockerhub.GetLatestKafkaVersion()
}

// getLatestZookeeperVersion gets the latest Zookeeper version from DockerHub
func (k *KafkaService) getLatestZookeeperVersion() (string, error) {
	return dockerhub.GetLatestZookeeperVersion()
} 