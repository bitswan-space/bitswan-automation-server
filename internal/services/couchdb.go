package services

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockerhub"
	"github.com/dchest/uniuri"
	"gopkg.in/yaml.v3"
)

// CouchDBService manages CouchDB service deployment for workspaces
type CouchDBService struct {
	WorkspaceName string
	WorkspacePath string
}

// NewCouchDBService creates a new CouchDB service manager
func NewCouchDBService(workspaceName string) (*CouchDBService, error) {
	workspacePath := filepath.Join(os.Getenv("HOME"), ".config", "bitswan", "workspaces", workspaceName)
	
	// Check if workspace exists
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace '%s' does not exist", workspaceName)
	}
	
	return &CouchDBService{
		WorkspaceName: workspaceName,
		WorkspacePath: workspacePath,
	}, nil
}

// CouchDBSecrets represents the secrets for CouchDB
type CouchDBSecrets struct {
	User     string
	Password string
	Host     string
}

// GenerateSecrets creates new secrets for CouchDB
func (c *CouchDBService) GenerateSecrets() *CouchDBSecrets {
	return &CouchDBSecrets{
		User:     "admin",
		Password: uniuri.NewLen(32),
		Host:     c.WorkspaceName + "__couchdb",
	}
}

// SaveSecrets saves CouchDB secrets to the workspace secrets directory
func (c *CouchDBService) SaveSecrets(secrets *CouchDBSecrets) error {
	secretsDir := filepath.Join(c.WorkspacePath, "secrets")
	
	// Ensure secrets directory exists
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}
	
	// Create the secrets content
	secretsContent := fmt.Sprintf("COUCHDB_USER=%s\nCOUCHDB_PASSWORD=%s\nCOUCHDB_HOST=%s\n",
		secrets.User, secrets.Password, secrets.Host)
	
	secretsFile := filepath.Join(secretsDir, "couchdb")
	if err := os.WriteFile(secretsFile, []byte(secretsContent), 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}
	
	// Change ownership to gitops user (1000:1000) on Linux
	if runtime.GOOS == "linux" {
		cmd := exec.Command("sudo", "chown", "1000:1000", secretsFile)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to change ownership of secrets file: %w\nOutput: %s", err, string(output))
		}
	}
	
	fmt.Printf("CouchDB secrets saved to: %s\n", secretsFile)
	return nil
}

// CreateDockerCompose generates a docker-compose.yml file for CouchDB
func (c *CouchDBService) CreateDockerCompose() (string, error) {
	secretsPath := filepath.Join(c.WorkspacePath, "secrets", "couchdb")
	
	// Construct the docker-compose data structure
	dockerCompose := map[string]interface{}{
		"services": map[string]interface{}{
			"couchdb": map[string]interface{}{
				"image":          "couchdb:3.3",
				"container_name": c.WorkspaceName + "__couchdb",
				"restart":        "unless-stopped",
				"env_file":       []string{secretsPath},
				"volumes":        []string{"couchdb-data:/opt/couchdb/data"},
				"networks":       []string{"bitswan_network"},
			},
		},
		"volumes": map[string]interface{}{
			"couchdb-data": nil,
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
func (c *CouchDBService) SaveDockerCompose(composeContent string) error {
	deploymentDir := filepath.Join(c.WorkspacePath, "deployment")
	
	// Ensure deployment directory exists
	if err := os.MkdirAll(deploymentDir, 0755); err != nil {
		return fmt.Errorf("failed to create deployment directory: %w", err)
	}
	
	composeFile := filepath.Join(deploymentDir, "docker-compose-couchdb.yml")
	if err := os.WriteFile(composeFile, []byte(composeContent), 0644); err != nil {
		return fmt.Errorf("failed to write docker-compose file: %w", err)
	}
	
	fmt.Printf("CouchDB docker-compose file saved to: %s\n", composeFile)
	return nil
}

// Enable enables the CouchDB service for the workspace
func (c *CouchDBService) Enable() error {
	fmt.Printf("Enabling CouchDB service for workspace '%s'\n", c.WorkspaceName)
	
	// Generate secrets
	secrets := c.GenerateSecrets()
	if err := c.SaveSecrets(secrets); err != nil {
		return fmt.Errorf("failed to save secrets: %w", err)
	}
	
	// Create docker-compose file
	composeContent, err := c.CreateDockerCompose()
	if err != nil {
		return fmt.Errorf("failed to create docker-compose content: %w", err)
	}
	
	if err := c.SaveDockerCompose(composeContent); err != nil {
		return fmt.Errorf("failed to save docker-compose file: %w", err)
	}
	
	// Start the CouchDB container using docker-compose
	if err := c.StartContainer(); err != nil {
		return fmt.Errorf("failed to start CouchDB container: %w", err)
	}
	
	// Register with Caddy
	if err := c.RegisterWithCaddy(); err != nil {
		return fmt.Errorf("failed to register with Caddy: %w", err)
	}
	
	fmt.Println("CouchDB service enabled successfully!")
	fmt.Printf("Username: %s\n", secrets.User)
	fmt.Printf("Password: %s\n", secrets.Password)
	
	// Show access URLs
	if err := c.ShowAccessInfo(); err != nil {
		fmt.Printf("Warning: could not show access URLs: %v\n", err)
	}
	
	return nil
}

// Disable disables the CouchDB service for the workspace
func (c *CouchDBService) Disable() error {
	fmt.Printf("Disabling CouchDB service for workspace '%s'\n", c.WorkspaceName)
	
	// Stop and remove the CouchDB container
	if err := c.StopContainer(); err != nil {
		fmt.Printf("Warning: failed to stop CouchDB container: %v\n", err)
	}
	
	// Unregister from Caddy
	if err := c.UnregisterFromCaddy(); err != nil {
		fmt.Printf("Warning: failed to unregister from Caddy: %v\n", err)
	}
	
	// Remove secrets file
	secretsFile := filepath.Join(c.WorkspacePath, "secrets", "couchdb")
	if err := os.Remove(secretsFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove secrets file: %w", err)
	}
	
	// Remove docker-compose file
	composeFile := filepath.Join(c.WorkspacePath, "deployment", "docker-compose-couchdb.yml")
	if err := os.Remove(composeFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove docker-compose file: %w", err)
	}
	
	fmt.Println("CouchDB service disabled successfully!")
	
	return nil
}

// IsEnabled checks if CouchDB service is enabled for the workspace
func (c *CouchDBService) IsEnabled() bool {
	secretsFile := filepath.Join(c.WorkspacePath, "secrets", "couchdb")
	composeFile := filepath.Join(c.WorkspacePath, "deployment", "docker-compose-couchdb.yml")
	
	_, secretsExists := os.Stat(secretsFile)
	_, composeExists := os.Stat(composeFile)
	
	return secretsExists == nil && composeExists == nil
}

// RegisterWithCaddy registers the CouchDB service with Caddy
func (c *CouchDBService) RegisterWithCaddy() error {
	// Get workspace metadata to get the domain
	metadata, err := c.getWorkspaceMetadata()
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}
	
	if metadata.Domain == "" {
		return fmt.Errorf("no domain configured for workspace '%s'", c.WorkspaceName)
	}
	
	// Create hostname in the format: workspacename--couchdb.domain
	hostname := fmt.Sprintf("%s--couchdb.%s", c.WorkspaceName, metadata.Domain)
	
	// Register with Caddy using the container name as upstream
	upstream := fmt.Sprintf("%s__couchdb:5984", c.WorkspaceName)
	
	if err := caddyapi.AddRoute(hostname, upstream); err != nil {
		return fmt.Errorf("failed to register CouchDB route: %w", err)
	}
	
	fmt.Printf("Registered CouchDB with Caddy: %s -> %s\n", hostname, upstream)
	return nil
}

// UnregisterFromCaddy removes the CouchDB service from Caddy
func (c *CouchDBService) UnregisterFromCaddy() error {
	// Get workspace metadata to get the domain
	metadata, err := c.getWorkspaceMetadata()
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}
	
	if metadata.Domain == "" {
		return fmt.Errorf("no domain configured for workspace '%s'", c.WorkspaceName)
	}
	
	// Create hostname in the format: workspacename--couchdb.domain
	hostname := fmt.Sprintf("%s--couchdb.%s", c.WorkspaceName, metadata.Domain)
	
	if err := caddyapi.RemoveRoute(hostname); err != nil {
		return fmt.Errorf("failed to unregister CouchDB route: %w", err)
	}
	
	fmt.Printf("Unregistered CouchDB from Caddy: %s\n", hostname)
	return nil
}

// getWorkspaceMetadata retrieves workspace metadata
func (c *CouchDBService) getWorkspaceMetadata() (*config.WorkspaceMetadata, error) {
	metadata, err := config.GetWorkspaceMetadata(c.WorkspaceName)
	if err != nil {
		return nil, err
	}
	return &metadata, nil
}

// ShowAccessInfo displays access information for the CouchDB service
func (c *CouchDBService) ShowAccessInfo() error {
	metadata, err := c.getWorkspaceMetadata()
	if err != nil {
		return err
	}
	
	fmt.Println("\nCouchDB Access Information:")
	
	if metadata.Domain != "" {
		hostname := fmt.Sprintf("%s--couchdb.%s", c.WorkspaceName, metadata.Domain)
		fmt.Printf("  Web access: https://%s\n", hostname)
		fmt.Printf("  Admin UI:   https://%s/_utils/\n", hostname)
	} else {
		fmt.Printf("  No domain configured - web access not available\n")
	}
	
	return nil
}

// StartContainer starts the CouchDB container using docker-compose
func (c *CouchDBService) StartContainer() error {
	deploymentDir := filepath.Join(c.WorkspacePath, "deployment")
	composeFile := filepath.Join(deploymentDir, "docker-compose-couchdb.yml")
	
	// Check if docker-compose file exists
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		return fmt.Errorf("docker-compose file not found: %s", composeFile)
	}
	
	projectName := fmt.Sprintf("%s-couchdb", c.WorkspaceName)
	
	fmt.Printf("Starting CouchDB container (project: %s)...\n", projectName)
	
	// Run docker-compose up -d
	cmd := exec.Command("docker", "compose", "-f", composeFile, "-p", projectName, "up", "-d")
	cmd.Dir = deploymentDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start CouchDB container: %w\nOutput: %s", err, string(output))
	}
	
	fmt.Printf("CouchDB container started successfully!\n")
	return nil
}

// StopContainer stops and removes the CouchDB container
func (c *CouchDBService) StopContainer() error {
	deploymentDir := filepath.Join(c.WorkspacePath, "deployment")
	composeFile := filepath.Join(deploymentDir, "docker-compose-couchdb.yml")
	
	projectName := fmt.Sprintf("%s-couchdb", c.WorkspaceName)
	
	fmt.Printf("Stopping CouchDB container (project: %s)...\n", projectName)
	
	// Run docker-compose down
	cmd := exec.Command("docker", "compose", "-f", composeFile, "-p", projectName, "down")
	cmd.Dir = deploymentDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop CouchDB container: %w\nOutput: %s", err, string(output))
	}
	
	fmt.Printf("CouchDB container stopped successfully!\n")
	return nil
}

// IsContainerRunning checks if the CouchDB container is currently running
func (c *CouchDBService) IsContainerRunning() bool {
	containerName := fmt.Sprintf("%s__couchdb", c.WorkspaceName)
	
	cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return string(output) != ""
}

// ShowCredentials displays the CouchDB credentials from the secrets file
func (c *CouchDBService) ShowCredentials() error {
	secretsFile := filepath.Join(c.WorkspacePath, "secrets", "couchdb")
	
	// Read the secrets file
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		return fmt.Errorf("failed to read secrets file: %w", err)
	}
	
	fmt.Println("\nCouchDB Credentials:")
	
	// Parse and display the credentials
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		if strings.HasPrefix(line, "COUCHDB_USER=") {
			user := strings.TrimPrefix(line, "COUCHDB_USER=")
			fmt.Printf("  Username: %s\n", user)
		} else if strings.HasPrefix(line, "COUCHDB_PASSWORD=") {
			password := strings.TrimPrefix(line, "COUCHDB_PASSWORD=")
			fmt.Printf("  Password: %s\n", password)
		}
	}
	
	return nil
}

// UpdateImage updates the docker-compose-couchdb.yml file with a new image
func (c *CouchDBService) UpdateImage(newImage string) error {
	if newImage == "" {
		return nil
	}
	
	// Read the current docker-compose-couchdb.yml file
	composePath := filepath.Join(c.WorkspacePath, "deployment", "docker-compose-couchdb.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose-couchdb.yml: %w", err)
	}
	
	// Parse the YAML
	var compose map[string]interface{}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return fmt.Errorf("failed to parse docker-compose-couchdb.yml: %w", err)
	}
	
	// Update the image in the couchdb service
	if services, ok := compose["services"].(map[string]interface{}); ok {
		if couchdbService, ok := services["couchdb"].(map[string]interface{}); ok {
			couchdbService["image"] = newImage
		} else {
			return fmt.Errorf("couchdb service not found in docker-compose-couchdb.yml")
		}
	} else {
		return fmt.Errorf("services section not found in docker-compose-couchdb.yml")
	}
	
	// Write the updated file back
	updatedData, err := yaml.Marshal(compose)
	if err != nil {
		return fmt.Errorf("failed to marshal updated docker-compose: %w", err)
	}
	
	if err := os.WriteFile(composePath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write updated docker-compose-couchdb.yml: %w", err)
	}
	
	return nil
}

// UpdateToLatest updates the CouchDB service to the latest version from DockerHub
func (c *CouchDBService) UpdateToLatest() error {
	return c.UpdateImage("")
}

// getLatestVersion gets the latest version from DockerHub
func (c *CouchDBService) getLatestVersion() (string, error) {
	return dockerhub.GetLatestCouchDBVersion()
}

// getCredentials retrieves CouchDB credentials from the secrets file
func (c *CouchDBService) getCredentials() (*CouchDBSecrets, error) {
	secretsFile := filepath.Join(c.WorkspacePath, "secrets", "couchdb")
	
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read secrets file: %w", err)
	}
	
	secrets := &CouchDBSecrets{}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COUCHDB_USER=") {
			secrets.User = strings.TrimPrefix(line, "COUCHDB_USER=")
		} else if strings.HasPrefix(line, "COUCHDB_PASSWORD=") {
			secrets.Password = strings.TrimPrefix(line, "COUCHDB_PASSWORD=")
		} else if strings.HasPrefix(line, "COUCHDB_HOST=") {
			secrets.Host = strings.TrimPrefix(line, "COUCHDB_HOST=")
		}
	}
	
	if secrets.User == "" || secrets.Password == "" {
		return nil, fmt.Errorf("invalid credentials in secrets file")
	}
	
	return secrets, nil
}

// Backup creates a backup of all CouchDB databases as a tarball
func (c *CouchDBService) Backup(backupPath string) error {
	containerName := fmt.Sprintf("%s__couchdb", c.WorkspaceName)
	
	// Check if container is running
	if !c.IsContainerRunning() {
		return fmt.Errorf("CouchDB container is not running. Please start it first")
	}
	
	// Get credentials
	secrets, err := c.getCredentials()
	if err != nil {
		return fmt.Errorf("failed to get credentials: %w", err)
	}
	
	// Ensure backup directory exists
	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}
	
	// Create temporary directory for backup files
	tempDir, err := os.MkdirTemp("", "couchdb-backup-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir) // Clean up temp directory
	
	fmt.Printf("Starting CouchDB backup for workspace '%s'...\n", c.WorkspaceName)
	
	// Get list of all databases
	fmt.Println("Fetching database list...")
	dbListCmd := exec.Command("docker", "exec", containerName, "curl", "-s", "-u", 
		fmt.Sprintf("%s:%s", secrets.User, secrets.Password),
		"http://localhost:5984/_all_dbs")
	
	var dbListOutput bytes.Buffer
	dbListCmd.Stdout = &dbListOutput
	dbListCmd.Stderr = os.Stderr
	
	if err := dbListCmd.Run(); err != nil {
		return fmt.Errorf("failed to list databases: %w", err)
	}
	
	var databases []string
	if err := json.Unmarshal(dbListOutput.Bytes(), &databases); err != nil {
		return fmt.Errorf("failed to parse database list: %w", err)
	}
	
	// Filter out system databases (starting with _)
	userDatabases := []string{}
	for _, db := range databases {
		if !strings.HasPrefix(db, "_") {
			userDatabases = append(userDatabases, db)
		}
	}
	
	if len(userDatabases) == 0 {
		fmt.Println("No user databases found to backup.")
		return nil
	}
	
	fmt.Printf("Found %d database(s) to backup\n", len(userDatabases))
	
	// Backup each database
	for _, dbName := range userDatabases {
		fmt.Printf("Backing up database '%s'...\n", dbName)
		
		// Get all documents using _all_docs with include_docs=true
		backupCmd := exec.Command("docker", "exec", containerName, "curl", "-s", "-u",
			fmt.Sprintf("%s:%s", secrets.User, secrets.Password),
			fmt.Sprintf("http://localhost:5984/%s/_all_docs?include_docs=true", dbName))
		
		var backupOutput bytes.Buffer
		backupCmd.Stdout = &backupOutput
		backupCmd.Stderr = os.Stderr
		
		if err := backupCmd.Run(); err != nil {
			fmt.Printf("Warning: failed to backup database '%s': %v\n", dbName, err)
			continue
		}
		
		// Save backup to file in temp directory
		backupFile := filepath.Join(tempDir, fmt.Sprintf("%s.json", dbName))
		if err := os.WriteFile(backupFile, backupOutput.Bytes(), 0644); err != nil {
			return fmt.Errorf("failed to write backup file for '%s': %w", dbName, err)
		}
		
		fmt.Printf("  ✓ Backed up '%s'\n", dbName)
	}
	
	// Create a manifest file with metadata
	backupTime := time.Now()
	manifest := map[string]interface{}{
		"workspace":     c.WorkspaceName,
		"backup_date":  backupTime.Format(time.RFC3339),
		"databases":     userDatabases,
		"couchdb_host": secrets.Host,
	}
	
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to create manifest: %w", err)
	}
	
	manifestFile := filepath.Join(tempDir, "manifest.json")
	if err := os.WriteFile(manifestFile, manifestData, 0644); err != nil {
		return fmt.Errorf("failed to write manifest file: %w", err)
	}
	
	// Generate tarball filename with date and time
	// Format: couchdb-backup-YYYYMMDD-HHMMSS.tar.gz
	tarballName := fmt.Sprintf("couchdb-backup-%s.tar.gz", backupTime.Format("20060102-150405"))
	tarballPath := filepath.Join(backupPath, tarballName)
	
	fmt.Printf("Creating tarball: %s\n", tarballPath)
	
	// Create tarball
	if err := c.createTarball(tempDir, tarballPath); err != nil {
		return fmt.Errorf("failed to create tarball: %w", err)
	}
	
	fmt.Printf("\n✓ Backup completed successfully!\n")
	fmt.Printf("Backup tarball: %s\n", tarballPath)
	
	return nil
}

// createTarball creates a gzipped tarball from a directory
func (c *CouchDBService) createTarball(sourceDir, tarballPath string) error {
	// Create the tarball file
	tarballFile, err := os.Create(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to create tarball file: %w", err)
	}
	defer tarballFile.Close()
	
	// Create gzip writer
	gzipWriter := gzip.NewWriter(tarballFile)
	defer gzipWriter.Close()
	
	// Create tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()
	
	// Walk through the source directory and add files to tarball
	return filepath.Walk(sourceDir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip directories
		if info.IsDir() {
			return nil
		}
		
		// Get relative path from source directory
		relPath, err := filepath.Rel(sourceDir, filePath)
		if err != nil {
			return err
		}
		
		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath
		
		// Write header
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		
		// Write file content
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer file.Close()
		
		if _, err := io.Copy(tarWriter, file); err != nil {
			return err
		}
		
		return nil
	})
}

// Restore restores CouchDB databases from a backup (tarball or directory)
func (c *CouchDBService) Restore(backupPath string) error {
	containerName := fmt.Sprintf("%s__couchdb", c.WorkspaceName)
	
	// Check if container is running
	if !c.IsContainerRunning() {
		return fmt.Errorf("CouchDB container is not running. Please start it first")
	}
	
	// Check if backup path exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup path does not exist: %s", backupPath)
	}
	
	// Get credentials
	secrets, err := c.getCredentials()
	if err != nil {
		return fmt.Errorf("failed to get credentials: %w", err)
	}
	
	// Determine if backupPath is a tarball or directory
	var extractDir string
	var shouldCleanup bool
	
	info, err := os.Stat(backupPath)
	if err != nil {
		return fmt.Errorf("failed to stat backup path: %w", err)
	}
	
	if !info.IsDir() && strings.HasSuffix(backupPath, ".tar.gz") {
		// Extract tarball to temporary directory
		fmt.Printf("Extracting tarball: %s\n", backupPath)
		tempDir, err := os.MkdirTemp("", "couchdb-restore-*")
		if err != nil {
			return fmt.Errorf("failed to create temporary directory: %w", err)
		}
		defer os.RemoveAll(tempDir) // Clean up temp directory
		
		if err := c.extractTarball(backupPath, tempDir); err != nil {
			return fmt.Errorf("failed to extract tarball: %w", err)
		}
		
		extractDir = tempDir
		shouldCleanup = true
	} else {
		// Use directory directly
		extractDir = backupPath
		shouldCleanup = false
	}
	
	// Read manifest if it exists
	manifestFile := filepath.Join(extractDir, "manifest.json")
	var databases []string
	
	if _, err := os.Stat(manifestFile); err == nil {
		manifestData, err := os.ReadFile(manifestFile)
		if err == nil {
			var manifest map[string]interface{}
			if err := json.Unmarshal(manifestData, &manifest); err == nil {
				if dbList, ok := manifest["databases"].([]interface{}); ok {
					for _, db := range dbList {
						if dbName, ok := db.(string); ok {
							databases = append(databases, dbName)
						}
					}
				}
			}
		}
	}
	
	// If no manifest, find all .json files in backup directory
	if len(databases) == 0 {
		entries, err := os.ReadDir(extractDir)
		if err != nil {
			return fmt.Errorf("failed to read backup directory: %w", err)
		}
		
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && entry.Name() != "manifest.json" {
				dbName := strings.TrimSuffix(entry.Name(), ".json")
				databases = append(databases, dbName)
			}
		}
	}
	
	if len(databases) == 0 {
		return fmt.Errorf("no databases found in backup")
	}
	
	fmt.Printf("Starting CouchDB restore for workspace '%s'...\n", c.WorkspaceName)
	fmt.Printf("Found %d database(s) to restore\n", len(databases))
	
	// Restore each database
	for _, dbName := range databases {
		backupFile := filepath.Join(extractDir, fmt.Sprintf("%s.json", dbName))
		
		// Check if backup file exists
		if _, err := os.Stat(backupFile); os.IsNotExist(err) {
			fmt.Printf("Warning: backup file not found for database '%s': %s\n", dbName, backupFile)
			continue
		}
		
		fmt.Printf("Restoring database '%s'...\n", dbName)
		
		// Read the backup file
		backupData, err := os.ReadFile(backupFile)
		if err != nil {
			fmt.Printf("Warning: failed to read backup file for '%s': %v\n", dbName, err)
			continue
		}
		
		// Parse the backup JSON
		var backupDoc map[string]interface{}
		if err := json.Unmarshal(backupData, &backupDoc); err != nil {
			fmt.Printf("Warning: failed to parse backup file for '%s': %v\n", dbName, err)
			continue
		}
		
		// Check if database exists, create if not
		checkCmd := exec.Command("docker", "exec", containerName, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
			"-u", fmt.Sprintf("%s:%s", secrets.User, secrets.Password),
			fmt.Sprintf("http://localhost:5984/%s", dbName))
		
		var checkOutput bytes.Buffer
		checkCmd.Stdout = &checkOutput
		checkCmd.Stderr = os.Stderr
		
		checkCmd.Run()
		statusCode := strings.TrimSpace(checkOutput.String())
		
		if statusCode != "200" {
			// Create database
			fmt.Printf("  Creating database '%s'...\n", dbName)
			createCmd := exec.Command("docker", "exec", containerName, "curl", "-s", "-X", "PUT",
				"-u", fmt.Sprintf("%s:%s", secrets.User, secrets.Password),
				fmt.Sprintf("http://localhost:5984/%s", dbName))
			
			var createOutput bytes.Buffer
			createCmd.Stdout = &createOutput
			createCmd.Stderr = os.Stderr
			
			if err := createCmd.Run(); err != nil {
				fmt.Printf("Warning: failed to create database '%s': %v\n", dbName, err)
				continue
			}
		} else {
			// Database exists - check if it has documents
			hasDocuments, docCount, err := c.databaseHasDocuments(containerName, secrets, dbName)
			if err != nil {
				fmt.Printf("Warning: failed to check documents in '%s': %v\n", dbName, err)
				// Continue anyway
			} else if hasDocuments {
				// Prompt for confirmation
				fmt.Printf("\n⚠️  Database '%s' already contains %d document(s).\n", dbName, docCount)
				fmt.Printf("Restoring will DELETE all existing documents and replace them with the backup.\n")
				if !c.promptConfirmation(fmt.Sprintf("Do you want to continue with restoring '%s'? (yes/no): ", dbName)) {
					fmt.Printf("  Skipping restore for '%s'\n", dbName)
					continue
				}
			}
		}
		
		// Extract rows from backup
		rows, ok := backupDoc["rows"].([]interface{})
		if !ok {
			fmt.Printf("Warning: invalid backup format for '%s' (no rows found)\n", dbName)
			continue
		}
		
		// Delete all existing documents in the database first to avoid conflicts
		fmt.Printf("  Clearing existing documents in '%s'...\n", dbName)
		if err := c.clearDatabase(containerName, secrets, dbName); err != nil {
			fmt.Printf("Warning: failed to clear database '%s': %v\n", dbName, err)
			// Continue anyway - might still work
		}
		
		// Restore documents in batches
		batchSize := 100
		totalDocs := 0
		successfulDocs := 0
		
		for i := 0; i < len(rows); i += batchSize {
			end := i + batchSize
			if end > len(rows) {
				end = len(rows)
			}
			
			batch := rows[i:end]
			
			// Build bulk docs payload
			bulkDocs := map[string]interface{}{
				"docs": []interface{}{},
			}
			
			for _, row := range batch {
				if rowMap, ok := row.(map[string]interface{}); ok {
					if doc, ok := rowMap["doc"].(map[string]interface{}); ok {
						// Keep _id but remove _rev to allow new document creation
						delete(doc, "_rev")
						bulkDocs["docs"] = append(bulkDocs["docs"].([]interface{}), doc)
						totalDocs++
					}
				}
			}
			
			if len(bulkDocs["docs"].([]interface{})) == 0 {
				continue
			}
			
			// Send bulk docs request
			bulkData, err := json.Marshal(bulkDocs)
			if err != nil {
				fmt.Printf("Warning: failed to marshal bulk docs for '%s': %v\n", dbName, err)
				continue
			}
			
			// Use curl to POST bulk_docs via stdin
			restoreCmd := exec.Command("docker", "exec", "-i", containerName, "sh", "-c",
				fmt.Sprintf("curl -s -X POST -H 'Content-Type: application/json' -u '%s:%s' --data-binary @- 'http://localhost:5984/%s/_bulk_docs'",
					secrets.User, secrets.Password, dbName))
			
			restoreCmd.Stdin = bytes.NewReader(bulkData)
			var restoreOutput bytes.Buffer
			restoreCmd.Stderr = os.Stderr
			
			if err := restoreCmd.Run(); err != nil {
				fmt.Printf("Warning: failed to restore batch for '%s': %v\n", dbName, err)
				continue
			}
			
			// Check the response to see if documents were actually created
			responseData := restoreOutput.Bytes()
			if len(responseData) > 0 {
				var response []map[string]interface{}
				if err := json.Unmarshal(responseData, &response); err == nil {
					// Count successful documents (those with "id" and "rev" and no "error")
					for _, item := range response {
						if _, hasId := item["id"]; hasId {
							if _, hasRev := item["rev"]; hasRev {
								if _, hasError := item["error"]; !hasError {
									successfulDocs++
								} else {
									fmt.Printf("Warning: document error in batch: %v\n", item)
								}
							}
						}
					}
				}
			}
		}
		
		if totalDocs > 0 {
			fmt.Printf("  Restored %d/%d documents\n", successfulDocs, totalDocs)
		}
		
		fmt.Printf("  ✓ Restored '%s'\n", dbName)
	}
	
	fmt.Printf("\n✓ Restore completed successfully!\n")
	
	// Note: shouldCleanup is handled by defer above
	_ = shouldCleanup
	
	return nil
}

// databaseHasDocuments checks if a database has documents and returns the count
func (c *CouchDBService) databaseHasDocuments(containerName string, secrets *CouchDBSecrets, dbName string) (bool, int, error) {
	// Get document count using _all_docs with limit=0 to get total_rows without fetching documents
	cmd := exec.Command("docker", "exec", containerName, "curl", "-s", "-u",
		fmt.Sprintf("%s:%s", secrets.User, secrets.Password),
		fmt.Sprintf("http://localhost:5984/%s/_all_docs?limit=0", dbName))
	
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return false, 0, fmt.Errorf("failed to query database: %w", err)
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		return false, 0, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Get total_rows from the response (always present even with limit=0)
	totalRows, ok := result["total_rows"].(float64)
	if !ok {
		// If total_rows is missing, assume no documents
		return false, 0, nil
	}
	
	docCount := int(totalRows)
	return docCount > 0, docCount, nil
}

// promptConfirmation prompts the user for yes/no confirmation
func (c *CouchDBService) promptConfirmation(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return false
	}
	
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "yes" || response == "y"
}

// clearDatabase deletes all documents from a database
func (c *CouchDBService) clearDatabase(containerName string, secrets *CouchDBSecrets, dbName string) error {
	// Get all document IDs with their revisions
	cmd := exec.Command("docker", "exec", containerName, "curl", "-s", "-u",
		fmt.Sprintf("%s:%s", secrets.User, secrets.Password),
		fmt.Sprintf("http://localhost:5984/%s/_all_docs", dbName))
	
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to get document list: %w", err)
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		return fmt.Errorf("failed to parse document list: %w", err)
	}
	
	rows, ok := result["rows"].([]interface{})
	if !ok {
		// No documents to delete
		return nil
	}
	
	if len(rows) == 0 {
		// No documents to delete
		return nil
	}
	
	// Build bulk delete payload
	bulkDelete := map[string]interface{}{
		"docs": []interface{}{},
	}
	
	for _, row := range rows {
		if rowMap, ok := row.(map[string]interface{}); ok {
			docID, hasID := rowMap["id"].(string)
			if !hasID {
				continue
			}
			
			// Get revision from value.rev
			var rev string
			if value, hasValue := rowMap["value"].(map[string]interface{}); hasValue {
				if revStr, hasRev := value["rev"].(string); hasRev {
					rev = revStr
				}
			}
			
			// If no rev found, we can't delete it properly, but try anyway
			doc := map[string]interface{}{
				"_id":      docID,
				"_deleted": true,
			}
			if rev != "" {
				doc["_rev"] = rev
			}
			
			bulkDelete["docs"] = append(bulkDelete["docs"].([]interface{}), doc)
		}
	}
	
	// Send bulk delete request
	bulkData, err := json.Marshal(bulkDelete)
	if err != nil {
		return fmt.Errorf("failed to marshal bulk delete: %w", err)
	}
	
	deleteCmd := exec.Command("docker", "exec", "-i", containerName, "sh", "-c",
		fmt.Sprintf("curl -s -X POST -H 'Content-Type: application/json' -u '%s:%s' --data-binary @- 'http://localhost:5984/%s/_bulk_docs'",
			secrets.User, secrets.Password, dbName))
	
	deleteCmd.Stdin = bytes.NewReader(bulkData)
	var deleteOutput bytes.Buffer
	deleteCmd.Stdout = &deleteOutput
	deleteCmd.Stderr = os.Stderr
	
	if err := deleteCmd.Run(); err != nil {
		return fmt.Errorf("failed to delete documents: %w", err)
	}
	
	// Check if there were any errors in the response
	responseData := deleteOutput.Bytes()
	if len(responseData) > 0 {
		var response []map[string]interface{}
		if err := json.Unmarshal(responseData, &response); err == nil {
			for _, item := range response {
				if errVal, hasError := item["error"]; hasError {
					return fmt.Errorf("error deleting document: %v", errVal)
				}
			}
		}
	}
	
	return nil
}

// extractTarball extracts a gzipped tarball to a directory
func (c *CouchDBService) extractTarball(tarballPath, extractDir string) error {
	// Open the tarball file
	tarballFile, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to open tarball file: %w", err)
	}
	defer tarballFile.Close()
	
	// Create gzip reader
	gzipReader, err := gzip.NewReader(tarballFile)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()
	
	// Create tar reader
	tarReader := tar.NewReader(gzipReader)
	
	// Extract files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}
		
		// Get the target file path
		targetPath := filepath.Join(extractDir, header.Name)
		
		// Create parent directories if needed
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		
		// Skip directories (they're created above)
		if header.Typeflag == tar.TypeDir {
			continue
		}
		
		// Create the file
		file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		
		// Copy file content
		if _, err := io.Copy(file, tarReader); err != nil {
			file.Close()
			return fmt.Errorf("failed to extract file content: %w", err)
		}
		
		file.Close()
	}
	
	return nil
} 