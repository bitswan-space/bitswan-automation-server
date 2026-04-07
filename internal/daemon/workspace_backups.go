package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/automations"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// enableWorkspaceBackups creates an S3 backup bucket via AOC and configures
// the workspace's gitops service with the backup credentials.
func enableWorkspaceBackups(workspaceName string, publisher *MQTTPublisher, requestID string) error {
	metadata, err := config.GetWorkspaceMetadata(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to get workspace metadata: %w", err)
	}

	if metadata.WorkspaceId == nil || *metadata.WorkspaceId == "" {
		return fmt.Errorf("workspace is not registered with AOC yet")
	}

	// Create backup bucket via AOC backend
	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		return fmt.Errorf("failed to create AOC client: %w", err)
	}

	publisher.publishLog(requestID, "info", "Creating S3 backup bucket...")
	backupCreds, err := aocClient.CreateBackupBucket(*metadata.WorkspaceId)
	if err != nil {
		return fmt.Errorf("failed to create backup bucket: %w", err)
	}

	publisher.publishLog(requestID, "info", fmt.Sprintf("Backup bucket created: %s", backupCreds.BucketName))

	// Configure gitops backup service
	gitopsPayload := map[string]interface{}{
		"s3_endpoint":   backupCreds.S3Endpoint,
		"s3_bucket":     backupCreds.BucketName,
		"s3_access_key": backupCreds.AccessKey,
		"s3_secret_key": backupCreds.SecretKey,
		"s3_region":     backupCreds.Region,
	}

	reqURL := fmt.Sprintf("%s/backups/config", metadata.GitopsURL)
	reqURL = automations.TransformURLForDaemon(reqURL, workspaceName)

	bodyBytes, err := json.Marshal(gitopsPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal backup config: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+metadata.GitopsSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send backup config to gitops: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("gitops returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
