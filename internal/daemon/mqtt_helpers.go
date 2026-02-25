package daemon

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// syncWorkspaceListToAOC syncs the workspace list with AOC via REST API
// Returns nil if AOC is not configured (not an error)
func syncWorkspaceListToAOC() error {
	// Get the current workspace list
	result, err := GetWorkspaceList(false, false)
	if err != nil {
		return fmt.Errorf("failed to get workspace list: %w", err)
	}

	// Build workspace entries with IDs from metadata
	workspaceEntries := make([]map[string]interface{}, 0, len(result.Workspaces))
	for _, ws := range result.Workspaces {
		entry := map[string]interface{}{
			"name": ws.Name,
		}

		// Try to read workspace ID from metadata.yaml
		if metadata, err := config.GetWorkspaceMetadata(ws.Name); err == nil && metadata.WorkspaceId != nil {
			entry["id"] = *metadata.WorkspaceId
		}

		// Add editor_url and domain if available in metadata
		if metadata, err := config.GetWorkspaceMetadata(ws.Name); err == nil {
			if metadata.EditorURL != nil {
				entry["editor_url"] = *metadata.EditorURL
			}
			if metadata.Domain != "" {
				entry["domain"] = metadata.Domain
			}
		}

		workspaceEntries = append(workspaceEntries, entry)
	}

	// Create AOC client
	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		// AOC not configured, this is not an error
		return nil
	}

	// Sync workspace list with AOC
	if err := aocClient.SyncWorkspaceList(workspaceEntries); err != nil {
		return fmt.Errorf("failed to sync workspace list: %w", err)
	}

	fmt.Printf("Successfully synced workspace list to AOC: %d workspaces\n", len(workspaceEntries))
	return nil
}

