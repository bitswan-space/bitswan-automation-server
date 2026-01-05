package test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newCleanupCmd() *cobra.Command {
	var pattern string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Remove all test workspaces",
		Long:  "Removes all workspaces matching the test pattern (default: 'test-'). Use --pattern to customize.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestCleanup(pattern, dryRun)
		},
	}

	cmd.Flags().StringVar(&pattern, "pattern", "test-", "Pattern to match workspace names (default: 'test-')")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be removed without actually removing")

	return cmd
}

func runTestCleanup(pattern string, dryRun bool) error {
	fmt.Println("=== BitSwan Test Cleanup ===")
	fmt.Println()

	client, err := daemon.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create daemon client: %w", err)
	}

	// List all workspaces
	result, err := client.ListWorkspaces(false, false)
	if err != nil {
		return fmt.Errorf("failed to list workspaces: %w", err)
	}

	// Filter test workspaces
	var testWorkspaces []string
	for _, workspace := range result.Workspaces {
		if strings.HasPrefix(workspace.Name, pattern) {
			testWorkspaces = append(testWorkspaces, workspace.Name)
		}
	}

	if len(testWorkspaces) == 0 {
		fmt.Printf("No workspaces found matching pattern '%s'\n", pattern)
		return nil
	}

	fmt.Printf("Found %d test workspace(s) matching pattern '%s':\n", len(testWorkspaces), pattern)
	for _, name := range testWorkspaces {
		fmt.Printf("  • %s\n", name)
	}

	if dryRun {
		fmt.Println("\n[DRY RUN] Would remove the above workspaces. Run without --dry-run to actually remove them.")
		return nil
	}

	fmt.Printf("\n⚠️  This will remove %d workspace(s) without confirmation.\n", len(testWorkspaces))
	fmt.Printf("\nRemoving %d workspace(s)...\n\n", len(testWorkspaces))

	successCount := 0
	failCount := 0

	for i, workspaceName := range testWorkspaces {
		fmt.Printf("[%d/%d] Removing %s...\n", i+1, len(testWorkspaces), workspaceName)

		// Try to remove via daemon first
		if err := client.WorkspaceRemove(workspaceName); err != nil {
			// If removal fails due to missing deployment directory (broken workspace),
			// try to remove the directory directly
			if strings.Contains(err.Error(), "no such file or directory") || 
			   strings.Contains(err.Error(), "deployment") {
				fmt.Printf("  ⚠️  Workspace appears broken, attempting direct directory removal...\n")
				
				// Get workspace directory path
				homeDir := os.Getenv("HOME")
				if homeDir == "" {
					homeDir = os.Getenv("HOME")
				}
				workspacePath := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)
				
				// Remove directory directly
				if err := os.RemoveAll(workspacePath); err != nil {
					fmt.Printf("  ❌ Failed to remove broken workspace %s: %v\n", workspaceName, err)
					failCount++
				} else {
					fmt.Printf("  ✅ Removed broken workspace %s (directory only)\n", workspaceName)
					successCount++
				}
			} else {
				fmt.Printf("  ❌ Failed to remove %s: %v\n", workspaceName, err)
				failCount++
			}
		} else {
			fmt.Printf("  ✅ Removed %s\n", workspaceName)
			successCount++
		}
	}

	fmt.Println()
	fmt.Printf("=== Cleanup Complete ===\n")
	fmt.Printf("Successfully removed: %d\n", successCount)
	if failCount > 0 {
		fmt.Printf("Failed to remove: %d\n", failCount)
	}

	return nil
}

