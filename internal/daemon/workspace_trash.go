package daemon

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// Trash semantics:
//
// A "trashed" workspace has all its containers stopped (docker compose
// down WITHOUT --volumes — data is preserved) and a marker file
// `<workspace>/.trashed` written next to its `deployment/`. The
// workspace stays in the listing under a separate "Trash" section.
// Ingress routes are *not* removed: hits to a trashed workspace
// return 502 from traefik (no upstream). ACL rows + AOC registration
// stay untouched so a restore is a no-op on the identity side.
//
// Empty-trash invokes the full hard-delete path (RunWorkspaceRemove)
// on each trashed workspace.

const trashMarkerName = ".trashed"

// trashMarkerPath returns the path to the .trashed marker for a
// workspace. It lives directly under the workspace directory so it's
// trivial to scan with a single filepath.Walk-style listing.
func trashMarkerPath(workspaceName string) (string, error) {
	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		homeDir = os.Getenv("HOME")
	}
	return filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName, trashMarkerName), nil
}

// IsWorkspaceTrashed reports whether a workspace has the trash marker.
func IsWorkspaceTrashed(workspaceName string) bool {
	p, err := trashMarkerPath(workspaceName)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// composeProjectsForWorkspace returns every docker-compose project
// name we know to be associated with a workspace, in stop order. The
// sub-traefik has two historical names (workspace_init writes
// `<ws>__traefik`; legacy code writes `bitswan-<ws>-traefik`) so we
// try both.
func composeProjectsForWorkspace(workspaceName string) []string {
	lc := strings.ToLower(workspaceName)
	return []string{
		lc + "-site",
		lc + "-dashboard",
		lc + "__traefik",
		"bitswan-" + lc + "-traefik",
	}
}

// TrashWorkspace stops all containers belonging to the workspace
// without deleting any data, then writes the trash marker. Idempotent.
func TrashWorkspace(workspaceName string, writer io.Writer) error {
	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		homeDir = os.Getenv("HOME")
	}
	wsDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)
	if _, err := os.Stat(wsDir); os.IsNotExist(err) {
		return fmt.Errorf("workspace %q not found", workspaceName)
	}

	fmt.Fprintf(writer, "Trashing workspace %s — stopping containers, keeping data on disk.\n", workspaceName)

	deploymentDir := filepath.Join(wsDir, "deployment")
	for _, project := range composeProjectsForWorkspace(workspaceName) {
		// `docker compose down` (no --volumes) leaves volumes + networks
		// alone so a restore can bring them back without losing state.
		cmd := exec.Command("docker", "compose", "-p", project, "down")
		if _, err := os.Stat(deploymentDir); err == nil {
			cmd.Dir = deploymentDir
		}
		cmd.Stdout = writer
		cmd.Stderr = writer
		_ = cmd.Run()
	}

	marker, _ := trashMarkerPath(workspaceName)
	if err := os.WriteFile(marker, []byte("trashed\n"), 0o644); err != nil {
		return fmt.Errorf("write trash marker: %w", err)
	}
	fmt.Fprintln(writer, "Workspace moved to trash.")
	return nil
}

// RestoreWorkspace removes the trash marker and brings the
// containers back up with `docker compose up -d`.
func RestoreWorkspace(workspaceName string, writer io.Writer) error {
	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		homeDir = os.Getenv("HOME")
	}
	wsDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces", workspaceName)
	if _, err := os.Stat(wsDir); os.IsNotExist(err) {
		return fmt.Errorf("workspace %q not found", workspaceName)
	}

	deploymentDir := filepath.Join(wsDir, "deployment")
	if _, err := os.Stat(deploymentDir); os.IsNotExist(err) {
		return fmt.Errorf("workspace %q has no deployment directory; can't restore", workspaceName)
	}

	fmt.Fprintf(writer, "Restoring workspace %s — bringing containers back up.\n", workspaceName)

	// Bring up the main compose project (gitops + container-manager).
	lc := strings.ToLower(workspaceName)
	mainCmd := exec.Command("docker", "compose", "-p", lc+"-site", "up", "-d")
	mainCmd.Dir = deploymentDir
	mainCmd.Stdout = writer
	mainCmd.Stderr = writer
	if err := mainCmd.Run(); err != nil {
		return fmt.Errorf("docker compose up (main): %w", err)
	}

	// Dashboard compose file lives alongside, if present.
	dashboardCompose := filepath.Join(deploymentDir, "docker-compose-dashboard.yml")
	if _, err := os.Stat(dashboardCompose); err == nil {
		dCmd := exec.Command("docker", "compose", "-f", "docker-compose-dashboard.yml", "-p", lc+"-dashboard", "up", "-d")
		dCmd.Dir = deploymentDir
		dCmd.Stdout = writer
		dCmd.Stderr = writer
		_ = dCmd.Run()
	}

	// Sub-traefik compose file lives under the workspace's traefik dir.
	subTraefikDir := filepath.Join(wsDir, "traefik")
	subTraefikCompose := filepath.Join(subTraefikDir, "docker-compose.yaml")
	if _, err := os.Stat(subTraefikCompose); err == nil {
		tCmd := exec.Command("docker", "compose", "-p", workspaceName+"__traefik", "up", "-d")
		tCmd.Dir = subTraefikDir
		tCmd.Stdout = writer
		tCmd.Stderr = writer
		_ = tCmd.Run()
	}

	marker, _ := trashMarkerPath(workspaceName)
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove trash marker: %w", err)
	}
	fmt.Fprintln(writer, "Workspace restored.")
	return nil
}

// EmptyTrashFor permanently removes every trashed workspace the
// caller owns (resolved by checking the workspace's gitops-endpoint
// ACL row). Server owners empty the whole trash regardless of who
// owns each entry.
func EmptyTrashFor(callerEmail string, callerGroups []string, isServerOwner bool, writer io.Writer) error {
	homeDir, err := config.GetRealUserHomeDir()
	if err != nil {
		homeDir = os.Getenv("HOME")
	}
	workspacesDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces")
	entries, err := os.ReadDir(workspacesDir)
	if err != nil {
		return fmt.Errorf("read workspaces dir: %w", err)
	}

	sc, _ := config.NewAutomationServerConfig().LoadConfig()
	domain := ""
	if sc != nil {
		domain = sc.ProtectedHostnameDomain()
	}

	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !IsWorkspaceTrashed(name) {
			continue
		}
		if !isServerOwner {
			// Only empty trash entries the caller owns. Owner of the
			// gitops endpoint is the workspace's owner of record.
			gitopsHost := name + "-gitops." + domain
			role, _ := roleFor(gitopsHost, callerEmail, callerGroups)
			if role != roleOwner {
				fmt.Fprintf(writer, "Skipping %s (not owner).\n", name)
				continue
			}
		}
		fmt.Fprintf(writer, "Permanently removing trashed workspace %s...\n", name)
		if err := RunWorkspaceRemove(name, writer); err != nil {
			fmt.Fprintf(writer, "Warning: failed to remove %s: %v\n", name, err)
			continue
		}
		removed++
	}
	fmt.Fprintf(writer, "Emptied %d workspace(s) from trash.\n", removed)
	return nil
}
