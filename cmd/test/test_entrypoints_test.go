package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each integration-test entrypoint relies on the same pre-conditions:
//   - bitswan/gitops-local:latest built from the matching feature branch
//   - bitswan/container-manager:latest built locally (no published image)
//
// ensureGitopsImage() and ensureContainerManagerImage() are the helpers
// that do that work. A regression that adds a new entrypoint without
// calling them would silently fall back to the workflow's main-clone
// gitops image (incompatible) or a missing container-manager image
// (workspace init fails at compose up). Pin all four entrypoint files
// so a missing call fails this test instead of just CI.

func mustReadEntrypoint(t *testing.T, rel string) string {
	t.Helper()
	// Tests run from cmd/test/ so the file is sibling.
	data, err := os.ReadFile(filepath.Join(".", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func TestEntrypoints_BuildGitopsImage(t *testing.T) {
	entrypoints := []string{
		"init.go",
		"update.go",
		"pull_and_deploy.go",
		"mqtt_workspace.go",
	}
	for _, ep := range entrypoints {
		t.Run(ep, func(t *testing.T) {
			src := mustReadEntrypoint(t, ep)
			if !strings.Contains(src, "ensureGitopsImage()") {
				t.Errorf("%s does not call ensureGitopsImage() — workflow main-clone will leak through", ep)
			}
		})
	}
}

func TestEntrypoints_BuildContainerManagerImage(t *testing.T) {
	entrypoints := []string{
		"init.go",
		"update.go",
		"pull_and_deploy.go",
		"mqtt_workspace.go",
	}
	for _, ep := range entrypoints {
		t.Run(ep, func(t *testing.T) {
			src := mustReadEntrypoint(t, ep)
			if !strings.Contains(src, "ensureContainerManagerImage()") {
				t.Errorf("%s does not call ensureContainerManagerImage() — docker compose up will fail to pull the missing image", ep)
			}
		})
	}
}

func TestEntrypoints_PassOwnerFlag(t *testing.T) {
	// The bailey ACL refactor made --owner mandatory on workspace init.
	// Every cmd/test path that runs 'workspace init' (directly or via the
	// MQTT bridge as 'owner') must include a stable placeholder email so
	// CI doesn't fail with 'owner is required'.
	cases := []struct {
		file   string
		needle string
	}{
		{"init.go", `"--owner", "ci-test@example.com"`},
		{"update.go", `"--owner", "ci-test@example.com"`},
		{"pull_and_deploy.go", `"--owner", "ci-test@example.com"`},
		// MQTT goes through the JSON wire schema instead of CLI args.
		{"mqtt_workspace.go", `"owner":      "ci-test@example.com"`},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			src := mustReadEntrypoint(t, c.file)
			if !strings.Contains(src, c.needle) {
				t.Errorf("%s missing owner placeholder %q — workspace init will fail with 'owner is required'", c.file, c.needle)
			}
		})
	}
}
