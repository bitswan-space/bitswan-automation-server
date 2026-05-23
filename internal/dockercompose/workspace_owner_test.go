package dockercompose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupGitopsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "gitops"), 0o755); err != nil {
		t.Fatalf("mkdir gitops: %v", err)
	}
	return dir
}

// The gitops container needs BITSWAN_WORKSPACE_OWNER in its environment
// so it can pass the deployer's email to /ingress/add-route when an
// automation is registered with `expose: true`. Without it the bailey
// ACL row gets created with no owner and the app never appears on
// the dashboard. Pin this wiring.

func TestComposeFile_GitopsHasWorkspaceOwnerEnv(t *testing.T) {
	cfg := &DockerComposeConfig{
		GitopsPath:     setupGitopsDir(t),
		WorkspaceName:  "owner-test",
		GitopsImage:    "test/gitops:latest",
		Domain:         "example.com",
		WorkspaceOwner: "alice@example.com",
	}
	yaml, _, err := cfg.CreateDockerComposeFile()
	if err != nil {
		t.Fatalf("CreateDockerComposeFile: %v", err)
	}
	if !strings.Contains(yaml, "BITSWAN_WORKSPACE_OWNER=alice@example.com") {
		t.Errorf("compose YAML missing BITSWAN_WORKSPACE_OWNER env, got:\n%s", yaml)
	}
}

func TestComposeFile_OmitsOwnerEnvWhenUnset(t *testing.T) {
	// If somebody constructs a Config without a WorkspaceOwner (older
	// callers, tests), don't inject an empty BITSWAN_WORKSPACE_OWNER= line
	// — gitops checks the env var with `or None`, so empty is fine, but
	// a missing key is clearer.
	cfg := &DockerComposeConfig{
		GitopsPath:    setupGitopsDir(t),
		WorkspaceName: "owner-test",
		GitopsImage:   "test/gitops:latest",
		Domain:        "example.com",
	}
	yaml, _, err := cfg.CreateDockerComposeFile()
	if err != nil {
		t.Fatalf("CreateDockerComposeFile: %v", err)
	}
	if strings.Contains(yaml, "BITSWAN_WORKSPACE_OWNER") {
		t.Errorf("compose YAML should not include BITSWAN_WORKSPACE_OWNER when unset, got:\n%s", yaml)
	}
}
