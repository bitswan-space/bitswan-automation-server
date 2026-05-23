package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Phase 5 meta-tests: editor support is gone. The workspace-dashboard
// is the only workspace-facing app the daemon brings up. These tests
// fail loudly if the editor service ever crawls back in.
//
// We can't import internal/services here because it would create an
// import cycle (daemon → services → daemon helpers). Instead the
// tests grep the daemon source and config tree as a static check.

// repoRoot finds the repository root by walking up from this test file.
// Cheaper than depending on $GOPATH-style layouts.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(here)
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found walking up from test file")
	return ""
}

// readFile is a tiny wrapper that fails the test rather than ignoring errors.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestWorkspaceInit_NoEditorEnable(t *testing.T) {
	root := repoRoot(t)
	src := readFile(t, filepath.Join(root, "internal/daemon/workspace_init.go"))
	for _, needle := range []string{
		"NewEditorService(",
		"editorService.Enable(",
		"editorService.StartContainer(",
		"editorService.WaitForEditorReady(",
		"editorService.GetEditorPassword(",
	} {
		if strings.Contains(src, needle) {
			t.Errorf("workspace_init.go still calls %q — editor service must not be brought up at init", needle)
		}
	}
}

func TestWorkspaceInit_NoEditorRoute(t *testing.T) {
	root := repoRoot(t)
	src := readFile(t, filepath.Join(root, "internal/daemon/workspace_init.go"))
	if strings.Contains(src, `Fprintf(writer, "Bitswan Editor URL`) ||
		strings.Contains(src, `Bitswan Editor URL: https://%s-editor.%s`) {
		t.Error("workspace_init.go is still printing the BITSWAN EDITOR URL banner")
	}
	if strings.Contains(src, `editorHostname := fmt.Sprintf("%s-editor.`) {
		t.Error("workspace_init.go is still computing the editor hostname for route registration")
	}
}

func TestWorkspaceInit_NoEditorURLInRegisterWorkspace(t *testing.T) {
	root := repoRoot(t)
	src := readFile(t, filepath.Join(root, "internal/daemon/workspace_init.go"))
	// The editor URL used to be assembled into a *string and passed to
	// aocClient.RegisterWorkspace. Now nil is always passed.
	if strings.Contains(src, `editorURL = &url`) {
		t.Error("workspace_init.go still assigns &url to editorURL — editor URL must be nil in RegisterWorkspace")
	}
}

func TestSaveMetadata_NoEditorURL(t *testing.T) {
	root := repoRoot(t)
	src := readFile(t, filepath.Join(root, "internal/daemon/workspace_init.go"))
	// metadata.EditorURL = &editorURL was the only assignment of EditorURL
	// in the daemon's init flow.
	if strings.Contains(src, "metadata.EditorURL = &editorURL") {
		t.Error("saveMetadata still writes EditorURL into the workspace metadata; should be nil now")
	}
}
