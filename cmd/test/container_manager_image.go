package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ensureContainerManagerImage builds bitswan/container-manager:latest from
// the local Dockerfile.container-manager if the image is not already
// present on the host. The container-manager binary is in this repo
// (cmd/containermanager) but its Docker image is not published, so
// docker compose --pull missing fails to fetch it. Cheap workaround:
// build it on first test invocation; subsequent invocations no-op.
func ensureContainerManagerImage() error {
	const image = "bitswan/container-manager:latest"

	// `docker image inspect` exits 0 if present, non-0 otherwise.
	if err := exec.Command("docker", "image", "inspect", image).Run(); err == nil {
		fmt.Printf("✓ %s already present\n", image)
		return nil
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		return fmt.Errorf("locate repo root: %w", err)
	}
	dockerfile := filepath.Join(repoRoot, "Dockerfile.container-manager")
	if _, err := os.Stat(dockerfile); err != nil {
		return fmt.Errorf("%s not found: %w", dockerfile, err)
	}

	fmt.Printf("Building %s from %s...\n", image, dockerfile)
	cmd := exec.Command("docker", "build",
		"-t", image,
		"-f", dockerfile,
		repoRoot,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker build %s failed: %w", image, err)
	}
	fmt.Printf("✓ Built %s\n", image)
	return nil
}

// findRepoRoot walks up from cwd looking for go.mod. The integration
// test binary is normally invoked from the repo root in CI, but we
// don't want to hard-code that — workspaceless test runs from /tmp
// would never find Dockerfile.container-manager that way.
func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Fallback: cwd. The caller will surface a "Dockerfile not found"
	// error if this is wrong, which is at least debuggable.
	return wd, nil
}
