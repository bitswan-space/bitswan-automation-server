package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ensureGitopsImage clones the bitswan-gitops repo (branch picked
// from $BITSWAN_GITOPS_BRANCH, see defaultGitopsBranch) and rebuilds
// the bitswan/gitops-local:latest image used by the integration
// tests.
//
// The workflow's own 'Build gitops image from source' step always
// clones main (`git clone --depth 1`), but the automation-server
// feature branches under test usually need a matching gitops feature
// branch — without this rebuild, the integration test runs new
// daemon code against an old gitops image and trips on contracts
// that only landed on the gitops branch. Re-clone here so the test
// always uses a coherent pair.
//
// TODO: drop this helper once feat/bailey-protected-ingress lands on
// both repos' main branches. At that point the workflow's main-clone
// is sufficient again.
func ensureGitopsImage() error {
	branch := os.Getenv("BITSWAN_GITOPS_BRANCH")
	if branch == "" {
		branch = defaultGitopsBranch
	}

	const image = "bitswan/gitops-local:latest"
	tmp := os.TempDir()
	clone := filepath.Join(tmp, "bitswan-gitops-test-clone")

	// Always wipe and re-clone so a stale checkout from a previous
	// test run doesn't silently mask a real bug.
	if err := os.RemoveAll(clone); err != nil {
		return fmt.Errorf("clean previous gitops clone: %w", err)
	}

	fmt.Printf("Cloning bitswan-gitops@%s into %s...\n", branch, clone)
	cloneCmd := exec.Command("git", "clone",
		"--depth", "1",
		"--branch", branch,
		"https://github.com/bitswan-space/bitswan-gitops.git",
		clone,
	)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone bitswan-gitops@%s: %w", branch, err)
	}

	fmt.Printf("Building %s from %s...\n", image, clone)
	buildCmd := exec.Command("docker", "build", "-t", image, clone)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("docker build %s: %w", image, err)
	}
	fmt.Printf("✓ Built %s from %s\n", image, branch)
	return nil
}

// defaultGitopsBranch is the gitops branch the integration tests
// pull in by default. Keep this in lock-step with whichever
// automation-server branch is under test.
const defaultGitopsBranch = "feat/bailey-protected-ingress"
