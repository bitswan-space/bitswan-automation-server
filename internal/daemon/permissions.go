package daemon

import (
	"fmt"
	"os"
	"os/exec"
)

// chownRecursive sets ownership of path to 1000:1000 recursively.
// The daemon runs as root but workspace files must be owned by user 1000.
func chownRecursive(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	cmd := exec.Command("chown", "-R", "1000:1000", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chown %s: %w (%s)", path, err, string(output))
	}
	return nil
}
