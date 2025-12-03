package util

import (
	"os"
	"os/exec"
)

// BuildSudoCommand builds a command, using sudo only if not running as root
// This is useful when sudo might not be installed (e.g., in containers running as root)
func BuildSudoCommand(cmd string, args ...string) *exec.Cmd {
	// Check if we're running as root (UID 0)
	// On non-Unix systems, Geteuid() returns -1, so we check for that too
	if os.Geteuid() == 0 {
		// Running as root, no need for sudo
		return exec.Command(cmd, args...)
	}
	// Not root, use sudo
	return exec.Command("sudo", append([]string{cmd}, args...)...)
}

