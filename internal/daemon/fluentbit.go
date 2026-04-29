package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/siem"
)

// fluentBitProjectName is the docker-compose project name used by the
// fluent-bit log collector.
const fluentBitProjectName = "fluent-bit"

// fluentBitDirs returns (daemon-local config dir, daemon-local state dir,
// host config dir, host state dir). The daemon writes into the daemon-local
// paths; the compose file bind-mounts the host paths.
func fluentBitDirs() (string, string, string, string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", "", err
	}
	cfgDir := filepath.Join(homeDir, ".config", "bitswan", "fluent-bit")
	stateDir := filepath.Join(homeDir, ".config", "bitswan", "fluent-bit-state")

	hostHome := os.Getenv("HOST_HOME")
	hostCfg, hostState := cfgDir, stateDir
	if hostHome != "" {
		hostCfg = filepath.Join(hostHome, ".config", "bitswan", "fluent-bit")
		hostState = filepath.Join(hostHome, ".config", "bitswan", "fluent-bit-state")
	}
	return cfgDir, stateDir, hostCfg, hostState, nil
}

// ensureFluentBit renders fluent-bit.conf from the current SIEM config,
// writes the compose file, and brings the container up (idempotent). If
// fluent-bit is already running, a SIGHUP is sent so it reloads the new
// config without dropping buffered events.
func ensureFluentBit() error {
	cfgDir, stateDir, hostCfg, hostState, err := fluentBitDirs()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}

	cfg := siem.Default().Config()
	if err := siem.WriteFluentBitConfig(cfgDir, cfg); err != nil {
		return fmt.Errorf("write fluent-bit.conf: %w", err)
	}

	compose, err := dockercompose.CreateFluentBitDockerComposeFile(hostCfg, hostState)
	if err != nil {
		return fmt.Errorf("compose: %w", err)
	}

	running := containerRunning("fluent-bit")
	if err := dockerComposeUp(fluentBitProjectName, compose, cfgDir); err != nil {
		return fmt.Errorf("compose up: %w", err)
	}

	if running {
		// Config changed — a plain restart is the reliable reload path.
		// Events in flight survive on disk thanks to storage.type=filesystem
		// on the forward input. Hot_Reload SIGHUP is flaky under fluent-bit
		// 3.x when multiple reloads queue up.
		if err := exec.Command("docker", "restart", "fluent-bit").Run(); err != nil {
			fmt.Printf("Warning: fluent-bit restart failed: %v\n", err)
		}
	}
	return nil
}

func containerRunning(name string) bool {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
	if err != nil {
		return false
	}
	return string(bytesTrim(out)) == "true"
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
