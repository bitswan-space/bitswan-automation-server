package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// runProxy is the entry point for the lightweight network-facing
// container (BAILEY_MODE=proxy). It starts only the MFA gate
// listener — oauth2-proxy lives in its own container in front, the
// gate handles TOTP / device cookie / per-endpoint ACL / CSP
// injection / nav-sync injection / per-host upstream routing. None
// of the privileged daemon orchestration (Docker, workspace init,
// AOC client, MQTT, SIEM, ingress route admin) runs in this mode —
// the proxy container deliberately has no socket to make those
// surfaces unreachable.
func (s *Server) runProxy() error {
	fmt.Printf("Starting in PROXY mode (BAILEY_MODE=proxy). Version: %s\n", s.version)

	if err := startMFAGate(); err != nil {
		return fmt.Errorf("MFA gate: %w", err)
	}

	// Block until signalled. The MFA gate's HTTP listener is its own
	// goroutine; we just sit here.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("Shutting down proxy.")
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return nil
}

// upstreamDaemonHost returns the address of the privileged daemon's
// docs server. In daemon mode (single-container topology) both the
// MFA gate and the docs server run in the same process, so
// localhost is fine. In proxy mode the daemon is a separate
// container reached by name on the bridge network.
func upstreamDaemonHost() string {
	if h := os.Getenv("BAILEY_DAEMON_HOST"); h != "" {
		return h
	}
	if currentRunMode() == modeProxy {
		return "bitswan-automation-server-daemon"
	}
	return "localhost"
}

// proxyContainerName is the docker name for the bailey-proxy
// container. Kept here so the reconcile helper and the network-map
// classifier agree on what to look for.
const proxyContainerName = "bailey-proxy"

// reconcileBaileyProxy starts (or restarts) the bailey-proxy
// container so it carries the network-facing MFA gate on behalf of
// the privileged daemon. Opt-in for now via the BAILEY_PROXY_ENABLE
// env var — until the routing migration repointing oauth2-proxy at
// bailey-proxy:9080 ships, having a second container listen on the
// same gate code is wasted work. Once the operator flips the env
// var, the next daemon boot brings the proxy up.
func reconcileBaileyProxy() error {
	if os.Getenv("BAILEY_PROXY_ENABLE") != "1" {
		return nil
	}
	if containerRunning(proxyContainerName) {
		return nil
	}
	fmt.Printf("Starting %s container…\n", proxyContainerName)
	return startBaileyProxyContainer()
}

// startBaileyProxyContainer brings up the proxy container using the
// same image as the daemon (so they always agree on the binary
// version). Networking: bitswan_network (shared with oauth2-proxy
// and workspace traefiks). Volumes: only the bailey SQLite database
// (mounted read+write so it can persist ACL changes from access
// requests, device approvals, and the like). Crucially: no Docker
// socket, no /var/run/bitswan socket, no broad host mounts.
func startBaileyProxyContainer() error {
	homeDir, _ := os.UserHomeDir()
	hostHome := os.Getenv("HOST_HOME")
	if hostHome == "" {
		hostHome = homeDir
	}
	baileyDir := hostHome + "/.config/bitswan/bailey"
	if err := os.MkdirAll(homeDir+"/.config/bitswan/bailey", 0700); err != nil {
		return err
	}

	args := []string{
		"run", "-d",
		"--name", proxyContainerName,
		"--restart", "always",
		"--network", "bitswan_network",
		"-e", "BAILEY_MODE=proxy",
		"-e", "BAILEY_DAEMON_HOST=bitswan-automation-server-daemon",
		"-v", baileyDir + ":/root/.config/bitswan/bailey",
		// Same image as this daemon: read via /proc/self.
		daemonImageName(),
	}
	return runDocker(args...)
}

// daemonImageName returns the image the running daemon was started
// from, by reading the container's labels via the Docker API. If we
// can't determine it (e.g. running outside Docker for tests), fall
// back to a sensible default.
func daemonImageName() string {
	if v := os.Getenv("BAILEY_IMAGE"); v != "" {
		return v
	}
	return "bitswan/automation-server-runtime:latest"
}

// runDocker is a thin wrapper that exec()s `docker ...` and surfaces
// any error including stderr — used by container lifecycle helpers
// throughout the daemon.
func runDocker(args ...string) error {
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker %v: %s", args, string(out))
	}
	return nil
}

