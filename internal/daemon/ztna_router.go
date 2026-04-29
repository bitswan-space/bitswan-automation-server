package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/bitswan-space/bitswan-workspaces/internal/vpn"
	"github.com/bitswan-space/bitswan-workspaces/internal/ztna"
)

// ztnaRouterProjectName is the docker-compose project for the NetBird
// routing-peer container.
const ztnaRouterProjectName = "netbird-router"

// ensureZTNARouter is the daemon-side companion to ztna.Provider.Provision:
// it runs the provider's API setup, then brings up the routing-peer
// container with the resulting setup key. Idempotent — repeated calls with
// unchanged config are no-ops past the first.
//
// The dance: ZTNA config is saved → provider provisions groups + setup
// keys against its API → daemon writes a docker-compose with those creds
// → docker brings up the container → first run enrols the routing peer.
func ensureZTNARouter(ctx context.Context) error {
	cfg, err := ztna.Load()
	if err != nil {
		return fmt.Errorf("load ztna config: %w", err)
	}
	if !cfg.Enabled {
		return nil
	}
	provider, err := ztna.Build(cfg)
	if err != nil {
		return err
	}

	serverCfg := config.NewAutomationServerConfig()
	sc, _ := serverCfg.LoadConfig()
	if sc == nil || sc.Slug == "" {
		return fmt.Errorf("automation server has no slug; register with AOC first")
	}

	traefikIPv6 := containerIPv6("traefik-vpn", "bitswan_vpn_network")

	params := ztna.ProvisionParams{
		ServerSlug:     sc.Slug,
		ServerName:     sc.Name,
		ServiceSubnet:  vpn.ServiceSubnet,
		InternalDomain: sc.InternalDomain(),
		TraefikVPNIPv6: traefikIPv6,
	}
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := provider.Provision(pctx, params)
	if err != nil {
		return fmt.Errorf("provider provision: %w", err)
	}
	if res.RoutingPeerSetupKey == "" {
		return fmt.Errorf("provider returned empty routing-peer setup key")
	}

	stateDir, hostStateDir, err := ztnaRouterDirs()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	compose, err := dockercompose.CreateNetBirdRoutingPeerComposeFile(
		res.RoutingPeerSetupKey, res.ManagementURL, hostStateDir,
	)
	if err != nil {
		return fmt.Errorf("compose: %w", err)
	}

	// Re-up always — compose detects no-change and returns quickly.
	// Setup-key changes (e.g. key rotation) appear as env-var diffs and
	// trigger a recreate, which is exactly what we want.
	composeDir := filepath.Join(stateDir, "compose")
	if err := os.MkdirAll(composeDir, 0700); err != nil {
		return err
	}
	if err := dockerComposeUp(ztnaRouterProjectName, compose, composeDir); err != nil {
		return fmt.Errorf("compose up: %w", err)
	}
	return nil
}

// ztnaRouterDirs returns (daemon-local state dir, host state dir). The host
// path is the one bind-mounted into the netbird-router container's
// /etc/netbird so its registration persists across container recreations.
func ztnaRouterDirs() (string, string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	state := filepath.Join(homeDir, ".config", "bitswan", "netbird-router")
	hostHome := os.Getenv("HOST_HOME")
	hostState := state
	if hostHome != "" {
		hostState = filepath.Join(hostHome, ".config", "bitswan", "netbird-router")
	}
	return state, hostState, nil
}

// teardownZTNARouter stops and removes the routing-peer container. Used
// when the admin disables the integration. State on disk is preserved so
// a re-enable doesn't have to re-register the peer with NetBird.
func teardownZTNARouter() error {
	stateDir, _, err := ztnaRouterDirs()
	if err != nil {
		return err
	}
	composeDir := filepath.Join(stateDir, "compose")
	if _, err := os.Stat(filepath.Join(composeDir, "docker-compose.yaml")); os.IsNotExist(err) {
		return nil
	}
	cmd := exec.Command("docker", "compose", "-p", ztnaRouterProjectName, "-f", filepath.Join(composeDir, "docker-compose.yaml"), "down")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
