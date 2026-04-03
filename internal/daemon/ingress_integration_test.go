//go:build integration

package daemon

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/docker"
	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
)

// cleanup stops and removes all ingress containers and config
func cleanup(t *testing.T) {
	t.Helper()
	for _, name := range []string{"caddy", "traefik"} {
		exec.Command("docker", "rm", "-f", name).Run()
	}
	for _, project := range []string{"bitswan-caddy", "bitswan-traefik"} {
		exec.Command("docker", "compose", "-p", project, "down", "--volumes").Run()
	}
	homeDir := os.Getenv("HOME")
	os.RemoveAll(homeDir + "/.config/bitswan/caddy")
	os.RemoveAll(homeDir + "/.config/bitswan/traefik")
	time.Sleep(2 * time.Second)
}

func waitForHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

// --- Unit-level ingress tests ---

func TestDetectIngressType_NoneRunning(t *testing.T) {
	cleanup(t)
	defer cleanup(t)

	ingressType := DetectIngressType()
	if ingressType != IngressTraefik {
		t.Errorf("expected IngressTraefik when nothing is running, got %s", ingressType)
	}
}

func TestCaddySetup(t *testing.T) {
	cleanup(t)
	defer cleanup(t)

	docker.EnsureDockerNetwork("bitswan_network", false)

	newlyInitialized, err := initCaddyIngress(true)
	if err != nil {
		t.Fatalf("failed to start Caddy: %v", err)
	}
	if !newlyInitialized {
		t.Error("expected Caddy to be newly initialized")
	}

	if DetectIngressType() != IngressCaddy {
		t.Errorf("expected IngressCaddy, got %s", DetectIngressType())
	}

	if err := waitForHTTP("http://localhost:2019", 10*time.Second); err != nil {
		t.Fatalf("Caddy admin API not reachable: %v", err)
	}

	// Add route
	err = addRouteToIngress(IngressAddRouteRequest{
		Hostname: "test-service.bitswan.localhost",
		Upstream: "localhost:9999",
	}, "")
	if err != nil {
		t.Fatalf("failed to add route via Caddy: %v", err)
	}

	// Verify route exists
	routes, err := caddyapi.ListRoutes()
	if err != nil {
		t.Fatalf("failed to list Caddy routes: %v", err)
	}
	found := false
	for _, route := range routes {
		for _, match := range route.Match {
			for _, host := range match.Host {
				if host == "test-service.bitswan.localhost" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("route not found in Caddy after adding")
	}

	// Remove route
	err = removeRouteFromIngress("test-service.bitswan.localhost")
	if err != nil {
		t.Fatalf("failed to remove route from Caddy: %v", err)
	}

	// Idempotency
	newlyInitialized, err = initCaddyIngress(false)
	if err != nil {
		t.Fatalf("second init failed: %v", err)
	}
	if newlyInitialized {
		t.Error("expected Caddy to NOT be newly initialized on second call")
	}
}

func TestTraefikSetup(t *testing.T) {
	cleanup(t)
	defer cleanup(t)

	docker.EnsureDockerNetwork("bitswan_network", false)

	newlyInitialized, err := initTraefikIngress(true)
	if err != nil {
		t.Fatalf("failed to start Traefik: %v", err)
	}
	if !newlyInitialized {
		t.Error("expected Traefik to be newly initialized")
	}

	if DetectIngressType() != IngressTraefik {
		t.Errorf("expected IngressTraefik, got %s", DetectIngressType())
	}

	if err := waitForHTTP("http://localhost:9080/api/overview", 10*time.Second); err != nil {
		t.Fatalf("Traefik API not reachable: %v", err)
	}

	// Add route
	err = addRouteToIngress(IngressAddRouteRequest{
		Hostname: "test-service.bitswan.localhost",
		Upstream: "localhost:9999",
	}, "")
	if err != nil {
		t.Fatalf("failed to add route via Traefik: %v", err)
	}

	// Verify route exists
	routes, err := traefikapi.ListRoutes()
	if err != nil {
		t.Fatalf("failed to list Traefik routes: %v", err)
	}
	found := false
	for _, route := range routes {
		for _, match := range route.Match {
			for _, host := range match.Host {
				if host == "test-service.bitswan.localhost" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("route not found in Traefik after adding")
	}

	// Remove route
	err = removeRouteFromIngress("test-service.bitswan.localhost")
	if err != nil {
		t.Fatalf("failed to remove route from Traefik: %v", err)
	}

	// Verify route is gone
	routes, err = traefikapi.ListRoutes()
	if err != nil {
		t.Fatalf("failed to list routes after removal: %v", err)
	}
	for _, route := range routes {
		for _, match := range route.Match {
			for _, host := range match.Host {
				if host == "test-service.bitswan.localhost" {
					t.Error("route still exists after removal")
				}
			}
		}
	}

	// Idempotency
	newlyInitialized, err = initTraefikIngress(false)
	if err != nil {
		t.Fatalf("second init failed: %v", err)
	}
	if newlyInitialized {
		t.Error("expected Traefik to NOT be newly initialized on second call")
	}
}

func TestBackwardCompatibility_CaddyPreserved(t *testing.T) {
	cleanup(t)
	defer cleanup(t)

	docker.EnsureDockerNetwork("bitswan_network", false)

	// Start Caddy first (simulating existing setup)
	_, err := initCaddyIngress(false)
	if err != nil {
		t.Fatalf("failed to start Caddy: %v", err)
	}

	err = caddyapi.AddRoute("existing-service.bitswan.localhost", "localhost:8888")
	if err != nil {
		t.Fatalf("failed to add route to Caddy: %v", err)
	}

	// initIngress should detect Caddy and NOT replace it
	newlyInitialized, err := initIngress(false)
	if err != nil {
		t.Fatalf("initIngress failed with existing Caddy: %v", err)
	}
	if newlyInitialized {
		t.Error("initIngress should not start new ingress when Caddy is running")
	}

	if DetectIngressType() != IngressCaddy {
		t.Error("expected Caddy to still be detected")
	}

	// Abstraction layer should work with Caddy
	err = addRouteToIngress(IngressAddRouteRequest{
		Hostname: "new-service.bitswan.localhost",
		Upstream: "localhost:7777",
	}, "")
	if err != nil {
		t.Fatalf("failed to add route via abstraction with Caddy running: %v", err)
	}

	// Verify both routes exist
	routes, err := caddyapi.ListRoutes()
	if err != nil {
		t.Fatalf("failed to list routes: %v", err)
	}

	existingFound, newFound := false, false
	for _, route := range routes {
		for _, match := range route.Match {
			for _, host := range match.Host {
				if host == "existing-service.bitswan.localhost" {
					existingFound = true
				}
				if host == "new-service.bitswan.localhost" {
					newFound = true
				}
			}
		}
	}
	if !existingFound {
		t.Error("existing route was lost after initIngress")
	}
	if !newFound {
		t.Error("new route was not added through abstraction layer")
	}
}

func TestMigration_CaddyToTraefik(t *testing.T) {
	cleanup(t)
	defer cleanup(t)

	docker.EnsureDockerNetwork("bitswan_network", false)

	// Start Caddy and add routes
	_, err := initCaddyIngress(false)
	if err != nil {
		t.Fatalf("failed to start Caddy: %v", err)
	}

	testRoutes := []struct{ hostname, upstream string }{
		{"svc1.bitswan.localhost", "localhost:1111"},
		{"svc2.bitswan.localhost", "localhost:2222"},
		{"svc3.bitswan.localhost", "localhost:3333"},
	}
	for _, r := range testRoutes {
		if err := caddyapi.AddRoute(r.hostname, r.upstream); err != nil {
			t.Fatalf("failed to add route %s: %v", r.hostname, err)
		}
	}

	// Verify Caddy has the routes
	caddyRoutes, err := caddyapi.ListRoutes()
	if err != nil {
		t.Fatalf("failed to list Caddy routes: %v", err)
	}
	if len(caddyRoutes) < len(testRoutes) {
		t.Fatalf("expected at least %d routes in Caddy, got %d", len(testRoutes), len(caddyRoutes))
	}

	// Run migration
	if err := MigrateCaddyToTraefik(true); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	// Verify Caddy is stopped
	caddyId, _ := exec.Command("docker", "ps", "-q", "-f", "name=^caddy$").Output()
	if strings.TrimSpace(string(caddyId)) != "" {
		t.Error("Caddy should be stopped after migration")
	}

	// Verify Traefik is running
	if DetectIngressType() != IngressTraefik {
		t.Error("expected Traefik to be running after migration")
	}

	// Verify all routes were migrated
	traefikRoutes, err := traefikapi.ListRoutes()
	if err != nil {
		t.Fatalf("failed to list Traefik routes: %v", err)
	}

	migratedCount := 0
	for _, tr := range traefikRoutes {
		for _, match := range tr.Match {
			for _, host := range match.Host {
				for _, r := range testRoutes {
					if host == r.hostname {
						migratedCount++
					}
				}
			}
		}
	}
	if migratedCount != len(testRoutes) {
		t.Errorf("expected %d routes migrated, found %d", len(testRoutes), migratedCount)
	}

	// Verify routes work via the abstraction layer (should use Traefik now)
	err = addRouteToIngress(IngressAddRouteRequest{
		Hostname: "post-migration.bitswan.localhost",
		Upstream: "localhost:4444",
	}, "")
	if err != nil {
		t.Fatalf("failed to add route after migration: %v", err)
	}
}

func TestInitIngress_DefaultsToTraefik(t *testing.T) {
	cleanup(t)
	defer cleanup(t)

	docker.EnsureDockerNetwork("bitswan_network", false)

	newlyInitialized, err := initIngress(false)
	if err != nil {
		t.Fatalf("initIngress failed: %v", err)
	}
	if !newlyInitialized {
		t.Error("expected new initialization")
	}

	if DetectIngressType() != IngressTraefik {
		t.Error("expected Traefik as default for new installs")
	}
}
