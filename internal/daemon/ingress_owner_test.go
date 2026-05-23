package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Phase 6 test: /ingress/add-route's OwnerEmail field surfaces the
// endpoint in bailey's ACL table. Gitops deploys an exposed automation
// → POST /ingress/add-route with the deployer's email → the bailey
// workspaces page renders it as an app card.
//
// We can't exercise the HTTP handler end-to-end without a live traefik
// container, but the side effect we actually want (bailey ACL row +
// Keycloak redirect URI) is gated by req.OwnerEmail being non-empty
// in addRouteToIngress AFTER the route registration succeeds. Test the
// ACL-row write directly by calling registerEndpoint and asserting the
// row turns up via getEndpoint.

func TestRegisterEndpoint_AddsRow(t *testing.T) {
	// Isolate the SQLite DB to a tmp dir so we don't clobber the real one.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".config", "bitswan"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	host := "my-automation.example.com"
	owner := "alice@example.com"
	display := "My Automation"

	rec, err := registerEndpoint(host, owner, display)
	if err != nil {
		t.Fatalf("registerEndpoint: %v", err)
	}
	if !strings.EqualFold(rec.Hostname, host) {
		t.Errorf("hostname: got %q want %q", rec.Hostname, host)
	}
	if !strings.EqualFold(rec.OwnerEmail, owner) {
		t.Errorf("owner: got %q want %q", rec.OwnerEmail, owner)
	}
	if rec.DisplayName != display {
		t.Errorf("display: got %q want %q", rec.DisplayName, display)
	}

	// Idempotency: re-registering doesn't error and returns the same row.
	rec2, err := registerEndpoint(host, owner, display)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if rec2.CreatedAt != rec.CreatedAt {
		t.Errorf("re-register changed created_at: %q → %q", rec.CreatedAt, rec2.CreatedAt)
	}

	// Sanity: lookup returns it.
	found, err := getEndpoint(host)
	if err != nil {
		t.Fatalf("getEndpoint: %v", err)
	}
	if found == nil {
		t.Fatal("getEndpoint returned nil for just-registered host")
	}
	if !strings.EqualFold(found.OwnerEmail, owner) {
		t.Errorf("getEndpoint owner: got %q want %q", found.OwnerEmail, owner)
	}
}

func TestIngressAddRouteRequest_OwnerEmailField(t *testing.T) {
	// Schema-stability check: the OwnerEmail field must exist on
	// IngressAddRouteRequest so gitops + workspace_init can pass the
	// deployer's identity through to the daemon.
	r := IngressAddRouteRequest{
		Hostname:    "foo.example.com",
		Upstream:    "bar:80",
		OwnerEmail:  "deployer@example.com",
		DisplayName: "Foo",
	}
	if r.OwnerEmail != "deployer@example.com" {
		t.Error("OwnerEmail not set/preserved")
	}
	if r.DisplayName != "Foo" {
		t.Error("DisplayName not set/preserved")
	}
}
