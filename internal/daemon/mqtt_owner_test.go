package daemon

import (
	"encoding/json"
	"testing"
)

// The MQTT workspace-create bridge must forward the deployer's email
// through to the CLI as `--owner <email>` — same contract as direct
// CLI invocation, so MQTT-driven workspace creation is not allowed
// to bypass the ACL-row write.
//
// We verify the *wire schema* and JSON round-trip; the arg-building
// branch itself is exercised by the cmd/test integration suite.

func TestWorkspaceCreateRequest_OwnerJSONTag(t *testing.T) {
	body := []byte(`{
		"request-id": "rid-1",
		"name": "ws-test",
		"local": true,
		"no-ide": true,
		"no-oauth": true,
		"owner": "deployer@example.com"
	}`)

	var req WorkspaceCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Owner != "deployer@example.com" {
		t.Errorf("Owner unmarshal: got %q want %q", req.Owner, "deployer@example.com")
	}
	if req.Name != "ws-test" {
		t.Errorf("Name unmarshal: got %q", req.Name)
	}
	if !req.NoIde {
		t.Error("NoIde unmarshal: expected true")
	}
}

func TestWorkspaceCreateRequest_OwnerOmittedWhenEmpty(t *testing.T) {
	req := WorkspaceCreateRequest{
		RequestID: "rid-2",
		Name:      "ws-no-owner",
		Local:     true,
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if _, present := round["owner"]; present {
		t.Errorf("owner key should be omitted when empty; got %s", raw)
	}
}

func TestWorkspaceCreateRequest_OwnerPreservedRoundTrip(t *testing.T) {
	orig := WorkspaceCreateRequest{
		RequestID: "rid-3",
		Name:      "ws-rt",
		Owner:     "alice@example.com",
	}
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got WorkspaceCreateRequest
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Owner != orig.Owner {
		t.Errorf("round-trip Owner: got %q want %q", got.Owner, orig.Owner)
	}
}
