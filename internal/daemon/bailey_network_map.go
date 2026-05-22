package daemon

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"sort"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/traefikapi"
)

// Bailey / Network map — server-wide graph of docker networks,
// ingresses, endpoints, and containers. Rendered client-side with
// Cytoscape.js; the daemon just publishes the graph data here.
//
// Node kinds:
//   ingress   — platform-traefik / bitswan-protected-proxy / traefik-protected
//   endpoint  — outer hostnames registered in the endpoints table
//   workspace_traefik — per-workspace __traefik
//   container — gitops/editor/dashboard/automation containers
//   network   — docker bridge networks (bitswan_network, bitswan_protected_network,
//               <workspace>-dev, <workspace>-staging, <workspace>-production)
//
// Edges:
//   endpoint → ingress             (host routed by platform traefik)
//   ingress  → workspace_traefik   (auth chain delivers traffic to workspace traefik)
//   workspace_traefik → container  (workspace traefik routes to container)
//   container ∈ network            (container attached to network — undirected, shown via the network's parent-of relation)

type nmNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Parent string `json:"parent,omitempty"`
	// Detail-panel-only fields.
	OwnerEmail  string `json:"owner_email,omitempty"`
	Workspace   string `json:"workspace,omitempty"`
	Stage       string `json:"stage,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
}

type nmEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label,omitempty"`
	Kind   string `json:"kind,omitempty"`
}

type nmGraph struct {
	Nodes []nmNode `json:"nodes"`
	Edges []nmEdge `json:"edges"`
}

func handleNetworkMapAPI(w http.ResponseWriter, r *http.Request) {
	g := buildNetworkMap()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(g)
}

func buildNetworkMap() nmGraph {
	var nodes []nmNode
	var edges []nmEdge

	// (1) Ingresses are well-known. Hardcoded; matches the actual
	// container set in the protected-ingress topology.
	ingresses := []struct{ id, label string }{
		{"ingress:platform-traefik", "platform-traefik"},
		{"ingress:bitswan-protected-proxy", "bitswan-protected-proxy"},
		{"ingress:traefik-protected", "traefik-protected"},
	}
	for _, in := range ingresses {
		nodes = append(nodes, nmNode{ID: in.id, Label: in.label, Kind: "ingress"})
	}
	// Auth chain edges.
	edges = append(edges,
		nmEdge{Source: "ingress:platform-traefik", Target: "ingress:bitswan-protected-proxy", Kind: "chain", Label: "oauth"},
		nmEdge{Source: "ingress:bitswan-protected-proxy", Target: "ingress:traefik-protected", Kind: "chain", Label: "MFA + ACL"},
	)

	// (2) Docker networks.
	netToContainers := dockerNetworksWithContainers()

	// (3) Per-workspace structure: workspace_traefik + container nodes,
	//     networks grouped under the workspace.
	containerToWorkspace := map[string]string{}
	containerToStage := map[string]string{}
	workspaces := workspacesFromNetworks(netToContainers)
	sort.Strings(workspaces)
	for _, ws := range workspaces {
		wsID := "ws:" + ws
		nodes = append(nodes, nmNode{ID: wsID, Label: ws, Kind: "workspace"})

		// Workspace traefik node.
		wsTraefikID := "wstraefik:" + ws
		nodes = append(nodes, nmNode{
			ID: wsTraefikID, Label: ws + "__traefik",
			Kind: "workspace_traefik", Parent: wsID, Workspace: ws,
		})
		// traefik-protected → workspace_traefik (the route that gets
		// hit after the MFA gate hands off).
		edges = append(edges, nmEdge{
			Source: "ingress:traefik-protected", Target: wsTraefikID,
			Kind: "chain",
		})

		// Stage networks under this workspace.
		for _, stage := range []string{"dev", "staging", "production"} {
			netName := ws + "-" + stage
			containers, ok := netToContainers[netName]
			if !ok {
				continue
			}
			netID := "net:" + netName
			nodes = append(nodes, nmNode{
				ID: netID, Label: stage + " network",
				Kind: "network", Parent: wsID, Workspace: ws, Stage: stage,
			})
			for _, c := range containers {
				if isInfraContainer(c) {
					continue
				}
				cID := "container:" + c
				if !containsNode(nodes, cID) {
					nodes = append(nodes, nmNode{
						ID: cID, Label: c, Kind: "container",
						Parent: netID, Workspace: ws, Stage: stage,
					})
					containerToWorkspace[c] = ws
					containerToStage[c] = stage
				}
			}
		}
	}

	// (4) Endpoints from the ACL table. Pair each outer host with its
	//     ingress (always platform-traefik in the current topology)
	//     and, if it maps to a workspace container, an edge to the
	//     workspace traefik.
	eps, _ := listAllEndpoints()
	for _, ep := range eps {
		if isInnerHost(ep.Hostname) {
			continue
		}
		epID := "ep:" + ep.Hostname
		nodes = append(nodes, nmNode{
			ID: epID, Label: ep.Hostname, Kind: "endpoint",
			OwnerEmail: ep.OwnerEmail, Hostname: ep.Hostname,
		})
		// endpoint → platform traefik (always)
		edges = append(edges, nmEdge{
			Source: epID, Target: "ingress:platform-traefik", Kind: "route",
		})
		// If the endpoint belongs to a workspace, draw the route
		// from workspace_traefik → service container.
		if ws := workspaceForEndpoint(ep.Hostname, containerToWorkspace); ws != "" {
			service := serviceLabelForEndpoint(ep.Hostname, ws)
			if service != "" {
				// e.g. bailey-e2e-editor → container bailey-e2e-editor
				cID := "container:" + ws + "-" + service
				if containsNode(nodes, cID) {
					edges = append(edges, nmEdge{
						Source: "wstraefik:" + ws, Target: cID, Kind: "route",
						Label: ep.Hostname,
					})
				}
			}
		}
	}

	// (5) Bailey itself (special — daemon serves the wrap).
	if d := protectedHostnameDomain(); d != "" {
		baileyEP := "bailey." + d
		if !endpointInList(eps, baileyEP) {
			// Insert a synthetic node so the map isn't missing the
			// management surface before it's been bootstrapped.
			nodes = append(nodes, nmNode{
				ID: "ep:" + baileyEP, Label: baileyEP, Kind: "endpoint",
				Hostname: baileyEP,
			})
			edges = append(edges, nmEdge{
				Source: "ep:" + baileyEP, Target: "ingress:platform-traefik", Kind: "route",
			})
		}
	}

	return nmGraph{Nodes: nodes, Edges: edges}
}

// dockerNetworksWithContainers returns {network_name: [container_names]}.
func dockerNetworksWithContainers() map[string][]string {
	out := map[string][]string{}
	// Use the docker CLI rather than the Go SDK to avoid adding a
	// new dependency for this single feature.
	cmd := exec.Command("docker", "network", "ls", "--format", "{{.Name}}")
	raw, err := cmd.Output()
	if err != nil {
		return out
	}
	nets := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for _, n := range nets {
		n = strings.TrimSpace(n)
		if n == "" || n == "host" || n == "none" || n == "bridge" {
			continue
		}
		// Skip docker's default networks we don't care about.
		if strings.HasPrefix(n, "br-") {
			continue
		}
		insp := exec.Command("docker", "network", "inspect", "-f",
			`{{range $k,$v := .Containers}}{{$v.Name}} {{end}}`, n)
		o, err := insp.Output()
		if err != nil {
			continue
		}
		var containers []string
		for _, c := range strings.Fields(string(o)) {
			if c != "" {
				containers = append(containers, c)
			}
		}
		if len(containers) > 0 || isWorkspaceStageNet(n) {
			out[n] = containers
		}
	}
	return out
}

func isWorkspaceStageNet(n string) bool {
	return strings.HasSuffix(n, "-dev") || strings.HasSuffix(n, "-staging") || strings.HasSuffix(n, "-production")
}

func isInfraContainer(name string) bool {
	switch name {
	case "traefik", "bitswan-protected-proxy", "traefik-protected", "bitswan-automation-server-daemon":
		return true
	}
	return false
}

func workspacesFromNetworks(nets map[string][]string) []string {
	seen := map[string]bool{}
	for n := range nets {
		for _, suffix := range []string{"-dev", "-staging", "-production"} {
			if strings.HasSuffix(n, suffix) {
				ws := strings.TrimSuffix(n, suffix)
				if ws != "" {
					seen[ws] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for w := range seen {
		out = append(out, w)
	}
	return out
}

// workspaceForEndpoint tries to find the workspace a hostname belongs
// to. Hostname pattern: <workspace>-<service>.<domain>.
func workspaceForEndpoint(host string, knownContainers map[string]string) string {
	label := host
	if i := strings.Index(label, "."); i > 0 {
		label = label[:i]
	}
	// Try longest workspace prefix that matches a known container.
	for c, ws := range knownContainers {
		if strings.EqualFold(c, label) {
			return ws
		}
	}
	// Fallback: split by '-' and match against known workspace names.
	knownWS := map[string]bool{}
	for _, ws := range knownContainers {
		knownWS[ws] = true
	}
	parts := strings.Split(label, "-")
	for i := len(parts) - 1; i > 0; i-- {
		candidate := strings.Join(parts[:i], "-")
		if knownWS[candidate] {
			return candidate
		}
	}
	return ""
}

// serviceLabelForEndpoint extracts the service tail (editor/gitops/dashboard/...).
func serviceLabelForEndpoint(host, workspace string) string {
	label := host
	if i := strings.Index(label, "."); i > 0 {
		label = label[:i]
	}
	tail := strings.TrimPrefix(label, workspace+"-")
	if tail == label {
		return ""
	}
	return tail
}

func containsNode(nodes []nmNode, id string) bool {
	for _, n := range nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

func endpointInList(eps []endpointRecord, hostname string) bool {
	for _, e := range eps {
		if strings.EqualFold(e.Hostname, hostname) {
			return true
		}
	}
	return false
}

// listRoutesWithTraefikSafe is a small wrapper so the unused import
// helper traefikapi compiles cleanly (used implicitly by buildNetworkMap
// in future when we link routes to upstreams).
var _ = traefikapi.ListRoutes
