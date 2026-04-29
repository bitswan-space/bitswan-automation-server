package dockercompose

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// CreateNetBirdRoutingPeerComposeFile writes a docker-compose for the
// NetBird routing-peer agent that bridges the NetBird overlay to
// bitswan_vpn_network. The agent enrols itself with the supplied setup key
// on first start; subsequent starts reuse the persistent state mounted
// from hostStateDir.
//
// The container needs:
//   - NET_ADMIN + tun device (to create wt0)
//   - IP forwarding (so traffic from the NetBird tunnel can hit
//     bitswan_vpn_network containers)
//   - Membership in bitswan_vpn_network (where traefik-vpn lives)
func CreateNetBirdRoutingPeerComposeFile(setupKey, managementURL, hostStateDir string) (string, error) {
	if setupKey == "" {
		return "", fmt.Errorf("setupKey is required")
	}
	if managementURL == "" {
		managementURL = "https://api.netbird.io"
	}
	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"netbird-router": map[string]interface{}{
				"image":          "netbirdio/netbird:latest",
				"restart":        "always",
				"container_name": "netbird-router",
				"hostname":       "netbird-router",
				"cap_add":        []string{"NET_ADMIN", "SYS_RESOURCE"},
				"devices":        []string{"/dev/net/tun:/dev/net/tun"},
				"sysctls": []string{
					"net.ipv4.ip_forward=1",
					"net.ipv6.conf.all.forwarding=1",
					"net.ipv6.conf.all.disable_ipv6=0",
				},
				"environment": []string{
					"NB_SETUP_KEY=" + setupKey,
					"NB_MANAGEMENT_URL=" + managementURL,
					"NB_LOG_LEVEL=info",
				},
				"networks": []string{"bitswan_network", "bitswan_vpn_network"},
				"volumes": []string{
					hostStateDir + ":/etc/netbird",
				},
				"logging": map[string]interface{}{
					"driver": "json-file",
					"options": map[string]string{
						"max-size": "10m",
						"max-file": "1",
					},
				},
			},
		},
		"networks": map[string]interface{}{
			"bitswan_network": map[string]interface{}{
				"external": true,
			},
			"bitswan_vpn_network": map[string]interface{}{
				"external": true,
			},
		},
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("encode compose: %w", err)
	}
	return buf.String(), nil
}
