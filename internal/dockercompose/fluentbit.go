package dockercompose

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// CreateFluentBitDockerComposeFile creates a docker-compose file for the
// fluent-bit log collector. It listens on localhost:24224 for the forward
// protocol — the daemon emits VPN/app events there, and Docker's fluentd
// log driver pushes container stdout there too.
//
// hostConfigDir is the host path that holds fluent-bit.conf; the same path
// is bind-mounted into /fluent-bit/etc. hostStateDir holds the disk-backed
// buffer.
func CreateFluentBitDockerComposeFile(hostConfigDir, hostStateDir string) (string, error) {
	dockerCompose := map[string]interface{}{
		"version": "3.8",
		"services": map[string]interface{}{
			"fluent-bit": map[string]interface{}{
				"image":          "fluent/fluent-bit:3.1",
				"restart":        "always",
				"container_name": "fluent-bit",
				// Bind forward-input to localhost on the host so nothing
				// external can push events in.
				"ports": []string{
					"127.0.0.1:24224:24224/tcp",
					"127.0.0.1:24224:24224/udp",
					"127.0.0.1:2020:2020/tcp",
				},
				"command": "/fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluent-bit.conf",
				"volumes": []string{
					hostConfigDir + ":/fluent-bit/etc:ro",
					hostStateDir + ":/fluent-bit/state",
				},
				"networks": []string{"bitswan_network"},
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
		},
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(dockerCompose); err != nil {
		return "", fmt.Errorf("failed to encode docker-compose data structure: %w", err)
	}
	return buf.String(), nil
}
