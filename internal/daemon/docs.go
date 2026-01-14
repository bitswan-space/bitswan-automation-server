package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
)

const (
	docsHostname = "automation-server-daemon-docs.bitswan.localhost"
	docsPort     = 8080
)

// handleDocs serves the Swagger UI documentation
func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Serve Swagger UI HTML
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, getSwaggerUIHTML())
}

// SetupDocsIngress sets up the ingress route for the docs endpoint (exported for CLI use)
func SetupDocsIngress() error {
	s := &Server{}
	return s.setupDocsIngress()
}

// setupDocsIngress sets up the ingress route for the docs endpoint
func (s *Server) setupDocsIngress() error {
	// Use the container name as upstream since Caddy is in a different container
	// The daemon container is named "bitswan-automation-server-daemon" and listens on port 8080
	upstream := fmt.Sprintf("bitswan-automation-server-daemon:%d", docsPort)

	// AddRoute will automatically remove any existing route with the same hostname before adding
	// This ensures we always have the correct upstream (fixes issue if route was created with wrong upstream)
	if err := caddyapi.AddRoute(docsHostname, upstream); err != nil {
		// If Caddy is not available, that's okay - we'll try again later
		return nil
	}

	return nil
}

// getSwaggerUIHTML returns the HTML for Swagger UI with the OpenAPI spec embedded
func getSwaggerUIHTML() string {
	openAPISpecJSON := getOpenAPISpec()
	// Parse and re-encode to ensure valid JSON
	var spec map[string]interface{}
	if err := json.Unmarshal([]byte(openAPISpecJSON), &spec); err != nil {
		// If parsing fails, use the raw string
		openAPISpecJSON = `{"error": "Failed to parse OpenAPI spec"}`
	} else {
		// Re-encode to ensure proper formatting
		encoded, _ := json.Marshal(spec)
		openAPISpecJSON = string(encoded)
	}
	
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>Bitswan Automation Server Daemon API Documentation</title>
	<link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
	<style>
		html {
			box-sizing: border-box;
			overflow: -moz-scrollbars-vertical;
			overflow-y: scroll;
		}
		*, *:before, *:after {
			box-sizing: inherit;
		}
		body {
			margin:0;
			background: #fafafa;
		}
	</style>
</head>
<body>
	<div id="swagger-ui"></div>
	<script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
	<script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
	<script>
		window.onload = function() {
			const spec = %s;
			const ui = SwaggerUIBundle({
				spec: spec,
				dom_id: '#swagger-ui',
				deepLinking: true,
				presets: [
					SwaggerUIBundle.presets.apis,
					SwaggerUIStandalonePreset
				],
				plugins: [
					SwaggerUIBundle.plugins.DownloadUrl
				],
				layout: "StandaloneLayout",
				requestInterceptor: (request) => {
					// Get token from localStorage or prompt user
					let token = localStorage.getItem('bitswan_daemon_token');
					if (!token) {
						token = prompt('Enter authentication token:');
						if (token) {
							localStorage.setItem('bitswan_daemon_token', token);
						}
					}
					if (token) {
						request.headers['Authorization'] = 'Bearer ' + token;
					}
					return request;
				}
			});
		};
	</script>
</body>
</html>`, openAPISpecJSON)
}

// getOpenAPISpec returns the OpenAPI 3.0 specification as a JSON string
func getOpenAPISpec() string {
	// This is a simplified OpenAPI spec - you can expand it with more details
	mqttDocs := "API for managing automations, workspaces, certificate authorities, and ingress in the Bitswan automation server daemon.\n\n" +
		"## MQTT API\n\n" +
		"The automation server daemon also provides an MQTT-based API for workspace management. " +
		"All MQTT topics are relative to the automation server's mountpoint: `/orgs/{org_id}/automation-servers/{automation_server_id}`.\n\n" +
		"### Workspace List Topic\n\n" +
		"**Topic:** `workspaces` (published by daemon)\n\n" +
		"**QoS:** 1 (At least once delivery)\n\n" +
		"**Retain:** true\n\n" +
		"**Message Format:**\n```json\n{\n  \"workspaces\": [\n    {\"id\": \"workspace-uuid-1\", \"name\": \"workspace-1\"},\n    {\"id\": \"workspace-uuid-2\", \"name\": \"workspace-2\"}\n  ],\n  \"timestamp\": \"2024-01-15T10:30:00Z\"\n}\n```\n\n" +
		"The daemon publishes this list whenever workspaces are added or removed.\n\n" +
		"### Workspace Create Command\n\n" +
		"**Topic:** `workspace/create` (subscribe to send commands)\n\n" +
		"**QoS:** 1\n\n" +
		"**Request Format:**\n```json\n{\n  \"request-id\": \"unique-request-id\",\n  \"name\": \"workspace-name\",\n  \"remote\": \"git-repo-url\",\n  \"branch\": \"branch-name\",\n  \"domain\": \"example.com\",\n  \"certs-dir\": \"/path/to/certs\",\n  \"verbose\": false,\n  \"mkcerts\": false,\n  \"no-ide\": false,\n  \"set-hosts\": false,\n  \"local\": false,\n  \"gitops-image\": \"image:tag\",\n  \"editor-image\": \"image:tag\",\n  \"gitops-dev-source-dir\": \"/path/to/source\",\n  \"oauth-config\": \"/path/to/oauth.json\",\n  \"no-oauth\": false,\n  \"ssh-port\": \"2222\"\n}\n```\n\n" +
		"**Response:** Logs and results are published to the `logs` topic (see below).\n\n" +
		"### Workspace Delete Command\n\n" +
		"**Topic:** `workspace/delete` (subscribe to send commands)\n\n" +
		"**QoS:** 1\n\n" +
		"**Request Format:**\n```json\n{\n  \"request-id\": \"unique-request-id\",\n  \"id\": \"workspace-uuid\"\n}\n```\n\n" +
		"**Note:** The `id` field is required. The `name` field is optional and provided for backwards compatibility only. " +
		"Workspaces are identified by ID to support renaming.\n\n" +
		"**Response:** Logs and results are published to the `logs` topic (see below).\n\n" +
		"### Logs Topic\n\n" +
		"**Topic:** `logs` (subscribe to receive logs and results)\n\n" +
		"**QoS:** 1\n\n" +
		"**Message Types:**\n\n" +
		"1. **Log Message** (Docker NDJSON format with request-id):\n```json\n{\n  \"request-id\": \"unique-request-id\",\n  \"time\": \"2024-01-15T10:30:00Z\",\n  \"level\": \"info\",\n  \"message\": \"Log message content\"\n}\n```\n\n" +
		"2. **Result Message** (final status):\n```json\n{\n  \"request-id\": \"unique-request-id\",\n  \"success\": true,\n  \"message\": \"Workspace created successfully\",\n  \"error\": \"\"\n}\n```\n\n" +
		"Or on failure:\n```json\n{\n  \"request-id\": \"unique-request-id\",\n  \"success\": false,\n  \"message\": \"\",\n  \"error\": \"Error description\"\n}\n```\n\n" +
		"### Authentication\n\n" +
		"MQTT connections require JWT authentication. Obtain credentials from the AOC API endpoint:\n" +
		"`GET /api/automation_server/emqx/jwt/`\n\n" +
		"The JWT token should include:\n" +
		"- `username`: Automation server ID\n" +
		"- `client_attrs.mountpoint`: `/orgs/{org_id}/automation-servers/{automation_server_id}`\n\n" +
		"### Connection\n\n" +
		"Connect to the MQTT broker using the URL and token from the AOC API. " +
		"The URL typically uses WSS protocol through the ingress (e.g., `wss://mqtt.bitswan.localhost`)."
	
	// Escape the description for JSON
	escapedDesc := strings.ReplaceAll(mqttDocs, `"`, `\"`)
	escapedDesc = strings.ReplaceAll(escapedDesc, "\n", "\\n")
	
	return `{
		"openapi": "3.0.0",
		"info": {
			"title": "Bitswan Automation Server Daemon API",
			"version": "1.0.0",
			"description": "` + escapedDesc + `"
		},
		"servers": [
			{
				"url": "http://unix",
				"description": "Unix socket (internal)"
			}
		],
		"components": {
			"securitySchemes": {
				"bearerAuth": {
					"type": "http",
					"scheme": "bearer",
					"bearerFormat": "JWT"
				}
			}
		},
		"security": [
			{
				"bearerAuth": []
			}
		],
		"paths": {
			"/ping": {
				"get": {
					"summary": "Health check",
					"responses": {
						"200": {
							"description": "Pong"
						}
					}
				}
			},
			"/version": {
				"get": {
					"summary": "Get daemon version",
					"responses": {
						"200": {
							"description": "Version information"
						}
					}
				}
			},
			"/status": {
				"get": {
					"summary": "Get daemon status",
					"responses": {
						"200": {
							"description": "Status information"
						}
					}
				}
			},
			"/automations": {
				"get": {
					"summary": "List automations",
					"parameters": [
						{
							"name": "workspace",
							"in": "query",
							"schema": {
								"type": "string"
							}
						}
					],
					"responses": {
						"200": {
							"description": "List of automations"
						}
					}
				}
			},
			"/automations/{id}/logs": {
				"get": {
					"summary": "Get automation logs",
					"parameters": [
						{
							"name": "id",
							"in": "path",
							"required": true,
							"schema": {
								"type": "string"
							}
						},
						{
							"name": "workspace",
							"in": "query",
							"schema": {
								"type": "string"
							}
						},
						{
							"name": "lines",
							"in": "query",
							"schema": {
								"type": "integer"
							}
						}
					],
					"responses": {
						"200": {
							"description": "Automation logs"
						}
					}
				}
			},
			"/automations/{id}/start": {
				"post": {
					"summary": "Start automation",
					"parameters": [
						{
							"name": "id",
							"in": "path",
							"required": true,
							"schema": {
								"type": "string"
							}
						},
						{
							"name": "workspace",
							"in": "query",
							"schema": {
								"type": "string"
							}
						}
					],
					"responses": {
						"200": {
							"description": "Automation started"
						}
					}
				}
			},
			"/automations/{id}/stop": {
				"post": {
					"summary": "Stop automation",
					"parameters": [
						{
							"name": "id",
							"in": "path",
							"required": true,
							"schema": {
								"type": "string"
							}
						},
						{
							"name": "workspace",
							"in": "query",
							"schema": {
								"type": "string"
							}
						}
					],
					"responses": {
						"200": {
							"description": "Automation stopped"
						}
					}
				}
			},
			"/automations/{id}/restart": {
				"post": {
					"summary": "Restart automation",
					"parameters": [
						{
							"name": "id",
							"in": "path",
							"required": true,
							"schema": {
								"type": "string"
							}
						},
						{
							"name": "workspace",
							"in": "query",
							"schema": {
								"type": "string"
							}
						}
					],
					"responses": {
						"200": {
							"description": "Automation restarted"
						}
					}
				}
			},
			"/automations/{id}": {
				"delete": {
					"summary": "Remove automation",
					"parameters": [
						{
							"name": "id",
							"in": "path",
							"required": true,
							"schema": {
								"type": "string"
							}
						},
						{
							"name": "workspace",
							"in": "query",
							"schema": {
								"type": "string"
							}
						}
					],
					"responses": {
						"200": {
							"description": "Automation removed"
						}
					}
				}
			},
			"/workspace/list": {
				"get": {
					"summary": "List workspaces",
					"responses": {
						"200": {
							"description": "List of workspaces"
						}
					}
				}
			},
			"/workspace/select": {
				"post": {
					"summary": "Select workspace",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"workspace": {
											"type": "string"
										}
									}
								}
							}
						}
					},
					"responses": {
						"200": {
							"description": "Workspace selected"
						}
					}
				}
			},
			"/certauthority/list": {
				"get": {
					"summary": "List certificate authorities",
					"responses": {
						"200": {
							"description": "List of certificate authorities"
						}
					}
				}
			},
			"/certauthority/add": {
				"post": {
					"summary": "Add certificate authority",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"file_name": {
											"type": "string"
										},
										"file_content": {
											"type": "string"
										}
									}
								}
							}
						}
					},
					"responses": {
						"200": {
							"description": "Certificate authority added"
						}
					}
				}
			},
			"/certauthority/remove/{name}": {
				"delete": {
					"summary": "Remove certificate authority",
					"parameters": [
						{
							"name": "name",
							"in": "path",
							"required": true,
							"schema": {
								"type": "string"
							}
						}
					],
					"responses": {
						"200": {
							"description": "Certificate authority removed"
						}
					}
				}
			},
			"/ingress/init": {
				"post": {
					"summary": "Initialize ingress",
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"verbose": {
											"type": "boolean"
										}
									}
								}
							}
						}
					},
					"responses": {
						"200": {
							"description": "Ingress initialized"
						}
					}
				}
			},
			"/ingress/add-route": {
				"post": {
					"summary": "Add ingress route",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"hostname": {
											"type": "string"
										},
										"upstream": {
											"type": "string"
										},
										"mkcert": {
											"type": "boolean"
										},
										"certs_dir": {
											"type": "string"
										}
									}
								}
							}
						}
					},
					"responses": {
						"200": {
							"description": "Route added"
						}
					}
				}
			},
			"/ingress/list-routes": {
				"get": {
					"summary": "List ingress routes",
					"responses": {
						"200": {
							"description": "List of routes"
						}
					}
				}
			},
			"/ingress/remove-route/{hostname}": {
				"delete": {
					"summary": "Remove ingress route",
					"parameters": [
						{
							"name": "hostname",
							"in": "path",
							"required": true,
							"schema": {
								"type": "string"
							}
						}
					],
					"responses": {
						"200": {
							"description": "Route removed"
						}
					}
				}
			}
		}
	}`
}

// OpenBrowser opens the docs URL in the default browser (exported for CLI use)
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch {
	case commandExists("xdg-open"):
		cmd = exec.Command("xdg-open", url)
	case commandExists("open"):
		cmd = exec.Command("open", url)
	case commandExists("start"):
		cmd = exec.Command("start", url)
	default:
		return fmt.Errorf("no browser launcher found (tried xdg-open, open, start)")
	}
	return cmd.Run()
}

// commandExists checks if a command exists in PATH
func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

