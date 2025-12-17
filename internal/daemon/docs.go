package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"

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
	return `{
		"openapi": "3.0.0",
		"info": {
			"title": "Bitswan Automation Server Daemon API",
			"version": "1.0.0",
			"description": "API for managing automations, workspaces, certificate authorities, and ingress in the Bitswan automation server daemon"
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

