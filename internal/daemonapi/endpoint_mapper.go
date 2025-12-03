package daemonapi

import (
	"encoding/json"
	"fmt"
	"strings"
)

// getRESTEndpoint maps a command to its REST API endpoint
func getRESTEndpoint(command string, args []string, workspace string) (string, string, string) {
	// Map commands to REST endpoints
	switch command {
	case "workspace":
		if len(args) == 0 {
			return "GET", "/api/v1/workspaces", ""
		}

		subcommand := args[0]
		switch subcommand {
		case "init":
			return "POST", "/api/v1/workspaces", buildWorkspaceInitPayload(args[1:])
		case "remove":
			workspaceName := ""
			if len(args) > 1 {
				workspaceName = args[len(args)-1]
			}
			return "DELETE", fmt.Sprintf("/api/v1/workspaces/%s", workspaceName), buildWorkspaceRemovePayload(args)
		case "update":
			workspaceName := ""
			if len(args) > 1 {
				workspaceName = args[1]
			}
			return "PUT", fmt.Sprintf("/api/v1/workspaces/%s", workspaceName), buildWorkspaceUpdatePayload(args)
		case "select":
			workspaceName := ""
			if len(args) > 1 {
				workspaceName = args[1]
			}
			return "POST", fmt.Sprintf("/api/v1/workspaces/%s/select", workspaceName), ""
		case "open":
			workspaceName := ""
			if len(args) > 1 {
				workspaceName = args[1]
			}
			return "POST", fmt.Sprintf("/api/v1/workspaces/%s/open", workspaceName), ""
		case "pull-and-deploy":
			workspaceName := ""
			if len(args) > 1 {
				workspaceName = args[1]
			}
			return "POST", fmt.Sprintf("/api/v1/workspaces/%s/pull-and-deploy", workspaceName), buildPullAndDeployPayload(args)
		case "list":
			return "GET", "/api/v1/workspaces", ""
		case "service":
			if len(args) >= 3 {
				serviceType := args[1]
				action := args[2]
				workspaceName := workspace
				if workspaceName == "" && len(args) > 3 {
					// Try to extract from args
					for i, arg := range args {
						if arg == "--workspace" && i+1 < len(args) {
							workspaceName = args[i+1]
							break
						}
					}
				}
				switch action {
				case "enable":
					return "POST", fmt.Sprintf("/api/v1/workspaces/%s/services/%s/enable", workspaceName, serviceType), ""
				case "disable":
					return "POST", fmt.Sprintf("/api/v1/workspaces/%s/services/%s/disable", workspaceName, serviceType), ""
				case "status":
					showPasswords := false
					for _, arg := range args {
						if arg == "--passwords" {
							showPasswords = true
							break
						}
					}
					query := ""
					if showPasswords {
						query = "?show_passwords=true"
					}
					return "GET", fmt.Sprintf("/api/v1/workspaces/%s/services/%s/status%s", workspaceName, serviceType, query), ""
				}
			}
		}

	case "register":
		if len(args) > 0 {
			return "POST", "/api/v1/register", fmt.Sprintf(`{"aoc_url":"%s"}`, args[0])
		}

	case "ingress":
		if len(args) == 0 {
			break
		}

		subcommand := args[0]
		switch subcommand {
		case "init":
			verbose := false
			for _, arg := range args {
				if arg == "--verbose" || arg == "-v" {
					verbose = true
					break
				}
			}
			payload := fmt.Sprintf(`{"verbose":%t}`, verbose)
			return "POST", "/api/v1/ingress/init", payload
		case "list-routes":
			return "GET", "/api/v1/ingress/routes", ""
		case "add-route":
			if len(args) >= 3 {
				path := args[1]
				target := args[2]
				payload := fmt.Sprintf(`{"path":"%s","target":"%s"}`, path, target)
				if len(args) > 3 {
					for i, arg := range args {
						if arg == "--workspace" && i+1 < len(args) {
							payload = fmt.Sprintf(`{"path":"%s","target":"%s","workspace_name":"%s"}`, path, target, args[i+1])
							break
						}
					}
				}
				return "POST", "/api/v1/ingress/routes", payload
			}
		case "remove-route":
			if len(args) >= 2 {
				path := args[1]
				return "DELETE", fmt.Sprintf("/api/v1/ingress/routes/%s", path), ""
			}
		}

	case "automation":
		if len(args) == 0 {
			break
		}

		subcommand := args[0]
		// Workspace should be passed in the workspace parameter
		workspaceName := workspace
		if workspaceName == "" {
			// Can't proceed without workspace
			break
		}

		switch subcommand {
		case "list":
			return "GET", fmt.Sprintf("/api/v1/workspaces/%s/automations", workspaceName), ""
		case "logs":
			if len(args) >= 2 {
				automationID := args[1]
				lines := 0
				for i, arg := range args {
					if (arg == "--lines" || arg == "-l") && i+1 < len(args) {
						// Parse lines value
						fmt.Sscanf(args[i+1], "%d", &lines)
						break
					}
				}
				query := ""
				if lines > 0 {
					query = fmt.Sprintf("?lines=%d", lines)
				}
				return "GET", fmt.Sprintf("/api/v1/workspaces/%s/automations/%s/logs%s", workspaceName, automationID, query), ""
			}
		case "start":
			if len(args) >= 2 {
				automationID := args[1]
				return "POST", fmt.Sprintf("/api/v1/workspaces/%s/automations/%s/start", workspaceName, automationID), ""
			}
		case "stop":
			if len(args) >= 2 {
				automationID := args[1]
				return "POST", fmt.Sprintf("/api/v1/workspaces/%s/automations/%s/stop", workspaceName, automationID), ""
			}
		case "restart":
			if len(args) >= 2 {
				automationID := args[1]
				return "POST", fmt.Sprintf("/api/v1/workspaces/%s/automations/%s/restart", workspaceName, automationID), ""
			}
		case "remove":
			if len(args) >= 2 {
				automationID := args[1]
				return "DELETE", fmt.Sprintf("/api/v1/workspaces/%s/automations/%s", workspaceName, automationID), ""
			}
		}

	case "ca", "certauthority":
		if len(args) == 0 {
			break
		}

		subcommand := args[0]
		switch subcommand {
		case "list":
			return "GET", "/api/v1/certauthorities", ""
		case "add":
			// The payload should already contain the certificate content
			// This is set by the cmd file before calling getRESTEndpoint
			// For now, we'll check if there's a payload in the args (unusual but workable)
			// Actually, the payload should be built in docker_exec.go before calling getRESTEndpoint
			// Let's use a special marker to indicate we have certificate content
			if len(args) >= 2 && strings.HasPrefix(args[1], "CERT_CONTENT:") {
				// Certificate content is in the args, extract it
				certContent := strings.TrimPrefix(args[1], "CERT_CONTENT:")
				certName := ""
				if len(args) >= 3 {
					certName = args[2]
				}
				payload := fmt.Sprintf(`{"certificate":"%s","name":"%s"}`, strings.ReplaceAll(certContent, "\"", "\\\""), certName)
				return "POST", "/api/v1/certauthorities", payload
			}
			// Fallback: try to read from file path (this won't work in container, but kept for compatibility)
			if len(args) >= 2 {
				certPath := args[1]
				certName := ""
				if len(args) >= 3 {
					certName = args[2]
				}
				payload := fmt.Sprintf(`{"certificate_path":"%s","name":"%s"}`, certPath, certName)
				return "POST", "/api/v1/certauthorities", payload
			}
		case "remove", "rm":
			if len(args) >= 2 {
				certName := args[1]
				return "DELETE", fmt.Sprintf("/api/v1/certauthorities/%s", certName), ""
			}
		}
	}

	// Fallback to legacy execute endpoint
	return "POST", "/api/v1/execute", ""
}

func buildWorkspaceInitPayload(args []string) string {
	req := WorkspaceInitRequest{}

	for i, arg := range args {
		switch arg {
		case "--remote":
			if i+1 < len(args) {
				req.Remote = args[i+1]
			}
		case "--branch":
			if i+1 < len(args) {
				req.Branch = args[i+1]
			}
		case "--domain":
			if i+1 < len(args) {
				req.Domain = args[i+1]
			}
		case "--certs-dir":
			if i+1 < len(args) {
				req.CertsDir = args[i+1]
			}
		case "--gitops-image":
			if i+1 < len(args) {
				req.GitopsImage = args[i+1]
			}
		case "--editor-image":
			if i+1 < len(args) {
				req.EditorImage = args[i+1]
			}
		case "--oauth-config":
			if i+1 < len(args) {
				req.OauthConfig = args[i+1]
			}
		case "--ssh-port":
			if i+1 < len(args) {
				req.SSHPort = args[i+1]
			}
		case "--gitops-dev-source-dir":
			if i+1 < len(args) {
				req.GitopsDevSourceDir = args[i+1]
			}
		case "--verbose", "-v":
			req.Verbose = true
		case "--mkcerts":
			req.MkCerts = true
		case "--set-hosts":
			req.SetHosts = true
		case "--local":
			req.Local = true
		case "--no-ide":
			req.NoIde = true
		case "--no-oauth":
			req.NoOauth = true
		default:
			// First non-flag argument is the workspace name
			if !strings.HasPrefix(arg, "--") && req.Name == "" {
				req.Name = arg
			}
		}
	}

	json, _ := json.Marshal(req)
	return string(json)
}

func buildWorkspaceRemovePayload(args []string) string {
	req := WorkspaceRemoveRequest{}

	for _, arg := range args {
		if arg == "--yes" {
			req.Yes = true
		} else if !strings.HasPrefix(arg, "--") && req.Name == "" {
			req.Name = arg
		}
	}

	json, _ := json.Marshal(req)
	return string(json)
}

func buildWorkspaceUpdatePayload(args []string) string {
	req := WorkspaceUpdateRequest{}

	for i, arg := range args {
		switch arg {
		case "--gitops-image":
			if i+1 < len(args) {
				req.GitopsImage = args[i+1]
			}
		case "--staging":
			req.Staging = true
		case "--trust-ca":
			req.TrustCA = true
		default:
			if !strings.HasPrefix(arg, "--") && req.Name == "" {
				req.Name = arg
			}
		}
	}

	json, _ := json.Marshal(req)
	return string(json)
}

func buildPullAndDeployPayload(args []string) string {
	req := WorkspacePullAndDeployRequest{}

	for i, arg := range args {
		switch arg {
		case "--branch", "-b":
			if i+1 < len(args) {
				req.Branch = args[i+1]
			}
		case "--force":
			req.Force = true
		case "--no-build":
			req.NoBuild = true
		default:
			if !strings.HasPrefix(arg, "--") && req.WorkspaceName == "" {
				req.WorkspaceName = arg
			}
		}
	}

	json, _ := json.Marshal(req)
	return string(json)
}
