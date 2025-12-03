// Package daemonapi provides the REST API for the Bitswan Automation Server Daemon
// @title Bitswan Automation Server Daemon API
// @version 1.0
// @description REST API for Bitswan Automation Server Daemon. This API allows you to manage workspaces, automations, services, and more through a secure REST interface.
//
// @termsOfService http://swagger.io/terms/
//
// @contact.name API Support
// @contact.url http://www.bitswan.ai/support
// @contact.email support@bitswan.ai
//
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
//
// @host localhost:8080
// @BasePath /api/v1
// @schemes http
//
// @securityDefinitions.bearer Bearer
// @securityDefinitions.bearer.type apiKey
// @securityDefinitions.bearer.in header
// @securityDefinitions.bearer.name Authorization
// @securityDefinitions.bearer.description Bearer token authentication. Use format: "Bearer <token>". Global tokens have full access. Workspace tokens can only access their own workspace.
package daemonapi

