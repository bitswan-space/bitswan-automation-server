# Bitswan Automation Server Daemon REST API Documentation

## API Structure

### Base URL
- **Development**: `http://localhost:8080`
- **Base Path**: `/api/v1`

### Authentication

All endpoints (except `/health`) require Bearer token authentication:

```
Authorization: Bearer <token>
```

Two types of tokens are supported:
- **Global Tokens**: Full access to all endpoints
- **Workspace Tokens**: Limited to operations on their specific workspace

## Endpoints

### Workspaces

#### List Workspaces
- **GET** `/api/v1/workspaces`
- Lists all available workspaces

#### Initialize Workspace
- **POST** `/api/v1/workspaces`
- Creates a new workspace
- Request body: `WorkspaceInitRequest`

#### Remove Workspace
- **DELETE** `/api/v1/workspaces/{name}`
- Removes an existing workspace
- Request body (optional): `WorkspaceRemoveRequest`

#### Update Workspace
- **PUT** `/api/v1/workspaces/{name}`
- Updates workspace configuration
- Request body: `WorkspaceUpdateRequest`

#### Select Workspace
- **POST** `/api/v1/workspaces/{name}/select`
- Sets a workspace as the active workspace

#### Open Workspace
- **POST** `/api/v1/workspaces/{name}/open`
- Opens a workspace in the browser

#### Pull and Deploy
- **POST** `/api/v1/workspaces/{name}/pull-and-deploy`
- Pulls a branch and deploys automations
- Request body: `WorkspacePullAndDeployRequest`

### Services

#### Enable Service
- **POST** `/api/v1/workspaces/{workspace}/services/{service}/enable`
- Enables a service (couchdb, kafka, or editor)

#### Disable Service
- **POST** `/api/v1/workspaces/{workspace}/services/{service}/disable`
- Disables a service

#### Get Service Status
- **GET** `/api/v1/workspaces/{workspace}/services/{service}/status?show_passwords=false`
- Gets the status of a service
- Query parameter: `show_passwords` (default: false)

### Registration

#### Register with AOC
- **POST** `/api/v1/register`
- Registers the automation server with AOC
- Request body: `RegisterRequest`

### Ingress

#### List Routes
- **GET** `/api/v1/ingress/routes`
- Lists all ingress routes

#### Add Route
- **POST** `/api/v1/ingress/routes`
- Adds a new ingress route
- Request body: `IngressAddRouteRequest`

#### Remove Route
- **DELETE** `/api/v1/ingress/routes/{path}`
- Removes an ingress route

### Token Management

#### List Tokens
- **GET** `/api/v1/tokens`
- Lists all tokens (requires global token)

#### Create Global Token
- **POST** `/api/v1/tokens/global`
- Creates a new global token (requires global token)
- Request body: `{"description": "Token description"}`

#### Create Workspace Token
- **POST** `/api/v1/tokens/workspace`
- Creates a new workspace token (requires global token)
- Request body: `{"workspace": "workspace-name", "description": "Token description"}`

#### Delete Token
- **DELETE** `/api/v1/tokens/{token}`
- Deletes a token (requires global token)

## Swagger Documentation

Interactive Swagger documentation is available at:
- **Swagger UI**: `http://localhost:8080/swagger/index.html`
- **OpenAPI JSON**: `http://localhost:8080/swagger/doc.json`

### Generating Swagger Documentation

To generate/update the Swagger documentation:

```bash
make swagger
```

This will generate the documentation in `internal/daemonapi/docs/`.

## Request/Response Models

All request and response models are defined in `internal/daemonapi/models.go`. See the Swagger documentation for detailed schemas.

### Standard Response Format

All endpoints return a standard response format:

```json
{
  "success": true,
  "message": "Operation completed successfully",
  "output": "Command output here...",
  "error": "",
  "exit_code": 0
}
```

## Usage from CLI

The CLI automatically routes commands through the REST API when running outside the daemon container. The `docker_exec.go` module maps CLI commands to their corresponding REST endpoints.

## Examples

### Initialize a workspace via REST API

```bash
curl -X POST http://localhost:8080/api/v1/workspaces \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "my-workspace",
    "domain": "example.com",
    "local": true,
    "mkcerts": true
  }'
```

## Security

- All endpoints require authentication via Bearer tokens
- Workspace tokens are scoped to their specific workspace
- Global tokens have full access
- Tokens are stored securely in `~/.config/bitswan/daemon_tokens.yaml`

