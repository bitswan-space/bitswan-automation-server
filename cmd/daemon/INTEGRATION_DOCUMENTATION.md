# Automation Server Daemon Integration Documentation

## Overview

The Automation Server Daemon is a containerized service that runs continuously and listens for workspace management commands via MQTT. It enables remote control of workspace initialization and removal operations without requiring direct access to the automation server host.

## Concept

The daemon runs as a Docker container with the following characteristics:

- **Isolated Execution**: Runs in a separate container, isolated from the host system
- **MQTT-Based Communication**: Receives commands via MQTT topics and publishes logs
- **Docker Socket Access**: Has access to the Docker socket to manage workspace containers
- **Persistent Configuration**: Mounts `~/.config/bitswan` to persist workspace configurations
- **Auto-Restart**: Configured with `--restart unless-stopped` for reliability

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MQTT Broker                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ workspace/  │  │ workspace/   │  │    logs      │     │
│  │   init      │  │   remove     │  │   (publish)  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                        ▲              │
                        │              │
                        │              ▼
        ┌──────────────────────────────────────────┐
        │  Automation Server Daemon Container       │
        │  ┌────────────────────────────────────┐  │
        │  │  MQTT Client (Subscriber/Publisher)│  │
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │  bitswan binary (mounted)           │  │
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │  Docker Socket (mounted)            │  │
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │  ~/.config/bitswan (mounted)       │  │
        │  └────────────────────────────────────┘  │
        └──────────────────────────────────────────┘
                        │
                        ▼
        ┌──────────────────────────────────────────┐
        │  Host System (Docker Engine)             │
        │  - Workspace containers                  │
        │  - Docker networks                       │
        └──────────────────────────────────────────┘
```

## Setup

### Initialization

To start the daemon, run:

```bash
bitswan automation-server-daemon init
```

This command:
1. Detects the currently running `bitswan` binary
2. Creates a Docker container named `bitswan-automation-server-daemon`
3. Mounts the binary, config directory, and Docker socket
4. Starts the daemon with `bitswan automation-server-daemon __run`

### Container Configuration

The daemon container is configured with:
- **Image**: `alpine:latest`
- **Name**: `bitswan-automation-server-daemon`
- **Restart Policy**: `unless-stopped`
- **Network**: `host` (for MQTT connectivity)
- **Volumes**:
  - `/usr/local/bin/bitswan:ro` - The bitswan binary (read-only)
  - `/root/.config/bitswan` - Configuration directory
  - `/var/run/docker.sock` - Docker socket for container management

## MQTT Topics

### Subscribed Topics

The daemon subscribes to the following topics to receive commands:

#### `workspace/init`

**Purpose**: Initialize a new workspace

**QoS**: 0

**Message Schema**:

```json
{
  "name": "string (required)",
  "remote": "string (optional)",
  "branch": "string (optional)",
  "domain": "string (optional)",
  "editor-image": "string (optional)",
  "gitops-image": "string (optional)",
  "oauth-config": "string (optional)",
  "no-oauth": "boolean (optional)",
  "ssh-port": "string (optional)",
  "mkcerts": "boolean (optional)",
  "set-hosts": "boolean (optional)",
  "local": "boolean (optional)",
  "no-ide": "boolean (optional)"
}
```

**Field Descriptions**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | The name of the workspace to initialize |
| `remote` | string | No | The remote repository URL to clone |
| `branch` | string | No | The branch to clone from (defaults to repository's default branch) |
| `domain` | string | No | The domain to use for the Caddyfile |
| `editor-image` | string | No | Custom Docker image for the editor |
| `gitops-image` | string | No | Custom Docker image for the gitops service |
| `oauth-config` | string | No | Path to OAuth config file |
| `no-oauth` | boolean | No | Disable automatically fetching OAuth configuration from AOC |
| `ssh-port` | string | No | Use SSH over a custom port (e.g., 443, 22) |
| `mkcerts` | boolean | No | Automatically generate local certificates using mkcerts |
| `set-hosts` | boolean | No | Automatically set hosts to /etc/hosts file |
| `local` | boolean | No | Automatically use `--set-hosts` and `--mkcerts`. If no domain is set, defaults to `bs-<workspacename>.localhost` |
| `no-ide` | boolean | No | Do not start Bitswan Editor |

**Example Message**:

```json
{
  "name": "my-workspace",
  "remote": "git@github.com:user/repo.git",
  "branch": "main",
  "domain": "example.com",
  "local": true,
  "mkcerts": true
}
```

**Behavior**:
- The daemon receives the message and executes `bitswan workspace init <name>` with the appropriate flags
- All output (stdout and stderr) is streamed to the `logs` topic
- The command runs synchronously; the daemon waits for completion before processing the next message

#### `workspace/remove`

**Purpose**: Remove an existing workspace

**QoS**: 0

**Message Schema**:

```json
{
  "name": "string (required)"
}
```

**Field Descriptions**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | The name of the workspace to remove |

**Example Message**:

```json
{
  "name": "my-workspace"
}
```

**Behavior**:
- The daemon receives the message and executes `bitswan workspace remove <name>`
- All output (stdout and stderr) is streamed to the `logs` topic
- The command runs synchronously

### Published Topics

The daemon publishes to the following topic:

#### `logs`

**Purpose**: Stream real-time output from workspace operations

**QoS**: 0

**Retain**: false

**Message Schema**:

```json
{
  "command": "string",
  "object": "string",
  "output": "string",
  "status": "string (optional)"
}
```

**Field Descriptions**:

| Field | Type | Description |
|-------|------|-------------|
| `command` | string | The command being executed. Values: `"workspace-init"` or `"workspace-remove"` |
| `object` | string | The workspace name (the `name` field from the init/remove message) |
| `output` | string | A single line of output from the command (stdout or stderr) |
| `status` | string | The status of the command execution. Values: `"running"` (during execution), `"success"` (on successful completion), or `"failure"` (on error). Omitted for regular log lines during execution. |

**Example Messages**:

```json
{"command": "workspace-init", "object": "my-workspace", "output": "Creating BitSwan Docker network...", "status": "running"}
{"command": "workspace-init", "object": "my-workspace", "output": "BitSwan Docker network created!", "status": "running"}
{"command": "workspace-init", "object": "my-workspace", "output": "Cloning remote repository...", "status": "running"}
{"command": "workspace-init", "object": "my-workspace", "output": "Command completed successfully", "status": "success"}
{"command": "workspace-remove", "object": "my-workspace", "output": "Removing docker containers and volumes...", "status": "running"}
{"command": "workspace-remove", "object": "my-workspace", "output": "Command completed successfully", "status": "success"}
```

**Behavior**:
- Each line of output (from both stdout and stderr) is published as a separate message with `status: "running"`
- Messages are published in real-time as the command executes
- Both stdout and stderr are captured and published
- The `output` field contains exactly one line of text (newlines are stripped)
- Upon command completion, a final message is published with `status: "success"` or `status: "failure"`
- The final status message indicates whether the command completed successfully or failed

## MQTT Connection

### Authentication

The daemon uses MQTT credentials obtained from the Automation Operations Center (AOC):

1. Loads automation server configuration from `~/.config/bitswan/automation_server_config.toml`
2. Creates an AOC client using the configuration
3. Retrieves MQTT credentials using the automation server ID
4. Connects to the MQTT broker with the obtained credentials

### Connection Settings

- **Client ID**: `bitswan-automation-server-daemon-<timestamp>`
- **Auto Reconnect**: Enabled
- **Connect Retry**: Enabled (5 second interval)
- **Keep Alive**: 30 seconds
- **Ping Timeout**: 10 seconds

### Broker URL

The broker URL is constructed from the MQTT credentials:
- **Format**: `tcp://<broker>:<port>`
- **Broker and Port**: Retrieved from AOC MQTT credentials

## Error Handling

### Message Parsing Errors

If a message cannot be parsed as valid JSON or is missing required fields:
- An error message is logged to the daemon's stdout/stderr
- The message is ignored (no response is published)
- The daemon continues processing other messages

### Command Execution Errors

If a workspace init or remove command fails:
- The error is logged to the daemon's stdout/stderr
- Error output is still streamed to the `logs` topic
- The daemon continues processing other messages

### MQTT Connection Errors

If the MQTT connection is lost:
- The daemon automatically attempts to reconnect
- Reconnection attempts occur every 5 seconds
- Once reconnected, subscriptions are automatically restored

## Usage Examples

### Initialize a Workspace

**Publish to `workspace/init`**:

```json
{
  "name": "production-env",
  "remote": "git@github.com:company/infrastructure.git",
  "branch": "main",
  "domain": "prod.example.com",
  "mkcerts": true,
  "set-hosts": true
}
```

**Subscribe to `logs`** to monitor progress:

```json
{"command": "workspace-init", "object": "production-env", "output": "Creating BitSwan Docker network...", "status": "running"}
{"command": "workspace-init", "object": "production-env", "output": "BitSwan Docker network created!", "status": "running"}
{"command": "workspace-init", "object": "production-env", "output": "Cloning remote repository...", "status": "running"}
...
{"command": "workspace-init", "object": "production-env", "output": "Command completed successfully", "status": "success"}
```

### Remove a Workspace

**Publish to `workspace/remove`**:

```json
{
  "name": "production-env"
}
```

**Subscribe to `logs`** to monitor progress:

```json
{"command": "workspace-remove", "object": "production-env", "output": "Removing docker containers and volumes...", "status": "running"}
{"command": "workspace-remove", "object": "production-env", "output": "Docker containers and volumes removed successfully.", "status": "running"}
...
{"command": "workspace-remove", "object": "production-env", "output": "Command completed successfully", "status": "success"}
```

### Local Development Workspace

**Publish to `workspace/init`**:

```json
{
  "name": "dev-workspace",
  "local": true,
  "no-ide": false
}
```

This will:
- Automatically set `--set-hosts` and `--mkcerts`
- Use domain `bs-dev-workspace.localhost` (if domain not specified)
- Start the Bitswan Editor

## Integration Notes

### Message Ordering

- Messages are processed sequentially (one at a time)
- If multiple init/remove messages are received, they are queued and processed in order
- Log messages are published in real-time as they are generated

### Concurrency

- Only one workspace operation (init or remove) runs at a time
- The daemon waits for each command to complete before processing the next message
- Log streaming happens concurrently (stdout and stderr are read in parallel)

### State Management

- Workspace state is persisted in `~/.config/bitswan/workspaces/<workspace-name>/`
- The daemon does not maintain internal state about running operations
- Each message is processed independently

## Troubleshooting

### Daemon Not Starting

1. Check if Docker is running: `docker ps`
2. Verify the binary path is correct
3. Check container logs: `docker logs bitswan-automation-server-daemon`
4. Ensure `~/.config/bitswan` directory exists and is writable

### MQTT Connection Issues

1. Verify automation server configuration exists: `~/.config/bitswan/automation_server_config.toml`
2. Check MQTT broker connectivity from the host
3. Verify MQTT credentials are valid
4. Check daemon logs for connection errors

### Workspace Operations Failing

1. Subscribe to the `logs` topic to see detailed error messages
2. Check Docker socket permissions
3. Verify workspace name doesn't already exist (for init) or exists (for remove)
4. Ensure sufficient disk space and Docker resources

## Security Considerations

- The daemon has full access to the Docker socket, allowing it to manage containers
- MQTT credentials should be kept secure
- The daemon runs with host network access for MQTT connectivity
- Workspace configurations may contain sensitive data (SSH keys, OAuth configs)
- Consider network isolation and access controls for production deployments

