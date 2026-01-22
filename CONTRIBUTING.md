# Contributing to Bitswan Automation Server

This document provides guidelines and instructions for contributing to the Bitswan Automation Server project.

## Building the Binary

To build the `bitswan` binary:

```bash
make build
```

This will create a `bitswan` binary in the current directory.

## Installing the Binary

After building, you can install the binary to your system PATH:

```bash
mv bitswan $(which bitswan)
```

This replaces the existing `bitswan` binary with the newly built one.

## Updating the Automation Server Daemon

After building and installing the binary, you need to update the running daemon container to use the new binary:

```bash
bitswan automation-server-daemon update
```

This command will:
1. Stop the existing daemon container
2. Remove the existing daemon container
3. Start a new daemon container with the updated binary

## Development Workflow

A typical development workflow when making changes to the daemon:

1. Make your code changes
2. Build the binary: `make build`
3. Install the binary: `mv bitswan $(which bitswan)`
4. Update the daemon: `bitswan automation-server-daemon update`

The daemon will automatically restart with your changes.

## Development Mode for Workspaces

The `bitswan workspace update` command supports development mode flags that enable live-reloading for the GitOps and Editor services. This is useful when developing the bitswan-gitops or bitswan-editor projects.

### Dev Mode Flags

| Flag | Description |
|------|-------------|
| `--dev-mode` | Enable development mode with live-reloading for gitops and editor extension |
| `--disable-dev-mode` | Disable development mode |
| `--gitops-dev-source-dir <path>` | Directory to mount as `/src/app` in gitops container for development |
| `--editor-dev-source-dir <path>` | Directory to mount as `/opt/bitswan-extension-dev` in editor container for development |

### Enabling Dev Mode

To enable development mode for a workspace:

```bash
# Enable dev mode for both gitops and editor
bitswan workspace update <workspace-name> --dev-mode \
    --gitops-dev-source-dir /path/to/bitswan-gitops \
    --editor-dev-source-dir /path/to/bitswan-editor/Extension

# Enable dev mode for gitops only
bitswan workspace update <workspace-name> --dev-mode \
    --gitops-dev-source-dir /path/to/bitswan-gitops

# Enable dev mode for editor only
bitswan workspace update <workspace-name> --dev-mode \
    --editor-dev-source-dir /path/to/bitswan-editor/Extension
```

### What Dev Mode Does

**For GitOps:**
- Mounts your local gitops source at `/src/app` inside the container
- Automatically sets `DEBUG=true` for hot-reload support
- Changes to Python files are reflected without container restart

**For Editor:**
- Mounts your local extension source at `/opt/bitswan-extension-dev`
- Sets `BITSWAN_DEV_MODE=true` environment variable
- Creates a symlink to your development extension directory
- Starts a watch process for automatic TypeScript compilation
- Use "Developer: Reload Window" in code-server to reload changes

### Disabling Dev Mode

To disable development mode:

```bash
bitswan workspace update <workspace-name> --disable-dev-mode
```

This removes the source directory mounts and clears the dev mode settings from workspace metadata.

### Dev Mode Configuration Storage

Dev mode settings are stored in the workspace metadata file at:
```
~/.config/bitswan/workspaces/<workspace-name>/metadata.yaml
```

The relevant fields are:
- `dev-mode`: Boolean indicating if dev mode is enabled
- `gitops-dev-source-dir`: Path to gitops source directory
- `editor-dev-source-dir`: Path to editor extension source directory

## Running Tests

To run tests:

```bash
make test
```

## Code Formatting

To format Go code:

```bash
make fmt
```

## Linting

To run linters:

```bash
make lint
```

