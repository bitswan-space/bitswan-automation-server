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

