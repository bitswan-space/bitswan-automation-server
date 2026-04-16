# Integration Tests

## Network Isolation & VPN Integration Tests

`integration-test.sh` is an end-to-end test suite that verifies:

### Network Isolation (per-stage)
- Stage networks (`{workspace}-dev`, `-staging`, `-production`) created during workspace init
- Gitops container on `bitswan_network` only (least privilege)
- Live-dev automations placed on dev network only
- Cross-stage DNS isolation (dev cannot resolve staging/production services)
- Same-stage connectivity (dev containers can reach each other)
- Management plane isolation (gitops cannot HTTP to automation containers)
- Selenium isolation (external testing network, no direct access to any stage)

### VPN (WireGuard)
- VPN init starts WireGuard, VPN Traefik, and CoreDNS containers
- Bootstrap generates valid WireGuard config with correct endpoint
- Device management: create, list, revoke individual devices
- Destroy + reinit lifecycle

## Prerequisites

- A server with Docker installed
- The `bitswan-automation-server` repo cloned and buildable (Go 1.24+)
- The `bitswan-gitops` repo cloned (for dev-mode gitops)
- A DNS wildcard record pointing to the server (e.g., `*.example.bswn.io`)

## Configuration

Edit the top of `integration-test.sh`:

```bash
DOMAIN="editor-network-test.bswn.io"   # Your test domain
WORKSPACE="editor-network-test"         # Workspace name
GITOPS_DEV_SRC="/root/bitswan-gitops"   # Path to gitops repo
SERVER_IP="88.99.15.208"                # Server public IP
```

## Running

```bash
./tests/integration-test.sh
```

The script:
1. Tears down any previous test state
2. Builds the bitswan binary from the current branch
3. Starts the daemon
4. Creates a workspace with dev-mode gitops
5. Deploys a real automation via the gitops API
6. Runs all isolation tests
7. Runs VPN lifecycle tests
8. Tears everything down

## Cron Setup

Run every 30 minutes on a test server:

```bash
*/30 * * * * /path/to/tests/integration-test.sh >> /var/log/bitswan-integration-tests.log 2>&1
```

## Output

Results are logged to `/var/log/bitswan-integration-tests.log`:

```
[2026-04-16T21:30:53Z] Results: 36 passed, 0 failed, 0 skipped, 36 total
```
