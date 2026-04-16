# Network Security Model

## Overview

BitSwan uses a layered network isolation model combining Docker network segmentation, WireGuard VPN, and dual-ingress routing to enforce least-privilege access between components.

## Network Topology

```
Internet (untrusted)
    │
    ▼
[External Traefik] ── ports 80/443
    │
    ├─ staging/production automations (expose=true)
    ├─ expose_to + expose_to_internet=true automations
    └─ VPN admin external page (OAuth-protected)

WireGuard VPN (UDP 51820)
    │
    ▼
[VPN Traefik] ── no host ports, bswn.internal TLD
    │
    ├─ editor, gitops (management)
    ├─ all dev/live-dev automations
    ├─ infra services (pgadmin, minio console)
    └─ VPN admin internal page
```

## Docker Network Segmentation

### Per-Workspace Stage Networks
Each workspace gets three isolated networks:
- `{workspace}-dev` — dev + live-dev automations + dev infra services
- `{workspace}-staging` — staging automations + staging infra services  
- `{workspace}-production` — production automations + production infra services

### Management Plane
- `bitswan_network` — gitops, editor, coding-agent, daemon, global Traefik
- Management services communicate via HTTP APIs, NOT direct container access
- Gitops orchestrates containers via Docker socket, not network connectivity

### Bridge Component
- **Only** the workspace sub-Traefik is multi-homed (on all stage networks + bitswan_network)
- It routes HTTP traffic between the ingress and stage-isolated containers

## Security Properties

### P1: Cross-Stage Isolation
A container on `{workspace}-dev` CANNOT reach any container on `{workspace}-staging` or `{workspace}-production`. This is enforced by Docker network boundaries — no shared network, no DNS resolution.

**Tested by:** `test_cross_stage_dns_isolation` — verifies dev cannot resolve staging/production postgres.

### P2: Management Plane Isolation  
Automation containers CANNOT reach management services (gitops, daemon, global Traefik). The management plane is on `bitswan_network` which stage containers are not connected to.

**Tested by:** `test_cross_stage_dns_isolation` — verifies dev cannot resolve gitops, traefik, daemon.

### P3: Least Privilege for Management
Gitops, editor, and coding-agent are on `bitswan_network` ONLY. They cannot directly access automation containers or infrastructure services on stage networks.

**Tested by:** `test_gitops_least_privilege`, `test_management_cannot_reach_containers`.

### P4: Selenium Testing Isolation
When stage networks are enabled, Selenium testing containers are placed on `{workspace}-dev` — the same network as dev automations. This means:
- Selenium CAN reach dev services directly (same network, realistic testing)
- Selenium CANNOT reach staging or production services (different network)
- Selenium CANNOT reach other workspaces (different network)
- Selenium CANNOT reach management plane (different network)

Without stage networks (backward compat), Selenium uses the `bitswan_external_testing` isolated bridge.

**Tested by:** `pentest_selenium` — verifies Selenium can HTTP to dev services but cannot reach staging/production.

### P5: Same-Stage Connectivity
Containers within the same stage CAN communicate (e.g., dev app reaches dev postgres via DNS).

**Tested by:** `test_same_stage_connectivity`.

### P6: VPN-Only Internal Access
When VPN is enabled, editor/gitops/dev automations are only routed through the VPN Traefik. External Traefik does not have routes for internal services.

### P7: External Exposure Control
Only staging/production automations with `expose=true` are routed via external Traefik. Dev automations are internal-only.

## Pen Test Results

_This section is updated automatically by the security test cron._

| Date | Test | Result | Notes |
|------|------|--------|-------|
| — | — | — | No tests run yet |

## Known Limitations

- Docker network limit: ~30 networks per host (3 per workspace = ~8-9 workspaces max)
- No mTLS between containers on the same network (trust boundary is the network)
- WireGuard session monitoring relies on iptables LOG + polling, not kernel-level hooks
