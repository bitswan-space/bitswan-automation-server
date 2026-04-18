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
| 2026-04-17 | DNS cross-network leak | PASS | Docker DNS returns SERVFAIL for all cross-network queries |
| 2026-04-17 | Docker API exposure (2375/2376) | PASS | Ports closed, socket not mounted in automations |
| 2026-04-17 | host.docker.internal | PASS | Not resolvable from dev containers |
| 2026-04-17 | **Traefik API via gateway** | **FIXED** | Dev containers could read all routers via gateway:9080. Fixed: bound to 127.0.0.1 |
| 2026-04-17 | Host SSH via gateway | INFO | Port 22 reachable — general host hardening concern, not isolation-specific |
| 2026-04-17 | Gateway ports 80/443 | OK | Expected — containers need outbound internet access |
| 2026-04-17 | ARP scanning | INFO | /proc/net/arp readable, reveals IPs on same network (expected for same-stage) |
| 2026-04-17 | VPN bypass via external Traefik | PASS | Dev container reaches gateway:80/443 but gets 404 — Traefik can't resolve upstreams on stage networks |
| 2026-04-17 | Stale routes on external Traefik | WARN | Editor/gitops routes persist from pre-fix daemon. Dead (404) but leak service names. Clean with daemon update |
| 2026-04-17 | Traefik API binding regression | WARN | `ingress init` uses daemon container's binary. If stale, recreates Traefik with 0.0.0.0:9080 |
| 2026-04-17 | **Cloud metadata (169.254.169.254)** | **FIXED** | Dev containers could read Hetzner metadata (hostname, SSH keys, network config). Fixed: iptables DROP in DOCKER-USER chain |
| 2026-04-17 | Container env var secrets | PASS | No secrets in /proc/1/environ. No secret leakage from orchestrator |
| 2026-04-17 | Docker socket variants | PASS | No docker.sock, run/docker.sock, or bitswan socket in dev containers |
| 2026-04-17 | Host filesystem mount | PASS | No /host mount. Standard overlay filesystem only |
| 2026-04-17 | /proc/sysrq-trigger | PASS | Read-only filesystem, permission denied |
| 2026-04-17 | cgroup escape (release_agent) | PASS | cgroup2 mounted read-only, cannot write notify_on_release |
| 2026-04-17 | IP address manipulation | PASS | RTNETLINK operation not permitted — no NET_ADMIN |
| 2026-04-17 | Promiscuous mode | PASS | ioctl blocked — cannot sniff traffic |
| 2026-04-17 | Route injection | PASS | RTNETLINK blocked — cannot redirect traffic |
| 2026-04-17 | nsenter host namespace | PASS | setns() operation not permitted |
| 2026-04-17 | Kernel module loading | PASS | No /lib/modules, insmod blocked |
| 2026-04-17 | Block device access | PASS | No /dev/sd*, /dev/vd*, /dev/dm-* |
| 2026-04-17 | /proc/1/root symlink | INFO | Reads container's own files only (not host). Container ID visible |
| 2026-04-17 | resolv.conf writable | INFO | Container can modify its own DNS config. Isolated per-container |
| 2026-04-17 | mountinfo host paths | INFO | Container ID and Docker storage paths visible. Information disclosure only |
| 2026-04-17 | Raw packet sockets | PASS | No raw or packet sockets available — ARP spoofing not possible |
| 2026-04-17 | Gitops Docker socket — all 4 vectors | **FIXED** | Container-manager proxy: workspace-scoped, blocks host mounts, blocks cross-workspace access |
| 2026-04-17 | Volume mount traversal | PASS | `../` from /app stays in container root, cannot reach host |
| 2026-04-17 | Secrets dir from automation | PASS | Secrets not in automation mount, not accessible |
| 2026-04-17 | Live-dev source mount writable | INFO | By design — RW mount for live editing. Can modify automation.toml and Dockerfile |
| 2026-04-17 | Dockerfile injection via volume | MEDIUM | Compromised dev container can inject malicious Dockerfile for next build. Mitigated by git review before promotion |
| 2026-04-17 | Gitops API auth on all endpoints | PASS | All endpoints return 401 without valid Bearer token |
| 2026-04-17 | Path traversal in relative_path | PASS | Returns 404, validate_relative_path blocks ../ |
| 2026-04-17 | Path traversal in deployment URL | PASS | Returns 404 |
| 2026-04-17 | Arbitrary deployment_id creation | MEDIUM | Any authenticated caller can create entries in bitswan.yaml with arbitrary IDs. Deploys fail but config is polluted |
| 2026-04-17 | YAML injection via automation_name | PASS | Special characters properly escaped by YAML library |
| 2026-04-17 | Auth brute force / rate limiting | **FIXED** | Added: 10 failures/60s per IP → 429. Warning at 5 failures broadcasts SSE to editor |
| 2026-04-17 | Endpoint spray detection | **FIXED** | Added: 20 404s/60s per IP → blocked 5 min. Warning at 10. SSE to editor |
| 2026-04-17 | DNS poisoning (hostname change) | PASS | sethostname: Operation not permitted |
| 2026-04-17 | Port impersonation on dev network | INFO | Containers can listen on any port — inherent to shared network model |
| 2026-04-17 | Passive traffic sniffing | PASS | No tcpdump, no promiscuous mode (tested iter 4) |
| 2026-04-17 | Secret file mounts in automations | PASS | No secrets mounted into automation containers |
| 2026-04-17 | **Container resource limits** | **CRITICAL** | No memory, PID, or CPU limits. Fork bomb / OOM can crash the host |
| 2026-04-17 | Container-manager proxy bypass via Docker socket | PASS | Docker socket removed from gitops. Only proxy socket available |
| 2026-04-17 | Container-manager proxy bypass via TCP | PASS | Docker TCP (2375) not accessible |
| 2026-04-17 | Exec into container-manager from proxy | PASS | CM has no workspace label, ownership check blocks exec |
| 2026-04-17 | Daemon socket exposure from gitops | WARN | Daemon socket still mounted for ingress IPC. Less critical than Docker socket (no container creation) but allows cross-workspace management. Future: switch to HTTP with auth |
| 2026-04-17 | Proxy bypass via API version prefix | PASS | /v1.44/, /v1.52/ all correctly caught by suffix matching |
| 2026-04-17 | Proxy bypass via URL encoding | PASS | %63reate not interpreted as create |
| 2026-04-17 | Proxy bypass via double-slash | PASS | //containers/create blocked |
| 2026-04-17 | **Capability smuggling via compose** | **FIXED** | cap_add: [ALL] through compose was allowed. Fixed: proxy blocks ALL, SYS_ADMIN, SYS_PTRACE, SYS_MODULE, NET_ADMIN, etc. |
| 2026-04-18 | VPN CA private key from dev | PASS | CA files not mounted in automation containers |
| 2026-04-18 | **Sub-Traefik API from dev** | **FIXED** | Dev containers could read all routes (hostnames, upstreams) via sub-Traefik API port 8080. Fixed: switched to file provider, removed API. Port 8080 now connection refused. |
| 2026-04-18 | Container-manager socket from dev | PASS | Socket not mounted in automation containers |
| 2026-04-18 | VPN Traefik API from dev | PASS | Different network (bitswan_network vs dev). Connection timed out. |
| 2026-04-18 | CoreDNS from dev | PASS | Different network (vpn_network). Connection timed out. |
| 2026-04-18 | Daemon socket from dev | PASS | Socket not mounted in automation containers. DNS resolution fails. |
| 2026-04-18 | SSRF via gitops API | PASS | Malicious relative_path returns 404. Path validation prevents traversal. |
| 2026-04-18 | /proc env secrets leak | PASS | No secrets in automation container /proc/1/environ |
| 2026-04-18 | Inter-container on dev network | INFO | Dev containers CAN reach each other (same network). Expected — same-stage connectivity. |
| 2026-04-18 | Sub-Traefik route manipulation | PASS | REST API now removed. File provider is read-only mount. |
| 2026-04-18 | Coding agent workspace label | **FIXED** | Agent container was missing `gitops.workspace` label, causing container-manager proxy to block creation. Fixed: label added. |
| 2026-04-18 | Sub-Traefik /dynamic writable from dev | PASS | /dynamic not accessible from dev containers (different filesystem) |
| 2026-04-18 | Host header injection via sub-Traefik | PASS | Forged Host header returns 404 — no route match for gitops hostname at sub-Traefik |
| 2026-04-18 | WireGuard config from dev | PASS | /config/ not mounted in automation containers |
| 2026-04-18 | /proc/self/maps readable | INFO | ASLR addresses visible — standard container behavior, no fix needed |
| 2026-04-18 | Unix socket discovery in dev | PASS | No Unix sockets found in dev containers |
| 2026-04-18 | OverlayFS lower dir paths | INFO | Container sees only its own overlay. /proc/1/root stays in container. |
| 2026-04-18 | K8s service account token | PASS | Not K8s environment — no token files present |
| 2026-04-18 | Sub-Traefik port scan from dev | PASS | Only port 80 open (web entrypoint). Port 8080 (API) connection refused. |
| 2026-04-18 | Gitops from dev via bitswan_network IP | PASS | Different Docker networks. Connection timed out. |
| 2026-04-18 | Container-manager from dev | PASS | Different Docker networks. Connection timed out. |
| 2026-04-18 | Daemon from dev | PASS | Different Docker networks. Connection timed out. |

## Active Vulnerabilities

### FIXED: Gitops Docker Socket → Container Manager Proxy
Gitops no longer has direct Docker socket access. A per-workspace `container-manager` sidecar proxies Docker API requests and enforces:
- Container operations filtered to `gitops.workspace={workspace}` label
- Container creation only allowed from this workspace's compose project
- Host mounts (`/`, `/etc`, `/root`, `docker.sock`) blocked
- Network mode `host`/`none` blocked
- Network create/connect/disconnect blocked
- Docker socket mounted read-only on the proxy

In K8s, the container-manager becomes a sidecar with namespace-scoped ServiceAccount.

### CRITICAL: No Container Resource Limits
Automation containers have no memory, PID, or CPU limits. A compromised or buggy container can:
- Fork bomb (infinite processes → host unresponsive)
- OOM (allocate all memory → other containers killed by OOM killer)
- CPU exhaust (mine crypto → starve other workspaces)

**Remediation:** Add default resource limits to `generate_docker_compose()`:
```yaml
deploy:
  resources:
    limits:
      memory: 2G
      cpus: "2.0"
      pids: 256
```

## Known Limitations

- Docker network limit: ~30 networks per host (3 per workspace = ~8-9 workspaces max)
- No mTLS between containers on the same network (trust boundary is the network)
- WireGuard session monitoring relies on iptables LOG + polling, not kernel-level hooks
I w