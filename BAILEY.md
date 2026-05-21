# Bailey design

The protected-ingress + MFA + per-endpoint ACL layer of the bitswan
automation server. This document describes the architecture, the
trust model, and the security boundaries — the *intent*. Test suites
under `/root/test-*.sh` and `/root/test-*.py` exercise the
behaviour; this file explains why the behaviour is shaped the way it
is and what attacks it does (and does not) defend against.

## High-level picture

```
                            Internet
                                │
                                ▼
┌────────────────────────────────────────────────────────────────┐
│  platform traefik (host net, :80/:443, Let's Encrypt)          │
│  Dispatches by Host:                                           │
│    bailey-admin.<domain>  → bailey-admin oauth2-proxy (:9998)  │
│    <ws>-editor.<domain>   → bitswan-protected-proxy            │
│    <ws>-gitops.<domain>   → bitswan-protected-proxy            │
└────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────┐
│  bitswan-protected-proxy (oauth2-proxy)                        │
│  - One shared Keycloak client                                  │
│  - Verifies user identity                                      │
│  - Forwards X-Forwarded-Email + X-Forwarded-Groups upstream    │
│  - Upstream: http://bitswan-automation-server-daemon:9080      │
└────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────┐
│  MFA gate (daemon :9080)                                       │
│  Two-phase enforcement:                                        │
│   1. MFA                                                       │
│      - Admin? require TOTP cookie (_bailey_2fa)                │
│      - Everyone needs a device cookie (_bailey_device)         │
│      - First admin on empty server → bootstrap-TOFU            │
│      - No device → /pending-pair (6-digit cross-device code)   │
│   2. ACL                                                       │
│      - Look up Host in endpoints table                         │
│      - Original owner OR matching email/group grant → through  │
│      - Nothing → 403 + "Request access" form                   │
│                                                                │
│  On top-level GETs (Sec-Fetch-Dest: document) wraps the        │
│  response in a chrome iframe (footer with server name +        │
│  email + share + logout).                                      │
└────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────┐
│  traefik-protected (workspace-facing, bitswan_network only)    │
│  - Routes per-hostname → workspace's editor / gitops service   │
│  - Strips X-Frame-Options + CSP frame-ancestors on responses   │
└────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                Per-workspace editor / gitops container
                (their own oauth2-proxy → upstream)
```

The chain is intentionally narrow: every request from the internet
ends up at the daemon's MFA gate before hitting any workspace
service. The only public-facing oauth2-proxy is the shared
`bitswan-protected-proxy` — workspace-specific oauth proxies still
exist (so workspace services don't see raw Keycloak tokens), but
they're never directly reachable from outside the chain.

## Trust model

| Actor | What they get | What they need to prove |
|---|---|---|
| **Anonymous internet** | Keycloak login page only | nothing |
| **Authenticated Keycloak user, no device** | `/pending-pair` page with a 6-digit code | valid Keycloak session |
| **Authenticated user, device cookie** | ACL check → endpoint access if granted | session + device cookie |
| **Admin (Keycloak `/admin` group), no TOTP** | `/admin/challenge` then forced to enrol | session |
| **First-ever admin on empty server** | Auto-trusted as first device, forced to enrol TOTP, becomes server owner | session + admin group |
| **Endpoint owner** | All operations on the endpoint, including share UI | session + device + owner row |
| **Endpoint grantee (`access`)** | Read-only access to the endpoint, no share | session + device + grant |
| **Endpoint grantee (`owner`)** | Same as owner | session + device + grant |

Notably, **admin status grants no automatic endpoint access**. The
admin role is purely about device-trust approvals: an admin can
approve a non-admin's pending device pair if the non-admin has no
other trusted devices. The admin doesn't get to peek inside the
non-admin's workspace.

## Device trust (WhatsApp-style)

Adapted from the WhatsApp Web pairing UX:

1. User on a new browser hits any protected endpoint.
2. Keycloak login → MFA gate sees no device cookie → renders
   `/pending-pair` with a randomly-generated 6-digit code.
3. The new browser's JS polls `/pending-pair/poll` every 2s.
4. The user reads the code to:
   - Someone on an already-trusted device (any user, peer-trust), or
   - An admin (if they have no trusted devices yet).
5. The trusted party posts `email + code` to `/approve`.
6. Next poll returns 200 + an HMAC-signed `_bailey_device` cookie.
7. The new device is trusted forever (until manually removed).

Each device row is keyed by `(email, device_id)` in SQLite. The
cookie carries `email . device_id . expiry . hmac(server_signing_key)`
and the gate cross-references the ID against the user's stored
devices on every request, so revoking a device on the server
invalidates the cookie immediately.

### TOTP recovery

A user with no trusted devices and no admin to call can fall back to
TOTP if they enrolled it ahead of time:

1. Admin TOTP is **mandatory** — every admin is forced through
   `/2fa-gate/admin/enroll` on first sign-in.
2. Non-admin TOTP is **opt-in** — they can enrol via `/2fa-gate/account/2fa`.
3. With a TOTP record on file, the user can hit
   `/2fa-gate/recovery`, enter a current code, and instantly mint a
   `_bailey_device` cookie for the current browser without needing
   an external approver.

### Bootstrap window

The first admin to sign in on an empty server (no devices ever
paired) gets:

- Auto-trusted as their first device (TOFU).
- Forced through TOTP enrol immediately.
- Recorded as the **server's owner** for the `bailey-admin.<domain>` endpoint.

After this single bootstrap, the TOFU path is closed. Every
subsequent device must be approved via the pending-pair flow.

## Per-endpoint ACL

The ACL system layers on top of MFA. Every protected hostname has at
most one row in the `endpoints` table:

```sql
CREATE TABLE endpoints (
  hostname     TEXT PRIMARY KEY COLLATE NOCASE,
  owner_email  TEXT NOT NULL COLLATE NOCASE,
  display_name TEXT,
  created_at   TEXT NOT NULL
);
```

Additional access is granted via `endpoint_grants`:

```sql
CREATE TABLE endpoint_grants (
  endpoint_host   TEXT NOT NULL,
  principal_type  TEXT NOT NULL CHECK (principal_type IN ('email','group')),
  principal_value TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('owner','access')),
  granted_at      TEXT NOT NULL,
  granted_by      TEXT NOT NULL,
  PRIMARY KEY (endpoint_host, principal_type, principal_value, role)
);
```

Resolution on every request:

1. Endpoint not registered? Treat as "bootstrap window" (the next
   `registerEndpoint` call will set the owner). For `bailey-admin.*`,
   auto-register the current caller as server owner.
2. Caller's email == endpoint owner? Allow as `owner`.
3. Caller's email has a grant? Use the highest matching role.
4. Caller's Keycloak group matches a grant's group? Use that role.
5. Otherwise: write an `access_requests` row, render the
   "Request access" page.

Owners can:
- Grant access to specific emails or Keycloak groups
- Promote a grantee to `owner` (multiple owners allowed)
- Revoke any grant they made
- View pending access requests
- Approve / deny pending requests

The group dropdown is populated from the caller's own
`X-Forwarded-Groups` header — no Keycloak admin API call, so a user
can only grant access to groups they themselves are in.

## Endpoint registration

| Endpoint kind | Owner = |
|---|---|
| Workspace editor (`<ws>-editor.<domain>`) | Whoever ran `bitswan workspace init`'s `--owner` flag |
| Workspace gitops (`<ws>-gitops.<domain>`) | Same |
| Automation (`<ws>-<auto>.<domain>`) | Whoever deployed the automation |
| `bailey-admin.<domain>` | First user to sign in on a fresh server |

`--owner` is mandatory on `bitswan workspace init` — there's no
default. The MQTT command handler must pass it through from the
frontend's authenticated session.

## Chrome wrap

For top-level browser navigations (`Sec-Fetch-Dest: document`,
`Accept: text/html`, no `_bailey_iframe=1` marker), the MFA gate
substitutes the response body with a wrapper page:

```
┌─────────────────────────────────────────────────────────┐
│              [the upstream service in iframe]           │
│                                                         │
│                                                         │
├─────────────────────────────────────────────────────────┤
│ 🛡 Protected by Bitswan Bailey <server>  ·  Logged in as │
│   <email>  ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲  [Share][Logout]│
└─────────────────────────────────────────────────────────┘
```

The iframe URL includes `?_bailey_iframe=1` so subsequent loads of
the same URL (from the iframe, not the top-level) skip the wrap.
Subresources (Accept != text/html), POSTs, and iframe loads
(`Sec-Fetch-Dest: iframe`) never get wrapped.

The `Share` button takes the user to
`/2fa-gate/share/<this-hostname>`. The `Logout` button goes to
`/oauth2/sign_out`. Both targets are on the bailey-admin host so
they're not subject to the wrap themselves.

## Threats and mitigations

**T1: Stolen device cookie.**
Cookies are HMAC-signed with a server-only key, expire after a year,
and cross-reference the device row in SQLite. Revoking the device
row on the server invalidates the cookie immediately. The user can
revoke their own devices from `/2fa-gate/account/devices`.

**T2: TOTP secret exfiltration during enrol.**
The candidate secret lives in a path-scoped, HttpOnly,
Secure-when-TLS cookie (`_bailey_enroll` for admin, `_bailey_account_enroll`
for self-service) and is only persisted to SQLite after the user
successfully proves a code. Reloading the enrol page re-uses the
same candidate cookie so the QR doesn't change between scan and submit
— this also means the secret on the wire is the same one
displayed on screen.

**T3: Replay of the 6-digit pair code.**
Codes live in memory only, expire after 5 minutes, and are deleted
on first successful poll. Each `/pending-pair` GET regenerates the
code for that email (last one wins). The 6-digit space (1M values)
makes brute force from a hostile third party impractical within the
5-minute window: at the rate-limited approve handler's effective
throughput, fewer than ~600 attempts can be made before expiry.

**T4: Cross-tab cookie contamination across subdomains.**
The TOTP and device cookies are issued with `Domain=.<protected-domain>`
so they're shared across all `*.<domain>` subdomains. The oauth2-proxy
session cookies are per-host (no Domain attribute), so signing out
of one workspace's chrome doesn't clobber the others.

**T5: Endpoint owner escalation via Keycloak group spoofing.**
oauth2-proxy is responsible for setting `X-Forwarded-Groups`. The
daemon trusts this header. An attacker who can interpose between
oauth2-proxy and the daemon could spoof any group. Mitigation: the
daemon listens only on the docker-internal network; the only thing
that should reach it is oauth2-proxy itself.

**T6: Insecure direct object reference on share endpoints.**
`/2fa-gate/share/<hostname>` is the only way to manage grants. The
handler explicitly calls `roleFor(host, caller_email, caller_groups)`
and refuses if the result isn't `owner`. The `request-access`
endpoint accepts any authenticated user (writing into a
fixed-schema `access_requests` table by hostname + email), no
spoofing risk.

**T7: First-sign-in race on a fresh server.**
The first user to sign in on `bailey-admin.<domain>` becomes server
owner. This is a TOFU window. Mitigation: the operator should sign
in immediately after `bitswan automation-server-daemon init`. A
future hardening would be to require a pre-set `creator_email`
field in `automation_server_config.toml` and refuse to bootstrap
otherwise.

**T8: Admin abusing device-approval power.**
An admin can approve any user's pending device pair, including
their own (to silently impersonate). Mitigation: the device
appearing in the user's `/account/devices` page records the
approver's email — the user can see who trusted any given device
and revoke it.

## Known limitations / future work

- **Hardcoded "no admin override" for endpoint ACL** — there's
  currently no way to grant emergency access without the original
  owner. Adding a server-owner / org-admin escape hatch would help
  recovery from a lost-owner situation, at the cost of weakening
  the strict ACL guarantees. Out of scope for this iteration.

- **No bulk grant management** — every grant goes through a form
  submission. For organisations with many endpoints, a future
  `/2fa-gate/admin/bulk-share` page could help.

- **No per-grant expiry** — grants are forever until revoked. A
  future schema migration could add `expires_at`.

- **No audit log** — grant changes are not logged anywhere except
  in the `endpoint_grants.granted_at + granted_by` columns
  themselves. A SIEM-forwardable audit log is a natural extension.

- **No CSRF tokens** — the share UI submits via form POST with no
  CSRF token. The cookies are SameSite=None for iframe
  compatibility, which is the worst case for CSRF. Mitigation
  options: add a CSRF token to share forms, OR drop SameSite=None
  on the bailey-admin cookies (and accept that the chrome wrap
  iframe needs to live on a separate host).

## Test surface

The repo's E2E suite (`/root/run-all-e2e.sh`) exercises:

- MFA gate flows (`test-mfa-flows.sh`) — 9 curl scenarios
- bailey-admin API (`test-bailey-admin-api.sh`) — 17 curl scenarios
- Restart resilience (`test-restart-resilience.sh`) — cookies +
  records survive daemon restart
- SIEM forwarding end-to-end (`test-siem-e2e.sh`)
- Browser admin happy path (`run-mfa-e2e.sh`) — Selenium
- Browser non-admin pending-pair (`run-mfa-e2e-nonadmin.sh`) — Selenium
- Full workspace lifecycle (`run-workspace-e2e.sh`) — Selenium +
  requests, creates a new workspace and drives cross-device
  approval against the chrome wrap
- Workspace remove cleanup (`test-workspace-lifecycle.sh`)

Pen-tests run against the deployed daemon via `test-pentest.sh`
(separately maintained — see that file for the attack matrix).
