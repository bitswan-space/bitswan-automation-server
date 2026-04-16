#!/bin/bash
set -uo pipefail
export PATH=/usr/local/go/bin:$PATH

DOMAIN="editor-network-test.bswn.io"
WORKSPACE="editor-network-test"
GITOPS_SECRET=""
GITOPS_DEV_SRC="/root/bitswan-gitops"
SERVER_IP="88.99.15.208"
LOG="/var/log/bitswan-integration-tests.log"
PASS=0
FAIL=0
SKIP=0
TOTAL=0
RUN_ID="$(date +%s)"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG"; }
pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); log "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); log "  FAIL: $1 — $2"; }
skip() { SKIP=$((SKIP+1)); TOTAL=$((TOTAL+1)); log "  SKIP: $1"; }

WS_DIR="/root/.config/bitswan/workspaces/${WORKSPACE}/workspace"

# ── SETUP / TEARDOWN ───────────────────────────────────────────────────

teardown() {
    log "=== TEARDOWN ==="
    # Stop VPN
    wg-quick down bitswan-test 2>/dev/null || true
    rm -f /etc/wireguard/bitswan-test.conf 2>/dev/null || true
    # Remove workspace containers
    docker ps -a --format '{{.Names}}' | grep "${WORKSPACE}" | xargs -r docker rm -f 2>/dev/null || true
    # Remove VPN containers
    docker rm -f wireguard traefik-vpn coredns-vpn 2>/dev/null || true
    # Remove workspace dir
    rm -rf "/root/.config/bitswan/workspaces/${WORKSPACE}" 2>/dev/null || true
    rm -rf "/root/.config/bitswan/vpn" 2>/dev/null || true
    rm -rf "/root/.config/bitswan/traefik-vpn" 2>/dev/null || true
    # Remove networks
    docker network rm ${WORKSPACE}-dev ${WORKSPACE}-staging ${WORKSPACE}-production \
        ${WORKSPACE}-external-testing bitswan_vpn_network 2>/dev/null || true
    log "Teardown complete"
}

setup() {
    log "=== SETUP ==="
    teardown

    log "Building bitswan CLI (combined branch)..."
    cd /root/bitswan-automation-server
    git checkout test/combined 2>/dev/null
    make build 2>&1 | tail -1
    docker stop bitswan-automation-server-daemon 2>/dev/null || true
    docker rm -f bitswan-automation-server-daemon 2>/dev/null || true
    cp -f bitswan /usr/local/bin/bitswan

    log "Updating gitops source..."
    cd "$GITOPS_DEV_SRC"
    git checkout feat/stage-networks 2>/dev/null
    git pull origin feat/stage-networks 2>/dev/null

    log "Initializing daemon..."
    bitswan automation-server-daemon init 2>&1 | tail -3
    sleep 5

    log "Creating workspace..."
    bitswan workspace init --domain "$DOMAIN" \
        --gitops-dev-source-dir "$GITOPS_DEV_SRC" \
        --no-ide "$WORKSPACE" 2>&1 | tail -5

    local metadata="/root/.config/bitswan/workspaces/${WORKSPACE}/metadata.yaml"
    [ ! -f "$metadata" ] && { log "FATAL: metadata.yaml not found"; return 1; }
    GITOPS_SECRET=$(grep 'gitops-secret' "$metadata" | awk '{print $2}')
    [ -z "$GITOPS_SECRET" ] && { log "FATAL: No gitops secret"; return 1; }

    # Wait for gitops
    local gc=$(gc_name)
    for i in $(seq 1 60); do
        docker exec "$gc" curl -sf -o /dev/null \
            -H "Authorization: Bearer $GITOPS_SECRET" \
            "http://localhost:8079/automations/" 2>/dev/null && break
        sleep 2
    done
    log "Gitops ready. STAGE_NETWORKS=$(docker exec "$gc" printenv BITSWAN_STAGE_NETWORKS 2>/dev/null)"

    # Create test automations
    mkdir -p "${WS_DIR}/TestBP/test-app"
    cat > "${WS_DIR}/TestBP/test-app/automation.toml" << 'TOML'
[deployment]
image = "nginx:alpine"
expose = true
port = 80
TOML

    # Create worktree
    docker exec "$gc" curl -sf -X POST "http://localhost:8079/worktrees/create" \
        -H "Authorization: Bearer $GITOPS_SECRET" \
        -H "Content-Type: application/json" \
        -d '{"branch_name": "test-wt"}' 2>/dev/null || true
    sleep 2
    mkdir -p "${WS_DIR}/worktrees/test-wt/TestBP/test-app"
    cp "${WS_DIR}/TestBP/test-app/automation.toml" "${WS_DIR}/worktrees/test-wt/TestBP/test-app/"

    log "Setup complete"
}

# ── HELPERS ─────────────────────────────────────────────────────────────

gc_name() { docker ps --format '{{.Names}}' | grep "${WORKSPACE}.*gitops" | head -1; }

container_networks() {
    docker inspect "$1" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null
}

container_ip() {
    docker inspect "$1" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | awk '{print $1}'
}

can_reach() {
    docker exec "$1" sh -c "getent hosts $2 2>/dev/null" > /dev/null 2>&1
}

can_ping() {
    docker exec "$1" ping -c 1 -W 2 "$2" > /dev/null 2>&1
}

can_http() {
    docker exec "$1" sh -c "wget -q -O /dev/null --timeout=3 http://$2 2>/dev/null" > /dev/null 2>&1
}

wait_container() {
    local pattern="$1" timeout="${2:-30}"
    for i in $(seq 1 "$timeout"); do
        local c=$(docker ps --format '{{.Names}}' | grep "$pattern" | head -1)
        [ -n "$c" ] && echo "$c" && return 0
        sleep 2
    done
    return 1
}

deploy_live_dev() {
    docker exec "$(gc_name)" curl -sf -X POST "http://localhost:8079/automations/start-live-dev" \
        -H "Authorization: Bearer $GITOPS_SECRET" \
        -H "Content-Type: application/json" \
        -d '{"relative_path": "worktrees/test-wt/TestBP/test-app", "worktree": "test-wt"}' 2>&1
}

# ── NETWORK ISOLATION TESTS ────────────────────────────────────────────

test_stage_networks_created() {
    log "--- Stage networks created by workspace init ---"
    for stage in dev staging production; do
        docker network inspect "${WORKSPACE}-${stage}" > /dev/null 2>&1 && \
            pass "Network ${WORKSPACE}-${stage} exists" || \
            fail "Network ${WORKSPACE}-${stage} missing" "workspace init should create it"
    done
}

test_gitops_least_privilege() {
    log "--- Gitops network isolation (least privilege) ---"
    local gc=$(gc_name)
    [ -z "$gc" ] && { fail "Gitops not running" ""; return; }
    local nets=$(container_networks "$gc")

    echo "$nets" | grep -q "bitswan_network" && \
        pass "Gitops on bitswan_network" || \
        fail "Gitops not on bitswan_network" "$nets"

    for stage in dev staging production; do
        echo "$nets" | grep -q "${WORKSPACE}-${stage}" && \
            fail "Gitops on ${stage} network" "least privilege violated" || \
            pass "Gitops NOT on ${stage} network"
    done
}

test_live_dev_network_placement() {
    log "--- Live-dev lands on dev network only ---"
    local result=$(deploy_live_dev)
    log "  Deploy: ${result:0:120}"

    local container=$(wait_container "test-app.*live-dev" 30) || true
    if [ -z "$container" ]; then
        docker logs "$(gc_name)" 2>&1 | grep -i "error\|traceback" | tail -3 | while read l; do log "  gitops: $l"; done
        fail "Live-dev container not started" "deploy failed"
        return
    fi
    log "  Container: $container"
    local nets=$(container_networks "$container")

    echo "$nets" | grep -q "${WORKSPACE}-dev" && \
        pass "Live-dev on dev network" || \
        fail "Live-dev NOT on dev network" "$nets"

    for net in staging production bitswan_network; do
        echo "$nets" | grep -q "${WORKSPACE}-${net}\|${net}" && \
            fail "Live-dev on ${net}" "should be dev only" || \
            pass "Live-dev NOT on ${net}"
    done
}

test_cross_stage_dns_isolation() {
    log "--- Cross-stage DNS isolation ---"
    local c=$(docker ps --format '{{.Names}}' | grep "test-app.*live-dev" | head -1)
    [ -z "$c" ] && { skip "No dev container for DNS test"; return; }

    can_reach "$c" "${WORKSPACE}__postgres-staging" && \
        fail "Dev resolves staging postgres" "DNS leak" || \
        pass "Dev cannot resolve staging postgres"

    can_reach "$c" "${WORKSPACE}__postgres" && \
        fail "Dev resolves production postgres" "DNS leak" || \
        pass "Dev cannot resolve production postgres"

    can_reach "$c" "${WORKSPACE}-gitops" && \
        fail "Dev resolves gitops" "management plane leak" || \
        pass "Dev cannot resolve gitops"

    can_reach "$c" "traefik" && \
        fail "Dev resolves global traefik" "management plane leak" || \
        pass "Dev cannot resolve global traefik"

    can_reach "$c" "bitswan-automation-server-daemon" && \
        fail "Dev resolves daemon" "management plane leak" || \
        pass "Dev cannot resolve daemon"
}

test_same_stage_connectivity() {
    log "--- Same-stage containers can communicate ---"
    local c=$(docker ps --format '{{.Names}}' | grep "test-app.*live-dev" | head -1)
    [ -z "$c" ] && { skip "No dev container"; return; }

    docker run -d --name ${WORKSPACE}-dev-peer --network ${WORKSPACE}-dev \
        --hostname dev-peer alpine sleep 60 > /dev/null 2>&1

    can_reach "$c" "dev-peer" && \
        pass "Dev app can reach dev-peer (same stage)" || \
        fail "Dev app cannot reach dev-peer" "same-stage DNS broken"

    docker rm -f ${WORKSPACE}-dev-peer 2>/dev/null || true
}

test_management_cannot_reach_containers() {
    log "--- Management plane cannot HTTP to automation containers ---"
    local gc=$(gc_name)
    local c=$(docker ps --format '{{.Names}}' | grep "test-app.*live-dev" | head -1)
    [ -z "$gc" ] || [ -z "$c" ] && { skip "Missing containers"; return; }

    local dev_ip=$(container_ip "$c")
    [ -z "$dev_ip" ] && { skip "Cannot get dev container IP"; return; }

    can_http "$gc" "${dev_ip}:80" && \
        fail "Gitops can HTTP to dev container at $dev_ip" "network isolation broken" || \
        pass "Gitops cannot HTTP to dev container (isolated)"
}

test_selenium_full_isolation() {
    log "--- Selenium network isolation ---"
    docker network create ${WORKSPACE}-external-testing 2>/dev/null || true
    docker run -d --name ${WORKSPACE}-selenium --network ${WORKSPACE}-external-testing \
        alpine sleep 60 > /dev/null 2>&1

    local c=$(docker ps --format '{{.Names}}' | grep "test-app.*live-dev" | head -1)
    if [ -n "$c" ]; then
        local dev_ip=$(container_ip "$c")

        can_reach "${WORKSPACE}-selenium" "$c" && \
            fail "Selenium resolves dev by name" "isolation broken" || \
            pass "Selenium cannot resolve dev container"

        [ -n "$dev_ip" ] && {
            can_ping "${WORKSPACE}-selenium" "$dev_ip" && \
                fail "Selenium pings dev IP $dev_ip" "L3 isolation broken" || \
                pass "Selenium cannot ping dev IP"
        }
    fi

    can_ping "${WORKSPACE}-selenium" "8.8.8.8" && \
        pass "Selenium has internet access" || \
        fail "Selenium cannot reach internet" "outbound broken"

    # Selenium cannot reach management plane either
    can_reach "${WORKSPACE}-selenium" "traefik" && \
        fail "Selenium resolves traefik" "should be fully isolated" || \
        pass "Selenium cannot resolve traefik"

    docker rm -f ${WORKSPACE}-selenium 2>/dev/null || true
    docker network rm ${WORKSPACE}-external-testing 2>/dev/null || true
}

# ── VPN TESTS ──────────────────────────────────────────────────────────

test_vpn_init() {
    log "--- VPN initialization ---"

    # Init VPN
    local result
    result=$(bitswan vpn init --endpoint "$SERVER_IP" 2>&1)
    log "  vpn init: $(echo "$result" | tail -3 | tr '\n' ' ')"

    # Check containers started
    docker ps --format '{{.Names}}' | grep -q "wireguard" && \
        pass "WireGuard container running" || \
        fail "WireGuard not running" "vpn init failed to start container"

    docker ps --format '{{.Names}}' | grep -q "traefik-vpn" && \
        pass "VPN Traefik running" || \
        fail "VPN Traefik not running" "vpn init failed"

    docker ps --format '{{.Names}}' | grep -q "coredns-vpn" && \
        pass "CoreDNS VPN running" || \
        fail "CoreDNS VPN not running" "vpn init failed"

    # Check VPN network created
    docker network inspect bitswan_vpn_network > /dev/null 2>&1 && \
        pass "bitswan_vpn_network exists" || \
        fail "bitswan_vpn_network missing" "vpn init should create it"
}

test_vpn_bootstrap() {
    log "--- VPN bootstrap (generate admin credentials) ---"

    local result
    result=$(bitswan vpn bootstrap --device test-device 2>&1)
    log "  bootstrap: $(echo "$result" | head -1)"

    # Check config file was created
    local slug=$(grep 'slug' /root/.config/bitswan/automation_server_config.toml 2>/dev/null | awk -F'"' '{print $2}')
    [ -z "$slug" ] && slug="wireguard"
    local conf="${slug}.conf"

    [ -f "$conf" ] && \
        pass "VPN config file created: $conf" || \
        { fail "VPN config file not created" "expected $conf"; return; }

    # Verify it's valid WireGuard config
    grep -q "PrivateKey" "$conf" && \
        pass "Config has PrivateKey" || \
        fail "Config missing PrivateKey" "invalid wireguard config"

    grep -q "Endpoint = ${SERVER_IP}" "$conf" && \
        pass "Config has correct endpoint" || \
        fail "Config has wrong endpoint" "expected $SERVER_IP"

    grep -q "AllowedIPs" "$conf" && \
        pass "Config has AllowedIPs" || \
        fail "Config missing AllowedIPs" "invalid config"

    rm -f "$conf" 2>/dev/null
}

test_vpn_device_management() {
    log "--- VPN device management ---"

    # List devices
    local devices
    devices=$(bitswan vpn list-devices 2>&1)
    echo "$devices" | grep -q "test-device" && \
        pass "Device test-device listed" || \
        fail "Device test-device not in list" "$devices"

    # Generate second device
    bitswan vpn bootstrap --device second-device 2>/dev/null
    devices=$(bitswan vpn list-devices 2>&1)
    echo "$devices" | grep -q "second-device" && \
        pass "Second device listed" || \
        fail "Second device not in list" "$devices"

    # Revoke second device
    bitswan vpn revoke "root/second-device" 2>/dev/null
    devices=$(bitswan vpn list-devices 2>&1)
    echo "$devices" | grep -q "second-device" && \
        fail "Revoked device still listed" "$devices" || \
        pass "Revoked device removed"

    # First device still exists
    echo "$devices" | grep -q "test-device" && \
        pass "First device still exists after revoking second" || \
        fail "First device disappeared" "$devices"

    # Cleanup conf files
    rm -f *.conf 2>/dev/null
}

test_vpn_destroy_and_reinit() {
    log "--- VPN destroy and reinit ---"

    bitswan vpn destroy 2>/dev/null
    sleep 2

    docker ps --format '{{.Names}}' | grep -q "wireguard" && \
        fail "WireGuard still running after destroy" "" || \
        pass "WireGuard stopped after destroy"

    # Reinit should work
    bitswan vpn init --endpoint "$SERVER_IP" 2>/dev/null
    sleep 3

    docker ps --format '{{.Names}}' | grep -q "wireguard" && \
        pass "WireGuard running after reinit" || \
        fail "WireGuard not running after reinit" ""

    # Cleanup
    bitswan vpn destroy 2>/dev/null
}

# ── MAIN ────────────────────────────────────────────────────────────────

main() {
    log "========================================================"
    log "BitSwan Integration Test Suite (run $RUN_ID)"
    log "$(date -u) | Server: $SERVER_IP | Domain: $DOMAIN"
    log "========================================================"

    if ! setup; then
        log "FATAL: Setup failed"
        teardown
        exit 1
    fi

    # Network isolation tests
    log "== NETWORK ISOLATION =="
    test_stage_networks_created
    test_gitops_least_privilege
    test_live_dev_network_placement
    test_cross_stage_dns_isolation
    test_same_stage_connectivity
    test_management_cannot_reach_containers
    test_selenium_full_isolation

    # VPN tests
    log "== VPN =="
    # Ensure daemon is still running
    if ! docker ps --format "{{.Names}}" | grep -q bitswan-automation-server-daemon; then
        log "Restarting daemon for VPN tests..."
        bitswan automation-server-daemon init 2>&1 | tail -1
        sleep 5
    fi
    test_vpn_init
    test_vpn_bootstrap
    test_vpn_device_management
    test_vpn_destroy_and_reinit

    teardown

    log "========================================================"
    log "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped, ${TOTAL} total"
    log "========================================================"

    [ "$FAIL" -gt 0 ] && exit 1 || exit 0
}

main "$@"
