#!/usr/bin/env python3
"""End-to-end smoke test that exercises the bailey-dev custom images.

Flow:
  1. Create a workspace via the bailey admin API (NDJSON stream).
     The daemon's server_settings table is expected to point
     default_gitops_image + default_dashboard_image at the
     bailey-dev tags, so the workspace is built on the locally-
     built dashboard / gitops images.
  2. Wait for the workspace's dashboard container to be running.
  3. Launch chromedriver, inject X-Forwarded-Email + X-Forwarded-Groups
     headers via CDP, navigate to the dashboard's inner hostname,
     and assert the dashboard HTML loads (<title> or similar marker).
  4. Take a screenshot to /tmp/ for human review.
  5. Clean up the test workspace.

Why CDP headers instead of a real Keycloak login: the bailey wrap
chain is designed to be hard to bypass without paired credentials
(MFA + OIDC session). Headless headers are the only practical
auth path for an automated test on this stack — they exercise the
same upstream code as a real signed-in browser would, just skipping
the OIDC handshake.

Run from the sandbox host where chromedriver + chromium are
installed and where /var/run/docker.sock works:
    python3 tests/selenium_bailey_dev_smoke.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

ADMIN_EMAIL = os.environ.get("BAILEY_ADMIN_EMAIL", "timothy.hobbs@libertyaces.com")
ADMIN_GROUPS = os.environ.get("BAILEY_ADMIN_GROUPS", "admin")
DAEMON_CONTAINER = "bitswan-automation-server-daemon"
DOMAIN = os.environ.get("BAILEY_DOMAIN", "sandbox.bitswan.ai")


def docker_exec_curl(args: list[str]) -> bytes:
    """Run `curl` inside the daemon container so we hit the docs server
    on localhost:8080 (admin headers are accepted there without going
    through oauth2-proxy first)."""
    cmd = ["docker", "exec", DAEMON_CONTAINER, "curl", "-sS"] + args
    return subprocess.check_output(cmd)


def create_workspace(name: str) -> dict:
    """POST /bailey/api/workspaces, stream the NDJSON, return the
    parsed `done` (or `error`) event."""
    print(f"[create] {name}")
    body = json.dumps({"name": name})
    raw = docker_exec_curl(
        [
            "-N",
            "--max-time",
            "180",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            f"X-Forwarded-Email: {ADMIN_EMAIL}",
            "-H",
            f"X-Forwarded-Groups: {ADMIN_GROUPS}",
            "--data",
            body,
            "http://localhost:8080/bailey/api/workspaces",
        ]
    )
    last_event = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        ev = event.get("event")
        if ev == "log":
            stream = event.get("stream", "")
            msg = event.get("message", "")
            tag = "[stderr]" if stream == "stderr" else "[stdout]"
            print(f"  {tag} {msg}")
        elif ev == "start":
            print(f"  [start] {event.get('message', '')}")
        elif ev in {"done", "error"}:
            last_event = event
            print(f"  [{ev}] {event}")
    if last_event is None:
        raise RuntimeError("workspace create stream ended without done/error event")
    if last_event.get("event") == "error":
        raise RuntimeError(f"create failed: {last_event.get('error')}")
    return last_event


def wait_for_dashboard(workspace: str, attempts: int = 30, pause: float = 2.0) -> str:
    """Poll the dashboard's inner hostname until it returns 200. Returns
    the URL when ready."""
    dashboard_host = f"{workspace}-dashboard--inner.{DOMAIN}"
    url = f"https://{dashboard_host}/"
    print(f"[wait] {url}")
    for i in range(attempts):
        try:
            raw = subprocess.check_output(
                [
                    "curl",
                    "-sS",
                    "-k",
                    "--resolve",
                    f"{dashboard_host}:443:127.0.0.1",
                    "-o",
                    "/tmp/_probe_dash.html",
                    "-w",
                    "%{http_code}",
                    "-H",
                    f"X-Forwarded-Email: {ADMIN_EMAIL}",
                    "-H",
                    f"X-Forwarded-Groups: {ADMIN_GROUPS}",
                    url,
                ],
                timeout=10,
            )
        except subprocess.CalledProcessError:
            time.sleep(pause)
            continue
        status = raw.decode().strip()
        print(f"  attempt {i + 1}/{attempts}: HTTP {status}")
        if status == "200":
            return url
        time.sleep(pause)
    raise RuntimeError(f"dashboard {url} never returned 200")


def selenium_open_dashboard(workspace: str) -> None:
    """Drive headless chromium to the dashboard inner URL with admin
    headers injected via the Chrome DevTools Protocol."""
    dashboard_host = f"{workspace}-dashboard--inner.{DOMAIN}"
    url = f"https://{dashboard_host}/"
    print(f"[selenium] opening {url}")

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--ignore-certificate-errors")
    # --resolve equivalent for chrome: point the public-looking hostname
    # at our local traefik so chromedriver doesn't go through real DNS.
    options.add_argument(f"--host-resolver-rules=MAP {dashboard_host} 127.0.0.1")

    service = Service(executable_path="/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=service, options=options)
    try:
        # Inject the X-Forwarded-* headers via CDP so the daemon's
        # admin-gated paths see us as signed-in. enableNetwork has to
        # be on before setExtraHTTPHeaders takes effect.
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd(
            "Network.setExtraHTTPHeaders",
            {
                "headers": {
                    "X-Forwarded-Email": ADMIN_EMAIL,
                    "X-Forwarded-Groups": ADMIN_GROUPS,
                }
            },
        )
        driver.get(url)
        # Wait for the document to have a <title> and the body to
        # contain SOMETHING. The dashboard is a React app — the initial
        # HTML has a <title>; once the SPA hydrates, the body fills.
        WebDriverWait(driver, 20).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
        title = driver.title
        body_text = driver.find_element(By.TAG_NAME, "body").text
        print(f"[selenium] title={title!r}")
        print(f"[selenium] body bytes={len(body_text)} first 80 chars={body_text[:80]!r}")

        # Persist a screenshot so a human can sanity-check what the
        # headless browser actually saw.
        screenshot_path = f"/tmp/dashboard-{workspace}.png"
        driver.save_screenshot(screenshot_path)
        print(f"[selenium] screenshot: {screenshot_path}")

        # The dashboard's index.html ships with a non-empty <title>.
        # Empty title would mean the response wasn't the dashboard
        # (e.g. an OAuth login page, a Caddy 502, etc.).
        if not title.strip():
            raise RuntimeError("dashboard loaded but page <title> is empty")
        # Body text might be empty for the unhydrated SPA, but the page
        # source should contain the React root div.
        page_source = driver.page_source
        if "<div id=" not in page_source and "<div id" not in page_source:
            raise RuntimeError(
                "dashboard page source doesn't contain a React-style root div"
            )
        print("[selenium] dashboard renders OK")
    finally:
        driver.quit()


def cleanup(workspace: str) -> None:
    print(f"[cleanup] removing {workspace}")
    # `bitswan workspace remove` prompts y/N — pipe yes through.
    subprocess.run(
        ["bash", "-lc", f"yes yes | bitswan workspace remove {workspace}"],
        check=False,
    )


def main() -> int:
    workspace = f"selenium-bailey-dev-{int(time.time())}"
    try:
        create_workspace(workspace)
        wait_for_dashboard(workspace)
        selenium_open_dashboard(workspace)
        print("\n✓ selenium smoke test PASSED")
        return 0
    except Exception as exc:  # noqa: BLE001 — top-level handler is fine
        print(f"\n✗ selenium smoke test FAILED: {exc}", file=sys.stderr)
        return 1
    finally:
        # Best-effort cleanup even on failure so we don't accumulate
        # selenium-* workspaces across runs.
        cleanup(workspace)


if __name__ == "__main__":
    sys.exit(main())
