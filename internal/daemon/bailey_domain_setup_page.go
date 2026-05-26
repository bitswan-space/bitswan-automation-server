package daemon

import (
	"fmt"
	"html"
	"strings"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// /bailey/domain-setup is the docs page operators land on when the
// AOC isn't managing DNS for this server's domain. The bailey learns
// this from the local config flag `AOC.dns_managed_by_aoc`, set at
// register time from the AOC-reported value — this avoids hardcoding
// any specific parent zone (bswn.io today, anything else tomorrow).
//
// Three things matter to the operator:
//   1. Which DNS records to publish — apex + wildcard, both pointing
//      at the box's public IP.
//   2. How to handle TLS — the daemon today uses Let's Encrypt
//      HTTP-01 by default, which has a 50-cert-per-week-per-registered-
//      domain cap. If they're testing DNS-01 they need to swap the
//      certResolver block in the traefik static config + supply
//      provider creds.
//   3. Where to get help if their DNS provider isn't on lego's
//      supported list (link out to the traefik / lego docs).
//
// We deliberately do NOT auto-detect a public IP here — the daemon
// runs inside a container and what it'd see from any local probe is
// the docker-network IP, not the real public one. Better to tell
// the operator how to find it themselves than to render a wrong
// value confidently.

func customDomainSetupHTML(sc *config.Config) string {
	domain := ""
	if sc != nil {
		domain = strings.TrimSpace(sc.Domain)
	}
	if domain == "" {
		return `
<div class="card" style="margin-top:0;">
  <p class="note" style="color:#b00020;">
    No domain is configured on this server. Set one on the AOC web admin under your automation server's settings, then come back here for DNS instructions.
  </p>
</div>`
	}
	apex := html.EscapeString(domain)
	wildcard := html.EscapeString("*." + domain)
	return fmt.Sprintf(`
<style>
  .ds-card { background:#fff; border:1px solid #E4E4E7; border-radius:10px;
    padding:18px 20px; margin-bottom:14px; }
  .ds-card h2 { margin:0 0 6px; font-size:15px; color:#18181B; font-weight:600; }
  .ds-card p.note { font-size:13px; color:#71717A; margin:0 0 12px; }
  .ds-card pre {
    background:#0F172A; color:#E2E8F0; padding:12px 14px; border-radius:6px;
    font-size:12px; overflow-x:auto; margin:8px 0;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  }
  .ds-records {
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px;
    background:#FAFAFA; border:1px solid #E4E4E7; border-radius:6px;
    padding:10px 14px; margin:8px 0;
  }
  .ds-records .row {
    display:grid; grid-template-columns:60px 1fr 70px 1fr; gap:14px;
    padding:4px 0; align-items:baseline;
  }
  .ds-records .head { color:#71717A; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; border-bottom:1px solid #E4E4E7; padding-bottom:6px; margin-bottom:4px; }
  .ds-records code { color:#3F3F46; }
  .ds-warn {
    background:#FFFBEB; border:1px solid #FDE68A; border-radius:6px;
    padding:10px 14px; margin:8px 0; font-size:13px; color:#92400E;
  }
  .ds-card a { color:#093DF5; text-decoration:none; }
  .ds-card a:hover { text-decoration:underline; }
</style>

<div class="ds-card">
  <h2>Why you're seeing this</h2>
  <p class="note">
    This bailey is running on <code>%s</code>, which isn't under the
    <code>.bswn.io</code> zone the AOC manages. Anything DNS- or TLS-related
    that the AOC would normally automate has to be set up by hand here.
    Switch to a <code>.bswn.io</code> subdomain on your AOC if you'd rather
    skip all this.
  </p>
</div>

<div class="ds-card">
  <h2>1. Find this server's public IPv4</h2>
  <p class="note">Run this on the host where the bailey daemon lives:</p>
  <pre>curl -4 ifconfig.me</pre>
  <p class="note">
    Don't use any address you see inside a container or from
    <code>ip addr</code> — those are docker-network or private-range
    addresses that won't be reachable from the public internet.
  </p>
</div>

<div class="ds-card">
  <h2>2. Publish two DNS A records</h2>
  <p class="note">On your DNS provider, create:</p>
  <div class="ds-records">
    <div class="row head">
      <div>Type</div><div>Name</div><div>TTL</div><div>Value</div>
    </div>
    <div class="row">
      <div><code>A</code></div>
      <div><code>%s</code></div>
      <div><code>300</code></div>
      <div>your public IPv4 from step 1</div>
    </div>
    <div class="row">
      <div><code>A</code></div>
      <div><code>%s</code></div>
      <div><code>300</code></div>
      <div>your public IPv4 from step 1</div>
    </div>
  </div>
  <p class="note">
    The wildcard <code>%s</code> covers every workspace endpoint the bailey
    creates (<code>&lt;ws&gt;-gitops.&lt;domain&gt;</code>,
    <code>&lt;ws&gt;-dashboard.&lt;domain&gt;</code>, etc.) without you having to
    add a new record per workspace. If your provider doesn't support
    wildcards, add a record per endpoint instead.
  </p>
  <p class="note">
    Add AAAA records too if your server has IPv6 — same shape, just point at
    the v6 address.
  </p>
</div>

<div class="ds-card">
  <h2>3. TLS: HTTP-01 (default) vs DNS-01</h2>
  <p class="note">
    Out of the box the bailey traefik static config issues certs via Let's
    Encrypt's HTTP-01 challenge. That works without any extra setup as long
    as port 80 is reachable from the internet — but LE rate-limits at
    <b>50 certificates per registered domain per 168h</b>, which is easy to
    hit on a dev box that spins workspaces up and down.
  </p>
  <div class="ds-warn">
    Already rate-limited? Either wait for the window to reset, switch to a
    <code>.bswn.io</code> domain, or set up DNS-01 below.
  </div>
  <p class="note">
    DNS-01 issues one wildcard cert covering everything under
    <code>*.%s</code> and avoids the per-host rate limit entirely. It requires
    write access to your DNS zone via an API your provider supports.
    Steps:
  </p>
  <ol style="font-size:13px;color:#3F3F46;line-height:1.7;">
    <li>Pick your DNS provider on the <a href="https://doc.traefik.io/traefik/https/acme/#providers" target="_blank" rel="noopener">traefik / lego provider list</a> — Cloudflare, Route53, DigitalOcean, etc. each have an env-var name they expect for their API token.</li>
    <li>Edit <code>~/.config/bitswan/traefik/traefik.yml</code> on the host. Under <code>certificatesResolvers.letsencrypt.acme</code>, replace the <code>httpChallenge</code> block with:
      <pre>dnsChallenge:
  provider: cloudflare   # or whichever provider you picked
  delayBeforeCheck: 0</pre>
    </li>
    <li>Edit <code>~/.config/bitswan/traefik/docker-compose.yml</code> and add the provider's API creds as env vars on the traefik service, e.g. <code>CF_DNS_API_TOKEN=…</code>.</li>
    <li>Restart traefik: <code>docker compose -p bitswan-traefik up -d --force-recreate</code>.</li>
    <li>The next workspace you create will get its cert via DNS-01. Existing certs stay valid until renewal.</li>
  </ol>
</div>

<div class="ds-card">
  <h2>Sanity check</h2>
  <p class="note">After DNS propagation, both of these should return the bailey login page (and not a connection error):</p>
  <pre>curl -I https://%s/
curl -I https://test-anything.%s/</pre>
  <p class="note">
    The second URL won't have a route yet, but if DNS + TLS are wired up
    correctly it'll get an HTTPS response from traefik (likely a 404 since
    no route is registered for that hostname — that's the right kind of
    failure).
  </p>
</div>`,
		apex, apex, wildcard, wildcard, apex, apex, apex)
}
