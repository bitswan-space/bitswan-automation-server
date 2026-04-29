package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/ztna"
)

// endUserSetup is the data shape returned to the public admin page so its
// JS can decide which card to render: the install instructions for normal
// users, or the bootstrap admin form for the very first admin landing on a
// freshly-deployed server.
//
// IsAdmin is filled in from the request, not from the provider; it's the
// hinge that lets the public page double as a bootstrap UI without an
// extra "internal admin" hop the first admin can't reach yet anyway.
type endUserSetup struct {
	Provider      string `json:"provider,omitempty"`
	Configured    bool   `json:"configured"`
	ManagementURL string `json:"management_url,omitempty"`
	SetupKey      string `json:"setup_key,omitempty"`
	InstallURL    string `json:"install_url,omitempty"`
	IsAdmin       bool   `json:"is_admin"`
	InternalAdminURL string `json:"internal_admin_url,omitempty"`
	Error         string `json:"error,omitempty"`
}

// currentEndUserSetup pulls the current ZTNA config and asks the configured
// provider for end-user setup data. Used by both the page renderer (for
// initial render) and the /vpn-admin/setup JSON endpoint (so the page can
// refresh without a reload).
func currentEndUserSetup(parent context.Context, admin bool) endUserSetup {
	out := endUserSetup{IsAdmin: admin}
	if admin {
		if sc := loadServerConfig(); sc != nil && sc.Slug != "" {
			out.InternalAdminURL = "https://vpn-admin." + sc.InternalDomain() + "/vpn-admin-internal/network"
		}
	}
	cfg, err := ztna.Load()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if !cfg.Enabled {
		return out
	}
	provider, err := ztna.Build(cfg)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Provider = string(cfg.Provider)
	out.Configured = true
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	inst, err := provider.EndUserInstructions(ctx)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.ManagementURL = inst.ManagementURL
	out.SetupKey = inst.SetupKey
	out.InstallURL = inst.InstallURL
	if inst.ProviderName != "" {
		out.Provider = inst.ProviderName
	}
	return out
}

func loadServerConfig() *config.Config {
	sc, _ := config.NewAutomationServerConfig().LoadConfig()
	return sc
}

// vpnAdminExternalPage renders the public VPN admin page (vpn-admin.<domain>).
// Two modes, switched by the page's JS based on the /vpn-admin/setup payload:
//   - bootstrap: an admin lands on a freshly-deployed server with no ZTNA
//     yet. The page shows the same Network Access form the internal admin
//     hosts so the admin can configure it from here without first being on
//     the (yet-to-exist) tunnel.
//   - user install: ZTNA is up and a user setup key is available; show the
//     install steps with the prefilled command.
//
// Always shows the CA install section so non-admin users can trust internal
// HTTPS once they're connected.
func vpnAdminExternalPage(email string) string {
	cfg := config.NewAutomationServerConfig()
	sc, _ := cfg.LoadConfig()
	serverName := "BitSwan"
	internalDomain := ""
	if sc != nil {
		if sc.Name != "" {
			serverName = sc.Name
		}
		internalDomain = sc.InternalDomain()
	}

	caFilename := "bitswan-vpn-ca.crt"
	if sc != nil && sc.Name != "" {
		caFilename = sc.Name + "-ca.crt"
	}

	signOut := ""
	if email != "" {
		signOut = `<a href="/vpn-admin/signout" class="sign-out">Sign out</a>`
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8">`+bitswanFavicon+`<title>%[1]s — VPN Access</title>
<style>`+bitswanPageCSS+`</style></head><body>
<div class="header">`+bitswanLogoSVG+`<h1>%[1]s — VPN Access</h1>%[2]s</div>

<div class="card highlight" id="setup-card">
<h2>1. Connect to the VPN</h2>
<p id="setup-status" class="note">Loading…</p>

<div id="setup-user" style="display:none;">
  <p>This server delegates VPN access to <b id="setup-provider">a ZTNA provider</b>. Install the agent on your device and connect with the setup key below.</p>
  <ol class="step-list">
    <li>Install the agent: <a id="setup-install" href="" target="_blank" class="install-link">Download</a></li>
    <li>Run <code>netbird up --management-url <span id="setup-mgmt"></span> --setup-key <span id="setup-key"></span></code></li>
    <li>Once connected, internal services are reachable at <code>*.%[3]s</code>.</li>
  </ol>
  <p class="note" id="setup-admin-link" style="display:none;margin-top:12px;">Admin? <a id="setup-internal-link" href="" style="color:#093DF5;">Manage in the internal admin →</a></p>
</div>

<div id="setup-bootstrap" style="display:none;">
  <p>This server has no ZTNA provider configured yet. As an admin, you can set one up here to allow user devices in.</p>
  <form onsubmit="bootstrapSave(event)" style="margin-top:12px;">
    <label style="display:block;margin:8px 0 4px;font-size:13px;color:#3F3F46;">Provider</label>
    <select id="bs-provider" style="padding:8px;border:1px solid #D1D5DB;border-radius:6px;">
      <option value="netbird">NetBird</option>
    </select>
    <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;">API URL</label>
    <input type="text" id="bs-api" placeholder="https://api.netbird.io" style="width:100%%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;box-sizing:border-box;">
    <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;">Management URL <span class="note">(usually same as API URL)</span></label>
    <input type="text" id="bs-mgmt" placeholder="https://api.netbird.io" style="width:100%%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;box-sizing:border-box;">
    <label style="display:block;margin:12px 0 4px;font-size:13px;color:#3F3F46;">Personal Access Token</label>
    <input type="password" id="bs-pat" placeholder="nb_personal_access_token_…" style="width:100%%;padding:8px;border:1px solid #D1D5DB;border-radius:6px;box-sizing:border-box;">
    <div style="margin-top:16px;">
      <button type="submit">Save and provision</button>
    </div>
    <div id="bs-result" class="note" style="margin-top:8px;"></div>
  </form>
</div>

<div id="setup-error" style="display:none;color:#B91C1C;font-size:13px;"></div>
</div>

<div class="card">
<h2>2. Trust the internal CA</h2>
<p>Internal services use HTTPS signed by this server's private certificate authority. Install the CA so your browser doesn't warn on every request.</p>
<div style="margin-bottom:16px;">
  <button onclick="downloadCA()">Download CA certificate</button>
</div>
<div class="tabs" id="cert-tabs">
  <button class="tab active" onclick="showTab('cert-tabs','cert-macos')">macOS</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-windows')">Windows</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-linux')">Linux</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-firefox')">Firefox</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-ios')">iOS</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-android')">Android</button>
</div>
<div id="cert-macos" class="tab-content active">
  <div class="step"><span class="step-num">1</span><div class="step-text">Double-click the downloaded <code>%[4]s</code> to open Keychain Access</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Find it (search for the server name), double-click, expand <b>Trust</b>, set <b>When using this certificate</b> to <b>Always Trust</b></div></div>
</div>
<div id="cert-windows" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Double-click the downloaded <code>%[4]s</code></div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Click <b>Install Certificate</b> → <b>Local Machine</b> → <b>Trusted Root Certification Authorities</b></div></div>
</div>
<div id="cert-linux" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text"><pre><code>sudo cp ~/Downloads/%[4]s /usr/local/share/ca-certificates/
sudo update-ca-certificates</code></pre></div></div>
  <div class="tip">Fedora/RHEL: copy to <code>/etc/pki/ca-trust/source/anchors/</code> and run <code>sudo update-ca-trust</code>.</div>
</div>
<div id="cert-firefox" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Settings → Privacy &amp; Security → Certificates → View Certificates → Authorities → Import</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Check "Trust this CA to identify websites"</div></div>
</div>
<div id="cert-ios" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Download in Safari → Allow when prompted</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Settings → General → VPN &amp; Device Management → tap profile → Install</div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Settings → General → About → Certificate Trust Settings → enable trust</div></div>
</div>
<div id="cert-android" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Tap <b>Install anyway</b> on the warning, select the downloaded file</div></div>
</div>
</div>

<script>
function downloadCA() {
  const a = document.createElement('a');
  a.href = '/vpn-admin/ca.crt';
  a.download = '%[4]s';
  a.click();
}
function showTab(groupId, tabId) {
  const group = document.getElementById(groupId);
  const card = group.closest('.card') || group.parentElement;
  card.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  group.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  group.querySelectorAll('.tab').forEach(el => {
    if (el.getAttribute('onclick') && el.getAttribute('onclick').includes(tabId)) el.classList.add('active');
  });
}
function loadSetup() {
  fetch('/vpn-admin/setup').then(r=>r.json()).then(d => {
    const status = document.getElementById('setup-status');
    const userBox = document.getElementById('setup-user');
    const bootBox = document.getElementById('setup-bootstrap');
    const errBox = document.getElementById('setup-error');
    userBox.style.display = 'none';
    bootBox.style.display = 'none';
    errBox.style.display = 'none';
    status.style.display = '';

    if (d.error) {
      errBox.style.display = 'block';
      errBox.textContent = 'Failed to load setup info: ' + d.error;
      // Even on error, admins can still try to (re)configure.
      if (d.is_admin) bootBox.style.display = 'block';
      status.style.display = 'none';
      return;
    }
    const ready = d.configured && d.setup_key;
    if (ready) {
      status.style.display = 'none';
      document.getElementById('setup-provider').textContent = d.provider || 'a ZTNA provider';
      document.getElementById('setup-install').href = d.install_url || '#';
      document.getElementById('setup-mgmt').textContent = d.management_url || '';
      document.getElementById('setup-key').textContent = d.setup_key;
      userBox.style.display = 'block';
      if (d.is_admin && d.internal_admin_url) {
        document.getElementById('setup-internal-link').href = d.internal_admin_url;
        document.getElementById('setup-admin-link').style.display = 'block';
      }
      return;
    }
    if (d.is_admin) {
      // First-admin bootstrap: render the form right here so they don't
      // have to chase the (yet-unreachable) internal admin.
      status.style.display = 'none';
      bootBox.style.display = 'block';
      return;
    }
    status.textContent = 'This server has no ZTNA access configured yet. Ask an admin to sign in here and set one up.';
  }).catch(e => {
    document.getElementById('setup-error').style.display = 'block';
    document.getElementById('setup-error').textContent = 'Failed to load setup info: ' + e.message;
  });
}
function bootstrapSave(e) {
  e.preventDefault();
  const out = document.getElementById('bs-result');
  out.textContent = 'Saving and provisioning…';
  fetch('/vpn-admin/api/ztna-config', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      provider: document.getElementById('bs-provider').value,
      enabled: true,
      netbird: {
        api_url: document.getElementById('bs-api').value.trim(),
        management_url: document.getElementById('bs-mgmt').value.trim(),
        pat: document.getElementById('bs-pat').value
      }
    })
  }).then(r=>r.json()).then(d => {
    if (d.error) { out.textContent = 'Error: ' + d.error; return; }
    if (d.router_error) { out.textContent = 'Saved, but routing-peer setup failed: ' + d.router_error; return; }
    out.textContent = 'Saved. Reloading…';
    setTimeout(loadSetup, 800);
  }).catch(err => out.textContent = 'Error: ' + err.message);
}
loadSetup();
</script>
</body></html>`,
		serverName, signOut, internalDomain, caFilename)
}
