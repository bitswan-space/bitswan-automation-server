package daemon

import "fmt"

// certTrustInstructionsHTML reproduces the external VPN admin page's
// Certificate Trust Setup card, minus the H2 header (we let the caller set
// the section heading). The four %s placeholders are all the CA filename for
// display in the copy/paste commands and iOS/Android download hints.
const certTrustInstructionsHTML = `
<div class="card" style="margin-top:0;">
<h2>Install the VPN CA on your device</h2>
<p>Internal services use HTTPS signed by this server's private certificate authority. Install the CA so your browser and OS trust them.</p>
<div style="margin-bottom:16px;">
  <button onclick="downloadCA()">Download CA Certificate</button>
</div>
<div class="tabs" id="cert-tabs">
  <button class="tab active" onclick="showTab('cert-tabs','cert-macos')">macOS</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-windows')">Windows</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-linux')">Linux</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-chrome')">Chrome</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-firefox')">Firefox</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-ios')">iOS</button>
  <button class="tab" onclick="showTab('cert-tabs','cert-android')">Android</button>
</div>

<div id="cert-macos" class="tab-content active">
  <div class="step"><span class="step-num">1</span><div class="step-text">Double-click the downloaded <code>%s</code> to open Keychain Access</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">The certificate is added to your login keychain. Find it by searching for the server name.</div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Double-click the certificate, expand <b>Trust</b>, and set <b>When using this certificate</b> to <b>Always Trust</b></div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Close the dialog and enter your password to confirm</div></div>
  <div class="tip">This trusts the CA for Safari and Chrome. Firefox uses its own store — see the Firefox tab.</div>
</div>

<div id="cert-windows" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Double-click the downloaded <code>%s</code></div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Click <b>Install Certificate</b></div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Select <b>Local Machine</b> (requires admin), click Next</div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Select <b>Place all certificates in the following store</b>, click Browse, choose <b>Trusted Root Certification Authorities</b></div></div>
  <div class="step"><span class="step-num">5</span><div class="step-text">Click Next, then Finish. Confirm the security warning.</div></div>
  <div class="tip">This trusts the CA for Edge and Chrome. Firefox uses its own store — see the Firefox tab.</div>
</div>

<div id="cert-linux" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Copy the certificate to the system trust store<pre><code>sudo cp ~/Downloads/%s /usr/local/share/ca-certificates/</code></pre></div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Update the certificate store<pre><code>sudo update-ca-certificates</code></pre></div></div>
  <div class="tip">This trusts the CA for <code>curl</code>, <code>wget</code>, and Chromium-based browsers. Firefox uses its own store — see the Firefox tab.<br><br>
On Fedora/RHEL, use instead:<pre><code>sudo cp ~/Downloads/%s /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust</code></pre></div>
</div>

<div id="cert-chrome" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Open Chrome and go to <code>chrome://settings/certificates</code></div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Click the <b>Authorities</b> tab</div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Click <b>Import</b> and select the downloaded <code>.crt</code> file</div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Check <b>Trust this certificate for identifying websites</b> and click OK</div></div>
  <div class="tip">On macOS/Windows, Chrome uses the system store — the OS instructions above are enough. Chrome import is mainly needed on Linux.</div>
</div>

<div id="cert-firefox" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Open Firefox and go to <code>about:preferences#privacy</code></div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Scroll down to <b>Certificates</b> and click <b>View Certificates</b></div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">In the <b>Authorities</b> tab, click <b>Import</b></div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Select the downloaded <code>.crt</code> file</div></div>
  <div class="step"><span class="step-num">5</span><div class="step-text">Check <b>Trust this CA to identify websites</b> and click OK</div></div>
  <div class="tip">Firefox uses its own certificate store on all platforms — importing at the OS level isn't enough.</div>
</div>

<div id="cert-ios" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Download the CA certificate on your iPhone or iPad using Safari</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">When prompted, tap <b>Allow</b> to download the configuration profile.</div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Open <b>Settings</b> → <b>General</b> → <b>VPN &amp; Device Management</b></div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">Tap the downloaded profile and tap <b>Install</b>. Enter your passcode when prompted.</div></div>
  <div class="step"><span class="step-num">5</span><div class="step-text">Go to <b>Settings</b> → <b>General</b> → <b>About</b> → <b>Certificate Trust Settings</b></div></div>
  <div class="step"><span class="step-num">6</span><div class="step-text">Enable full trust for the certificate. Confirm when prompted.</div></div>
  <div class="tip">Both steps are required on iOS: installing the profile AND enabling trust. Without the trust toggle, Safari still shows warnings.</div>
</div>

<div id="cert-android" class="tab-content">
  <div class="step"><span class="step-num">1</span><div class="step-text">Download the CA certificate on your Android device via Chrome</div></div>
  <div class="step"><span class="step-num">2</span><div class="step-text">Open <b>Settings</b> → <b>Security</b> → <b>Encryption &amp; credentials</b></div></div>
  <div class="step"><span class="step-num">3</span><div class="step-text">Tap <b>Install a certificate</b> → <b>CA certificate</b></div></div>
  <div class="step"><span class="step-num">4</span><div class="step-text">You may see a network-monitoring warning. Tap <b>Install anyway</b>.</div></div>
  <div class="step"><span class="step-num">5</span><div class="step-text">Select the downloaded <code>.crt</code> file and confirm</div></div>
  <div class="tip">The exact menu path varies by Android version. On Samsung: Settings → Biometrics and Security → Other security settings → Install from device storage.</div>
</div>
</div>`

// certsAdminBlockHTML is the admin-only management section beneath the
// trust-install instructions. It has two cards: trusted CAs, and per-hostname
// TLS certs.
const certsAdminBlockHTML = `
<div class="card">
<h2>Trusted CAs</h2>
<p class="note">Extra CAs trusted by every workspace container spawned on this server. Equivalent to <code>bitswan ca add</code>.</p>
<div id="ca-list">Loading...</div>
<hr style="border:0;border-top:1px solid #E4E4E7;margin:20px 0;">
<h3 style="font-size:14px;font-weight:600;margin:0 0 8px 0;">Add a CA</h3>
<div style="margin:8px 0;">
  <input type="text" id="ca-name" placeholder="File name (e.g. my-corp.crt)">
</div>
<textarea id="ca-pem" placeholder="-----BEGIN CERTIFICATE-----&#10;..." style="width:100%%;height:140px;font-family:monospace;font-size:12px;padding:8px;border:1px solid #D1D5DB;border-radius:6px;box-sizing:border-box;"></textarea>
<div style="margin-top:8px;">
  <button onclick="uploadCA()">Add CA</button>
  <span id="ca-msg" class="note" style="margin-left:10px;"></span>
</div>
</div>

<div class="card">
<h2>Hostname TLS certificates</h2>
<p class="note">Custom certs for specific hostnames served by the ingress Traefik. Equivalent to <code>bitswan ingress add-route --certs-dir</code>. Replaces any existing cert for the same hostname.</p>
<div id="host-list">Loading...</div>
<hr style="border:0;border-top:1px solid #E4E4E7;margin:20px 0;">
<h3 style="font-size:14px;font-weight:600;margin:0 0 8px 0;">Install a certificate</h3>
<div style="margin:8px 0;">
  <input type="text" id="host-name" placeholder="Hostname (e.g. app.example.com)">
</div>
<textarea id="host-cert" placeholder="-----BEGIN CERTIFICATE-----&#10;...full chain..." style="width:100%%;height:140px;font-family:monospace;font-size:12px;padding:8px;border:1px solid #D1D5DB;border-radius:6px;box-sizing:border-box;"></textarea>
<textarea id="host-key" placeholder="-----BEGIN PRIVATE KEY-----&#10;..." style="width:100%%;height:100px;font-family:monospace;font-size:12px;padding:8px;border:1px solid #D1D5DB;border-radius:6px;box-sizing:border-box;margin-top:8px;"></textarea>
<div style="margin-top:8px;">
  <button onclick="uploadHostCert()">Install Certificate</button>
  <span id="host-msg" class="note" style="margin-left:10px;"></span>
</div>
</div>`

// certsAdminScript returns the JS that powers the admin-only management
// cards. Empty string when the viewer isn't an admin (the cards aren't
// rendered, so the JS would just fail fetches with 403s).
func certsAdminScript(admin bool) string {
	if !admin {
		return ""
	}
	return fmt.Sprintf(`
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }
function loadCAs() {
  fetch('/vpn-admin-internal/api/cert-authorities').then(r=>r.json()).then(list => {
    if (!Array.isArray(list) || list.length === 0) {
      document.getElementById('ca-list').innerHTML = '<p class="note">No extra CAs installed.</p>';
      return;
    }
    let html = '<table><tr><th>Name</th><th>Subject</th><th>Expires</th><th></th></tr>';
    list.forEach(c => {
      html += '<tr><td><code>' + esc(c.name) + '</code></td>';
      html += '<td>' + esc(c.subject || '-') + '</td>';
      html += '<td>' + (c.not_after ? new Date(c.not_after).toLocaleDateString() : '-') + '</td>';
      html += '<td><button class="btn-secondary" onclick="removeCA(\'' + esc(c.name).replace(/'/g, "\\'") + '\')">Remove</button></td></tr>';
    });
    html += '</table>';
    document.getElementById('ca-list').innerHTML = html;
  });
}
function uploadCA() {
  const name = document.getElementById('ca-name').value.trim();
  const pem = document.getElementById('ca-pem').value;
  if (!name || !pem) { document.getElementById('ca-msg').textContent = 'Name and PEM are required.'; return; }
  fetch('/vpn-admin-internal/api/cert-authorities', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({name, pem})
  }).then(r => r.json()).then(d => {
    document.getElementById('ca-msg').textContent = d.status === 'added' ? 'Added.' : (d.error || 'Error');
    if (d.status === 'added') {
      document.getElementById('ca-name').value = '';
      document.getElementById('ca-pem').value = '';
      loadCAs();
    }
  });
}
function removeCA(name) {
  if (!confirm('Remove CA ' + name + '?')) return;
  fetch('/vpn-admin-internal/api/cert-authorities/' + encodeURIComponent(name), {method:'DELETE'})
    .then(r => r.json()).then(() => loadCAs());
}
function loadHostCerts() {
  fetch('/vpn-admin-internal/api/hostname-certs').then(r=>r.json()).then(list => {
    if (!Array.isArray(list) || list.length === 0) {
      document.getElementById('host-list').innerHTML = '<p class="note">No custom hostname certs installed.</p>';
      return;
    }
    let html = '<table><tr><th>Hostname</th><th>SANs</th><th>Expires</th><th></th></tr>';
    list.forEach(h => {
      html += '<tr><td><code>' + esc(h.hostname) + '</code></td>';
      html += '<td>' + esc((h.sans || []).join(', ') || '-') + '</td>';
      html += '<td>' + (h.not_after ? new Date(h.not_after).toLocaleDateString() : '-') + '</td>';
      html += '<td><button class="btn-secondary" onclick="removeHostCert(\'' + esc(h.hostname).replace(/'/g, "\\'") + '\')">Remove</button></td></tr>';
    });
    html += '</table>';
    document.getElementById('host-list').innerHTML = html;
  });
}
function uploadHostCert() {
  const hostname = document.getElementById('host-name').value.trim();
  const cert_pem = document.getElementById('host-cert').value;
  const key_pem = document.getElementById('host-key').value;
  if (!hostname || !cert_pem || !key_pem) {
    document.getElementById('host-msg').textContent = 'Hostname, cert and key are required.';
    return;
  }
  fetch('/vpn-admin-internal/api/hostname-certs', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({hostname, cert_pem, key_pem})
  }).then(r => r.json()).then(d => {
    document.getElementById('host-msg').textContent = d.status === 'installed' ? 'Installed.' : (d.error || 'Error');
    if (d.status === 'installed') {
      document.getElementById('host-name').value = '';
      document.getElementById('host-cert').value = '';
      document.getElementById('host-key').value = '';
      loadHostCerts();
    }
  });
}
function removeHostCert(host) {
  if (!confirm('Remove cert for ' + host + '?')) return;
  fetch('/vpn-admin-internal/api/hostname-certs/' + encodeURIComponent(host), {method:'DELETE'})
    .then(r => r.json()).then(() => loadHostCerts());
}
loadCAs();
loadHostCerts();
`)
}
