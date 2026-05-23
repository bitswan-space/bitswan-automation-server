package daemon

// The bailey admin Updates page. Two cards today (gitops + dashboard
// images), each with a Docker-Hub-tag dropdown + a free-form
// "custom" input that overrides the dropdown. A "Save" button
// commits to server_settings; an "Use Docker Hub latest" link
// clears the override.
//
// Future home for daemon self-update controls — the page is named
// Updates rather than "Default images" for that reason.

const updatesPageHTML = `
<style>
  .upd-card {
    background:#fff; border:1px solid #E4E4E7; border-radius:10px;
    padding:18px 20px; margin-bottom:14px;
  }
  .upd-card h2 {
    margin:0 0 4px; font-size:16px; color:#18181B;
  }
  .upd-card .note { color:#71717A; font-size:13px; margin:0 0 14px; }
  .upd-row { display:flex; gap:10px; align-items:center; margin-bottom:10px; }
  .upd-row label { width:130px; font-size:13px; color:#3F3F46; }
  .upd-row select, .upd-row input[type=text] {
    flex:1; padding:7px 10px; border:1px solid #D4D4D8;
    border-radius:6px; font-size:13px; font-family:inherit;
  }
  .upd-row select:focus, .upd-row input[type=text]:focus {
    outline:0; border-color:#93C5FD; box-shadow:0 0 0 3px rgba(147,197,253,0.3);
  }
  .upd-actions { display:flex; gap:10px; justify-content:flex-end; margin-top:14px; }
  .upd-actions button {
    padding:8px 16px; border-radius:6px; border:0; cursor:pointer;
    font-size:13px; font-weight:500;
  }
  .upd-actions .save { background:#093DF5; color:#fff; }
  .upd-actions .save:hover { background:#0731C4; }
  .upd-actions .save:disabled { background:#A1A1AA; cursor:not-allowed; }
  .upd-actions .clear {
    background:transparent; color:#71717A; border:1px solid #D4D4D8;
  }
  .upd-actions .clear:hover { color:#3F3F46; border-color:#A1A1AA; }
  .upd-effective {
    font-size:12px; color:#71717A; margin-top:8px;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  }
  .upd-effective code { color:#3F3F46; }
  .upd-status { font-size:12px; min-height:14px; margin-top:8px; }
  .upd-status.ok { color:#0a7d24; }
  .upd-status.err { color:#b00020; }
  .upd-section-head {
    margin:24px 0 12px; font-size:14px; color:#71717A;
    text-transform:uppercase; letter-spacing:0.04em;
  }
</style>

<p class="note">Defaults applied to new workspaces. Existing workspaces keep their current images until you update them individually from the Workspaces page.</p>

<div class="upd-section-head">Default images</div>
<div id="upd-cards"><p class="note">Loading…</p></div>
`

const updatesPageJS = `
function loadDefaultImages() {
  fetch('/bailey/api/admin/default-images', {credentials:'same-origin'})
    .then(function(r){ return r.json(); })
    .then(function(data){
      var box = document.getElementById('upd-cards');
      box.innerHTML = '';
      [
        {key:'default_gitops_image',    label:'GitOps image',    repoHint:'bitswan/gitops'},
        {key:'default_dashboard_image', label:'Dashboard image', repoHint:'bitswan/workspace-dashboard'},
      ].forEach(function(spec){
        var entry = data[spec.key] || {key:spec.key, suggestions:[]};
        var card = renderCard(spec, entry);
        box.appendChild(card);
      });
    })
    .catch(function(e){
      document.getElementById('upd-cards').innerHTML =
        '<p class="note" style="color:#b00020;">Couldn\\'t load: ' + e.message + '</p>';
    });
}

function renderCard(spec, entry) {
  var card = document.createElement('div');
  card.className = 'upd-card';
  var suggestions = (entry.suggestions || []).map(function(t){
    return '<option value="' + escapeAttr(spec.repoHint + ':' + t.name) + '">'
      + escapeText(t.name) + '</option>';
  }).join('');
  var configuredHTML = entry.configured
    ? 'Configured: <code>' + escapeText(entry.configured.value) + '</code> · set by ' + escapeText(entry.configured.updated_by || '?')
    : 'No override — using Docker Hub <em>latest</em>.';
  card.innerHTML = ''
    + '<h2>' + escapeText(spec.label) + '</h2>'
    + '<p class="note">' + configuredHTML + '</p>'
    + '<div class="upd-row">'
    +   '<label>Pick from Docker Hub:</label>'
    +   '<select class="upd-select"><option value="">— choose a tag —</option>' + suggestions + '</select>'
    + '</div>'
    + '<div class="upd-row">'
    +   '<label>Or custom image:</label>'
    +   '<input type="text" class="upd-custom" placeholder="bitswan/gitops:bailey-dev" value="' + escapeAttr(entry.configured ? entry.configured.value : '') + '">'
    + '</div>'
    + '<div class="upd-effective">Currently in use for new workspaces: <code>' + escapeText(entry.effective || '(none)') + '</code></div>'
    + '<div class="upd-actions">'
    +   '<button class="clear" type="button">Clear override</button>'
    +   '<button class="save" type="button">Save</button>'
    + '</div>'
    + '<div class="upd-status"></div>';

  var sel = card.querySelector('.upd-select');
  var custom = card.querySelector('.upd-custom');
  var status = card.querySelector('.upd-status');

  // Picking from the dropdown populates the custom box so the user
  // always sees the exact string that will be saved.
  sel.addEventListener('change', function(){
    if (sel.value) custom.value = sel.value;
  });

  card.querySelector('.save').addEventListener('click', function(){
    var value = custom.value.trim();
    saveOne(spec.key, value, status);
  });
  card.querySelector('.clear').addEventListener('click', function(){
    saveOne(spec.key, '', status);
    custom.value = '';
    sel.value = '';
  });
  return card;
}

function saveOne(key, value, statusEl) {
  statusEl.textContent = 'Saving…';
  statusEl.className = 'upd-status';
  var body = {};
  // Translate setting key to the JSON field the backend expects.
  if (key === 'default_gitops_image')    body.gitops_image    = value;
  if (key === 'default_dashboard_image') body.dashboard_image = value;
  fetch('/bailey/api/admin/default-images', {
    method:'POST', credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  }).then(function(r){ return r.json().catch(function(){ return {ok:r.ok}; }); }).then(function(d){
    if (d.ok === false || d.error) {
      statusEl.textContent = 'Failed: ' + (d.error || 'unknown');
      statusEl.className = 'upd-status err';
    } else {
      statusEl.textContent = value ? 'Saved.' : 'Cleared — will use Docker Hub latest.';
      statusEl.className = 'upd-status ok';
      loadDefaultImages();
    }
  }).catch(function(e){
    statusEl.textContent = 'Failed: ' + e.message;
    statusEl.className = 'upd-status err';
  });
}

function escapeText(s){ return String(s||'').replace(/[&<>]/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];}); }
function escapeAttr(s){ return String(s||'').replace(/[&<>"]/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }

loadDefaultImages();
`
