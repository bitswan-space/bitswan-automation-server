import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { createRoot } from 'react-dom/client';
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
  Handle,
  Position,
  useNodesState,
  useEdgesState,
} from 'reactflow';
import ELK from 'elkjs/lib/elk.bundled.js';

const elk = new ELK();

import 'reactflow/dist/style.css';
import './style.css';

// -----------------------------------------------------------------------------
// Custom node renderers. Each kind is a small card; the same component family
// is used everywhere to keep typography and spacing consistent.
// -----------------------------------------------------------------------------

const KIND_STYLE = {
  endpoint:          { bg: '#EFF6FF', border: '#93C5FD', text: '#1E3A8A', icon: '🌐', label: 'App endpoint' },
  ingress:           { bg: '#FEF3C7', border: '#FCD34D', text: '#78350F', icon: '🛡', label: 'Ingress' },
  platform_traefik:  { bg: '#FFFBEB', border: '#FCD34D', text: '#78350F', icon: '🛡', label: 'Platform traefik' },
  workspace_traefik: { bg: '#ECFDF5', border: '#6EE7B7', text: '#065F46', icon: '🚦', label: 'Workspace traefik' },
  container:         { bg: '#EEF2FF', border: '#A5B4FC', text: '#3730A3', icon: '▣', label: 'Container' },
  network:           { bg: '#FAFAFA', border: '#E5E7EB', text: '#374151', icon: '⬚', label: 'Network' },
  workspace:         { bg: '#F8FAFC', border: '#CBD5E1', text: '#0F172A', icon: '📦', label: 'Workspace' },
  cloud:             { bg: '#F0F9FF', border: '#7DD3FC', text: '#075985', icon: '☁', label: 'Public ingress' },
  // Privileged orchestration daemon. Distinct red palette so it visually
  // stands apart from the ingress chain — it's the "warning, this one
  // has docker.sock" node.
  daemon:            { bg: '#FEF2F2', border: '#FCA5A5', text: '#7F1D1D', icon: '⚙', label: 'Daemon' },
};

function BaseNode({ data, selected }) {
  const s = KIND_STYLE[data.kind] || KIND_STYLE.container;
  return (
    <div
      style={{
        background: s.bg,
        borderColor: selected ? '#093DF5' : s.border,
        borderWidth: selected ? 2 : 1.5,
        borderStyle: 'solid',
        borderRadius: 10,
        padding: '8px 14px',
        // FIXED dimensions matching the values handed to ELK. Without this
        // the actual DOM grows past what ELK sized the parent for, and the
        // endpoint cards overflow their compound box.
        width: LEAF_W, height: LEAF_H,
        boxSizing: 'border-box',
        overflow: 'hidden',
        boxShadow: selected ? '0 0 0 3px rgba(9,61,245,0.18)' : '0 1px 2px rgba(15,23,42,0.04)',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif',
        color: s.text,
        display: 'flex', flexDirection: 'column', justifyContent: 'center',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: 'transparent', border: 0 }} />
      <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5, opacity: 0.75, marginBottom: 3, whiteSpace: 'nowrap' }}>
        <span style={{ marginRight: 6 }}>{s.icon}</span>{s.label}
      </div>
      <div
        style={{
          fontSize: 13, fontWeight: 600, lineHeight: 1.25,
          // Hard limit: two lines max, then ellipsis. Long hostnames stay
          // inside the LEAF_H envelope ELK was given.
          display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
          overflow: 'hidden', textOverflow: 'ellipsis',
          wordBreak: 'break-all',
        }}
        title={data.label}
      >
        {data.label}
      </div>
      <Handle type="source" position={Position.Right} style={{ background: 'transparent', border: 0 }} />
    </div>
  );
}

function GroupNode({ data }) {
  const s = KIND_STYLE[data.kind] || KIND_STYLE.workspace;
  return (
    <div
      style={{
        background: s.bg,
        borderColor: s.border,
        borderWidth: 1.5,
        borderStyle: data.kind === 'network' ? 'dashed' : 'solid',
        borderRadius: 12,
        padding: '24px 16px 14px',
        width: '100%',
        height: '100%',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif',
        position: 'relative',
        color: s.text,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: 'transparent', border: 0 }} />
      <div
        style={{
          position: 'absolute', top: 8, left: 14,
          fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6,
          opacity: 0.85,
        }}
      >
        {s.icon} {data.label}
      </div>
      <Handle type="source" position={Position.Right} style={{ background: 'transparent', border: 0 }} />
    </div>
  );
}

// Custom puffy-cloud node for the public-ingress entry point.
function CloudNode({ data, selected }) {
  const s = KIND_STYLE.cloud;
  return (
    <div
      style={{
        position: 'relative',
        width: 200, height: 110,
        cursor: 'pointer',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif',
        color: s.text,
      }}
      title="Click for wildcard DNS + TLS cert setup instructions"
    >
      <svg width="200" height="110" viewBox="0 0 200 110" style={{ display: 'block', position: 'absolute', inset: 0 }}>
        {/* Five-bump cloud shape that fills the full 200×110 bounding box. */}
        <path
          d="M 18 78 C 4 78, 4 56, 18 54 C 18 32, 50 26, 56 44 C 64 24, 100 22, 108 44 C 118 28, 152 30, 158 50 C 184 48, 196 70, 182 80 C 188 96, 168 102, 158 94 L 42 94 C 28 102, 8 96, 18 78 Z"
          fill={s.bg}
          stroke={selected ? '#0284C7' : s.border}
          strokeWidth={selected ? 2.5 : 1.5}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexDirection: 'column', textAlign: 'center', padding: '0 28px',
        pointerEvents: 'none',
      }}>
        <div style={{ fontSize: 12, fontWeight: 600, lineHeight: 1.2 }}>{data.label}</div>
        <div style={{ fontSize: 10, opacity: 0.7, marginTop: 3 }}>click for setup ↗</div>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: 'transparent', border: 0, right: 30 }} />
    </div>
  );
}

const nodeTypes = { base: BaseNode, group: GroupNode, cloud: CloudNode };

// -----------------------------------------------------------------------------
// Layout: ELK (eclipse layout kernel) running the `layered` algorithm with LR
// direction. ELK handles compound (parent-child) nodes natively — parents
// auto-size from their children, so workspace/network/platform-traefik boxes
// always wrap their contents exactly. We hand it the leaf dimensions, set the
// hierarchy via children[], and let it return positions for every node.
// -----------------------------------------------------------------------------
const LEAF_W = 230;
const LEAF_H = 76;
const CLOUD_W = 200, CLOUD_H = 110;

// Recursively build the ELK graph from React Flow nodes. ELK's `children`
// scheme is the canonical compound-node representation; positions returned
// are absolute to the parent.
function buildElkTree(nodes, edges, parentId) {
  const groupKinds = new Set(['workspace', 'network', 'platform_traefik']);
  const kids = nodes.filter((n) => (n.parentNode || null) === parentId);
  return kids.map((n) => {
    const isGroup = groupKinds.has(n.data.kind);
    const node = { id: n.id };
    if (isGroup) {
      // All compound parents flow RIGHT internally. The "no edges between
      // siblings → same rank" rule means children without inter-sibling
      // edges (endpoints inside platform-traefik, containers inside a
      // network) stack vertically within the leftmost rank. Workspaces
      // get a proper LR sub-flow because workspace_traefik is upstream of
      // its networks' containers.
      node.layoutOptions = {
        'elk.algorithm': 'layered',
        'elk.direction': 'RIGHT',
        'elk.padding': n.data.kind === 'network'
          ? '[top=28,left=14,bottom=14,right=14]'
          : '[top=34,left=18,bottom=16,right=18]',
        'elk.spacing.nodeNode': '18',
        'elk.layered.spacing.nodeNodeBetweenLayers': '40',
      };
      node.children = buildElkTree(nodes, edges, n.id);
      // No fixed width/height — ELK derives them.
    } else if (n.data.kind === 'cloud') {
      node.width = CLOUD_W; node.height = CLOUD_H;
    } else {
      node.width = LEAF_W; node.height = LEAF_H;
    }
    return node;
  });
}

async function elkLayout(nodes, edges) {
  const graph = {
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'RIGHT',
      'elk.layered.spacing.nodeNodeBetweenLayers': '80',
      'elk.spacing.nodeNode': '40',
      'elk.spacing.edgeNode': '30',
      'elk.spacing.componentComponent': '60',
      'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
      'elk.padding': '[top=24,left=24,bottom=24,right=24]',
      'elk.hierarchyHandling': 'INCLUDE_CHILDREN',
    },
    children: buildElkTree(nodes, edges, null),
    edges: edges.map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  };
  const out = await elk.layout(graph);

  // Walk the result and flatten into { id → { x, y, w, h } } where positions
  // are RELATIVE to the immediate parent (React Flow's convention for
  // parentNode children).
  const result = new Map();
  const walk = (n, ax, ay) => {
    if (n.id === 'root') {
      (n.children || []).forEach((c) => walk(c, 0, 0));
      return;
    }
    // ELK gives positions relative to the parent — perfect for React Flow.
    result.set(n.id, { x: n.x || 0, y: n.y || 0, w: n.width, h: n.height });
    (n.children || []).forEach((c) => walk(c, n.x || 0, n.y || 0));
  };
  walk(out, 0, 0);
  return result;
}

function applyLayout(nodes, layoutMap) {
  const groupKinds = new Set(['workspace', 'network', 'platform_traefik']);
  return nodes.map((n) => {
    const l = layoutMap.get(n.id);
    if (!l) return { ...n, position: { x: 0, y: 0 } };
    const out = { ...n, position: { x: l.x, y: l.y } };
    if (groupKinds.has(n.data.kind)) {
      out.style = { width: l.w, height: l.h };
    }
    return out;
  });
}


// -----------------------------------------------------------------------------
// Detail panel
// -----------------------------------------------------------------------------
function DetailPanel({ node }) {
  const [acl, setAcl] = useState(null);
  const [aclErr, setAclErr] = useState('');

  useEffect(() => {
    setAcl(null);
    setAclErr('');
    if (!node || node.data.kind !== 'endpoint') return;
    fetch(`/2fa-gate/api/share/${encodeURIComponent(node.data.hostname)}`, { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('only the owner can see grants'))))
      .then(setAcl)
      .catch((e) => setAclErr(e.message));
  }, [node]);

  if (!node) {
    return <div style={{ color: '#A1A1AA', fontSize: 13, textAlign: 'center', padding: '40px 12px' }}>Click any node for details.</div>;
  }

  const s = KIND_STYLE[node.data.kind] || KIND_STYLE.container;
  return (
    <div>
      <span
        style={{
          display: 'inline-block', fontSize: 10, padding: '2px 8px', borderRadius: 999,
          background: '#F4F4F5', color: '#52525B', marginBottom: 10,
          textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 600,
        }}
      >
        {s.label}
      </span>
      <h3 style={{ margin: '0 0 4px', fontSize: 15, fontWeight: 600, color: '#18181B', wordBreak: 'break-all' }}>
        {node.data.label}
      </h3>

      {node.data.kind === 'endpoint' && (
        <Dl>
          <Dt>Hostname</Dt>
          <Dd><code>{node.data.hostname}</code></Dd>
          {node.data.owner_email && (<><Dt>Owner</Dt><Dd><code>{node.data.owner_email}</code></Dd></>)}
          <Dt>Open</Dt>
          <Dd>
            <a href={`https://${node.data.hostname}/`} target="_top">Visit ↗</a>
          </Dd>
          {/* Read-only share list. The sidebar is a topology overview —
              admins can audit who has access but can't reconfigure it
              from here. ACL changes happen only on the endpoint's own
              share page, where ownership is required. */}
          <Dt>Shared with</Dt>
          <Dd>
            {aclErr && <span style={{ color: '#A1A1AA' }}>{aclErr}</span>}
            {!aclErr && !acl && <span style={{ color: '#A1A1AA' }}>Loading…</span>}
            {acl && (
              <div>
                <div><code>{acl.owner_email}</code> <span style={{ color: '#71717A' }}>(owner)</span></div>
                {(acl.grants || []).map((g, i) => (
                  <div key={i}>
                    <code>{g.principal_value}</code>{' '}
                    <span style={{ color: '#71717A' }}>({g.principal_type === 'group' ? 'group' : 'user'}, {g.role})</span>
                  </div>
                ))}
                {(acl.grants || []).length === 0 && <span style={{ color: '#71717A' }}>No additional grants.</span>}
              </div>
            )}
          </Dd>
          {acl && acl.requests && acl.requests.length > 0 && (
            <>
              <Dt>Pending access requests</Dt>
              <Dd>
                {acl.requests.map((r, i) => (
                  <div key={i}><code>{r.Email}</code> <span style={{ color: '#71717A' }}>{r.RequestedAt}</span></div>
                ))}
              </Dd>
            </>
          )}
        </Dl>
      )}

      {(node.data.kind === 'workspace' || node.data.kind === 'network' || node.data.kind === 'container') && (
        <Dl>
          {node.data.workspace && (<><Dt>Workspace</Dt><Dd><code>{node.data.workspace}</code></Dd></>)}
          {node.data.stage && (<><Dt>Stage</Dt><Dd>{node.data.stage}</Dd></>)}
        </Dl>
      )}

      {node.data.kind === 'ingress' && (
        <p style={{ color: '#71717A', fontSize: 13 }}>
          Infrastructure ingress. Traffic flows through this on its way to your workspaces.
        </p>
      )}
    </div>
  );
}
function Dl({ children }) { return <dl style={{ margin: '10px 0' }}>{children}</dl>; }
function Dt({ children }) { return <dt style={{ fontSize: 10, color: '#A1A1AA', textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 12, fontWeight: 600 }}>{children}</dt>; }
function Dd({ children }) { return <dd style={{ margin: '4px 0 0', fontSize: 13, color: '#18181B', wordBreak: 'break-all' }}>{children}</dd>; }

// -----------------------------------------------------------------------------
// Main app
// -----------------------------------------------------------------------------
function NetworkMap() {
  const [raw, setRaw] = useState(null);
  const [err, setErr] = useState(null);
  const [selected, setSelected] = useState(null);
  const [cloudModal, setCloudModal] = useState(false);

  useEffect(() => {
    fetch('/bailey/api/admin/network-map', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status))))
      .then(setRaw)
      .catch((e) => setErr(e.message));
  }, []);

  // Convert raw graph data into React Flow shapes. Positions are placeholder
  // (0,0) here; the ELK pass below fills them in once.
  const initial = useMemo(() => {
    if (!raw) return { nodes: [], edges: [] };
    const groupKinds = new Set(['workspace', 'network', 'platform_traefik']);
    const typeFor = (kind) => {
      if (kind === 'cloud') return 'cloud';
      if (groupKinds.has(kind)) return 'group';
      return 'base';
    };
    const nodes = raw.nodes.map((n) => ({
      id: n.id,
      data: n,
      type: typeFor(n.kind),
      parentNode: n.parent || undefined,
      extent: n.parent ? 'parent' : undefined,
      draggable: false,
      selectable: true,
      position: { x: 0, y: 0 },
    }));
    const edges = raw.edges.map((e, i) => ({
      id: `e${i}-${e.source}-${e.target}`,
      source: e.source,
      target: e.target,
      label: e.label,
      labelStyle: { fontSize: 10, fill: '#71717A' },
      labelBgStyle: { fill: '#FFFFFF', fillOpacity: 0.9 },
      labelBgPadding: [4, 2],
      style: {
        stroke: e.kind === 'chain' ? '#F59E0B' : (e.kind === 'route' ? '#60A5FA' : '#CBD5E1'),
        strokeWidth: e.kind === 'chain' ? 2 : 1.5,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color: e.kind === 'chain' ? '#F59E0B' : (e.kind === 'route' ? '#60A5FA' : '#CBD5E1') },
      type: 'smoothstep',
    }));
    return { nodes, edges };
  }, [raw]);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState([]);

  // ELK lays the graph out asynchronously. Run it whenever the raw data
  // changes; until it completes we render at placeholder positions (which
  // React Flow happily shows as a stack at the origin — the fitView on
  // mount only triggers after positions arrive).
  useEffect(() => {
    if (!initial.nodes.length) {
      setRfNodes([]); setRfEdges([]); return;
    }
    let cancelled = false;
    elkLayout(initial.nodes, initial.edges).then((map) => {
      if (cancelled) return;
      setRfNodes(applyLayout(initial.nodes, map));
      setRfEdges(initial.edges);
    }).catch((e) => {
      if (cancelled) return;
      // Layout failed — fall back to unpositioned so the user sees SOMETHING
      // and we can debug from the console rather than silently blanking.
      console.error('ELK layout failed:', e);
      setRfNodes(initial.nodes);
      setRfEdges(initial.edges);
    });
    return () => { cancelled = true; };
  }, [initial, setRfNodes, setRfEdges]);

  const onNodeClick = useCallback((_, n) => {
    if (n.data.kind === 'cloud') {
      setCloudModal(true);
      return;
    }
    setSelected(n);
  }, []);
  const onPaneClick = useCallback(() => setSelected(null), []);

  if (err) {
    return <div style={{ color: '#b00020', padding: 20 }}>Couldn't load map: {err}</div>;
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16, height: 'calc(100vh - 140px)', minHeight: 520 }}>
      <div style={{ border: '1px solid #E4E4E7', borderRadius: 10, overflow: 'hidden', background: '#FAFAFA' }}>
        <ReactFlow
          nodes={rfNodes}
          edges={rfEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          onNodeClick={onNodeClick}
          onPaneClick={onPaneClick}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.25}
          maxZoom={1.5}
          nodesDraggable={false}
          nodesConnectable={false}
          panOnDrag
          zoomOnScroll
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={20} size={1} color="#E4E4E7" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <aside style={{ background: '#fff', border: '1px solid #E4E4E7', borderRadius: 10, padding: 18, overflowY: 'auto', fontSize: 13, lineHeight: 1.5 }}>
        <DetailPanel node={selected} />
      </aside>
      {cloudModal && <CloudSetupModal onClose={() => setCloudModal(false)} />}
    </div>
  );
}

function CloudSetupModal({ onClose }) {
  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(15,23,42,0.55)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 2147483646, fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: '#fff', borderRadius: 12, boxShadow: '0 24px 60px rgba(0,0,0,0.25)',
          width: 'min(680px, 92vw)', maxHeight: '88vh', overflowY: 'auto',
        }}
      >
        <div style={{ padding: '18px 22px 14px', borderBottom: '1px solid #EFEFF1', display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ fontSize: 22 }}>☁</div>
          <div style={{ flex: 1 }}>
            <h2 style={{ margin: 0, fontSize: 18, fontWeight: 600 }}>Public ingress setup</h2>
            <p style={{ margin: '4px 0 0', color: '#71717A', fontSize: 13 }}>
              How traffic gets from the open internet (or a private network) to your platform-traefik.
            </p>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 0, fontSize: 22, color: '#71717A', cursor: 'pointer', padding: 4 }}
            aria-label="Close"
          >×</button>
        </div>

        <div style={{ padding: '18px 22px 22px', fontSize: 14, lineHeight: 1.55, color: '#18181B' }}>
          <p>
            Bailey publishes every workspace endpoint at <code>&lt;name&gt;.&lt;domain&gt;</code> and its inner pair at
            <code> &lt;name&gt;--inner.&lt;domain&gt;</code>. Whatever sits in front of bailey needs to deliver requests for both
            patterns to <code>platform-traefik</code> on TCP/443, which means two things: a wildcard DNS record and a
            wildcard TLS cert.
          </p>

          <h3 style={H3}>1. Wildcard DNS</h3>
          <p>
            Point <code>*.&lt;domain&gt;</code> at whatever is the public face of your server. Three common options:
          </p>
          <Choice
            title="Open Internet"
            body={
              <>
                Add an A or CNAME record for <code>*.&lt;domain&gt;</code> in your DNS provider pointing at the server's
                public IPv4 (or CNAME to its hostname). Most providers also need a separate record for
                <code> &lt;domain&gt;</code> itself if you ever want the apex to resolve.
              </>
            }
          />
          <Choice
            title="ZTNA (Cloudflare Access / Tailscale / NetBird)"
            body={
              <>
                Bind <code>*.&lt;domain&gt;</code> in the ZTNA control plane so that only members of your tunnel can
                reach it. The mechanism varies — Cloudflare Tunnel uses a tunnel route, Tailscale uses MagicDNS
                + Funnel, NetBird uses a network resource — but in all cases the DNS record is created in the ZTNA
                provider, not in public DNS.
              </>
            }
          />
          <Choice
            title="Plain VPN (WireGuard / OpenVPN)"
            body={
              <>
                Push the wildcard into the VPN's internal DNS resolver (e.g. dnsmasq, CoreDNS) so connected peers
                resolve <code>*.&lt;domain&gt;</code> to the bailey's VPN-side IP. The bailey itself doesn't need to
                be reachable on the public internet at all.
              </>
            }
          />

          <h3 style={H3}>2. Wildcard TLS cert</h3>
          <p>
            <code>platform-traefik</code> terminates HTTPS, so it needs a cert that covers both
            <code> &lt;domain&gt;</code> and <code>*.&lt;domain&gt;</code>. Two common options:
          </p>
          <Choice
            title="Let's Encrypt via DNS-01 challenge"
            body={
              <>
                platform-traefik is preconfigured with a <code>letsencrypt</code> cert resolver. Wildcard certs
                require the DNS-01 challenge — Traefik talks to your DNS provider's API to plant a TXT record
                and prove control. Set the provider in the traefik static config (Cloudflare, Route53, etc.) and
                supply credentials via env vars. Traefik renews automatically every ~60 days.
              </>
            }
          />
          <Choice
            title="Internal CA (private network only)"
            body={
              <>
                If the bailey is only reachable over a VPN/ZTNA, you can skip ACME entirely: issue a wildcard cert
                from a private CA you control and distribute the CA cert to your team's devices. The bailey ships
                with a built-in CA helper (see <code>~/.config/bitswan/vpn/ca/</code>) usable for this.
              </>
            }
          />

          <h3 style={H3}>3. Verify</h3>
          <p>
            Once DNS and cert are in place, browsing to <code>https://bailey.&lt;domain&gt;</code> should land you on the
            wrap login page. If you see an "ERR_CERT_AUTHORITY_INVALID", your cert isn't wildcard or its DNS
            authority differs from the hostname; if you see "DNS_PROBE_FINISHED_NXDOMAIN", the wildcard record
            didn't propagate (or the resolver in front of you doesn't see it).
          </p>
          <p style={{ color: '#71717A', fontSize: 13 }}>
            This page is just a checklist — bailey doesn't manage DNS or the public-network layer. Each provider
            has its own setup docs; what matters here is that <em>both</em> the wildcard DNS and the wildcard cert
            are in place before any endpoint will resolve.
          </p>
        </div>
      </div>
    </div>
  );
}

const H3 = { fontSize: 14, fontWeight: 600, color: '#18181B', margin: '20px 0 6px' };

function Choice({ title, body }) {
  return (
    <div style={{ background: '#FAFAFA', border: '1px solid #E4E4E7', borderRadius: 8, padding: '10px 14px', margin: '8px 0' }}>
      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4, color: '#18181B' }}>{title}</div>
      <div style={{ fontSize: 13, color: '#3F3F46' }}>{body}</div>
    </div>
  );
}

const root = createRoot(document.getElementById('network-map-root'));
root.render(<NetworkMap />);
