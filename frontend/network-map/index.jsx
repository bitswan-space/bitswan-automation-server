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
import dagre from 'dagre';

import 'reactflow/dist/style.css';
import './style.css';

// -----------------------------------------------------------------------------
// Custom node renderers. Each kind is a small card; the same component family
// is used everywhere to keep typography and spacing consistent.
// -----------------------------------------------------------------------------

const KIND_STYLE = {
  endpoint:          { bg: '#EFF6FF', border: '#93C5FD', text: '#1E3A8A', icon: '🌐', label: 'Endpoint' },
  ingress:           { bg: '#FEF3C7', border: '#FCD34D', text: '#78350F', icon: '🛡', label: 'Ingress' },
  workspace_traefik: { bg: '#ECFDF5', border: '#6EE7B7', text: '#065F46', icon: '🚦', label: 'Workspace traefik' },
  container:         { bg: '#EEF2FF', border: '#A5B4FC', text: '#3730A3', icon: '▣', label: 'Container' },
  network:           { bg: '#FAFAFA', border: '#E5E7EB', text: '#374151', icon: '⬚', label: 'Network' },
  workspace:         { bg: '#F8FAFC', border: '#CBD5E1', text: '#0F172A', icon: '📦', label: 'Workspace' },
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
        minWidth: 160,
        maxWidth: 280,
        boxShadow: selected ? '0 0 0 3px rgba(9,61,245,0.18)' : '0 1px 2px rgba(15,23,42,0.04)',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif',
        color: s.text,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: 'transparent', border: 0 }} />
      <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5, opacity: 0.75, marginBottom: 2 }}>
        <span style={{ marginRight: 6 }}>{s.icon}</span>{s.label}
      </div>
      <div style={{ fontSize: 13, fontWeight: 600, lineHeight: 1.3, wordBreak: 'break-all' }}>
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
      <div
        style={{
          position: 'absolute', top: 8, left: 14,
          fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6,
          opacity: 0.85,
        }}
      >
        {s.icon} {data.label}
      </div>
    </div>
  );
}

const nodeTypes = { base: BaseNode, group: GroupNode };

// -----------------------------------------------------------------------------
// Layout: explicit hierarchical LR. Hand-rolled rather than dagre because
// dagre's flat layout doesn't respect parent grouping — children of different
// workspaces ended up sharing the same dagre column, causing the workspace
// bounding boxes to overlap unpredictably.
//
// Three nested layers:
//   • Top-level chain (LR): endpoints → platform-traefik → bitswan-protected-
//     proxy → daemon (MFA+ACL) → workspaces.
//   • Inside each workspace: workspace_traefik on the left, networks stacked
//     vertically on the right.
//   • Inside each network: containers stacked vertically.
//
// All position math runs once on the data and is direction-agnostic past the
// fact that we lay things out as columns + stacks.
// -----------------------------------------------------------------------------
const LEAF_W = 220;
const LEAF_H = 64;
const COL_GAP = 90;   // horizontal gap between top-level columns
const ROW_GAP = 24;   // vertical gap between siblings stacking in a column
const WS_INNER_X = 24, WS_INNER_TOP = 38, WS_INNER_BOTTOM = 18;
const NET_INNER_X = 14, NET_INNER_TOP = 30, NET_INNER_BOTTOM = 12;
const WS_INNER_GAP = 26; // gap between workspace_traefik column and network column inside a workspace

function layout(nodes /*, edges */) {
  const groupKinds = new Set(['workspace', 'network']);
  const childrenOf = (parentId) => nodes.filter((n) => n.parentNode === parentId);
  const positions = new Map();
  const sizes = new Map();

  // -------- Pass 1: lay out container leaves inside each network. -------------
  const networks = nodes.filter((n) => n.data.kind === 'network');
  for (const net of networks) {
    const kids = childrenOf(net.id);
    let y = NET_INNER_TOP;
    for (const k of kids) {
      positions.set(k.id, { x: NET_INNER_X, y });
      sizes.set(k.id, { w: LEAF_W, h: LEAF_H });
      y += LEAF_H + ROW_GAP;
    }
    const inner = y - ROW_GAP;
    sizes.set(net.id, {
      w: LEAF_W + NET_INNER_X * 2,
      h: Math.max(LEAF_H + NET_INNER_TOP + NET_INNER_BOTTOM, inner + NET_INNER_BOTTOM),
    });
  }

  // -------- Pass 2: lay out each workspace internally. ------------------------
  // workspace_traefik on the left, networks stacked vertically to the right.
  const workspaces = nodes.filter((n) => n.data.kind === 'workspace');
  for (const ws of workspaces) {
    const kids = childrenOf(ws.id);
    const wstraefik = kids.find((k) => k.data.kind === 'workspace_traefik');
    const wsNetworks = kids.filter((k) => k.data.kind === 'network');

    let netColX = WS_INNER_X;
    if (wstraefik) {
      sizes.set(wstraefik.id, { w: LEAF_W, h: LEAF_H });
      positions.set(wstraefik.id, { x: WS_INNER_X, y: WS_INNER_TOP });
      netColX = WS_INNER_X + LEAF_W + WS_INNER_GAP;
    }

    let netY = WS_INNER_TOP;
    let netColW = 0;
    for (const net of wsNetworks) {
      const ns = sizes.get(net.id);
      positions.set(net.id, { x: netColX, y: netY });
      netY += ns.h + ROW_GAP;
      if (ns.w > netColW) netColW = ns.w;
    }
    const innerBottom = Math.max(
      wstraefik ? (WS_INNER_TOP + LEAF_H) : 0,
      netY - ROW_GAP
    );
    sizes.set(ws.id, {
      w: netColX + netColW + WS_INNER_X,
      h: innerBottom + WS_INNER_BOTTOM,
    });
  }

  // -------- Pass 3: lay out the top-level LR chain. ---------------------------
  // Columns: endpoints (col 0), platform-traefik, bitswan-protected-proxy,
  // daemon (MFA+ACL), workspaces (each is its own row in this column).
  const endpoints = nodes.filter((n) => n.data.kind === 'endpoint');
  const ingressOrder = [
    'ingress:platform-traefik',
    'ingress:bitswan-protected-proxy',
    'ingress:daemon',
  ];

  // Stack endpoints in column 0.
  let epColW = LEAF_W, epColH = 0;
  endpoints.forEach((e, i) => {
    positions.set(e.id, { x: 0, y: i * (LEAF_H + ROW_GAP) });
    sizes.set(e.id, { w: LEAF_W, h: LEAF_H });
    epColH = (i + 1) * LEAF_H + i * ROW_GAP;
  });

  // Stack workspaces in their column.
  let wsColW = 0, wsColH = 0;
  workspaces.forEach((ws, i) => {
    const ss = sizes.get(ws.id);
    if (ss.w > wsColW) wsColW = ss.w;
    // y is provisional; will be re-applied after we know its column x.
    positions.set(ws.id, { x: 0, y: wsColH });
    wsColH += ss.h + (i === workspaces.length - 1 ? 0 : ROW_GAP);
  });

  // Tallest column drives the overall vertical centering.
  const colHeights = [epColH, LEAF_H, LEAF_H, LEAF_H, wsColH];
  const maxColH = Math.max(...colHeights);

  // Place columns left-to-right.
  const colXs = [];
  let cursor = 0;
  for (let i = 0; i < 5; i++) {
    colXs.push(cursor);
    const colW = [epColW, LEAF_W, LEAF_W, LEAF_W, wsColW][i];
    cursor += colW + COL_GAP;
  }

  // Re-place endpoints with column x + vertical centering.
  endpoints.forEach((e, i) => {
    const cx = colXs[0];
    const cy = (maxColH - epColH) / 2 + i * (LEAF_H + ROW_GAP);
    positions.set(e.id, { x: cx, y: cy });
  });
  // Place ingresses, one per column.
  ingressOrder.forEach((id, i) => {
    const n = nodes.find((x) => x.id === id);
    if (!n) return;
    const cx = colXs[i + 1];
    const cy = (maxColH - LEAF_H) / 2;
    positions.set(n.id, { x: cx, y: cy });
    sizes.set(n.id, { w: LEAF_W, h: LEAF_H });
  });
  // Place workspaces, stacked.
  let wsY = (maxColH - wsColH) / 2;
  workspaces.forEach((ws) => {
    const ss = sizes.get(ws.id);
    positions.set(ws.id, { x: colXs[4], y: wsY });
    wsY += ss.h + ROW_GAP;
  });

  // -------- Pass 4: convert to React Flow positions ---------------------------
  // Children must be expressed relative to their parent.
  return nodes.map((n) => {
    const isGroup = groupKinds.has(n.data.kind);
    let pos = positions.get(n.id) || { x: 0, y: 0 };
    if (n.parentNode) {
      // child positions are already PARENT-RELATIVE (set in passes 1 & 2),
      // so no adjustment is needed here.
    }
    const out = { ...n, position: pos };
    if (isGroup) {
      const sz = sizes.get(n.id) || { w: 220, h: 100 };
      out.style = { width: sz.w, height: sz.h };
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
          <Dt>Sharing</Dt>
          <Dd>
            <a href={`/2fa-gate/share/${encodeURIComponent(node.data.hostname)}`} target="_top">Manage →</a>
          </Dd>
          <Dt>Open</Dt>
          <Dd>
            <a href={`https://${node.data.hostname}/`} target="_top">Visit ↗</a>
          </Dd>
          <Dt>ACL</Dt>
          <Dd>
            {aclErr && <span style={{ color: '#A1A1AA' }}>{aclErr}</span>}
            {!aclErr && !acl && <span style={{ color: '#A1A1AA' }}>Loading…</span>}
            {acl && (
              <div>
                <div><code>{acl.owner_email}</code> <span style={{ color: '#71717A' }}>(original owner)</span></div>
                {(acl.grants || []).map((g, i) => (
                  <div key={i}>
                    <code>{g.principal_value}</code>{' '}
                    <span style={{ color: '#71717A' }}>({g.principal_type}, {g.role})</span>
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

  useEffect(() => {
    fetch('/bailey/api/admin/network-map', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status))))
      .then(setRaw)
      .catch((e) => setErr(e.message));
  }, []);

  const { nodes, edges } = useMemo(() => {
    if (!raw) return { nodes: [], edges: [] };
    const groupKinds = new Set(['workspace', 'network']);
    const initialNodes = raw.nodes.map((n) => ({
      id: n.id,
      data: n,
      type: groupKinds.has(n.kind) ? 'group' : 'base',
      parentNode: n.parent || undefined,
      extent: n.parent ? 'parent' : undefined,
      draggable: false,
      selectable: true,
      position: { x: 0, y: 0 },
    }));
    const initialEdges = raw.edges.map((e, i) => ({
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
    return { nodes: layout(initialNodes, initialEdges), edges: initialEdges };
  }, [raw]);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState([]);
  useEffect(() => { setRfNodes(nodes); setRfEdges(edges); }, [nodes, edges, setRfNodes, setRfEdges]);

  const onNodeClick = useCallback((_, n) => setSelected(n), []);
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
    </div>
  );
}

const root = createRoot(document.getElementById('network-map-root'));
root.render(<NetworkMap />);
