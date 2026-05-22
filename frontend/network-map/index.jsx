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
      <Handle type="target" position={Position.Top} style={{ background: 'transparent', border: 0 }} />
      <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5, opacity: 0.75, marginBottom: 2 }}>
        <span style={{ marginRight: 6 }}>{s.icon}</span>{s.label}
      </div>
      <div style={{ fontSize: 13, fontWeight: 600, lineHeight: 1.3, wordBreak: 'break-all' }}>
        {data.label}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: 'transparent', border: 0 }} />
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
// Layout. Dagre's compound (parent/child) support is incomplete in the JS
// port — workspace/network boxes end up wrong-sized relative to their actual
// children. Instead we use dagre purely for LEAF positioning, then derive each
// parent's bounding box from its children's positions + sizes. Two-tier
// nesting (workspace > network > container) is handled by computing
// network bboxes first, then workspaces from their child networks.
// -----------------------------------------------------------------------------
const LEAF_W = 220;
const LEAF_H = 64;
const PARENT_PAD = { x: 18, top: 38, bottom: 18 }; // header takes more space than the footer

function layout(nodes, edges) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const groupKinds = new Set(['workspace', 'network']);
  const leaves = nodes.filter((n) => !groupKinds.has(n.data.kind));

  // Build a flat dagre graph using ONLY leaves. Edges that touch a group
  // are remapped to a leaf representative so the layout still respects
  // the workspace's place in the chain.
  const repFor = (id) => {
    if (!groupKinds.has(byId.get(id)?.data.kind)) return id;
    // Use the first descendant leaf as the representative.
    const stack = [id];
    while (stack.length) {
      const cur = stack.pop();
      for (const n of nodes) {
        if (n.parentNode === cur) {
          if (!groupKinds.has(n.data.kind)) return n.id;
          stack.push(n.id);
        }
      }
    }
    return id;
  };

  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'TB', nodesep: 40, ranksep: 80, marginx: 24, marginy: 24 });
  g.setDefaultEdgeLabel(() => ({}));
  leaves.forEach((n) => g.setNode(n.id, { width: LEAF_W, height: LEAF_H }));
  edges.forEach((e) => {
    const s = repFor(e.source); const t = repFor(e.target);
    if (s !== t && g.hasNode(s) && g.hasNode(t)) g.setEdge(s, t);
  });
  dagre.layout(g);

  // Leaf positions (top-left coordinates).
  const positions = new Map();
  const sizes = new Map();
  leaves.forEach((n) => {
    const p = g.node(n.id);
    positions.set(n.id, { x: p.x - p.width / 2, y: p.y - p.height / 2 });
    sizes.set(n.id, { w: LEAF_W, h: LEAF_H });
  });

  // Compute parent bboxes bottom-up: network parents first, then workspaces.
  const computeBbox = (parentId) => {
    const kids = nodes.filter((n) => n.parentNode === parentId);
    if (!kids.length) {
      // Empty parent — give it a small placeholder size.
      positions.set(parentId, positions.get(parentId) || { x: 0, y: 0 });
      sizes.set(parentId, { w: 160, h: 60 });
      return;
    }
    // Ensure children are positioned first.
    kids.forEach((k) => { if (groupKinds.has(k.data.kind)) computeBbox(k.id); });
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const k of kids) {
      const p = positions.get(k.id);
      const s = sizes.get(k.id);
      if (!p || !s) continue;
      if (p.x < minX) minX = p.x;
      if (p.y < minY) minY = p.y;
      if (p.x + s.w > maxX) maxX = p.x + s.w;
      if (p.y + s.h > maxY) maxY = p.y + s.h;
    }
    const padL = PARENT_PAD.x, padR = PARENT_PAD.x, padT = PARENT_PAD.top, padB = PARENT_PAD.bottom;
    const parentX = minX - padL;
    const parentY = minY - padT;
    const parentW = (maxX - minX) + padL + padR;
    const parentH = (maxY - minY) + padT + padB;
    positions.set(parentId, { x: parentX, y: parentY });
    sizes.set(parentId, { w: parentW, h: parentH });
  };

  const topLevelGroups = nodes
    .filter((n) => groupKinds.has(n.data.kind) && !n.parentNode);
  topLevelGroups.forEach((p) => computeBbox(p.id));

  // Convert to React Flow positions. Children must be expressed relative
  // to their parent.
  return nodes.map((n) => {
    const isGroup = groupKinds.has(n.data.kind);
    let pos = positions.get(n.id);
    if (!pos) pos = { x: 0, y: 0 }; // shouldn't happen but be defensive
    if (n.parentNode) {
      const pp = positions.get(n.parentNode) || { x: 0, y: 0 };
      pos = { x: pos.x - pp.x, y: pos.y - pp.y };
    }
    return {
      ...n,
      position: pos,
      style: isGroup ? { width: sizes.get(n.id).w, height: sizes.get(n.id).h } : undefined,
    };
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
