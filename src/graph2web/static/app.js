// graph2web frontend: sigma.js (WebGL) + graphology, no build step.
/* global graphology, graphologyLibrary, Sigma */
"use strict";

// ---------------------------------------------------------------------------
// Visual encoding
// ---------------------------------------------------------------------------
// Categorical palette (8 fixed slots per theme; dark validated with the dataviz
// validator against surface #1a1a19). Assigned in fixed order; labels beyond
// 8 fold into the neutral "other" gray, never a generated 9th hue.
// Light mode uses the same 8 hues stepped for the light surface #fcfcfb (same
// slot order, so a label keeps its hue in both themes); validated with
// validate_palette.js --mode light: all hard checks pass, contrast WARN for
// aqua/yellow/magenta is relieved by the visible node labels and legend.
// The graph is drawn by WebGL (sigma), so its colors live here, not in CSS.
const THEMES = {
  dark: {
    palette: ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"],
    other: "#8a8984",
    dimNode: "#3a3a37",
    dimEdge: "#2b2b29",
    edge: "#55554f",
    edgeTouch: "#a9a89f",
    ring: "#f0efec",
    surface: [26, 26, 25],
    label: "#c3c2b7",
    edgeLabel: "#8f8e86",
    hoverRing: "#f0efec",
    hoverFill: "#212120",
    hoverLine: "#4a4a47",
    hoverInk: "#f0efec",
  },
  light: {
    palette: ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"],
    other: "#898781",
    dimNode: "#e2e1dc",
    dimEdge: "#ebeae6",
    edge: "#c3c2b7",
    edgeTouch: "#6f6e69",
    ring: "#1f1f1e",
    surface: [252, 252, 251],
    label: "#3d3c39",
    edgeLabel: "#6f6e69",
    hoverRing: "#0b0b0b",
    hoverFill: "#ffffff",
    hoverLine: "#c3c2b7",
    hoverInk: "#0b0b0b",
  },
};
const PALETTE_SIZE = 8;
let T = THEMES.light;   // current theme colors (set by applyTheme)

// Primary label of a node = first of these it has (most specific first)
const LABEL_ORDER = ["HighLevelEvent", "HTTPRequest", "AuthEvent", "SystemEvent", "IPAddress",
                     "User", "Page", "UserAgent", "Service", "LogFile", "Event"];
// Palette slot per label (fixed, never by rank)
const LABEL_SLOT = {
  HTTPRequest: 0, AuthEvent: 1, SystemEvent: 2, IPAddress: 3,
  User: 4, Page: 5, HighLevelEvent: 6, UserAgent: 7,
};
function labelColor(label) { return label in LABEL_SLOT ? T.palette[LABEL_SLOT[label]] : T.other; }
const BASE_SIZE = { HighLevelEvent: 8, IPAddress: 7, User: 7 };

const EXAMPLES = [
  ["High-level event chain", "MATCH (h:HighLevelEvent)-[r:FOLLOWED_BY]->(n) RETURN h, r, n"],
  ["HLE with more than one actor", "MATCH (h:HighLevelEvent) WHERE h.actor_count > 1\nRETURN h.hle_id, h.type, h.actor_ips, h.actor_users, h.actor_details"],
  ["All activity of one IP", "MATCH p=(ip:IPAddress {ip: '172.17.130.196'})-[:REQUEST|CONNECT]->(e)<-[:CONTAINS]-(h:HighLevelEvent)\nRETURN p"],
  ["Web attacker -> user -> sudo (cross-log)", "MATCH p=(ip:IPAddress)-[:REQUEST]->(:HTTPRequest)-[:RELATED_TO]->(u:User)-[:PERFORMED]->(a:AuthEvent)\nRETURN p"],
  ["Events not detected by SigmaDFT", "MATCH (e:Event) WHERE NOT e:Detected RETURN e.event_id, e.log_type, e.message"],
  ["Entity degree (top 20)", "MATCH (n) WHERE n:IPAddress OR n:User OR n:Page\nRETURN labels(n)[0] AS label, coalesce(n.ip, n.username, n.path) AS name, COUNT { (n)--() } AS degree\nORDER BY degree DESC LIMIT 20"],
];

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const $ = (id) => document.getElementById(id);
const state = {
  db: null,
  dbPrefix: "sigmadft-",  // only databases with this prefix are listed (from /api/connection)
  fullData: null,        // {nodes, edges} of the whole database
  view: "full",          // "full" | "query"
  graph: null,
  renderer: null,
  layout: null,
  layoutTimer: null,
  hiddenLabels: new Set(),
  hiddenTypes: new Set(),
  hovered: null,
  selected: null,        // {kind: "node"|"edge", id}
  neighbors: new Set(),
  colorMode: "label",
  communityColor: new Map(),
  communities: [],       // Louvain communities, largest first
  lastResult: null,
  time: {
    extent: null,        // {from, to} ms of all event times in the graph
    domain: null,        // {from, to} ms shown on the histogram (zoom)
    range: null,         // {from, to} ms selected (inclusive), null = no time filter
    hidden: new Set(),   // node ids hidden by the time filter
    drag: null,          // {start, end} bin indexes while brushing
  },
};
const TIME_BINS = 56;
const HIST_W = 224;
const HIST_H = 56;

function setStatus(text, isError = false) {
  const el = $("status");
  el.textContent = text;
  el.classList.toggle("error", isError);
}

// ---------------------------------------------------------------------------
// Loading indicator: Query -> Download -> Build -> Layout, then "Ready"
// ---------------------------------------------------------------------------
const loader = { t0: 0, clock: null, hideTimer: null, loading: false };
const LOAD_STEPS = ["Query", "Download", "Build", "Layout"];

// Names of the steps in the loader (case load, or the steps of a job)
function setLoaderSteps(names) {
  const list = $("loader-steps");
  if ([...list.children].map((li) => li.textContent).join("|") === names.join("|")) return;
  list.replaceChildren(...names.map((n) => el("li", "", n)));
}

function loaderTick() {
  $("loader-time").textContent = `${((performance.now() - loader.t0) / 1000).toFixed(1)} s`;
}

// step: index into the steps list (null hides the list, used for a manual layout);
// progress: 0..1, or null when the amount of work is unknown
function showLoader(step, text, progress = null) {
  clearTimeout(loader.hideTimer);
  const box = $("loader");
  if (box.hidden || box.classList.contains("done")) {
    loader.t0 = performance.now();
    clearInterval(loader.clock);
    loader.clock = setInterval(loaderTick, 100);
  }
  box.hidden = false;
  box.classList.remove("done");
  box.classList.toggle("indeterminate", progress === null);
  $("loader-bar").style.width = progress === null ? "" : `${Math.round(progress * 100)}%`;
  $("loader-text").textContent = text;
  const steps = $("loader-steps");
  steps.hidden = step === null;
  [...steps.children].forEach((li, i) => {
    li.classList.toggle("done", step !== null && i < step);
    li.classList.toggle("current", i === step);
  });
  // The old graph stays visible but dimmed while new data is on its way
  $("stage").classList.toggle("busy", loader.loading && step !== null && step < 3);
  loaderTick();
}

function finishLoader(text) {
  const box = $("loader");
  if (box.hidden) return;
  clearInterval(loader.clock);
  loaderTick();
  box.classList.remove("indeterminate");
  box.classList.add("done");
  $("loader-text").textContent = text;
  [...$("loader-steps").children].forEach((li) => { li.classList.add("done"); li.classList.remove("current"); });
  $("stage").classList.remove("busy");
  loader.hideTimer = setTimeout(() => { box.hidden = true; box.classList.remove("done"); }, 4000);
}

// End of a case load: the graph is fully loaded and arranged
function finishLoaded() {
  loader.loading = false;
  const g = state.graph;
  finishLoader(`Ready: ${g.order.toLocaleString()} nodes, ${g.size.toLocaleString()} relationships`);
}

function hideLoader() {
  clearInterval(loader.clock);
  clearTimeout(loader.hideTimer);
  $("loader").hidden = true;
  $("stage").classList.remove("busy");
  loader.loading = false;
}

const nextPaint = () => new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve)));
const megabytes = (n) => `${(n / 1048576).toFixed(1)} MB`;

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) { /* not JSON */ }
    throw new Error(detail);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Node helpers
// ---------------------------------------------------------------------------
function primaryLabel(labels) {
  for (const l of LABEL_ORDER) if (labels.includes(l)) return l;
  return labels[0] || "Node";
}

function shorten(text, n = 40) {
  text = String(text ?? "");
  return text.length > n ? text.slice(0, n - 1) + "…" : text;
}

// Full, untruncated name (inspector title)
function fullCaption(labels, p) {
  const label = primaryLabel(labels);
  if (label === "HighLevelEvent") return `HLE ${p.hle_id}: ${p.type ?? ""}`;
  if ("event_id" in p) return `#${p.event_id} ${p.sigmadft_type || p.pattern || p.log_type || ""}`;
  return p.ip ?? p.username ?? p.path ?? p.value ?? p.name ?? caption(labels, p);
}

function caption(labels, p) {
  const label = primaryLabel(labels);
  switch (label) {
    case "HighLevelEvent": return `HLE ${p.hle_id}: ${p.type ?? ""}`;
    case "IPAddress": return p.ip;
    case "User": return p.username;
    case "Page": return shorten(p.path, 50);
    case "UserAgent": return shorten(p.value, 40);
    case "Service": return p.name;
    case "LogFile": return String(p.path ?? "").split("/").pop();
    default:
      if ("event_id" in p) return `#${p.event_id} ${shorten(p.sigmadft_type || p.pattern || p.log_type || "", 36)}`;
      return shorten(Object.values(p)[0], 30);
  }
}

function mute(hex, amount = 0.55) {
  // Blend toward the surface (used for events SigmaDFT did not detect)
  const n = parseInt(hex.slice(1), 16);
  const rgb = [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  const mixed = rgb.map((c, i) => Math.round(c * (1 - amount) + T.surface[i] * amount));
  return `rgb(${mixed.join(",")})`;
}

function nodeColor(attrs) {
  let color;
  if (state.colorMode === "community") {
    const slot = state.communityColor.get(attrs.community);
    color = slot === undefined ? T.other : T.palette[slot];
  } else color = labelColor(attrs.nodeLabel);
  return attrs.isEvent && !attrs.detected ? mute(color) : color;
}

// ---------------------------------------------------------------------------
// Graph building
// ---------------------------------------------------------------------------
const NodeBorderProgram = Sigma.rendering.createNodeBorderProgram({
  borders: [
    { size: { value: 0.18 }, color: { attribute: "borderColor" } },
    { size: { fill: true }, color: { attribute: "color" } },
  ],
});

function buildGraph(data) {
  stopLayout();
  if (state.renderer) { state.renderer.kill(); state.renderer = null; }
  state.hovered = null;
  state.selected = null;
  state.neighbors = new Set();

  const graph = new graphology.MultiDirectedGraph();
  for (const n of data.nodes) {
    const label = primaryLabel(n.labels);
    graph.addNode(n.id, {
      label: caption(n.labels, n.props),
      labels: n.labels,
      props: n.props,
      nodeLabel: label,
      isEvent: n.labels.includes("Event"),
      detected: n.labels.includes("Detected"),
      x: Math.random() * 100,
      y: Math.random() * 100,
    });
  }
  for (const e of data.edges) {
    if (graph.hasNode(e.source) && graph.hasNode(e.target)) {
      graph.addDirectedEdgeWithKey(e.id, e.source, e.target, {
        relType: e.type, props: e.props, label: e.type, size: 1, type: "arrow",
      });
    }
  }
  graph.forEachNode((id, a) => {
    const deg = graph.degree(id);
    const base = BASE_SIZE[a.nodeLabel] || (a.isEvent ? 4 : 5);
    graph.mergeNodeAttributes(id, {
      baseSize: Math.min(base + 1.6 * Math.log2(1 + deg), 22),
      type: a.isEvent && a.detected ? "border" : "circle",
      borderColor: T.ring,
    });
  });
  state.graph = graph;
  applySizes();
  computeCommunities();
  applyColors();
  initTime();

  const big = graph.size > 20000;
  state.renderer = new Sigma(graph, $("graph"), {
    nodeProgramClasses: { border: NodeBorderProgram },
    defaultEdgeType: "arrow",
    renderEdgeLabels: true,
    renderLabels: $("opt-labels").checked,
    labelColor: { color: T.label },
    edgeLabelColor: { color: T.edgeLabel },
    labelFont: '"Atkinson Hyperlegible Next", system-ui, sans-serif',
    labelSize: 11,
    edgeLabelSize: 10,
    labelRenderedSizeThreshold: 7,
    hideEdgesOnMove: big,
    defaultDrawNodeHover: drawNodeHover,
    zIndex: true,
    nodeReducer,
    edgeReducer,
  });
  bindRendererEvents();
  renderFilters();
  renderDetails();
  startLayout(Math.min(2500 + graph.order * 4, 20000));
}

// Node size = size from label + degree, times an automatic factor (node sizes are
// screen pixels, so thousands of full-size nodes cover each other and every
// relationship when the graph is fitted to the view), times the Node size slider.
function sizeScale() {
  const auto = Math.min(1, Math.max(0.15, Math.sqrt(1500 / Math.max(1, state.graph.order))));
  return auto * Number($("opt-node-size").value) / 100;
}

function applySizes() {
  const k = sizeScale();
  state.graph.updateEachNodeAttributes((_, a) => ({ ...a, size: Math.max(1, a.baseSize * k) }), { attributes: ["size"] });
}

function showDisplayValues() {
  $("opt-node-size-val").textContent = `${$("opt-node-size").value}%`;
  $("opt-spacing-val").textContent = `${Number($("opt-spacing").value)}×`;
}

// Hover label in the interface's dark panel style (sigma's default is a white box)
function drawNodeHover(context, data, settings) {
  const size = settings.labelSize;
  const font = settings.labelFont;
  context.font = `600 ${size}px ${font}`;
  const label = data.label || "";
  const padX = 6;
  const textWidth = label ? context.measureText(label).width : 0;
  const x = data.x + data.size + 4;
  const h = size + 8;
  context.beginPath();
  context.arc(data.x, data.y, data.size + 3, 0, Math.PI * 2);
  context.strokeStyle = T.hoverRing;
  context.lineWidth = 1.5;
  context.stroke();
  if (!label) return;
  context.fillStyle = T.hoverFill;
  context.strokeStyle = T.hoverLine;
  context.lineWidth = 1;
  context.beginPath();
  context.roundRect(x, data.y - h / 2, textWidth + padX * 2, h, 4);
  context.fill();
  context.stroke();
  context.fillStyle = T.hoverInk;
  context.textBaseline = "middle";
  context.fillText(label, x + padX, data.y + 0.5);
}

function computeCommunities() {
  const g = state.graph;
  state.communityColor = new Map();
  if (g.order === 0) return;
  try {
    graphologyLibrary.communitiesLouvain.assign(g, { nodeCommunityAttribute: "community" });
  } catch (err) {
    console.warn("Louvain failed:", err);
    return;
  }
  // Largest communities take the 8 palette slots, the rest fold into "other"
  const info = new Map();
  g.forEachNode((id, a) => {
    if (!info.has(a.community)) info.set(a.community, { id: a.community, size: 0, labels: new Map(), hub: null, hubScore: -1 });
    const c = info.get(a.community);
    c.size += 1;
    c.labels.set(a.nodeLabel, (c.labels.get(a.nodeLabel) || 0) + 1);
    // Name a community after its most connected actor (IP/User), else most connected node
    const score = g.degree(id) + (a.nodeLabel === "IPAddress" || a.nodeLabel === "User" ? 1e6 : 0);
    if (score > c.hubScore) { c.hub = id; c.hubScore = score; }
  });
  state.communities = [...info.values()].sort((a, b) => b.size - a.size);
  // communityColor maps community -> palette slot (the hex comes from the theme)
  state.communities.slice(0, PALETTE_SIZE).forEach((c, i) => state.communityColor.set(c.id, i));
}

function renderCommunityLegend() {
  const section = $("community-section");
  section.hidden = state.colorMode !== "community";
  if (section.hidden) return;
  const all = state.communities || [];
  const colored = all.slice(0, PALETTE_SIZE);
  const rest = all.slice(PALETTE_SIZE);
  $("community-total").textContent = all.length.toLocaleString();
  const items = colored.map((c, i) => {
    const hub = state.graph.getNodeAttributes(c.hub);
    const li = document.createElement("li");
    li.title = `Community ${i + 1}: click to select ${hub.label}`;
    const sw = Object.assign(document.createElement("span"), { className: "swatch" });
    sw.style.background = T.palette[i];
    const tag = el("span", "tag", `C${i + 1}`);
    const name = el("span", "name", hub.label);
    const count = Object.assign(document.createElement("span"), { className: "count", textContent: c.size.toLocaleString() });
    const comp = [...c.labels.entries()].sort((a, b) => b[1] - a[1]).map(([l, n]) => `${n} ${l}`).join(", ");
    const sub = Object.assign(document.createElement("span"), { className: "sub", textContent: comp });
    sub.title = comp;
    li.append(sw, tag, name, count, sub);
    li.addEventListener("click", () => selectNode(c.hub));
    return li;
  });
  if (rest.length) {
    const li = document.createElement("li");
    li.className = "static";
    const sw = Object.assign(document.createElement("span"), { className: "swatch" });
    sw.style.background = T.other;
    const n = rest.reduce((sum, c) => sum + c.size, 0);
    li.append(sw, el("span", "tag", ""),
      Object.assign(document.createElement("span"), { className: "name", textContent: `Other (${rest.length} communities)` }),
      Object.assign(document.createElement("span"), { className: "count", textContent: n.toLocaleString() }));
    items.push(li);
  }
  $("community-legend").replaceChildren(...items);
}

function applyColors() {
  state.graph.forEachNode((id, a) => state.graph.setNodeAttribute(id, "color", nodeColor(a)));
  state.graph.forEachEdge((id) => state.graph.setEdgeAttribute(id, "color", T.edge));
}

// ---------------------------------------------------------------------------
// Reducers (filtering + highlight)
// ---------------------------------------------------------------------------
function nodeHidden(id) {
  return state.time.hidden.has(id) || state.hiddenLabels.has(state.graph.getNodeAttribute(id, "nodeLabel"));
}

function focusNode() {
  if (state.hovered) return state.hovered;
  return state.selected && state.selected.kind === "node" ? state.selected.id : null;
}

function nodeReducer(id, data) {
  const res = { ...data };
  if (nodeHidden(id)) { res.hidden = true; return res; }
  const focus = focusNode();
  if (focus && id !== focus && !state.neighbors.has(id)) {
    res.color = T.dimNode;
    res.label = "";
    res.type = "circle";
    res.zIndex = 0;
  } else if (focus) {
    res.zIndex = 1;
    res.forceLabel = true;
  }
  if (state.selected && state.selected.kind === "node" && id === state.selected.id) res.highlighted = true;
  return res;
}

function edgeReducer(id, data) {
  const res = { ...data };
  const g = state.graph;
  if (state.hiddenTypes.has(data.relType) || nodeHidden(g.source(id)) || nodeHidden(g.target(id))) {
    res.hidden = true;
    return res;
  }
  const focus = focusNode();
  const selectedEdge = state.selected && state.selected.kind === "edge" && state.selected.id === id;
  const touches = focus && (g.source(id) === focus || g.target(id) === focus);
  if (selectedEdge) {
    res.color = T.ring; res.size = 2.5; res.forceLabel = true;
  } else if (focus && !touches) {
    res.color = T.dimEdge; res.label = "";
  } else if (touches) {
    res.color = T.edgeTouch; res.size = 1.6;
  }
  // Relationship names only when readable: hidden around hubs with many neighbors
  const crowded = touches && state.neighbors.size > 15;
  if (!$("opt-edge-labels").checked || (!touches && !selectedEdge) || (crowded && !selectedEdge)) res.label = "";
  return res;
}

function refresh() { if (state.renderer) state.renderer.refresh({ skipIndexation: true }); }

function updateNeighbors() {
  const focus = focusNode();
  state.neighbors = new Set(focus ? state.graph.neighbors(focus) : []);
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------
// Node drag: press on a node and move. The dragged node is pinned (`fixed`,
// which ForceAtlas2 leaves in place); double-click a pinned node to release it.
// A click without movement still selects the node.
const drag = { node: null, moved: false };

function bindRendererEvents() {
  const r = state.renderer;
  const g = state.graph;
  const container = $("graph");
  r.on("enterNode", ({ node }) => {
    state.hovered = node; updateNeighbors(); refresh();
    if (!drag.node) container.style.cursor = "grab";
  });
  r.on("leaveNode", () => {
    state.hovered = null; updateNeighbors(); refresh();
    if (!drag.node) container.style.cursor = "";
  });
  r.on("downNode", ({ node }) => {
    drag.node = node;
    drag.moved = false;
  });
  r.on("moveBody", ({ event }) => {
    if (!drag.node) return;
    if (!drag.moved) {
      drag.moved = true;
      if (state.layout) stopLayout();       // the layout would fight the mouse
      // Freeze the graph bounds so the view does not rescale while dragging
      if (!r.getCustomBBox()) r.setCustomBBox(r.getBBox());
      container.style.cursor = "grabbing";
    }
    const pos = r.viewportToGraph(event);
    g.mergeNodeAttributes(drag.node, { x: pos.x, y: pos.y, fixed: true });
    event.preventSigmaDefault();             // no camera pan while dragging a node
    event.original.preventDefault();
    event.original.stopPropagation();
  });
  const endDrag = () => {
    if (!drag.node) return;
    const node = drag.node;
    drag.node = null;
    container.style.cursor = state.hovered ? "grab" : "";
    if (drag.moved && state.selected && state.selected.kind === "node" && state.selected.id === node) renderDetails();
  };
  r.on("upNode", endDrag);
  r.on("upStage", endDrag);
  r.on("clickNode", ({ node }) => {
    if (drag.moved) { drag.moved = false; return; }   // end of a drag, not a click
    selectNode(node, false);
  });
  r.on("doubleClickNode", ({ node, event }) => {
    event.preventSigmaDefault();             // no zoom on double-click of a node
    if (g.getNodeAttribute(node, "fixed")) {
      g.setNodeAttribute(node, "fixed", false);
      setStatus(`Released ${g.getNodeAttribute(node, "label")}: it follows the layout again`);
      renderDetails();
    }
  });
  r.on("clickEdge", ({ edge }) => { state.selected = { kind: "edge", id: edge }; updateNeighbors(); renderDetails(); refresh(); });
  r.on("clickStage", clearSelection);
  r.setSetting("enableEdgeEvents", true);
}

function selectNode(id, moveCamera = true) {
  state.selected = { kind: "node", id };
  updateNeighbors();
  renderDetails();
  refresh();
  if (moveCamera) {
    const pos = state.renderer.getNodeDisplayData(id);
    if (pos) state.renderer.getCamera().animate({ x: pos.x, y: pos.y, ratio: 0.25 }, { duration: 500 });
  }
}

// ---------------------------------------------------------------------------
// Layout (ForceAtlas2 in a web worker)
// ---------------------------------------------------------------------------
// The layout runs on a copy holding only what is shown (label, relationship and
// time filters), so hidden hubs and relationships do not pull the shown nodes;
// positions are copied back every frame. Hidden nodes keep their positions.
function layoutSubgraph() {
  const g = state.graph;
  const sub = new graphology.MultiDirectedGraph();
  g.forEachNode((id, a) => {
    if (!nodeHidden(id)) sub.addNode(id, { x: a.x, y: a.y, fixed: !!a.fixed, size: a.size });
  });
  g.forEachEdge((id, a, s, t) => {
    if (!state.hiddenTypes.has(a.relType) && sub.hasNode(s) && sub.hasNode(t)) sub.addDirectedEdgeWithKey(id, s, t);
  });
  return sub;
}

function syncLayout() {
  const sub = state.layoutGraph;
  if (!sub) return;
  state.graph.updateEachNodeAttributes((id, a) => {
    if (!sub.hasNode(id)) return a;
    const p = sub.getNodeAttributes(id);
    return { ...a, x: p.x, y: p.y };
  }, { attributes: ["x", "y"] });
}

function startLayout(autoStopMs) {
  stopLayout();
  const g = state.graph;
  if (!g) return;
  const sub = layoutSubgraph();
  if (sub.order < 2) {
    if (loader.loading) finishLoaded(); else setStatus("Layout needs at least two shown nodes");
    return;
  }
  // Bounds frozen by a node drag would keep the moving layout from rescaling
  if (state.renderer) state.renderer.setCustomBBox(null);
  // Defaults from graphology, without strong gravity (it packs large graphs into
  // a ball); Node spacing scales the repulsion.
  const settings = graphologyLibrary.layoutForceAtlas2.inferSettings(sub);
  settings.barnesHutOptimize = sub.order > 2000;
  settings.strongGravityMode = false;
  settings.gravity = 1;
  settings.scalingRatio = 10 * Number($("opt-spacing").value);
  state.layoutGraph = sub;
  state.layout = new graphologyLibrary.FA2Layout(sub, { settings });
  state.layout.start();
  // Indicator: the last step of a case load, or a layout started from the toolbar
  const t0 = performance.now();
  const progress = () => (autoStopMs ? Math.min(1, (performance.now() - t0) / autoStopMs) : null);
  const label = loader.loading ? `Arranging layout: ${sub.order.toLocaleString()} nodes…`
    : autoStopMs ? "Arranging layout…" : "Layout running: press Stop layout to end";
  showLoader(loader.loading ? 3 : null, label, progress());
  const tick = () => {
    syncLayout();
    if (autoStopMs) $("loader-bar").style.width = `${Math.round(progress() * 100)}%`;
    state.layoutFrame = requestAnimationFrame(tick);
  };
  state.layoutFrame = requestAnimationFrame(tick);
  $("btn-layout").classList.add("active");
  $("btn-layout").textContent = "Stop layout";
  $("btn-layout").setAttribute("aria-pressed", "true");
  if (autoStopMs) state.layoutTimer = setTimeout(() => {
    stopLayout();
    if (state.renderer) state.renderer.getCamera().animatedReset();
  }, autoStopMs);
}

function stopLayout() {
  clearTimeout(state.layoutTimer);
  cancelAnimationFrame(state.layoutFrame);
  if (state.layout) {
    state.layout.kill();
    state.layout = null;
    if (loader.loading) finishLoaded(); else finishLoader("Layout done");
  }
  if (state.layoutGraph) { syncLayout(); state.layoutGraph = null; }
  $("btn-layout").classList.remove("active");
  $("btn-layout").textContent = "Run layout";
  $("btn-layout").setAttribute("aria-pressed", "false");
}

// ---------------------------------------------------------------------------
// Sidebar filters / legend
// ---------------------------------------------------------------------------
function renderFilters() {
  const g = state.graph;
  const labelCounts = new Map();
  g.forEachNode((_, a) => labelCounts.set(a.nodeLabel, (labelCounts.get(a.nodeLabel) || 0) + 1));
  const typeCounts = new Map();
  g.forEachEdge((_, a) => typeCounts.set(a.relType, (typeCounts.get(a.relType) || 0) + 1));
  const detected = g.filterNodes((_, a) => a.isEvent && a.detected).length;

  $("node-total").textContent = g.order.toLocaleString();
  $("edge-total").textContent = g.size.toLocaleString();

  const maxLabel = Math.max(...labelCounts.values());
  const labels = [...labelCounts.keys()].sort((a, b) => LABEL_ORDER.indexOf(a) - LABEL_ORDER.indexOf(b));
  $("label-filters").replaceChildren(...labels.map((label) => {
    const swatch = state.colorMode === "label" ? labelColor(label) : "transparent";
    return filterItem(label, labelCounts.get(label), swatch, state.hiddenLabels, maxLabel);
  }));
  const hint = $("node-hint");
  hint.textContent = `A ring marks events detected by SigmaDFT (${detected}); faded events were not detected.`
    + (state.colorMode === "community" ? " Colors show communities (legend on the graph, right)." : "");
  renderCommunityLegend();

  const types = [...typeCounts.keys()].sort((a, b) => typeCounts.get(b) - typeCounts.get(a));
  const maxType = Math.max(...typeCounts.values());
  $("type-filters").replaceChildren(...types.map((t) => filterItem(t, typeCounts.get(t), null, state.hiddenTypes, maxType)));
}

function filterItem(name, count, color, hiddenSet, max) {
  const li = document.createElement("li");
  li.classList.toggle("off", hiddenSet.has(name));
  const label = document.createElement("label");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = !hiddenSet.has(name);
  box.addEventListener("change", () => {
    if (box.checked) hiddenSet.delete(name); else hiddenSet.add(name);
    li.classList.toggle("off", !box.checked);
    renderTime();
    refresh();
  });
  const sw = el("span", color === null ? "swatch line" : "swatch");
  if (color) sw.style.background = color;
  const bar = el("span", "bar");
  const fill = document.createElement("span");
  fill.style.setProperty("--w", `${Math.max(2, (100 * count) / (max || count))}%`);
  bar.append(fill);
  label.append(box, sw, el("span", "name", name), el("span", "count", count.toLocaleString()), bar);
  li.append(label);
  return li;
}

// ---------------------------------------------------------------------------
// Time range filter (all times UTC)
// ---------------------------------------------------------------------------
// Event: shown when its datetime is inside the range. HighLevelEvent: shown
// when its [min, max] overlaps the range. Nodes without a time of their own
// (IP, User, Page, ...): shown when linked to at least one event inside the
// range. Combined (AND) with the label and relationship filters.
function parseTime(value) {
  if (!value) return NaN;
  // Neo4j/SigmaDFT strings carry 6-9 fractional digits; Date.parse wants <= 3
  return Date.parse(String(value).replace(/(\.\d{3})\d+/, "$1"));
}

function isoUTC(ms) { return new Date(ms).toISOString(); }
// From/To inputs use yyyy/mm/dd hh:mm:ss (UTC)
function inputValue(ms) { return isoUTC(ms).slice(0, 19).replace("T", " ").replace(/-/g, "/"); }

// Parse "yyyy/mm/dd[ hh:mm[:ss]]" ("-" also accepted) as UTC. Returns {from, to}:
// the start and the end of what was typed (a day, a minute or a second), or null.
function parseInputTime(text) {
  const m = text.trim().match(/^(\d{4})[/-](\d{1,2})[/-](\d{1,2})(?:[ T]+(\d{1,2}):(\d{2})(?::(\d{2}))?)?$/);
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m.map((v) => (v === undefined ? undefined : Number(v)));
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || (h ?? 0) > 23 || (mi ?? 0) > 59 || (s ?? 0) > 59) return null;
  const from = Date.UTC(y, mo - 1, d, h ?? 0, mi ?? 0, s ?? 0);
  if (new Date(from).getUTCDate() !== d) return null;   // e.g. 2022/02/30
  const unit = h === undefined ? 86400e3 : s === undefined ? 60e3 : 1e3;
  return { from, to: from + unit - 1 };
}
function axisText(ms, span) {
  const s = isoUTC(ms).replace("T", " ");
  return span < 2 * 86400e3 ? s.slice(0, 19) : s.slice(0, 16);
}

// Chart span around [lo, hi] with ~1 bin of air on each side, so the first and
// last events do not sit under the chart border
function paddedSpan(lo, hi) {
  if (hi - lo < 2e3) { lo -= 1e3; hi += 1e3; }
  const pad = (hi - lo) / (TIME_BINS - 2);
  return { from: lo - pad, to: hi + pad };
}

function initTime() {
  const g = state.graph;
  const t = state.time;
  let min = Infinity, max = -Infinity;
  g.forEachNode((id, a) => {
    let lo = NaN, hi = NaN;
    if (a.isEvent) lo = hi = parseTime(a.props.timestamp ?? a.props.datetime);
    else if (a.nodeLabel === "HighLevelEvent") {
      lo = parseTime(a.props.timestamp_min ?? a.props.date_time_min);
      hi = parseTime(a.props.timestamp_max ?? a.props.date_time_max);
      if (!Number.isFinite(hi)) hi = lo;
    }
    g.mergeNodeAttributes(id, { tMin: lo, tMax: hi });
    if (a.isEvent && Number.isFinite(lo)) { min = Math.min(min, lo); max = Math.max(max, lo); }
  });
  t.extent = Number.isFinite(min) ? paddedSpan(min, max) : null;
  t.first = min;   // first and last event time (unpadded), used for empty inputs
  t.last = max;
  t.domain = t.extent ? { ...t.extent } : null;
  t.drag = null;
  computeTimeHidden();
  renderTime();
}

function computeTimeHidden() {
  const g = state.graph;
  const r = state.time.range;
  const hidden = new Set();
  if (r && g) {
    const timed = (a) => a.isEvent || a.nodeLabel === "HighLevelEvent";
    g.forEachNode((id, a) => {
      if (timed(a) && !(Number.isFinite(a.tMin) && a.tMax >= r.from && a.tMin <= r.to)) hidden.add(id);
    });
    g.forEachNode((id, a) => {
      if (timed(a)) return;
      if (!g.someNeighbor(id, (n, na) => na.isEvent && !hidden.has(n))) hidden.add(id);
    });
  }
  state.time.hidden = hidden;
}

function setTimeRange(range) {
  const t = state.time;
  if (range && range.from > range.to) range = { from: range.to, to: range.from };
  t.range = range;
  // Keep the selection visible on the chart: leave the zoom if it falls outside
  if (range && t.domain && (range.from < t.domain.from || range.to > t.domain.to)) t.domain = { ...t.extent };
  computeTimeHidden();
  const g = state.graph;
  if (state.selected && state.selected.kind === "node" && t.hidden.has(state.selected.id)) state.selected = null;
  if (state.selected && state.selected.kind === "edge" && g.hasEdge(state.selected.id)
      && (t.hidden.has(g.source(state.selected.id)) || t.hidden.has(g.target(state.selected.id)))) state.selected = null;
  if (state.hovered && t.hidden.has(state.hovered)) state.hovered = null;
  updateNeighbors();
  renderDetails();
  renderTime();
  refresh();
}

function binSpan(i) {
  const d = state.time.domain;
  const w = (d.to - d.from) / TIME_BINS;
  return { from: d.from + i * w, to: i === TIME_BINS - 1 ? d.to : d.from + (i + 1) * w - 1 };
}

function renderTime() {
  const t = state.time;
  const g = state.graph;
  const hasTime = Boolean(t.extent);
  $("time-body").hidden = !hasTime;
  let total = 0, inRange = 0;
  if (g) g.forEachNode((id, a) => {
    if (!a.isEvent || !Number.isFinite(a.tMin)) return;
    total += 1;
    if (!t.range || (a.tMin >= t.range.from && a.tMin <= t.range.to)) inRange += 1;
  });
  // The section header shows that a time filter is on even while the panel is closed
  const active = Boolean(hasTime && t.range);
  $("time-total").textContent = active ? `${inRange.toLocaleString()}/${total.toLocaleString()} events` : "";
  $("btn-time").classList.toggle("active", active);
  $("btn-time").title = active
    ? `Time filter on: ${inRange} of ${total} events, ${inputValue(t.range.from)} to ${inputValue(t.range.to)} UTC`
    : "Show or hide the time range filter";
  if (!hasTime) {
    $("time-hint").textContent = "No event timestamps in this graph.";
    return;
  }
  $("time-hint").classList.remove("error");
  const shown = g.order - g.filterNodes((id) => nodeHidden(id)).length;
  $("time-hint").textContent = t.range
    ? `${shown.toLocaleString()} of ${g.order.toLocaleString()} nodes shown. Entities stay when linked to an event in range.`
    : "Drag on the chart or click a bar to filter, or type a range and Apply.";

  // Histogram of event counts per bin over the current domain
  const d = t.domain;
  const span = d.to - d.from;
  const counts = new Array(TIME_BINS).fill(0);
  let first = Infinity, last = -Infinity;
  g.forEachNode((id, a) => {
    if (!a.isEvent || !Number.isFinite(a.tMin) || a.tMin < d.from || a.tMin > d.to) return;
    first = Math.min(first, a.tMin);
    last = Math.max(last, a.tMin);
    counts[Math.min(TIME_BINS - 1, Math.floor(((a.tMin - d.from) / span) * TIME_BINS))] += 1;
  });
  t.counts = counts;
  const max = Math.max(1, ...counts);
  const svg = $("time-hist");
  const NS = "http://www.w3.org/2000/svg";
  const bw = HIST_W / TIME_BINS;
  const sel = t.drag
    ? { a: Math.min(t.drag.start, t.drag.end), b: Math.max(t.drag.start, t.drag.end) } : null;
  const nodes = [];
  counts.forEach((c, i) => {
    if (!c) return;
    const h = Math.max(2, ((HIST_H - 6) * c) / max);
    const rect = document.createElementNS(NS, "rect");
    const b = binSpan(i);
    const inSel = sel ? i >= sel.a && i <= sel.b : t.range && b.to >= t.range.from && b.from <= t.range.to;
    rect.setAttribute("class", inSel ? "bar in" : "bar");
    rect.setAttribute("x", i * bw + 0.5);
    rect.setAttribute("width", Math.max(1, bw - 1));
    rect.setAttribute("y", HIST_H - h);
    rect.setAttribute("height", h);
    const title = document.createElementNS(NS, "title");
    title.textContent = `${c} event${c === 1 ? "" : "s"}, ${axisText(b.from, span)} to ${axisText(b.to, span)} UTC`;
    rect.append(title);
    nodes.push(rect);
  });
  let brush = null;
  if (sel) brush = { x0: sel.a * bw, x1: (sel.b + 1) * bw };
  else if (t.range && t.range.to >= d.from && t.range.from <= d.to) {
    const x = (ms) => ((Math.min(d.to, Math.max(d.from, ms)) - d.from) / span) * HIST_W;
    brush = { x0: x(t.range.from), x1: Math.max(x(t.range.from) + 1, x(t.range.to)) };
  }
  if (brush) {
    const rect = document.createElementNS(NS, "rect");
    rect.setAttribute("class", "brush");
    rect.setAttribute("x", brush.x0);
    rect.setAttribute("width", brush.x1 - brush.x0);
    rect.setAttribute("y", 0.5);
    rect.setAttribute("height", HIST_H - 1);
    rect.style.pointerEvents = "none";
    nodes.push(rect);
  }
  svg.replaceChildren(...nodes);
  svg.classList.toggle("has-range", Boolean(sel || t.range));

  // Axis ends = first and last event on the chart (the domain itself is padded)
  $("time-axis-from").textContent = axisText(Number.isFinite(first) ? first : d.from, span);
  $("time-axis-to").textContent = axisText(Number.isFinite(last) ? last : d.to, span);
  const zoomed = d.from !== t.extent.from || d.to !== t.extent.to;
  $("btn-time-zoom").disabled = !t.range;
  $("btn-time-full").disabled = !zoomed;
  $("btn-time-clear").disabled = !t.range;
  const r = sel ? { from: binSpan(sel.a).from, to: binSpan(sel.b).to } : t.range;
  if (r) {
    $("time-from").value = inputValue(r.from);
    $("time-to").value = inputValue(r.to);
    ["time-from", "time-to"].forEach((id) => $(id).removeAttribute("aria-invalid"));
  }
}

function histBin(e) {
  const box = $("time-hist").getBoundingClientRect();
  const x = Math.min(Math.max(e.clientX - box.left, 0), box.width - 0.01);
  return Math.floor((x / box.width) * TIME_BINS);
}

function bindTimeControls() {
  const svg = $("time-hist");
  svg.addEventListener("pointerdown", (e) => {
    if (!state.time.domain || e.button !== 0) return;
    svg.setPointerCapture(e.pointerId);
    const i = histBin(e);
    state.time.drag = { start: i, end: i };
    renderTime();
  });
  svg.addEventListener("pointermove", (e) => {
    const drag = state.time.drag;
    if (!drag) return;
    const i = histBin(e);
    if (i !== drag.end) { drag.end = i; renderTime(); }
  });
  const finish = () => {
    const drag = state.time.drag;
    if (!drag) return;
    state.time.drag = null;
    let a = Math.min(drag.start, drag.end), b = Math.max(drag.start, drag.end);
    // A plain click on a thin or empty spot picks the nearest bar (within 2 bins)
    const counts = state.time.counts || [];
    if (a === b && !counts[a]) {
      for (let k = 1; k <= 2; k++) {
        if (counts[a - k]) { a = b = a - k; break; }
        if (counts[a + k]) { a = b = a + k; break; }
      }
    }
    setTimeRange({ from: binSpan(a).from, to: binSpan(b).to });
  };
  svg.addEventListener("pointerup", finish);
  svg.addEventListener("pointercancel", () => { state.time.drag = null; renderTime(); });

  const apply = () => {
    const t = state.time;
    if (!t.extent) return;
    // Empty = first/last event. "To" covers the whole day, minute or second typed.
    const read = (id) => {
      const input = $(id);
      const text = input.value.trim();
      const parsed = text ? parseInputTime(text) : null;
      input.setAttribute("aria-invalid", String(Boolean(text && !parsed)));
      return text ? parsed : undefined;
    };
    const from = read("time-from");
    const to = read("time-to");
    if (from === null || to === null) {
      $("time-hint").textContent = "Use yyyy/mm/dd, yyyy/mm/dd hh:mm or yyyy/mm/dd hh:mm:ss (UTC).";
      $("time-hint").classList.add("error");
      return;
    }
    setTimeRange({ from: from ? from.from : t.first, to: to ? to.to : t.last });
  };
  $("btn-time-apply").addEventListener("click", apply);
  ["time-from", "time-to"].forEach((id) => $(id).addEventListener("keydown", (e) => { if (e.key === "Enter") apply(); }));
  $("btn-time-clear").addEventListener("click", () => {
    ["time-from", "time-to"].forEach((id) => { $(id).value = ""; $(id).removeAttribute("aria-invalid"); });
    setTimeRange(null);
  });
  $("btn-time-zoom").addEventListener("click", () => {
    const t = state.time;
    if (!t.range) return;
    // Fit the chart to the events actually inside the range (bins are wide on sparse data)
    let lo = Infinity, hi = -Infinity;
    state.graph.forEachNode((id, a) => {
      if (a.isEvent && a.tMin >= t.range.from && a.tMin <= t.range.to) { lo = Math.min(lo, a.tMin); hi = Math.max(hi, a.tMin); }
    });
    t.domain = Number.isFinite(lo) ? paddedSpan(lo, hi) : { ...t.range };
    renderTime();
  });
  $("btn-time-full").addEventListener("click", () => {
    state.time.domain = { ...state.time.extent };
    renderTime();
  });
}

// ---------------------------------------------------------------------------
// Inspector
// ---------------------------------------------------------------------------
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function parseJSON(value) {
  if (typeof value !== "string" || !/^[[{]/.test(value.trim())) return null;
  try { return JSON.parse(value); } catch (_) { return null; }
}

function formatTime(value) {
  if (!value) return "";
  return String(value).replace("T", " ").replace(/\.0+(?=[+-]|Z|$)/, "").replace("+00:00", " UTC");
}

function valueCell(value) {
  const parsed = parseJSON(value);
  if (parsed !== null || Array.isArray(value) || (value && typeof value === "object")) {
    return el("pre", null, JSON.stringify(parsed ?? value, null, 2));
  }
  return document.createTextNode(String(value));
}

function fieldName(key) {
  const text = key.replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function facts(rows) {
  const dl = el("dl", "facts");
  for (const [term, value] of rows) {
    if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) continue;
    dl.append(el("dt", null, term));
    const dd = el("dd");
    dd.textContent = Array.isArray(value) ? value.join(", ") : String(value);
    dl.append(dd);
  }
  return dl;
}

function evidence(title, text) {
  const wrap = el("div", "evidence");
  wrap.append(el("h3", null, title), el("pre", null, text));
  return wrap;
}

function allProperties(props) {
  const details = el("details", "all");
  details.append(el("summary", null, `All properties (${Object.keys(props).length})`));
  const table = document.createElement("table");
  for (const key of Object.keys(props).sort()) {
    const tr = document.createElement("tr");
    const td = el("td");
    td.append(valueCell(props[key]));
    tr.append(el("th", null, key), td);
    table.append(tr);
  }
  details.append(table);
  return details;
}

function kindLine(a) {
  const line = el("p", "kind");
  const sw = el("span", "swatch");
  sw.style.background = a.color;
  let text = a.labels.filter((l) => l !== "Detected" && l !== "Event").join(", ") || a.nodeLabel;
  if (a.isEvent) text += a.detected ? ", detected by SigmaDFT" : ", not detected by SigmaDFT";
  line.append(sw, document.createTextNode(text));
  return line;
}

// Raw Plaso columns and bookkeeping fields: shown under "All properties" only
const RAW_FIELDS = new Set(["datetime", "timestamp", "timestamp_desc", "source", "source_long", "message", "parser",
  "display_name", "tag", "event_id", "log_file", "log_type", "pattern", "decoded_payload",
  "sigmadft_type", "sigmadft_category", "sigmadft_description", "sigmadft_type_candidate"]);

function eventSummary(a) {
  const p = a.props;
  const extracted = Object.keys(p).filter((k) => !RAW_FIELDS.has(k)).sort()
    .map((k) => [fieldName(k), p[k]]);
  const parts = [facts([
    ["Time", formatTime(p.datetime)],
    ["SigmaDFT", p.sigmadft_type],
    ["Category", p.sigmadft_category],
    ["Log", [p.log_type, p.pattern].filter(Boolean).join(", ")],
    ["File", p.log_file],
    ...extracted,
  ]), evidence("Log message", p.message ?? "")];
  if (p.decoded_payload) parts.push(evidence("Decoded payload", p.decoded_payload));
  return parts;
}

function hleSummary(a) {
  const p = a.props;
  const parts = [];
  const range = p.date_time_min === p.date_time_max
    ? formatTime(p.date_time_min) : `${formatTime(p.date_time_min)} to ${formatTime(p.date_time_max)}`;
  parts.push(facts([
    ["Time", range],
    ["Events", `${p.count}: ${(p.ids || []).join(", ")}`],
    ["Category", p.category],
    ["Actors", p.actor_count],
  ]));
  if (p.description) {
    const block = el("div", "block");
    const text = el("p", null, p.description);
    text.style.margin = "0";
    block.append(el("h3", null, "Description"), text);
    parts.push(block);
  }
  const actors = parseJSON(p.actor_details) || [];
  if (actors.length) {
    const block = el("div", "block");
    const table = el("table", "actors");
    const head = document.createElement("tr");
    ["Actor", "Events", "First seen", "Last seen"].forEach((h) => head.append(el("th", null, h)));
    table.append(head);
    for (const x of actors) {
      const tr = document.createElement("tr");
      tr.append(el("td", null, `${x.kind === "ip" ? "IP" : "User"} ${x.value}`),
        el("td", null, x.event_ids.join(", ")),
        el("td", null, formatTime(x.first_seen).slice(11)),
        el("td", null, formatTime(x.last_seen).slice(11)));
      table.append(tr);
    }
    block.append(el("h3", null, "Actors"), table);
    parts.push(block);
  }
  const keys = parseJSON(p.keys) || {};
  if (Object.keys(keys).length) {
    const block = el("div", "block");
    block.append(el("h3", null, "Keys"), facts(Object.entries(keys).map(([k, v]) => [k.replace(/_/g, " "), v])));
    parts.push(block);
  }
  if (p.evidence_message) parts.push(evidence("First event message", p.evidence_message));
  return parts;
}

function entitySummary(id) {
  // Events directly linked to the entity and the high-level events containing them
  const g = state.graph;
  const events = new Set();
  g.forEachNeighbor(id, (n, na) => { if (na.isEvent) events.add(n); });
  const hles = new Set();
  events.forEach((e) => g.forEachInNeighbor(e, (n, na) => { if (na.nodeLabel === "HighLevelEvent") hles.add(n); }));
  const times = [...events].map((e) => g.getNodeAttribute(e, "props").datetime).filter(Boolean).sort();
  return [facts([
    ["Events", events.size],
    ["High-level events", hles.size],
    ["First seen", formatTime(times[0])],
    ["Last seen", formatTime(times[times.length - 1])],
  ])];
}

function openInspector(open) {
  $("inspector").hidden = !open;
  $("layout").classList.toggle("has-inspector", open);
}

function renderDetails() {
  const body = $("details-body");
  const sel = state.selected;
  const g = state.graph;
  if (!sel || !g || (sel.kind === "node" ? !g.hasNode(sel.id) : !g.hasEdge(sel.id))) {
    body.replaceChildren();
    openInspector(false);
    return;
  }
  const parts = [];
  if (sel.kind === "node") {
    const a = g.getNodeAttributes(sel.id);
    parts.push(kindLine(a), el("h2", "title", fullCaption(a.labels, a.props)));
    if (a.fixed) parts.push(el("p", "pinned", "Pinned where you dragged it. Double-click the node to release it."));
    if (a.nodeLabel === "HighLevelEvent") parts.push(...hleSummary(a));
    else if (a.isEvent) parts.push(...eventSummary(a));
    else parts.push(...entitySummary(sel.id));
    parts.push(allProperties(a.props), neighborList(sel.id));
  } else {
    const a = g.getEdgeAttributes(sel.id);
    const ends = el("div", "neighbors");
    const ul = document.createElement("ul");
    ul.append(nodeLink(g.source(sel.id), "From"), nodeLink(g.target(sel.id), "To"));
    ends.append(ul);
    parts.push(el("p", "kind", "Relationship"), el("h2", "title", a.relType), ends);
    if (Object.keys(a.props).length) parts.push(allProperties(a.props));
  }
  body.replaceChildren(...parts);
  openInspector(true);
}

function nodeLink(id, prefix) {
  const a = state.graph.getNodeAttributes(id);
  const li = el("li", "node-link");
  const sw = el("span", "swatch");
  sw.style.background = a.color;
  li.append(sw, el("span", "text", `${prefix ? prefix + ": " : ""}${a.label}`));
  li.title = `${a.nodeLabel}: ${a.label}`;
  li.addEventListener("click", () => selectNode(id));
  return li;
}

function neighborList(id) {
  const g = state.graph;
  const groups = new Map();
  const add = (key, other) => {
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(other);
  };
  g.forEachOutEdge(id, (_, a, s, t) => add(`${a.relType} (outgoing)`, t));
  g.forEachInEdge(id, (_, a, s) => add(`${a.relType} (incoming)`, s));
  const wrap = el("div", "neighbors");
  for (const [key, ids] of [...groups.entries()].sort()) {
    const ul = document.createElement("ul");
    ids.slice(0, 200).forEach((other) => ul.append(nodeLink(other)));
    if (ids.length > 200) ul.append(el("li", "more", `${ids.length - 200} more not listed`));
    wrap.append(el("h3", null, `${key}, ${ids.length}`), ul);
  }
  return wrap;
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------
function runSearch() {
  const q = $("search").value.trim().toLowerCase();
  const list = $("search-results");
  if (!q || !state.graph) { list.hidden = true; return; }
  const hits = [];
  state.graph.forEachNode((id, a) => {
    if (hits.length >= 50) return;
    const text = `${a.label} ${Object.values(a.props).join(" ")}`.toLowerCase();
    if (text.includes(q)) hits.push(id);
  });
  list.replaceChildren(...(hits.length ? hits.map((id) => {
    const li = nodeLink(id);
    li.addEventListener("click", () => { list.hidden = true; });
    return li;
  }) : [el("li", "more", `No node matches "${$("search").value.trim()}"`)]));
  list.hidden = false;
}

// ---------------------------------------------------------------------------
// Cypher
// ---------------------------------------------------------------------------
async function runCypher() {
  const out = $("cypher-result");
  const query = $("cypher").value.trim();
  if (!query || !state.db) return;
  setStatus("Running query…");
  try {
    const res = await api("/api/cypher", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ db: state.db, query }),
    });
    state.lastResult = res;
    $("btn-show-result").disabled = res.nodes.length === 0;
    out.replaceChildren(resultTable(res));
    setStatus(`${res.rows.length} rows${res.truncated ? " (truncated)" : ""}, ${res.nodes.length} nodes, ${res.edges.length} relationships`);
  } catch (err) {
    state.lastResult = null;
    $("btn-show-result").disabled = true;
    const p = document.createElement("p");
    p.className = "error";
    p.textContent = err.message;
    out.replaceChildren(p);
    setStatus("Query failed", true);
  }
}

function resultTable(res) {
  const byId = new Map(res.nodes.map((n) => [n.id, n]));
  const table = document.createElement("table");
  const head = document.createElement("tr");
  res.columns.forEach((c) => head.append(Object.assign(document.createElement("th"), { textContent: c })));
  table.append(head);
  const cell = (v) => {
    if (v && typeof v === "object" && "node" in v) {
      const n = byId.get(v.node);
      const span = document.createElement("span");
      span.className = "ref";
      span.textContent = n ? caption(n.labels, n.props) : v.node;
      span.addEventListener("click", () => {
        if (state.graph && state.graph.hasNode(v.node)) selectNode(v.node);
      });
      return span;
    }
    if (v && typeof v === "object" && "relationship" in v) return document.createTextNode(`[:${v.type}]`);
    if (v && typeof v === "object" && "path" in v) return document.createTextNode(`path (${v.path} rels)`);
    return document.createTextNode(typeof v === "object" && v !== null ? JSON.stringify(v) : String(v));
  };
  res.rows.forEach((row) => {
    const tr = document.createElement("tr");
    row.forEach((v) => {
      const td = document.createElement("td");
      td.append(cell(v));
      td.title = td.textContent;
      tr.append(td);
    });
    table.append(tr);
  });
  return table;
}

function showResultAsGraph() {
  const res = state.lastResult;
  if (!res || res.nodes.length === 0) return;
  state.view = "query";
  buildGraph(res);
  $("view-banner-text").textContent = `Query result: ${res.nodes.length} nodes, ${res.edges.length} relationships`;
  $("view-banner").hidden = false;
}

function backToFull() {
  state.view = "full";
  $("view-banner").hidden = true;
  if (state.fullData) buildGraph(state.fullData);
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------
async function loadDatabases({ pick = true } = {}) {
  const sel = $("db-select");
  let dbs;
  try {
    dbs = await api("/api/databases");
  } catch (err) {
    sel.replaceChildren();
    throw err;
  }
  const placeholder = Object.assign(document.createElement("option"), { value: "", textContent: "Choose a case…", disabled: true });
  sel.replaceChildren(placeholder, ...dbs.map((d) => Object.assign(document.createElement("option"), { value: d, textContent: d })));
  sel.value = state.db && dbs.includes(state.db) ? state.db : "";
  if (dbs.length === 0) setStatus(`No '${state.dbPrefix}*' database yet. Make one with New case.`);
  // No case is loaded until the user picks one (a large case takes a while to load)
  if (pick) openCasePicker(dbs);
  return dbs;
}

// ---------------------------------------------------------------------------
// Case picker: shown when the app opens and after reconnecting to Neo4j
// ---------------------------------------------------------------------------
function openCasePicker(dbs) {
  const saved = localStorage.getItem("graph2web.db");
  const chosen = dbs.includes(state.db) ? state.db : dbs.includes(saved) ? saved : dbs[0];
  const list = $("case-list");
  $("btn-case-open").disabled = dbs.length === 0;
  if (dbs.length === 0) {
    list.replaceChildren(list.querySelector("legend"), el("p", "empty", "No case yet. Upload a Plaso timeline CSV with New case."));
    $("case-dialog").showModal();
    $("btn-case-new").focus();
    return;
  }
  list.replaceChildren(list.querySelector("legend"), ...dbs.map((db) => {
    const label = el("label");
    const radio = Object.assign(document.createElement("input"), { type: "radio", name: "case", value: db, checked: db === chosen });
    const sub = el("span", "case-sub", db === saved ? "Last opened · counting…" : "Counting…");
    label.append(radio, el("span", "case-name", db), sub);
    // Size of each case, so a large one is not opened by surprise
    api(`/api/stats?db=${encodeURIComponent(db)}`).then((s) => {
      const n = (k) => (s.labels[k] || 0).toLocaleString();
      sub.textContent = `${db === saved ? "Last opened · " : ""}${n("Event")} events, ${n("HighLevelEvent")} high-level events`;
    }).catch(() => { sub.textContent = db === saved ? "Last opened" : ""; });
    radio.addEventListener("dblclick", () => $("case-form").requestSubmit());
    label.addEventListener("dblclick", () => $("case-form").requestSubmit());
    return label;
  }));
  $("case-dialog").showModal();
  const checked = list.querySelector("input:checked");
  if (checked) checked.focus();
}

function bindCasePicker() {
  const dialog = $("case-dialog");
  $("case-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const picked = $("case-list").querySelector("input:checked");
    if (!picked) return;
    dialog.close();
    $("db-select").value = picked.value;
    loadGraph();
  });
  $("btn-case-cancel").addEventListener("click", () => dialog.close());
  $("btn-case-new").addEventListener("click", () => { dialog.close(); openNewCase(); });
  dialog.addEventListener("click", (e) => { if (e.target === dialog) dialog.close(); });
  dialog.addEventListener("close", () => {
    if (!state.db) setStatus("No case open. Choose one from Case in the top bar.");
  });
}

// ---------------------------------------------------------------------------
// Settings > Database: Neo4j connection dialog
// ---------------------------------------------------------------------------
function connectionLabel(c) {
  let host = c.uri;
  try { host = new URL(c.uri).host || c.uri; } catch (_) { /* keep the raw URI */ }
  return `${c.user}@${host}`;
}

async function refreshConnectionLabel() {
  try {
    const c = await api("/api/connection");
    $("settings-db-sub").textContent = connectionLabel(c);
    $("btn-settings-db").title = `Neo4j connection: ${c.uri} as ${c.user}`;
    return c;
  } catch (_) { return null; }
}

function dbResult(text, kind = "") {
  $("db-result").textContent = text;
  $("db-result").className = `db-result ${kind}`;
}

function dbFormValues() {
  const uri = $("db-uri").value.trim(), user = $("db-user").value.trim();
  $("db-uri").setAttribute("aria-invalid", String(!uri));
  $("db-user").setAttribute("aria-invalid", String(!user));
  if (!uri || !user) { dbResult("URI and username are required.", "error"); return null; }
  return { uri, user, password: $("db-pass").value || null };
}

function dbBusy(busy) {
  ["btn-db-test", "btn-db-save", "btn-db-cancel"].forEach((id) => { $(id).disabled = busy; });
}

function dbFound(dbs) {
  return dbs.length
    ? `${dbs.length} '${state.dbPrefix}*' database${dbs.length > 1 ? "s" : ""}: ${dbs.join(", ")}`
    : `no '${state.dbPrefix}*' database on this server`;
}

async function openDbSettings() {
  const c = await refreshConnectionLabel();
  $("db-uri").value = c ? c.uri : "";
  $("db-user").value = c ? c.user : "";
  $("db-pass").value = "";
  ["db-uri", "db-user"].forEach((id) => $(id).removeAttribute("aria-invalid"));
  dbResult(c ? "" : "Cannot read the current settings from the backend.", c ? "" : "error");
  dbBusy(false);
  $("db-dialog").showModal();
  $("db-uri").focus();
}

async function submitDbSettings(apply) {
  const body = dbFormValues();
  if (!body) return;
  dbBusy(true);
  dbResult(apply ? "Connecting…" : "Testing…");
  try {
    const res = await api(apply ? "/api/connection" : "/api/connection/test", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    if (!apply) { dbResult(`Connected: ${dbFound(res.databases)}.`, "ok"); return; }
    $("db-dialog").close();
    await refreshConnectionLabel();
    setStatus(`Connected to ${body.uri}: ${dbFound(res.databases)}`);
    await loadDatabases();
  } catch (err) {
    dbResult(err.message, "error");
  } finally {
    dbBusy(false);
    $("db-pass").value = "";
  }
}

function bindDbSettings() {
  $("btn-settings-db").addEventListener("click", openDbSettings);
  $("btn-db-cancel").addEventListener("click", () => $("db-dialog").close());
  $("btn-db-test").addEventListener("click", () => submitDbSettings(false));
  $("db-form").addEventListener("submit", (e) => { e.preventDefault(); submitDbSettings(true); });
  // Click on the backdrop (outside the form) closes the dialog
  $("db-dialog").addEventListener("click", (e) => { if (e.target === $("db-dialog")) $("db-dialog").close(); });
}

async function loadGraph() {
  if (!$("db-select").value) return;
  state.db = $("db-select").value;
  localStorage.setItem("graph2web.db", state.db);
  setStatus(`Loading ${state.db}…`);
  // A newer load (another case picked meanwhile) cancels this one
  if (state.loadAbort) state.loadAbort.abort();
  const abort = state.loadAbort = new AbortController();
  stopLayout();
  loader.loading = true;
  setLoaderSteps(LOAD_STEPS);
  showLoader(0, `Querying ${state.db}…`);
  loadCaseInfo();
  await document.fonts.ready;
  const t0 = performance.now();
  try {
    const data = await fetchGraph(state.db, abort.signal);
    showLoader(2, `Building graph: ${data.nodes.length.toLocaleString()} nodes…`);
    await nextPaint();
    if (abort.signal.aborted) return;
    state.fullData = data;
    // A (re)loaded database starts without a time filter
    state.time.range = null;
    $("time-from").value = "";
    $("time-to").value = "";
    state.view = "full";
    $("view-banner").hidden = true;
    buildGraph(state.fullData);
    setStatus(`${state.db}: ${state.fullData.nodes.length.toLocaleString()} nodes, `
      + `${state.fullData.edges.length.toLocaleString()} relationships `
      + `(${Math.round(performance.now() - t0)} ms)`);
  } catch (err) {
    if (abort.signal.aborted) return;   // replaced by a newer load
    hideLoader();
    setStatus(`Failed to load: ${err.message}`, true);
  }
}

// GET /api/graph with download progress (the response carries Content-Length)
async function fetchGraph(db, signal) {
  const res = await fetch(`/api/graph?db=${encodeURIComponent(db)}`, { signal });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) { /* not JSON */ }
    throw new Error(detail);
  }
  const total = Number(res.headers.get("content-length")) || 0;
  const reader = res.body.getReader();
  const chunks = [];
  let received = 0;
  showLoader(1, "Downloading…", total ? 0 : null);
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    showLoader(1, `Downloading ${megabytes(received)}${total ? ` of ${megabytes(total)}` : ""}`, total ? received / total : null);
  }
  showLoader(2, "Reading data…");
  await nextPaint();
  return JSON.parse(await new Blob(chunks).text());
}

// ---------------------------------------------------------------------------
// Case pipeline: New case (upload -> graph), Analysis (anomaly detection ->
// event reconstruction) and Export. Each step is a background job on the
// server; the loader shows its steps and progress.
// ---------------------------------------------------------------------------
const PLASO_HEADER = "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag";
const JOB_NAMES = { import: "Import", detect: "Anomaly detection", reconstruct: "Event reconstruction" };
const RULE_NAMES = { all: "all rules", atlas: "atlas rules", sigma: "Sigma rules" };
const STAGE_NAMES = { imported: "graph only", detected: "detected", reconstructed: "reconstructed" };
const caseState = { info: null, loaded: false, error: "", busy: false };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Same rule as graph2web/cases.py case_slug (file name and database name)
function caseSlug(name) {
  return name.trim().replace(/\.csv$/i, "").toLowerCase().replace(/[^a-z0-9.]+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "").replace(/-{2,}/g, "-").slice(0, 54).replace(/[-.]+$/, "");
}

function shortTime(iso) {
  return iso ? `${iso.slice(0, 16).replace("T", " ").replace(/-/g, "/")} UTC` : "";
}

async function loadCaseInfo() {
  // Keep showing the same case while it refreshes; clear only when the case changes
  if (!caseState.info || caseState.info.name !== state.db) {
    caseState.info = null;
    caseState.loaded = false;
  }
  caseState.error = "";
  renderCase();
  if (!state.db) return;
  const db = state.db;
  try {
    const res = await api(`/api/case?db=${encodeURIComponent(db)}`);
    if (db !== state.db) return;
    caseState.info = res.case;
    caseState.loaded = true;
    renderCase();
    // A job that was still running when the page was (re)opened
    if (res.job && !caseState.busy) followJob(res.job, { onDone: () => reloadAfterJob(db) });
  } catch (err) {
    if (db !== state.db) return;
    caseState.error = `Case details unavailable: ${err.message}`;
    renderCase();
  }
}

function renderCase() {
  const info = caseState.info;
  const open = Boolean(state.db);
  $("case-empty").hidden = open;
  $("case-body").hidden = !open;
  $("btn-new-case").disabled = caseState.busy;
  $("analysis-total").textContent = info ? STAGE_NAMES[info.stage] || "" : "";
  if (!open) return;

  const err = $("case-error");
  const facts = $("case-facts");
  if (!info) {
    facts.replaceChildren();
    const missing = caseState.loaded && !caseState.error;
    err.hidden = !(missing || caseState.error);
    err.textContent = caseState.error || (missing
      ? "This case has no analysis metadata yet. Import it again (New case, or log2graph) to analyse it here."
      : "");
  } else {
    err.hidden = !caseState.error;
    err.textContent = caseState.error;
    const file = info.source_csv.split(/[\\/]/).pop();
    const rows = [["File", file, info.source_csv], ["Log lines", Number(info.rows).toLocaleString()],
      ["Decode", info.decode ? "yes" : "no"], ["Imported", shortTime(info.imported_at)]];
    facts.replaceChildren(...rows.flatMap(([k, v, title]) => {
      const dd = el("dd", "", v);
      if (title) dd.title = title;
      return [el("dt", "", k), dd];
    }));
  }

  const stage = info ? info.stage : null;
  const detected = stage === "detected" || stage === "reconstructed";
  const reconstructed = stage === "reconstructed";
  const disabled = caseState.busy || !info;
  $("step-detect").classList.toggle("done", detected);
  $("step-reconstruct").classList.toggle("done", reconstructed);
  $("step-reconstruct").classList.toggle("locked", !detected);
  if (info && info.rule_source && !caseState.busy) $("rule-source").value = info.rule_source;
  $("rule-source").disabled = disabled;
  $("btn-detect").disabled = disabled;
  $("btn-detect").textContent = detected ? "Run again" : "Run";
  $("btn-reconstruct").disabled = disabled || !detected;
  $("btn-reconstruct").textContent = reconstructed ? "Build again" : "Build high-level events";
  $("btn-export-json").disabled = disabled;
  $("btn-export-csv").disabled = disabled;

  $("detect-status").textContent = !info ? "" : detected
    ? `${Number(info.detected_events).toLocaleString()} events detected with ${RULE_NAMES[info.rule_source] || "unknown rules"}, `
      + `${shortTime(info.detected_at)}. Running again replaces this result and the high-level events.`
    : "Not run yet. Marks the log lines matched by SigmaDFT rules.";
  $("reconstruct-status").textContent = !info ? "" : reconstructed
    ? `${Number(info.hle_count).toLocaleString()} high-level events, ${shortTime(info.reconstructed_at)}.`
    : detected ? "Not run yet. Groups adjacent detected events of the same type." : "Needs anomaly detection first.";
  $("export-status").textContent = !info ? "" : reconstructed
    ? "High-level events, as the SigmaDFT _grouped output."
    : detected ? "Detected events, as the SigmaDFT output."
    : `All ${Number(info.rows).toLocaleString()} log lines; analysis fields are "-".`;
}

// Poll a job until it ends; prefix = loader steps shown before the job's own (e.g. Upload)
async function followJob(job, { prefix = [], onDone = null } = {}) {
  caseState.busy = true;
  renderCase();
  const name = JOB_NAMES[job.kind] || job.kind;
  while (job.status === "running") {
    setLoaderSteps([...prefix, ...job.steps]);
    showLoader(prefix.length + job.step, `${name}: ${job.text}`, job.progress);
    await sleep(500);
    try {
      job = await api(`/api/jobs/${job.id}`);
    } catch (err) {
      job = { ...job, status: "error", error: err.message };
    }
  }
  caseState.busy = false;
  if (job.status === "done") {
    setLoaderSteps([...prefix, ...job.steps]);
    finishLoader(`${name}: ${job.text}`);
    const summary = `${job.db}: ${job.text} (${job.elapsed} s)`;
    setStatus(summary);
    if (onDone) await onDone(job);
    setStatus(summary);
  } else {
    hideLoader();
    caseState.error = `${name} failed: ${job.error}`;
    setStatus(caseState.error, true);
  }
  renderCase();
}

// After a step: reload the graph so :Detected rings / HLE nodes show up
async function reloadAfterJob(db) {
  if (state.db === db) await loadGraph();
}

async function runAnalysis(kind) {
  if (!state.db || caseState.busy) return;
  caseState.error = "";
  const db = state.db;
  try {
    const body = kind === "detect" ? JSON.stringify({ rule_source: $("rule-source").value }) : "{}";
    const res = await api(`/api/cases/${encodeURIComponent(db)}/${kind}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body,
    });
    await followJob(res.job, { onDone: () => reloadAfterJob(db) });
  } catch (err) {
    caseState.error = `${JOB_NAMES[kind]}: ${err.message}`;
    setStatus(caseState.error, true);
    renderCase();
  }
}

async function exportCase(format) {
  if (!state.db) return;
  try {
    const res = await fetch(`/api/export?db=${encodeURIComponent(state.db)}&format=${format}`);
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch (_) { /* not JSON */ }
      throw new Error(detail);
    }
    const match = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") || "");
    const url = URL.createObjectURL(await res.blob());
    const a = Object.assign(document.createElement("a"), { href: url, download: match ? match[1] : `${state.db}.${format}` });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    setStatus(`Exported ${a.download}`);
  } catch (err) {
    setStatus(`Export failed: ${err.message}`, true);
  }
}

// --- New case dialog --------------------------------------------------------
function ncResult(text, kind = "") {
  $("nc-result").textContent = text;
  $("nc-result").className = `db-result ${kind}`;
}

function ncTarget() {
  const slug = caseSlug($("nc-name").value);
  $("nc-target").replaceChildren(...(slug
    ? ["Database ", el("strong", "", `${state.dbPrefix}${slug}`), ", file ", el("strong", "", `dataset/uploads/${slug}.csv`)]
    : []));
  return slug;
}

function ncBusy(busy) {
  ["nc-file", "nc-name", "nc-decode", "btn-nc-submit"].forEach((id) => { $(id).disabled = busy; });
}

function openNewCase() {
  if (caseState.busy) return;
  $("new-case-form").reset();
  ["nc-file", "nc-name"].forEach((id) => $(id).removeAttribute("aria-invalid"));
  ncTarget();
  ncResult("");
  ncBusy(false);
  $("new-case-dialog").showModal();
  $("nc-file").focus();
}

// The raw file is the request body (no multipart), so the upload shows real progress
function uploadCase(file, name, decode) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/cases?name=${encodeURIComponent(name)}&decode=${decode}`);
    xhr.setRequestHeader("Content-Type", "text/csv");
    xhr.upload.onprogress = (e) => showLoader(0, `Uploading ${megabytes(e.loaded)}${e.lengthComputable ? ` of ${megabytes(e.total)}` : ""}`,
      e.lengthComputable ? e.loaded / e.total : null);
    xhr.onload = () => {
      let body = null;
      try { body = JSON.parse(xhr.responseText); } catch (_) { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body);
      else reject(new Error((body && body.detail) || xhr.statusText || `HTTP ${xhr.status}`));
    };
    xhr.onerror = () => reject(new Error("Upload failed: the server could not be reached."));
    xhr.send(file);
  });
}

async function submitNewCase() {
  const file = $("nc-file").files[0];
  const slug = ncTarget();
  $("nc-file").setAttribute("aria-invalid", String(!file));
  $("nc-name").setAttribute("aria-invalid", String(!slug));
  if (!file) { ncResult("Choose a timeline CSV file.", "error"); return; }
  if (!slug) { ncResult("Give the case a name with at least one letter or digit.", "error"); return; }
  // Check the header before sending a large file
  const head = (await file.slice(0, 4096).text()).replace(/^﻿/, "").split(/\r?\n/)[0].trim();
  if (head !== PLASO_HEADER) {
    $("nc-file").setAttribute("aria-invalid", "true");
    ncResult(`Not a Plaso timeline CSV. The first line must be: ${PLASO_HEADER}`, "error");
    return;
  }
  ncBusy(true);
  ncResult(`Uploading ${megabytes(file.size)}…`);
  caseState.busy = true;
  renderCase();
  const prefix = ["Upload"];
  setLoaderSteps([...prefix, "Create database", "Read log", "Write graph"]);
  showLoader(0, "Uploading…", 0);
  let res;
  try {
    res = await uploadCase(file, $("nc-name").value, $("nc-decode").checked);
  } catch (err) {
    caseState.busy = false;
    hideLoader();
    renderCase();
    ncBusy(false);
    ncResult(err.message, "error");
    return;
  }
  $("new-case-dialog").close();
  await followJob(res.job, {
    prefix,
    onDone: async () => {
      await loadDatabases({ pick: false });
      $("db-select").value = res.db;
      await loadGraph();
    },
  });
}

function bindNewCase() {
  $("btn-new-case").addEventListener("click", openNewCase);
  $("nc-file").addEventListener("change", () => {
    const file = $("nc-file").files[0];
    $("nc-file").removeAttribute("aria-invalid");
    if (file && !$("nc-name").value) $("nc-name").value = caseSlug(file.name);
    ncTarget();
    ncResult(file ? `${file.name}, ${megabytes(file.size)}` : "");
  });
  $("nc-name").addEventListener("input", () => { $("nc-name").removeAttribute("aria-invalid"); ncTarget(); });
  $("new-case-form").addEventListener("submit", (e) => { e.preventDefault(); submitNewCase(); });
  $("btn-nc-cancel").addEventListener("click", () => $("new-case-dialog").close());
  $("new-case-dialog").addEventListener("click", (e) => { if (e.target === $("new-case-dialog")) $("new-case-dialog").close(); });
  $("btn-detect").addEventListener("click", () => runAnalysis("detect"));
  $("btn-reconstruct").addEventListener("click", () => runAnalysis("reconstruct"));
  $("btn-export-json").addEventListener("click", () => exportCase("json"));
  $("btn-export-csv").addEventListener("click", () => exportCase("csv"));
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
function setColorMode(mode) {
  state.colorMode = mode;
  document.querySelectorAll("#color-mode button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.mode === mode)));
  if (!state.graph) return;
  applyColors();
  renderFilters();
  renderDetails();
  refresh();
}

// Light (default) or dark. CSS follows <html data-theme>; the WebGL graph is
// recolored from THEMES without touching the layout.
function applyTheme(name) {
  if (!(name in THEMES)) name = "light";
  T = THEMES[name];
  document.documentElement.dataset.theme = name;
  localStorage.setItem("graph2web.theme", name);
  document.querySelectorAll("#theme-mode button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.theme === name)));
  if (!state.graph) return;
  state.graph.forEachNode((id) => state.graph.setNodeAttribute(id, "borderColor", T.ring));
  applyColors();
  if (state.renderer) {
    state.renderer.setSetting("labelColor", { color: T.label });
    state.renderer.setSetting("edgeLabelColor", { color: T.edgeLabel });
  }
  renderFilters();
  renderDetails();
  refresh();
}

function toggleDrawer(open) {
  const panel = $("cypher-panel");
  const willOpen = open ?? panel.classList.contains("collapsed");
  panel.classList.toggle("collapsed", !willOpen);
  $("btn-toggle-cypher").setAttribute("aria-expanded", String(willOpen));
  if (willOpen) $("cypher").focus();
}

function clearSelection() {
  state.selected = null;
  updateNeighbors();
  renderDetails();
  refresh();
}

function init() {
  $("db-select").addEventListener("change", loadGraph);
  $("btn-reload").addEventListener("click", loadGraph);
  $("btn-layout").addEventListener("click", () => (state.layout ? stopLayout() : startLayout()));
  $("btn-fit").addEventListener("click", () => state.renderer && state.renderer.getCamera().animatedReset());
  document.querySelectorAll("#color-mode button").forEach((btn) => btn.addEventListener("click", () => setColorMode(btn.dataset.mode)));
  document.querySelectorAll("#theme-mode button").forEach((btn) => btn.addEventListener("click", () => applyTheme(btn.dataset.theme)));
  applyTheme(document.documentElement.dataset.theme);
  $("btn-sidebar").addEventListener("click", (e) => {
    const hidden = $("layout").classList.toggle("no-sidebar");
    e.currentTarget.setAttribute("aria-pressed", String(!hidden));
  });
  $("btn-close-inspector").addEventListener("click", clearSelection);
  bindTimeControls();
  bindDbSettings();
  bindCasePicker();
  bindNewCase();
  renderCase();
  // Collapsible sidebar sections: each header opens/closes the panel it controls
  document.querySelectorAll("#sidebar .section-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const panel = $(btn.getAttribute("aria-controls"));
      const open = panel.hidden;
      panel.hidden = !open;
      btn.setAttribute("aria-expanded", String(open));
    });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "k" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); toggleDrawer(); return; }
    if ($("db-dialog").open || $("case-dialog").open || $("new-case-dialog").open) return; // dialogs handle their own Esc
    const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName);
    if (e.key === "Escape" && !typing) clearSelection();
  });
  $("opt-labels").addEventListener("change", (e) => state.renderer && state.renderer.setSetting("renderLabels", e.target.checked));
  $("opt-edge-labels").addEventListener("change", refresh);
  // Display sliders, remembered between visits
  for (const [id, key] of [["opt-node-size", "graph2web.nodeSize"], ["opt-spacing", "graph2web.spacing"]]) {
    const saved = localStorage.getItem(key);
    if (saved !== null) $(id).value = saved;
    $(id).addEventListener("change", () => localStorage.setItem(key, $(id).value));
  }
  showDisplayValues();
  $("opt-node-size").addEventListener("input", () => {
    showDisplayValues();
    if (state.graph) { applySizes(); refresh(); }
  });
  $("opt-spacing").addEventListener("input", showDisplayValues);
  $("opt-spacing").addEventListener("change", () => {
    if (state.graph) startLayout(Math.min(2500 + state.graph.order * 4, 20000));
  });

  $("search").addEventListener("input", runSearch);
  $("search").addEventListener("keydown", (e) => {
    if (e.key === "Escape") $("search-results").hidden = true;
    if (e.key === "Enter") { const first = $("search-results").querySelector("li"); if (first) first.click(); }
  });
  document.addEventListener("click", (e) => { if (!$("search-box").contains(e.target)) $("search-results").hidden = true; });

  const ex = $("cypher-examples");
  EXAMPLES.forEach(([name, q]) => ex.append(Object.assign(document.createElement("option"), { value: q, textContent: name })));
  ex.addEventListener("change", () => { if (ex.value) $("cypher").value = ex.value; ex.value = ""; });
  $("btn-run").addEventListener("click", runCypher);
  $("cypher").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) runCypher(); });
  $("btn-show-result").addEventListener("click", showResultAsGraph);
  $("btn-back").addEventListener("click", backToFull);
  $("btn-toggle-cypher").addEventListener("click", () => toggleDrawer());

  // Keep the WebGL canvas in sync with its container (panels resize it)
  new ResizeObserver(() => {
    if (state.renderer) { state.renderer.resize(); state.renderer.refresh(); }
  }).observe($("graph"));

  refreshConnectionLabel().then((c) => { if (c) state.dbPrefix = c.database_prefix; });
  loadDatabases().catch((err) => setStatus(`${err.message}. Change it in Settings > Database.`, true));
}

init();
