// graph2web frontend: sigma.js (WebGL) + graphology, no build step.
/* global graphology, graphologyLibrary, Sigma */
"use strict";

// ---------------------------------------------------------------------------
// Visual encoding
// ---------------------------------------------------------------------------
// Categorical palette (dark mode, 8 fixed slots, validated with the dataviz
// validator against surface #1a1a19). Assigned in fixed order; labels beyond
// 8 fold into the neutral "other" gray, never a generated 9th hue.
const PALETTE = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"];
const OTHER = "#8a8984";
const DIM_NODE = "#3a3a37";
const DIM_EDGE = "#2b2b29";
const EDGE = "#55554f";
const RING = "#f0efec";
const SURFACE = [26, 26, 25];

// Primary label of a node = first of these it has (most specific first)
const LABEL_ORDER = ["HighLevelEvent", "HTTPRequest", "AuthEvent", "SystemEvent", "IPAddress",
                     "User", "Page", "UserAgent", "Service", "LogFile", "Event"];
const LABEL_COLOR = {
  HTTPRequest: PALETTE[0], AuthEvent: PALETTE[1], SystemEvent: PALETTE[2], IPAddress: PALETTE[3],
  User: PALETTE[4], Page: PALETTE[5], HighLevelEvent: PALETTE[6], UserAgent: PALETTE[7],
};
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
};

function setStatus(text, isError = false) {
  const el = $("status");
  el.textContent = text;
  el.classList.toggle("error", isError);
}

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
  const mixed = rgb.map((c, i) => Math.round(c * (1 - amount) + SURFACE[i] * amount));
  return `rgb(${mixed.join(",")})`;
}

function nodeColor(attrs) {
  let color;
  if (state.colorMode === "community") color = state.communityColor.get(attrs.community) || OTHER;
  else color = LABEL_COLOR[attrs.nodeLabel] || OTHER;
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
      size: Math.min(base + 1.6 * Math.log2(1 + deg), 22),
      type: a.isEvent && a.detected ? "border" : "circle",
      borderColor: RING,
    });
  });
  state.graph = graph;
  computeCommunities();
  applyColors();

  const big = graph.size > 20000;
  state.renderer = new Sigma(graph, $("graph"), {
    nodeProgramClasses: { border: NodeBorderProgram },
    defaultEdgeType: "arrow",
    renderEdgeLabels: true,
    renderLabels: $("opt-labels").checked,
    labelColor: { color: "#c3c2b7" },
    edgeLabelColor: { color: "#8f8e86" },
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
  context.strokeStyle = "#f0efec";
  context.lineWidth = 1.5;
  context.stroke();
  if (!label) return;
  context.fillStyle = "#212120";
  context.strokeStyle = "#4a4a47";
  context.lineWidth = 1;
  context.beginPath();
  context.roundRect(x, data.y - h / 2, textWidth + padX * 2, h, 4);
  context.fill();
  context.stroke();
  context.fillStyle = "#f0efec";
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
  state.communities.slice(0, PALETTE.length).forEach((c, i) => state.communityColor.set(c.id, PALETTE[i]));
}

function renderCommunityLegend() {
  const section = $("community-section");
  section.hidden = state.colorMode !== "community";
  if (section.hidden) return;
  const all = state.communities || [];
  const colored = all.slice(0, PALETTE.length);
  const rest = all.slice(PALETTE.length);
  $("community-total").textContent = all.length.toLocaleString();
  const items = colored.map((c, i) => {
    const hub = state.graph.getNodeAttributes(c.hub);
    const li = document.createElement("li");
    li.title = `Community ${i + 1}: click to select ${hub.label}`;
    const sw = Object.assign(document.createElement("span"), { className: "swatch" });
    sw.style.background = PALETTE[i];
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
    sw.style.background = OTHER;
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
  state.graph.forEachEdge((id) => state.graph.setEdgeAttribute(id, "color", EDGE));
}

// ---------------------------------------------------------------------------
// Reducers (filtering + highlight)
// ---------------------------------------------------------------------------
function nodeHidden(id) {
  return state.hiddenLabels.has(state.graph.getNodeAttribute(id, "nodeLabel"));
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
    res.color = DIM_NODE;
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
    res.color = RING; res.size = 2.5; res.forceLabel = true;
  } else if (focus && !touches) {
    res.color = DIM_EDGE; res.label = "";
  } else if (touches) {
    res.color = "#a9a89f"; res.size = 1.6;
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
function bindRendererEvents() {
  const r = state.renderer;
  r.on("enterNode", ({ node }) => { state.hovered = node; updateNeighbors(); refresh(); });
  r.on("leaveNode", () => { state.hovered = null; updateNeighbors(); refresh(); });
  r.on("clickNode", ({ node }) => selectNode(node, false));
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
function startLayout(autoStopMs) {
  stopLayout();
  const g = state.graph;
  if (!g || g.order < 2) return;
  const settings = graphologyLibrary.layoutForceAtlas2.inferSettings(g);
  settings.barnesHutOptimize = g.order > 2000;
  state.layout = new graphologyLibrary.FA2Layout(g, { settings });
  state.layout.start();
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
  if (state.layout) { state.layout.kill(); state.layout = null; }
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
    const swatch = state.colorMode === "label" ? (LABEL_COLOR[label] || OTHER) : "transparent";
    return filterItem(label, labelCounts.get(label), swatch, state.hiddenLabels, maxLabel);
  }));
  const hint = document.querySelector("#sidebar .hint");
  hint.textContent = `A ring marks events detected by SigmaDFT (${detected}); faded events were not detected.`
    + (state.colorMode === "community" ? " Colors show communities, listed below." : "");
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
async function loadDatabases() {
  const dbs = await api("/api/databases");
  const sel = $("db-select");
  sel.replaceChildren(...dbs.map((d) => Object.assign(document.createElement("option"), { value: d, textContent: d })));
  if (dbs.length === 0) { setStatus("No 'sigmadft-*' database found", true); return; }
  const saved = localStorage.getItem("graph2web.db");
  sel.value = dbs.includes(saved) ? saved : dbs[0];
  await loadGraph();
}

async function loadGraph() {
  state.db = $("db-select").value;
  localStorage.setItem("graph2web.db", state.db);
  setStatus(`Loading ${state.db}…`);
  await document.fonts.ready;
  const t0 = performance.now();
  try {
    state.fullData = await api(`/api/graph?db=${encodeURIComponent(state.db)}`);
    state.view = "full";
    $("view-banner").hidden = true;
    buildGraph(state.fullData);
    setStatus(`${state.db}: ${state.fullData.nodes.length.toLocaleString()} nodes, `
      + `${state.fullData.edges.length.toLocaleString()} relationships `
      + `(${Math.round(performance.now() - t0)} ms)`);
  } catch (err) {
    setStatus(`Failed to load: ${err.message}`, true);
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
function setColorMode(mode) {
  state.colorMode = mode;
  document.querySelectorAll(".seg button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.mode === mode)));
  if (!state.graph) return;
  applyColors();
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
  document.querySelectorAll(".seg button").forEach((btn) => btn.addEventListener("click", () => setColorMode(btn.dataset.mode)));
  $("btn-sidebar").addEventListener("click", (e) => {
    const hidden = $("layout").classList.toggle("no-sidebar");
    e.currentTarget.setAttribute("aria-pressed", String(!hidden));
  });
  $("btn-close-inspector").addEventListener("click", clearSelection);
  document.addEventListener("keydown", (e) => {
    if (e.key === "k" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); toggleDrawer(); return; }
    const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName);
    if (e.key === "Escape" && !typing) clearSelection();
  });
  $("opt-labels").addEventListener("change", (e) => state.renderer && state.renderer.setSetting("renderLabels", e.target.checked));
  $("opt-edge-labels").addEventListener("change", refresh);

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

  loadDatabases().catch((err) => setStatus(`Cannot reach backend: ${err.message}`, true));
}

init();
