/* Forensic Analysis UI — read-only consumer of analysis_ui_snapshot.v1 */

const MARK = {
  FACT: "F",
  INFERENCE: "I",
  CORRELATION: "C",
  UNKNOWN: "?",
  NOT_PROVEN: "NP",
  INPUT_MISSING: "IM",
  REJECTED: "R",
  COMPLETE: "OK",
  READY: "OK",
  AVAILABLE: "OK",
  NOT_EXECUTED: "NE",
  DYNAMIC_DISPATCH: "DD",
  PARTIAL: "P",
  EMPTY: "E",
  GUIDANCE: "G",
};

let SNAP = null;
let selected = null;

function badge(status) {
  const s = String(status || "UNKNOWN");
  const mark = MARK[s] || "·";
  return `<span class="badge ${cssEscape(s)}" title="${escapeHtml(s)}"><span class="mark">[${escapeHtml(mark)}]</span> ${escapeHtml(s)}</span>`;
}

function cssEscape(s) {
  return String(s).replace(/[^A-Za-z0-9_-]/g, "_");
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function showDetail(title, obj) {
  selected = obj;
  const el = document.getElementById("detail");
  const lines = [];
  lines.push(`<h2>${escapeHtml(title)}</h2>`);
  if (!obj) {
    el.innerHTML = lines.join("") + `<p class="empty">Select a node, edge, or status chip.</p>`;
    return;
  }
  if (obj.classification || obj.status) {
    lines.push(`<p>${badge(obj.classification || obj.status)}</p>`);
  }
  lines.push(`<dl class="kv">`);
  for (const [k, v] of Object.entries(obj)) {
    if (k === "details" && v && typeof v === "object") {
      for (const [dk, dv] of Object.entries(v)) {
        lines.push(`<dt>${escapeHtml(dk)}</dt><dd class="mono">${escapeHtml(fmt(dv))}</dd>`);
      }
      continue;
    }
    if (typeof v === "object" && v !== null) {
      lines.push(`<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(JSON.stringify(v))}</dd>`);
    } else {
      lines.push(`<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(fmt(v))}</dd>`);
    }
  }
  lines.push(`</dl>`);
  el.innerHTML = lines.join("");
}

function fmt(v) {
  if (v === null || v === undefined || v === "") return "—";
  return String(v);
}

function setView(name) {
  document.querySelectorAll("[data-view]").forEach((el) => {
    el.classList.toggle("hidden", el.getAttribute("data-view") !== name);
  });
  document.querySelectorAll("nav button").forEach((b) => {
    b.classList.toggle("active", b.dataset.nav === name);
  });
}

function renderOverview() {
  const apk = SNAP.apk || {};
  const st = SNAP.analysis_status || {};
  const c = SNAP.counters || {};
  document.getElementById("overview-apk").innerHTML = `
    <dl class="kv">
      <dt>Package</dt><dd>${escapeHtml(apk.package)}</dd>
      <dt>Version</dt><dd>${escapeHtml(apk.version_name)} ${apk.version_code != null ? `(${escapeHtml(apk.version_code)})` : ""}</dd>
      <dt>SHA256</dt><dd>${escapeHtml(apk.sha256)}</dd>
      <dt>File</dt><dd>${escapeHtml(apk.file)}</dd>
      <dt>Analyzer</dt><dd>${escapeHtml(apk.analyzer_version)}</dd>
      <dt>Analyzed</dt><dd>${escapeHtml(apk.analyzed_at_utc)}</dd>
      <dt>Commit</dt><dd>${escapeHtml(apk.git_commit)}</dd>
    </dl>`;
  document.getElementById("overview-status").innerHTML = Object.entries(st)
    .map(([k, v]) => `<div class="kv"><dt>${escapeHtml(k)}</dt><dd>${badge(v)}</dd></div>`)
    .join("");
  document.getElementById("overview-counters").innerHTML = `
    <table class="table">
      <tbody>
        ${row("RFCOMM targets", c.rfcomm_targets)}
        ${row("Evidence paths", c.evidence_paths)}
        ${row("Communication paths", c.communication_paths)}
        ${row("Structured values", c.structured_values)}
        ${row("V5 roundtrip candidates", c.v5_roundtrip_candidates)}
        ${row("Field loads", c.field_loads)}
        ${row("Decoder candidates", c.decoder_candidates)}
        ${row("Encoder candidates", c.encoder_candidates)}
      </tbody>
    </table>`;
  document.getElementById("overview-pipeline").innerHTML = (SNAP.pipeline_stages || [])
    .map((s, i, arr) => {
      const arrow = i < arr.length - 1 ? `<span class="pipe-arrow">→</span>` : "";
      return `<button class="pipe-node" data-stage="${escapeHtml(s.id)}"><div class="name">${escapeHtml(s.label)}</div>${badge(s.status)}</button>${arrow}`;
    })
    .join("");
  document.querySelectorAll("[data-stage]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const stage = (SNAP.pipeline_stages || []).find((x) => x.id === btn.dataset.stage);
      showDetail(stage?.label || "Stage", stage);
    });
  });
}

function row(label, value) {
  return `<tr><th>${escapeHtml(label)}</th><td class="mono">${escapeHtml(fmt(value))}</td></tr>`;
}

function renderPath() {
  const nodes = SNAP.nodes || [];
  const edges = SNAP.edges || [];
  if (!nodes.length) {
    document.getElementById("path-view").innerHTML = `<div class="card"><p class="empty">No focus path nodes in this snapshot (e.g. no structured values / no V001 forensic closure).</p></div>`;
    return;
  }
  // Prefer ordered chain for V001
  const order = [
    "n-accessory-read",
    "n-internalread",
    "n-readpacket",
    "n-packet-mdata",
    "n-decodeversion",
    "n-value-v001",
    "n-mversion",
  ];
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const main = order.filter((id) => byId[id]).map((id) => byId[id]);
  const branch = ["n-clamp", "n-branch", "n-single", "n-gating"].map((id) => byId[id]).filter(Boolean);
  let html = `<div class="card"><h3>Focus path ${escapeHtml(SNAP.focus_value_id || "")}</h3><div class="path">`;
  main.forEach((n, i) => {
    html += `<div class="node" data-node="${escapeHtml(n.id)}"><span>${escapeHtml(n.label)}</span>${badge(n.classification || n.limit || n.status)}</div>`;
    if (i < main.length - 1) html += `<div class="connector">│</div><div class="connector">▼</div>`;
  });
  if (branch.length) {
    html += `<div class="connector">│</div><div class="connector">├── branches</div>`;
    branch.forEach((n) => {
      html += `<div class="node" data-node="${escapeHtml(n.id)}" style="margin-left:1rem"><span>${escapeHtml(n.label)}</span>${badge(n.classification)}</div>`;
    });
  }
  html += `</div></div>`;
  html += `<div class="card"><h3>Edges</h3><table class="table"><thead><tr><th>From</th><th>To</th><th>Relation</th><th>Class</th></tr></thead><tbody>`;
  edges.forEach((e) => {
    const a = byId[e.from]?.label || e.from;
    const b = byId[e.to]?.label || e.to;
    html += `<tr class="edge-row" data-edge="${escapeHtml(e.id)}"><td>${escapeHtml(a)}</td><td>${escapeHtml(b)}</td><td class="mono">${escapeHtml(e.relation)}</td><td>${badge(e.classification)}${e.limit ? " " + badge(e.limit) : ""}</td></tr>`;
  });
  html += `</tbody></table></div>`;
  document.getElementById("path-view").innerHTML = html;
  document.querySelectorAll("[data-node]").forEach((el) => {
    el.addEventListener("click", () => {
      document.querySelectorAll(".path .node").forEach((n) => n.classList.remove("selected"));
      el.classList.add("selected");
      showDetail(byId[el.dataset.node]?.label, byId[el.dataset.node]);
    });
  });
  document.querySelectorAll("[data-edge]").forEach((el) => {
    el.addEventListener("click", () => {
      const e = edges.find((x) => x.id === el.dataset.edge);
      showDetail(`Edge ${e?.id}`, e);
    });
  });
}

function renderOpenEdges() {
  const list = SNAP.open_edges || [];
  let html = `<div class="card"><h3>Open edges / boundaries</h3>`;
  if (!list.length) {
    html += `<p class="empty">No open-edge records in snapshot.</p></div>`;
  } else {
    html += `<table class="table"><thead><tr><th>Status</th><th>From → To</th><th>Reason</th><th>Not to confuse with</th></tr></thead><tbody>`;
    list.forEach((oe) => {
      html += `<tr data-oe="${escapeHtml(oe.id)}"><td>${badge(oe.status || oe.label)}</td><td class="mono">${escapeHtml(oe.from)} → ${escapeHtml(oe.to)}</td><td>${escapeHtml(oe.reason)}</td><td class="mono">${escapeHtml((oe.not || []).join(", "))}</td></tr>`;
    });
    html += `</tbody></table></div>`;
  }
  document.getElementById("open-view").innerHTML = html;
  document.querySelectorAll("[data-oe]").forEach((el) => {
    el.addEventListener("click", () => {
      const oe = list.find((x) => x.id === el.dataset.oe);
      showDetail(oe?.label || "Open edge", oe);
    });
  });
}

function renderRuntimeWire() {
  const rw = SNAP.runtime_wire || {};
  const cg = SNAP.correlation_graph || {};
  document.getElementById("runtime-view").innerHTML = `
    <div class="card"><h3>STATIC → RUNTIME → WIRE → CORRELATION</h3>
      <div class="grid-3">
        <div><dt>STATIC</dt><dd>${badge(rw.STATIC)}</dd></div>
        <div><dt>RUNTIME</dt><dd>${badge(rw.RUNTIME)}</dd></div>
        <div><dt>WIRE</dt><dd>${badge(rw.WIRE)}</dd></div>
        <div><dt>SAME_SESSION</dt><dd>${badge(rw.SAME_SESSION)}</dd></div>
        <div><dt>CORRELATION</dt><dd>${badge(rw.CORRELATION)}</dd></div>
      </div>
      ${rw.wire_artefact ? `<p class="mono" style="margin-top:0.75rem">Wire artefact: ${escapeHtml(rw.wire_artefact)}</p>` : ""}
      ${rw.warning ? `<div class="warn">${escapeHtml(rw.warning)}</div>` : ""}
    </div>
    <div class="card"><h3>Session mismatch rule</h3>
      <p>If Runtime Session <strong>≠</strong> Wire Session → ${badge("REJECTED")}</p>
      <p class="mono">Reason: SAME_SESSION not established (not “NO MATCH”, not “PROTOCOL NOT FOUND”).</p>
      <pre class="mono">${escapeHtml(JSON.stringify(cg.session_mismatch_example || {}, null, 2))}</pre>
    </div>
    <div class="card"><h3>Correlation graph (from snapshot only)</h3>
      <p>FULL_CHAIN present: <strong>${cg.full_chain_present ? "yes" : "no"}</strong> ${badge(cg.same_session || "UNKNOWN")}</p>
      <table class="table"><thead><tr><th>Edge</th><th>Class</th><th>Facets</th><th>Note</th></tr></thead><tbody>
      ${(cg.edges || []).map((e) => `<tr><td class="mono">${escapeHtml(e.from)} → ${escapeHtml(e.to)}</td><td>${badge(e.classification)}</td><td class="mono">${escapeHtml((e.facets || []).join(", "))}</td><td>${escapeHtml(e.note || "")}</td></tr>`).join("")}
      </tbody></table>
    </div>`;
}

function renderKnowledge() {
  const k = SNAP.knowledge || {};
  const nx = SNAP.next_experiment || {};
  document.getElementById("knowledge-view").innerHTML = `
    <div class="grid-2">
      <div class="card"><h3>Proven Facts</h3><ul class="list-block">${(k.proven_facts || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("") || "<li class='empty'>—</li>"}</ul></div>
      <div class="card"><h3>Not Proven</h3><ul class="list-block">${(k.not_proven || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("") || "<li class='empty'>—</li>"}</ul></div>
    </div>
    <div class="card"><h3>Missing Input</h3><ul class="list-block">${(k.missing_input || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("") || "<li class='empty'>—</li>"}</ul></div>
    <div class="card"><h3>${escapeHtml(nx.title || "NEXT REQUIRED EXPERIMENT")}</h3>
      ${badge(nx.classification || "GUIDANCE")}
      <p>${escapeHtml(nx.summary || "")}</p>
      <p class="mono">Target: ${escapeHtml(nx.target || "—")}</p>
      <ul class="list-block">${(nx.required_evidence || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>
      <p class="empty">${escapeHtml(nx.note || "")}</p>
    </div>
    <div class="card"><h3>Closing assessment</h3>
      <table class="table"><tbody>
      ${Object.entries(SNAP.closing_assessment || {}).map(([k, v]) => `<tr><th>${escapeHtml(k)}</th><td>${badge(String(v).split(" ")[0])}<span class="mono"> ${escapeHtml(v)}</span></td></tr>`).join("")}
      </tbody></table>
    </div>`;
}

function renderTimeline() {
  const items = SNAP.timeline || [];
  document.getElementById("timeline-view").innerHTML = `
    <div class="card"><h3>Timeline (no synthetic runtime clocks)</h3>
      <div class="path">
        ${items.map((t, i) => `
          <div class="node" data-tl="${escapeHtml(t.id)}"><span>${escapeHtml(t.label)}</span>${badge(t.status)}</div>
          ${i < items.length - 1 ? `<div class="connector">▼</div>` : ""}
        `).join("")}
      </div>
    </div>`;
  document.querySelectorAll("[data-tl]").forEach((el) => {
    el.addEventListener("click", () => {
      const t = items.find((x) => x.id === el.dataset.tl);
      showDetail(t?.label, t);
    });
  });
}

function renderSources() {
  document.getElementById("sources-view").innerHTML = `
    <div class="card"><h3>Evidence sources (referenced only)</h3>
      <table class="table"><thead><tr><th>Role</th><th>Path</th><th>Present</th><th>SHA256 prefix</th></tr></thead>
      <tbody>
      ${(SNAP.sources || []).map((s) => `<tr><td>${escapeHtml(s.role)}</td><td class="mono">${escapeHtml(s.path)}</td><td>${s.present ? badge("FACT") : badge("INPUT_MISSING")}</td><td class="mono">${escapeHtml(s.sha256_prefix || "—")}</td></tr>`).join("")}
      </tbody></table>
      <p class="empty">content_sha256=${escapeHtml(SNAP.content_sha256 || "")}</p>
    </div>`;
}

function renderValues() {
  const values = SNAP.values || [];
  document.getElementById("values-view").innerHTML = `
    <div class="card"><h3>Structured values (neutral IDs)</h3>
      <p class="empty">semantic_label is always null in snapshot — names are not protocol meaning.</p>
      <table class="table"><thead><tr><th>ID</th><th>Class</th><th>API / Method</th><th>Field</th><th>Value class</th></tr></thead>
      <tbody>
      ${values.map((v) => `<tr data-val="${escapeHtml(v.value_id)}" style="${v.focused ? "background:#eef6f1" : ""}"><td class="mono">${escapeHtml(v.value_id)}${v.focused ? " ★" : ""}</td><td>${badge(v.classification)}</td><td class="mono">${escapeHtml(v.source_api || v.source_method)}</td><td class="mono">${escapeHtml(v.stored_field)}</td><td class="mono">${escapeHtml(v.value_class)}</td></tr>`).join("") || `<tr><td colspan="5" class="empty">No structured values</td></tr>`}
      </tbody></table>
    </div>`;
  document.querySelectorAll("[data-val]").forEach((el) => {
    el.addEventListener("click", () => {
      const v = values.find((x) => x.value_id === el.dataset.val);
      showDetail(v?.value_id, v);
    });
  });
}

function renderAll() {
  const apk = SNAP.apk || {};
  document.getElementById("top-meta").innerHTML = `
    <div>${escapeHtml(SNAP.label || SNAP.case || "case")}</div>
    <div>${escapeHtml(apk.package || "")} ${escapeHtml(apk.version_name || "")}</div>
    <div>focus=${escapeHtml(SNAP.focus_value_id || "—")}</div>`;
  renderOverview();
  renderPath();
  renderValues();
  renderOpenEdges();
  renderRuntimeWire();
  renderKnowledge();
  renderTimeline();
  renderSources();
  showDetail("Snapshot", {
    schema: SNAP.schema,
    case: SNAP.case,
    generator: SNAP.generator,
    note: "UI does not analyze APKs or invent classifications.",
  });
}

async function boot() {
  const res = await fetch("/api/snapshot", { cache: "no-store" });
  if (!res.ok) throw new Error(`snapshot HTTP ${res.status}`);
  SNAP = await res.json();
  renderAll();
  document.querySelectorAll("nav button").forEach((btn) => {
    btn.addEventListener("click", () => setView(btn.dataset.nav));
  });
  setView("overview");
}

boot().catch((err) => {
  document.body.innerHTML = `<pre style="padding:2rem;color:#b91c1c">Failed to load snapshot: ${escapeHtml(err.message)}</pre>`;
});
