/* Forensic Analysis UI — Explorer + Workbench orchestrator (no evidence invention) */

const MARK = {
  FACT: "F", INFERENCE: "I", CORRELATION: "C", UNKNOWN: "?", NOT_PROVEN: "NP",
  INPUT_MISSING: "IM", REJECTED: "R", COMPLETE: "OK", READY: "OK", AVAILABLE: "OK",
  NOT_EXECUTED: "NE", DYNAMIC_DISPATCH: "DD", PARTIAL: "P", EMPTY: "E", GUIDANCE: "G",
  QUEUED: "Q", RUNNING: "▶", WARNING: "W", FAILED: "X", SKIPPED: "–", CANCELLED: "C",
  OK: "OK",
};

let SNAP = null;
let META = null;
let selected = null;
let WB = {
  input: null,
  planId: null,
  plan: null,
  criteria: null,
  policy: "standard",
  allowWarning: false,
  estimate: null,
  jobId: null,
  pollTimer: null,
  pendingWarningStart: false,
};

function badge(status) {
  const s = String(status || "UNKNOWN");
  const mark = MARK[s] || "·";
  return `<span class="badge ${cssEscape(s)}" title="${escapeHtml(s)}"><span class="mark">[${escapeHtml(mark)}]</span> ${escapeHtml(s)}</span>`;
}
function cssEscape(s) { return String(s).replace(/[^A-Za-z0-9_-]/g, "_"); }
function escapeHtml(s) {
  return String(s ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}
function fmt(v) { return v === null || v === undefined || v === "" ? "—" : String(v); }
function fmtBytes(n) {
  if (n == null) return "—";
  const u = ["B", "KiB", "MiB", "GiB"];
  let x = Number(n), i = 0;
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
  return `${x.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function showDetail(title, obj) {
  selected = obj;
  const el = document.getElementById("detail");
  const lines = [`<h2>${escapeHtml(title)}</h2>`];
  if (!obj) { el.innerHTML = lines.join("") + `<p class="empty">Select a node, edge, or status chip.</p>`; return; }
  if (obj.classification || obj.status) lines.push(`<p>${badge(obj.classification || obj.status)}</p>`);
  lines.push(`<dl class="kv">`);
  for (const [k, v] of Object.entries(obj)) {
    if (k === "details" && v && typeof v === "object") {
      for (const [dk, dv] of Object.entries(v)) lines.push(`<dt>${escapeHtml(dk)}</dt><dd class="mono">${escapeHtml(fmt(dv))}</dd>`);
      continue;
    }
    if (typeof v === "object" && v !== null) lines.push(`<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(JSON.stringify(v))}</dd>`);
    else lines.push(`<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(fmt(v))}</dd>`);
  }
  lines.push(`</dl>`);
  el.innerHTML = lines.join("");
}

function setView(name) {
  document.querySelectorAll("[data-view]").forEach((el) => {
    el.classList.toggle("hidden", el.getAttribute("data-view") !== name);
  });
  document.querySelectorAll("nav button").forEach((b) => {
    b.classList.toggle("active", b.dataset.nav === name);
  });
}

function row(label, value) {
  return `<tr><th>${escapeHtml(label)}</th><td class="mono">${escapeHtml(fmt(value))}</td></tr>`;
}

/* ---------- Explorer (snapshot) ---------- */

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
    .map(([k, v]) => `<div class="kv"><dt>${escapeHtml(k)}</dt><dd>${badge(v)}</dd></div>`).join("") || `<p class="empty">No snapshot status</p>`;
  document.getElementById("overview-counters").innerHTML = `
    <table class="table"><tbody>
      ${row("RFCOMM targets", c.rfcomm_targets)}
      ${row("Evidence paths", c.evidence_paths)}
      ${row("Communication paths", c.communication_paths)}
      ${row("Structured values", c.structured_values)}
      ${row("V5 roundtrip candidates", c.v5_roundtrip_candidates)}
      ${row("Field loads", c.field_loads)}
      ${row("Decoder candidates", c.decoder_candidates)}
      ${row("Encoder candidates", c.encoder_candidates)}
    </tbody></table>`;
  document.getElementById("overview-pipeline").innerHTML = (SNAP.pipeline_stages || [])
    .map((s, i, arr) => {
      const arrow = i < arr.length - 1 ? `<span class="pipe-arrow">→</span>` : "";
      return `<button class="pipe-node" data-stage="${escapeHtml(s.id)}"><div class="name">${escapeHtml(s.label)}</div>${badge(s.status)}</button>${arrow}`;
    }).join("") || `<p class="empty">No pipeline in snapshot — run New Analysis or load a snapshot.</p>`;
  document.querySelectorAll("[data-stage]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const stage = (SNAP.pipeline_stages || []).find((x) => x.id === btn.dataset.stage);
      showDetail(stage?.label || "Stage", stage);
    });
  });
}

function renderPath() {
  const nodes = SNAP.nodes || [];
  const edges = SNAP.edges || [];
  if (!nodes.length) {
    document.getElementById("path-view").innerHTML = `<div class="card"><p class="empty">No focus path nodes in this snapshot.</p></div>`;
    return;
  }
  const order = ["n-accessory-read","n-internalread","n-readpacket","n-packet-mdata","n-decodeversion","n-value-v001","n-mversion"];
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const main = order.filter((id) => byId[id]).map((id) => byId[id]);
  const branch = ["n-clamp","n-branch","n-single","n-gating"].map((id) => byId[id]).filter(Boolean);
  let html = `<div class="card"><h3>Focus path ${escapeHtml(SNAP.focus_value_id || "")}</h3><div class="path">`;
  main.forEach((n, i) => {
    html += `<div class="node" data-node="${escapeHtml(n.id)}"><span>${escapeHtml(n.label)}</span>${badge(n.classification || n.limit || n.status)}</div>`;
    if (i < main.length - 1) html += `<div class="connector">│</div><div class="connector">▼</div>`;
  });
  if (branch.length) {
    html += `<div class="connector">│</div><div class="connector">├── branches</div>`;
    branch.forEach((n) => { html += `<div class="node" data-node="${escapeHtml(n.id)}" style="margin-left:1rem"><span>${escapeHtml(n.label)}</span>${badge(n.classification)}</div>`; });
  }
  html += `</div></div><div class="card"><h3>Edges</h3><table class="table"><thead><tr><th>From</th><th>To</th><th>Relation</th><th>Class</th></tr></thead><tbody>`;
  edges.forEach((e) => {
    html += `<tr class="edge-row" data-edge="${escapeHtml(e.id)}"><td>${escapeHtml(byId[e.from]?.label || e.from)}</td><td>${escapeHtml(byId[e.to]?.label || e.to)}</td><td class="mono">${escapeHtml(e.relation)}</td><td>${badge(e.classification)}${e.limit ? " " + badge(e.limit) : ""}</td></tr>`;
  });
  html += `</tbody></table></div>`;
  document.getElementById("path-view").innerHTML = html;
  document.querySelectorAll("[data-node]").forEach((el) => {
    el.addEventListener("click", () => { el.classList.add("selected"); showDetail(byId[el.dataset.node]?.label, byId[el.dataset.node]); });
  });
  document.querySelectorAll("[data-edge]").forEach((el) => {
    el.addEventListener("click", () => { const e = edges.find((x) => x.id === el.dataset.edge); showDetail(`Edge ${e?.id}`, e); });
  });
}

function renderOpenEdges() {
  const list = SNAP.open_edges || [];
  let html = `<div class="card"><h3>Open edges / boundaries</h3>`;
  if (!list.length) html += `<p class="empty">No open-edge records in snapshot.</p></div>`;
  else {
    html += `<table class="table"><thead><tr><th>Status</th><th>From → To</th><th>Reason</th></tr></thead><tbody>`;
    list.forEach((oe) => {
      html += `<tr data-oe="${escapeHtml(oe.id)}"><td>${badge(oe.status || oe.label)}</td><td class="mono">${escapeHtml(oe.from)} → ${escapeHtml(oe.to)}</td><td>${escapeHtml(oe.reason)}</td></tr>`;
    });
    html += `</tbody></table></div>`;
  }
  document.getElementById("open-view").innerHTML = html;
  document.querySelectorAll("[data-oe]").forEach((el) => {
    el.addEventListener("click", () => { const oe = list.find((x) => x.id === el.dataset.oe); showDetail(oe?.label || "Open edge", oe); });
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
      <p class="mono">Reason: SAME_SESSION not established.</p>
    </div>
    <div class="card"><h3>Correlation graph</h3>
      <p>FULL_CHAIN present: <strong>${cg.full_chain_present ? "yes" : "no"}</strong></p>
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
    </div>`;
}

function renderTimeline() {
  const items = SNAP.timeline || [];
  document.getElementById("timeline-view").innerHTML = `
    <div class="card"><h3>Timeline</h3><div class="path">
      ${items.map((t, i) => `<div class="node"><span>${escapeHtml(t.label)}</span>${badge(t.status)}</div>${i < items.length - 1 ? `<div class="connector">▼</div>` : ""}`).join("") || "<p class='empty'>—</p>"}
    </div></div>`;
}

function renderSources() {
  document.getElementById("sources-view").innerHTML = `
    <div class="card"><h3>Evidence sources</h3>
      <table class="table"><thead><tr><th>Role</th><th>Path</th><th>Present</th></tr></thead>
      <tbody>${(SNAP.sources || []).map((s) => `<tr><td>${escapeHtml(s.role)}</td><td class="mono">${escapeHtml(s.path)}</td><td>${s.present ? badge("FACT") : badge("INPUT_MISSING")}</td></tr>`).join("")}
      </tbody></table>
    </div>`;
}

function renderValues() {
  const values = SNAP.values || [];
  document.getElementById("values-view").innerHTML = `
    <div class="card"><h3>Structured values</h3>
      <table class="table"><thead><tr><th>ID</th><th>Class</th><th>API / Method</th><th>Field</th></tr></thead>
      <tbody>${values.map((v) => `<tr data-val="${escapeHtml(v.value_id)}"><td class="mono">${escapeHtml(v.value_id)}</td><td>${badge(v.classification)}</td><td class="mono">${escapeHtml(v.source_api || v.source_method)}</td><td class="mono">${escapeHtml(v.stored_field)}</td></tr>`).join("") || `<tr><td colspan="4" class="empty">No structured values</td></tr>`}
      </tbody></table>
    </div>`;
  document.querySelectorAll("[data-val]").forEach((el) => {
    el.addEventListener("click", () => { const v = values.find((x) => x.value_id === el.dataset.val); showDetail(v?.value_id, v); });
  });
}

function renderAll() {
  const apk = SNAP.apk || {};
  document.getElementById("top-meta").innerHTML = `
    <div>${escapeHtml(SNAP.label || SNAP.case || "workbench")}</div>
    <div>${escapeHtml(apk.package || "")} ${escapeHtml(apk.version_name || "")}</div>
    <div>focus=${escapeHtml(SNAP.focus_value_id || "—")}</div>`;
  renderOverview(); renderPath(); renderValues(); renderOpenEdges();
  renderRuntimeWire(); renderKnowledge(); renderTimeline(); renderSources();
}

/* ---------- Workbench ---------- */

async function api(path, opts = {}) {
  const res = await fetch(path, { cache: "no-store", ...opts });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { ok: false, message: text }; }
  if (!res.ok || data.ok === false) {
    const err = new Error(data.message || `HTTP ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function collectOverrides() {
  const box = document.getElementById("criteria-form");
  if (!box || !WB.criteria) return null;
  const out = {};
  box.querySelectorAll("[data-crit]").forEach((el) => {
    const key = el.getAttribute("data-crit");
    const parts = key.split(".");
    let cur = out;
    for (let i = 0; i < parts.length - 1; i++) {
      cur[parts[i]] = cur[parts[i]] || {};
      cur = cur[parts[i]];
    }
    const leaf = parts[parts.length - 1];
    if (el.type === "checkbox") cur[leaf] = el.checked;
    else if (el.type === "number") cur[leaf] = Number(el.value);
  });
  return out;
}

function renderInputMeta() {
  const el = document.getElementById("input-meta");
  const i = WB.input;
  if (!i) { el.innerHTML = ""; return; }
  el.innerHTML = `
    <div><strong>Filename:</strong> ${escapeHtml(i.filename)}</div>
    <div><strong>Size:</strong> ${escapeHtml(fmtBytes(i.size_bytes))}</div>
    <div><strong>SHA256:</strong> ${escapeHtml(i.sha256)}</div>
    <div><strong>ZIP/APK valid:</strong> ${i.zip_apk_valid ? badge("FACT") : badge("REJECTED")}</div>
    <div><strong>DEX count / size:</strong> ${escapeHtml(i.dex_count)} / ${escapeHtml(fmtBytes(i.dex_size || i.dex_total_bytes))}</div>
    <div><strong>Native .so / size:</strong> ${escapeHtml(i.native_so_count)} / ${escapeHtml(fmtBytes(i.native_size || i.native_total_bytes))}</div>
    <div><strong>Artifact count:</strong> ${escapeHtml(i.artifact_count)}</div>
    <div><strong>Server path:</strong> ${escapeHtml(i.server_path || (i.paths && i.paths[0]) || "—")}</div>
    ${i.note ? `<div class="empty">${escapeHtml(i.note)}</div>` : ""}`;
  updateStartEnabled();
}

function renderPlans() {
  const list = document.getElementById("plan-list");
  const plans = (META && META.plans) || [];
  list.innerHTML = plans.filter((p) => p.valid).map((p) => `
    <label class="plan-option ${WB.planId === p.id ? "selected" : ""}">
      <input type="radio" name="plan" value="${escapeHtml(p.id)}" ${WB.planId === p.id ? "checked" : ""} />
      <span><strong>${escapeHtml(p.name || p.id)}</strong><br/><span class="empty">${escapeHtml(p.description || "").slice(0, 160)}</span></span>
    </label>`).join("") || `<p class="empty">No plans found under plans/*.yaml</p>`;
  list.querySelectorAll("input[name=plan]").forEach((inp) => {
    inp.addEventListener("change", async () => {
      WB.planId = inp.value;
      renderPlans();
      await loadPlanCriteria(WB.planId);
      updateStartEnabled();
    });
  });
  const policies = (META && META.resource_policies) || ["conservative", "standard", "unlimited"];
  document.getElementById("policy-list").innerHTML = policies.map((p) => `
    <label><input type="radio" name="policy" value="${escapeHtml(p)}" ${WB.policy === p ? "checked" : ""} /> ${escapeHtml(p)}</label>`).join("");
  document.querySelectorAll("input[name=policy]").forEach((inp) => {
    inp.addEventListener("change", () => { WB.policy = inp.value; updateStartEnabled(); });
  });
}

async function loadPlanCriteria(planId) {
  const data = await api(`/api/plans/${encodeURIComponent(planId)}/criteria`);
  WB.plan = data.plan;
  WB.criteria = data.plan.criteria;
  document.getElementById("plan-detail").innerHTML = `
    <div><strong>Plan:</strong> ${escapeHtml(data.plan.name)}</div>
    <div><strong>Plan SHA256:</strong> ${escapeHtml(data.plan.sha256)}</div>
    <div><strong>Description:</strong> ${escapeHtml(data.plan.description || "")}</div>`;
  const c = data.plan.criteria;
  const groups = [
    ["dex_xref", "DEX / XREF", [
      ["enabled", "checkbox", "DEX context"],
      ["xref_depth", "number", "XREF depth"],
      ["max_callers", "number", "Max callers"],
      ["max_callees", "number", "Max callees"],
      ["instruction_window", "number", "Instruction window"],
    ]],
    ["bluetooth", "Bluetooth", [
      ["enabled", "checkbox", "Bluetooth/RFCOMM"],
      ["reconstruct_callers", "checkbox", "Caller reconstruction"],
      ["reconstruct_streams", "checkbox", "Stream reconstruction"],
      ["reconstruct_read_write", "checkbox", "Read/write reconstruction"],
      ["interprocedural", "checkbox", "Interprocedural"],
      ["caller_depth", "number", "Caller depth"],
      ["dataflow_depth", "number", "Dataflow depth"],
      ["max_method_hops", "number", "Method hops"],
      ["max_field_hops", "number", "Field hops"],
      ["max_object_nodes", "number", "Object nodes"],
    ]],
    ["evidence_graph", "Evidence Graph", [
      ["enabled", "checkbox", "Evidence Graph"],
      ["max_paths", "number", "Max paths"],
    ]],
    ["communication", "Communication", [
      ["enabled", "checkbox", "Communication Evidence"],
      ["max_method_hops", "number", "Method hops"],
      ["max_field_hops", "number", "Field hops"],
      ["max_buffer_hops", "number", "Buffer hops"],
      ["max_parser_hops", "number", "Parser hops"],
      ["max_message_hops", "number", "Message hops"],
      ["max_dataflow_paths", "number", "Max dataflow paths"],
    ]],
    ["runtime_correlation", "Runtime/Correlation (offline plan flags)", [
      ["enabled", "checkbox", "Correlation enabled (does NOT execute APK)"],
    ]],
  ];
  let html = `<p class="empty">${escapeHtml(c.search_plan_limits_note || "")}</p>`;
  if (c.inventory) {
    html += `<p><strong>Inventory modules (from plan):</strong> ${Object.entries(c.inventory).filter(([,v])=>v).map(([k])=>k).join(", ") || "—"}</p>`;
  }
  for (const [gid, title, fields] of groups) {
    const g = c[gid] || {};
    html += `<h4>${escapeHtml(title)}</h4><div class="crit-grid">`;
    if (g.note) html += `<p class="empty">${escapeHtml(g.note)}</p>`;
    for (const [field, type, label] of fields) {
      const key = `${gid}.${field}`;
      const val = g[field];
      if (type === "checkbox") {
        html += `<label><input type="checkbox" data-crit="${escapeHtml(key)}" ${val ? "checked" : ""}/> ${escapeHtml(label)}</label>`;
      } else {
        html += `<label>${escapeHtml(label)} <input type="number" data-crit="${escapeHtml(key)}" value="${escapeHtml(val)}" /></label>`;
      }
    }
    html += `</div>`;
  }
  document.getElementById("criteria-form").innerHTML = html;
}

function updateStartEnabled() {
  const ready = !!(WB.input && WB.planId && WB.estimate && WB.estimate.risk !== "REJECT");
  document.getElementById("btn-start").disabled = !ready;
  const sum = document.getElementById("start-summary");
  if (!WB.input || !WB.planId) { sum.innerHTML = ""; return; }
  sum.innerHTML = `
    <div><strong>Input:</strong> ${escapeHtml(WB.input.filename)}</div>
    <div><strong>SearchPlan:</strong> ${escapeHtml(WB.planId)}</div>
    <div><strong>Resource Policy:</strong> ${escapeHtml(WB.policy)}</div>
    <div><strong>Estimated runtime:</strong> ${escapeHtml(WB.estimate?.estimated_runtime_display || "—")} <span class="empty">(heuristic)</span></div>
    <div><strong>Estimated memory:</strong> ${escapeHtml(WB.estimate?.estimated_memory_mb ?? "—")} MiB</div>
    <div><strong>Risk:</strong> ${WB.estimate ? badge(WB.estimate.risk) : "—"}</div>`;
}

function renderPreflight(est) {
  WB.estimate = est;
  const el = document.getElementById("preflight");
  const rows = (est.stage_estimates || []).map((r) =>
    `<tr><th>${escapeHtml(r.label)}</th><td class="mono">${escapeHtml(r.display)}</td><td class="empty">${escapeHtml(r.kind || "")}</td></tr>`
  ).join("");
  el.innerHTML = `
    <div><strong>APK:</strong> ${escapeHtml(WB.input?.filename)}</div>
    <div><strong>Plan:</strong> ${escapeHtml(est.plan?.name)} · SHA ${escapeHtml((est.plan?.sha256 || "").slice(0, 16))}…</div>
    <div><strong>Estimated runtime:</strong> ${escapeHtml(est.estimated_runtime_display)} <span class="empty">HEURISTIC</span></div>
    <div><strong>Estimated peak memory:</strong> ${escapeHtml(est.estimated_memory_mb)} MiB</div>
    <div><strong>Risk:</strong> ${badge(est.risk)}</div>
    <p class="empty">${escapeHtml(est.note || "")}</p>
    <table class="table"><thead><tr><th>Stage</th><th>Estimate</th><th>Kind</th></tr></thead><tbody>${rows}</tbody></table>`;
  document.getElementById("reject-box").classList.add("hidden");
  document.getElementById("warning-confirm").classList.add("hidden");
  if (est.risk === "REJECT") {
    document.getElementById("reject-box").classList.remove("hidden");
    document.getElementById("reject-box").innerHTML = `<p><strong>Analysis rejected by Resource Guard.</strong></p><pre class="mono">${escapeHtml(JSON.stringify(est.decision?.reasons || [], null, 2))}</pre>`;
  }
  updateStartEnabled();
}

function stageMark(status) {
  if (status === "COMPLETE") return "✓";
  if (status === "RUNNING") return "▶";
  if (status === "FAILED") return "✗";
  if (status === "SKIPPED") return "○";
  return "○";
}

function renderJob(job) {
  if (!job) return;
  WB.jobId = job.job_id;
  const t = job.timing || {};
  document.getElementById("job-header").innerHTML = `
    <div><strong>Job:</strong> ${escapeHtml((job.job_id || "").slice(0, 16))}…</div>
    <div><strong>Status:</strong> ${badge(job.status)}</div>
    <div><strong>APK:</strong> ${escapeHtml(job.input?.filename)}</div>
    <div><strong>Plan:</strong> ${escapeHtml(job.plan?.name)}</div>
    <div><strong>Started:</strong> ${escapeHtml(t.started_at || "—")}</div>
    <div><strong>Elapsed:</strong> ${escapeHtml(t.elapsed_display)}</div>
    <div><strong>Estimated:</strong> ${escapeHtml(t.estimated_display)} <span class="empty">heuristic</span></div>
    <p class="empty">${escapeHtml(job.disclaimer || "")}</p>`;
  document.getElementById("job-stages").innerHTML = `<div class="stage-list">${(job.stages || []).map((s) => `
    <div class="stage-row"><span><span class="mark-stage">${stageMark(s.status)}</span> ${escapeHtml(s.label)}</span>
    <span>${badge(s.status)} <span class="mono">${s.elapsed_seconds != null ? escapeHtml(String(s.elapsed_seconds) + "s") : ""}</span></span></div>`).join("")}</div>`;
  document.getElementById("job-eta").innerHTML = `
    <div>Elapsed: ${escapeHtml(t.elapsed_display)}</div>
    <div>Estimated total: ${escapeHtml(t.estimated_display)}</div>
    <div>Estimated remaining: ${escapeHtml(t.remaining_display)}</div>
    <p class="empty">ETA is a heuristic estimate (${escapeHtml(t.eta_kind || "HEURISTIC_ESTIMATE")}), not a guarantee.</p>
    ${job.status === "COMPLETE" ? `<div><strong>Actual:</strong> ${escapeHtml(t.elapsed_display)}</div>` : ""}`;
  const debug = document.getElementById("show-debug-log").checked;
  const logs = (job.logs || []).filter((l) => debug || l.level !== "DEBUG");
  document.getElementById("job-log").textContent = logs.map((l) => `${l.ts} ${l.level}  ${l.message}`).join("\n");
  const results = job.results || [];
  let html = "";
  if (job.status === "COMPLETE") {
    html += `<div class="warn" style="border-left-color:var(--fact)"><strong>ANALYSIS COMPLETE</strong> · Runtime ${escapeHtml(t.elapsed_display)} · Estimated ${escapeHtml(t.estimated_display)}</div>`;
    if (job.snapshot_path) {
      html += `<button type="button" class="btn primary" id="btn-open-explorer">Open Forensic Results</button>`;
    }
  }
  html += results.map((r) => `
    <div class="result-row">
      <span class="path">${escapeHtml(r.role)}: ${escapeHtml(r.path)}</span>
      <button type="button" class="btn" data-open="${escapeHtml(r.path)}">Open</button>
      <button type="button" class="btn" data-copy="${escapeHtml(r.path)}">Copy path</button>
    </div>`).join("") || `<p class="empty">No results yet.</p>`;
  document.getElementById("job-results").innerHTML = html;
  document.querySelectorAll("[data-open]").forEach((btn) => {
    btn.addEventListener("click", () => {
      window.open(`/api/result?path=${encodeURIComponent(btn.getAttribute("data-open"))}`, "_blank");
    });
  });
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(btn.getAttribute("data-copy")); } catch { /* ignore */ }
    });
  });
  const openEx = document.getElementById("btn-open-explorer");
  if (openEx) {
    openEx.addEventListener("click", async () => {
      const res = await fetch("/api/snapshot", { cache: "no-store" });
      SNAP = await res.json();
      renderAll();
      setView("overview");
    });
  }
}

function startPolling(jobId) {
  if (WB.pollTimer) clearInterval(WB.pollTimer);
  WB.pollTimer = setInterval(async () => {
    try {
      const data = await api(`/api/jobs/${encodeURIComponent(jobId)}/status`);
      renderJob(data.job);
      if (["COMPLETE", "FAILED", "CANCELLED", "REJECTED"].includes(data.job.status)) {
        clearInterval(WB.pollTimer);
        WB.pollTimer = null;
        if (data.job.status === "COMPLETE") {
          try {
            const res = await fetch("/api/snapshot", { cache: "no-store" });
            SNAP = await res.json();
            renderAll();
          } catch { /* keep previous snapshot */ }
        }
      }
    } catch { /* keep polling */ }
  }, 1500);
}

async function uploadFiles(files) {
  if (!files || !files.length) return;
  const paths = [];
  let lastMeta = null;
  for (const f of files) {
    const fd = new FormData();
    fd.append("file", f, f.name);
    const res = await fetch("/api/upload", { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok || data.ok === false) throw new Error(data.message || "upload failed");
    paths.push(data.input.server_path);
    lastMeta = data.input;
  }
  if (paths.length === 1) {
    WB.input = lastMeta;
  } else {
    const validated = await api("/api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ paths }),
    });
    WB.input = validated.input;
  }
  WB.estimate = null;
  renderInputMeta();
}

function wireWorkbench() {
  document.getElementById("wb-disclaimer").textContent = (META && META.disclaimer) || "";
  const warn = document.getElementById("bind-warn");
  if (META && META.bind_warning) {
    warn.textContent = META.bind_warning;
    warn.classList.remove("hidden");
  }
  document.querySelectorAll("[data-input-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-input-tab]").forEach((b) => b.classList.toggle("active", b === btn));
      const tab = btn.getAttribute("data-input-tab");
      document.getElementById("input-upload").classList.toggle("hidden", tab !== "upload");
      document.getElementById("input-server").classList.toggle("hidden", tab !== "server");
    });
  });
  const dz = document.getElementById("dropzone");
  const fileInp = document.getElementById("apk-file");
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("drag"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("drag"));
  dz.addEventListener("drop", async (e) => {
    e.preventDefault(); dz.classList.remove("drag");
    try { await uploadFiles(e.dataTransfer.files); } catch (err) { alert(err.message); }
  });
  fileInp.addEventListener("change", async () => {
    try { await uploadFiles(fileInp.files); } catch (err) { alert(err.message); }
  });
  document.getElementById("btn-validate-path").addEventListener("click", async () => {
    try {
      const path = document.getElementById("server-path").value.trim();
      const data = await api("/api/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ paths: [path] }),
      });
      WB.input = data.input;
      WB.estimate = null;
      renderInputMeta();
    } catch (err) { alert(err.message); }
  });
  document.getElementById("allow-warning").addEventListener("change", (e) => {
    WB.allowWarning = e.target.checked;
  });
  document.getElementById("btn-estimate").addEventListener("click", async () => {
    try {
      if (!WB.input || !WB.planId) throw new Error("Select APK and plan first");
      const data = await api("/api/estimate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          apk_paths: WB.input.paths || [WB.input.server_path],
          plan_id: WB.planId,
          resource_policy: WB.policy,
          plan_overrides: collectOverrides(),
          allow_resource_warning: WB.allowWarning,
        }),
      });
      renderPreflight(data);
    } catch (err) { alert(err.message); }
  });
  async function startJob(confirmWarning) {
    const data = await api("/api/jobs/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        apk_paths: WB.input.paths || [WB.input.server_path],
        plan_id: WB.planId,
        resource_policy: WB.policy,
        plan_overrides: collectOverrides(),
        allow_resource_warning: WB.allowWarning,
        confirm_warning: confirmWarning,
      }),
    });
    renderJob(data.job);
    setView("job");
    startPolling(data.job.job_id);
  }
  document.getElementById("btn-start").addEventListener("click", async () => {
    try {
      if (WB.estimate && WB.estimate.risk === "WARNING" && !WB.allowWarning) {
        document.getElementById("warning-confirm").classList.remove("hidden");
        WB.pendingWarningStart = true;
        return;
      }
      await startJob(false);
    } catch (err) {
      if (err.data && err.data.error === "RESOURCE_WARNING") {
        document.getElementById("warning-confirm").classList.remove("hidden");
        return;
      }
      if (err.data && err.data.error === "RESOURCE_REJECT") {
        document.getElementById("reject-box").classList.remove("hidden");
        document.getElementById("reject-box").innerHTML = `<p><strong>Analysis rejected by Resource Guard.</strong></p><pre>${escapeHtml(err.message)}</pre>`;
        return;
      }
      alert(err.message);
    }
  });
  document.getElementById("btn-cancel-warn").addEventListener("click", () => {
    document.getElementById("warning-confirm").classList.add("hidden");
    WB.pendingWarningStart = false;
  });
  document.getElementById("btn-proceed-warn").addEventListener("click", async () => {
    document.getElementById("warning-confirm").classList.add("hidden");
    try { await startJob(true); } catch (err) { alert(err.message); }
  });
  document.getElementById("show-debug-log").addEventListener("change", async () => {
    if (!WB.jobId) return;
    try {
      const data = await api(`/api/jobs/${encodeURIComponent(WB.jobId)}/status`);
      renderJob(data.job);
    } catch { /* ignore */ }
  });
}

async function boot() {
  const snapRes = await fetch("/api/snapshot", { cache: "no-store" });
  if (!snapRes.ok) throw new Error(`snapshot HTTP ${snapRes.status}`);
  SNAP = await snapRes.json();
  renderAll();
  try {
    META = await api("/api/meta");
    wireWorkbench();
    renderPlans();
    const first = (META.plans || []).find((p) => p.valid);
    if (first) {
      WB.planId = first.id;
      renderPlans();
      await loadPlanCriteria(first.id);
    }
  } catch (err) {
    document.getElementById("wb-disclaimer").textContent =
      "Workbench APIs unavailable (read-only Explorer mode). " + err.message;
  }
  document.querySelectorAll("nav button").forEach((btn) => {
    btn.addEventListener("click", () => setView(btn.dataset.nav));
  });
  setView("overview");
}

boot().catch((err) => {
  document.body.innerHTML = `<pre style="padding:2rem;color:#b91c1c">Failed to load UI: ${escapeHtml(err.message)}</pre>`;
});
