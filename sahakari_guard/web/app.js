// Sahakari-Guard dashboard. Plain ES module, no build step, works offline.
// All dynamic text goes through the `html` tagged template, which escapes it.

/* ------------------------------------------------------------------ safe templating */

class Raw { constructor(s) { this.s = s; } }
const raw = (s) => new Raw(s);
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);
function renderVal(v) {
  if (v === null || v === undefined || v === false) return "";
  if (v instanceof Raw) return v.s;
  if (Array.isArray(v)) return v.map(renderVal).join("");
  return esc(v);
}
function html(strings, ...vals) {
  let out = strings[0];
  vals.forEach((v, i) => { out += renderVal(v) + strings[i + 1]; });
  return raw(out);
}
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
function setHTML(el, tpl) { if (el) el.innerHTML = tpl instanceof Raw ? tpl.s : esc(tpl); }

/* ------------------------------------------------------------------ storage (never throws) */

const store = {
  get(k, d = null) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  sget(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  sset(k, v) { try { sessionStorage.setItem(k, v); } catch { /* ignore */ } },
};

/* ------------------------------------------------------------------ state */

const ACTIVE_DEMO = ["preparing", "fast_forward", "live", "finishing"];
const state = {
  lang: ["en", "ta", "hi"].includes(store.get("sg.lang")) ? store.get("sg.lang") : "en",
  i18n: {},
  fallback: {},
  config: null,
  summary: null,
  skew: 0,
  seen: new Set(),
  firstLoad: true,
  pollTimer: null,
  alertsQuery: { severity: "", rule: "", status: "OPEN", incident: "", offset: 0 },
  scenario: store.get("sg.scenario", "cosmos"),
  speed: Number(store.get("sg.speed", "120")) || 120,
  benchTimer: null,
};

/* ------------------------------------------------------------------ i18n & formatting */

function t(key, params = {}) {
  let v = state.i18n[key];
  if (v === undefined) v = state.fallback[key];
  if (v === undefined) return key;
  if (typeof v !== "string") return v;
  return v.replace(/\{(\w+)\}/g, (m, k) => (params[k] !== undefined ? String(params[k]) : m));
}
const nf = new Intl.NumberFormat("en-IN");
const fmtInt = (n) => (n === null || n === undefined ? "-" : nf.format(n));
const fmtPct = (x) => (x === null || x === undefined ? "-" : `${(x * 100).toFixed(x >= 0.9995 ? 1 : 2)}%`);
const dtFull = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const dtClock = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const dtDay = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", weekday: "short", day: "2-digit", month: "short", year: "numeric" });
function fmtTime(iso) { if (!iso) return "-"; const d = new Date(iso); return isNaN(d) ? "-" : dtFull.format(d); }
function fmtClock(iso) { if (!iso) return "--:--:--"; const d = new Date(iso); return isNaN(d) ? "--:--:--" : dtClock.format(d); }
function fmtDay(iso) { if (!iso) return ""; const d = new Date(iso); return isNaN(d) ? "" : dtDay.format(d); }
function fmtDuration(sec) {
  if (sec === null || sec === undefined || isNaN(sec)) return "-";
  const neg = sec < 0; let s = Math.round(Math.abs(sec));
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  let out;
  if (d) out = `${d}d ${h}h`;
  else if (h) out = `${h}h ${String(m).padStart(2, "0")}m`;
  else if (m) out = `${m}m ${String(s).padStart(2, "0")}s`;
  else out = `${s}s`;
  return (neg ? "-" : "") + out;
}
const rupees = (paise) => "₹" + nf.format(Math.round((Number(paise) || 0) / 100));

/* ------------------------------------------------------------------ API */

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  const key = store.sget("sg.key");
  if (key) headers["X-API-Key"] = key;
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.json);
  }
  const res = await fetch(path, { method: opts.method || (opts.body ? "POST" : "GET"), headers, body: opts.body });
  if (res.status === 401) {
    const entered = window.prompt("API key required (ask your administrator):");
    if (entered) { store.sset("sg.key", entered); return api(path, opts); }
  }
  let data = null;
  const text = await res.text();
  try { data = text ? JSON.parse(text) : null; } catch { data = { error: text }; }
  if (!res.ok) throw new Error((data && (data.error || data.detail && JSON.stringify(data.detail))) || `${res.status} ${res.statusText}`);
  return data;
}
function withKey(url) {
  const key = store.sget("sg.key");
  return key ? `${url}${url.includes("?") ? "&" : "?"}key=${encodeURIComponent(key)}` : url;
}

/* ------------------------------------------------------------------ shell */

async function loadLang(lang) {
  if (!state.fallback["app.title"]) state.fallback = await api("/api/i18n/en");
  state.i18n = lang === "en" ? state.fallback : await api(`/api/i18n/${lang}`);
  state.lang = lang;
  store.set("sg.lang", lang);
  document.documentElement.lang = lang;
  $$("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $$(".langs button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === lang)));
}

function updateShell() {
  const s = state.summary;
  if (!s) return;
  const pill = $("#net-pill");
  pill.classList.toggle("off", !s.network_online);
  $("#net-label").textContent = s.network_online ? t("network.online") : `${t("network.offline")} · ${fmtInt(s.kpi.queued_messages)}`;
  pill.title = s.network_online ? "" : t("network.offline.hint");
  const openAlerts = Object.values(s.alerts.by_rule || {}).reduce((a, b) => a + b, 0);
  const na = $("#nav-alerts");
  na.hidden = !openAlerts; na.textContent = openAlerts > 999 ? "999+" : String(openAlerts);
  const ni = $("#nav-incidents");
  ni.hidden = !s.kpi.open_incidents; ni.textContent = String(s.kpi.open_incidents);
}

/* ------------------------------------------------------------------ fuse (6-hour clock) */

function secondsLeft(deadlineIso) {
  if (!deadlineIso) return null;
  return (Date.parse(deadlineIso) - (Date.now() + state.skew)) / 1000;
}
function fuseCells(deadlineIso, total) {
  const left = secondsLeft(deadlineIso);
  const used = Math.min(total, Math.max(0, total - (left ?? total)));
  return Array.from({ length: 6 }, (_, i) => Math.min(1, Math.max(0, (used - i * (total / 6)) / (total / 6))));
}
function fuse(deadlineIso, cls = "red", big = true) {
  const total = (state.config?.engine?.reporting_deadline_hours || 6) * 3600;
  const left = secondsLeft(deadlineIso);
  const cells = fuseCells(deadlineIso, total);
  if (!big) {
    return html`<div class="mini-fuse" data-deadline="${deadlineIso}" data-total="${total}">${cells.map((f) => html`<i><b style="width:${(f * 100).toFixed(1)}%"></b></i>`)}</div>`;
  }
  return html`<div class="fuse ${cls}" data-deadline="${deadlineIso}" data-total="${total}">
    <div class="label">${t("kpi.next_deadline")}</div>
    <div class="clock" data-clock>${left !== null && left < 0 ? t("incident.overdue") : fmtDuration(left)}</div>
    <div class="cells" role="img" aria-label="${t("incident.time_left")}: ${fmtDuration(left)}">${cells.map((f) => html`<div class="cell"><i style="width:${(f * 100).toFixed(1)}%"></i></div>`)}</div>
    <div class="scale num"><span>0h</span><span>1h</span><span>2h</span><span>3h</span><span>4h</span><span>5h</span></div>
    <div class="deadline">${t("incident.deadline")}: <b>${fmtTime(deadlineIso)}</b></div>
  </div>`;
}
function tickFuses() {
  $$("[data-deadline]").forEach((el) => {
    const dl = el.dataset.deadline;
    if (!dl) return;
    const total = Number(el.dataset.total) || 21600;
    const left = secondsLeft(dl);
    const clock = $("[data-clock]", el);
    if (clock) clock.textContent = left < 0 ? t("incident.overdue") : fmtDuration(left);
    const cells = fuseCells(dl, total);
    $$(".cell i, i > b", el).forEach((bar, i) => { bar.style.width = `${(cells[i] * 100).toFixed(1)}%`; });
    $$("[data-left]", el.parentElement || el).forEach((n) => { n.textContent = left < 0 ? t("incident.overdue") : fmtDuration(left); });
  });
}

/* ------------------------------------------------------------------ small components */

const sevTag = (sev, label) => html`<span class="tag ${sev}">${label || t(`severity.${sev}`)}</span>`;
function statusTag(status) {
  const cls = { OPEN: "MEDIUM", CONFIRMED: "HIGH", REPORTED: "ok", DISMISSED: "neutral", AUTO_CLOSED: "ok" }[status] || "neutral";
  return html`<span class="tag ${cls} plain">${t(`incident.status.${status}`)}</span>`;
}
function alertRows(items, { fresh = true } = {}) {
  if (!items.length) return html`<tr><td colspan="6" class="empty">${t("alerts.empty")}</td></tr>`;
  return items.map((a) => {
    const isNew = fresh && !state.firstLoad && !state.seen.has(a.alert_id);
    state.seen.add(a.alert_id);
    return html`<tr class="click ${isNew ? "fresh" : ""}" data-alert="${a.alert_id}" tabindex="0">
      <td class="num">${fmtTime(a.detected_event_time)}</td>
      <td><b>${a.rule_id}</b> ${a.name}${a.status !== "OPEN" ? html`<br><span class="muted small">${a.status_label}</span>` : ""}</td>
      <td>${sevTag(a.severity, a.severity_label)}</td>
      <td class="amt">${a.amount}</td>
      <td class="ref">${a.account_masked || "-"}</td>
      <td class="ref">${a.rule_id === "SG-R5" ? "-" : a.rrn}</td>
    </tr>`;
  });
}
const alertHead = () => html`<thead><tr><th>${t("col.detected")}</th><th>${t("col.rule")}</th><th>${t("col.severity")}</th><th class="amt">${t("col.amount")}</th><th>${t("col.account")}</th><th>${t("col.rrn")}</th></tr></thead>`;
function bindAlertRows(root) {
  $$("tr[data-alert]", root).forEach((tr) => {
    const open = () => openAlert(tr.dataset.alert);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
  });
}
function notice(msg, kind = "") { return html`<div class="notice ${kind}" role="${kind === "error" ? "alert" : "status"}">${msg}</div>`; }

/* ------------------------------------------------------------------ charts */

function hourlyChart(stats, byHour) {
  const keys = Object.keys(stats.hourly_approvals || {}).sort();
  if (!keys.length) return html`<p class="empty">${t("status.empty.body")}</p>`;
  const day = keys[keys.length - 1].slice(0, 10);
  const hours = [];
  for (let h = 0; h < 24; h++) {
    const key = `${day}T${String(h).padStart(2, "0")}`;
    hours.push({ key, n: stats.hourly_approvals[key] || 0, alerts: byHour[key] || 0 });
  }
  const W = 640, H = 210, L = 38, R = 8, T = 18, B = 26;
  const max = Math.max(10, ...hours.map((h) => h.n));
  const step = Math.pow(10, Math.floor(Math.log10(max)));
  const tick = [1, 2, 2.5, 5, 10].map((m) => m * step).find((s) => max / s <= 4) || step * 10;
  const top = Math.ceil(max / tick) * tick;
  const bw = (W - L - R) / hours.length;
  const y = (v) => T + (H - T - B) * (1 - v / top);
  const ticks = []; for (let v = 0; v <= top; v += tick) ticks.push(v);
  const bars = hours.map((h, i) => {
    const x = L + i * bw + 1, w = Math.max(2, bw - 2), y0 = y(0), y1 = y(h.n), r = Math.min(4, w / 2, y0 - y1);
    const d = h.n > 0 ? `M${x},${y0} V${y1 + r} Q${x},${y1} ${x + r},${y1} H${x + w - r} Q${x + w},${y1} ${x + w},${y1 + r} V${y0} Z` : "";
    const label = `${h.key.slice(11, 13)}:00 · ${fmtInt(h.n)}${h.alerts ? ` · ${t("nav.alerts")}: ${fmtInt(h.alerts)}` : ""}`;
    return html`<g class="col" data-tip="${label}">
      <rect class="hit" x="${L + i * bw}" y="${T}" width="${bw}" height="${H - T - B}"></rect>
      ${d ? html`<path class="bar" d="${d}"></path>` : ""}
      ${h.alerts ? html`<circle class="alertmark" cx="${x + w / 2}" cy="${Math.max(T - 4, y1 - 9)}" r="5"></circle>` : ""}
      ${i % 3 === 0 ? html`<text x="${x + w / 2}" y="${H - 8}" text-anchor="middle">${h.key.slice(11, 13)}</text>` : ""}
    </g>`;
  });
  return html`<div class="chart" data-chart>
    <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${t("panel.activity")}">
      <g class="grid">${ticks.map((v) => html`<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"></line>`)}</g>
      <g class="axis">${ticks.map((v) => html`<text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${fmtInt(v)}</text>`)}</g>
      <g class="axis">${bars}</g>
    </svg>
  </div>`;
}
function chartDay(stats) {
  const keys = Object.keys(stats.hourly_approvals || {}).sort();
  return keys.length ? fmtDay(`${keys[keys.length - 1].slice(0, 10)}T12:00:00+05:30`) : "";
}
function bindChartTips(root) {
  $$("[data-chart]", root).forEach((chart) => {
    let tip = null;
    chart.addEventListener("mousemove", (e) => {
      const col = e.target.closest("[data-tip]");
      if (!col) { tip?.remove(); tip = null; return; }
      if (!tip) { tip = document.createElement("div"); tip.className = "tip"; chart.appendChild(tip); }
      tip.textContent = col.dataset.tip;
      const box = chart.getBoundingClientRect();
      tip.style.left = `${e.clientX - box.left}px`;
      tip.style.top = `${e.clientY - box.top}px`;
    });
    chart.addEventListener("mouseleave", () => { tip?.remove(); tip = null; });
  });
}
function ruleBars(byRule) {
  const entries = Object.entries(byRule || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return html`<p class="empty">${t("alerts.empty")}</p>`;
  const max = Math.max(...entries.map((e) => e[1]));
  const sev = Object.fromEntries((state.config?.rules || []).map((r) => [r.rule_id, r.severity]));
  return html`<div class="hbar">${entries.map(([rule, n]) => html`
    <div class="name"><span>${rule}</span>${t(`rule.${rule}.name`)}</div><div class="val">${fmtInt(n)}</div>
    <div class="track ${sev[rule] === "CRITICAL" ? "crit" : ""}" title="${t(`severity.${sev[rule] || "LOW"}`)}"><i style="width:${(n / max * 100).toFixed(1)}%"></i></div>`)}
  </div>`;
}

/* ------------------------------------------------------------------ views */

const views = {};

views.overview = async (main) => {
  const s = state.summary || await refreshSummary();
  const k = s.kpi;
  const top = s.top_incident;
  let band;
  if (s.status === "empty") {
    band = html`<section class="band idle"><div>
      <h1>${t("status.empty.title")}</h1><p>${t("status.empty.body")}</p>
      <div class="btn-row"><a class="btn primary" href="#/demo">${t("status.go_demo")}</a><a class="btn" href="#/upload">${t("nav.upload")}</a></div>
    </div><div></div></section>`;
  } else {
    const cls = s.status;
    const facts = top ? html`<div class="facts">
        <span><b>${top.incident_id}</b></span><span>${top.family_label}</span>
        <span>${t("incident.alerts")}: <b class="num">${fmtInt(top.open_alert_count)}</b></span>
        <span>${t("incident.amount")}: <b class="num">${top.amount_short}</b></span>
      </div>` : "";
    const right = top && top.deadline_at && top.reportable
      ? fuse(top.deadline_at, cls === "red" ? "red" : "amber")
      : html`<div class="fuse"><div class="ok">
          <svg width="44" height="44" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm-1.3 14.3-4-4 1.4-1.4 2.6 2.6 5.6-5.6 1.4 1.4-7 7Z"/></svg>
          <div><div class="label">${t("kpi.match_rate")}</div><div class="clock" style="margin:0">${fmtPct(k.match_rate)}</div></div>
        </div><div class="deadline">${t("kpi.checked")}: <b class="num">${fmtInt(k.checked)}</b></div></div>`;
    band = html`<section class="band ${cls}">
      <div>
        <h1>${t(`status.${cls}.title`)}</h1>
        <p>${t(`status.${cls}.body`)}</p>
        ${facts}
        ${top ? html`<div class="btn-row"><a class="btn ${cls === "red" ? "primary" : ""}" href="#/incident/${top.incident_id}">${t("status.open_incident")}</a></div>` : ""}
      </div>
      ${right}
    </section>`;
  }
  const strip = html`<div class="strip">
    <div><div class="k">${t("kpi.checked")}</div><div class="v">${fmtInt(k.checked)}</div></div>
    <div><div class="k">${t("kpi.match_rate")}</div><div class="v">${fmtPct(k.match_rate)}</div></div>
    <div><div class="k">${t("kpi.open_incidents")}</div><div class="v ${k.open_incidents ? "red" : ""}">${fmtInt(k.open_incidents)}</div></div>
    <div><div class="k">${t("kpi.at_risk")}</div><div class="v ${k.amount_at_risk_paise ? "red" : ""}">${k.amount_at_risk_paise ? k.amount_at_risk : "₹0"}</div></div>
    <div><div class="k">${t("kpi.queued")}</div><div class="v">${fmtInt(k.queued_messages)}</div></div>
  </div>`;
  const matchWindow = state.config?.engine?.match_window_seconds || 180;
  setHTML(main, html`${band}${strip}
    <div class="cols">
      <section class="panel"><h2>${t("panel.activity")}<small>${chartDay(s.stats)}</small></h2>${hourlyChart(s.stats, s.alerts.by_hour || {})}
        <p class="muted small" style="margin:6px 0 0">${t("panel.activity.hint")}</p></section>
      <section class="panel"><h2>${t("panel.by_rule")}</h2>${ruleBars(s.alerts.by_rule)}</section>
    </div>
    <section style="margin-top:26px"><h2>${t("panel.latest")}</h2>
      <div class="table-wrap"><table class="ledger">${alertHead()}<tbody>${alertRows(s.latest_alerts)}</tbody></table></div>
    </section>
    <section><h2>${t("panel.how")}</h2>
      <ol class="steps">
        <li><b>${t("how.watch")}.</b> ${t("how.watch.body")}</li>
        <li><b>${t("how.match")}.</b> ${t("how.match.body", { window: matchWindow })}</li>
        <li><b>${t("how.mask")}.</b> ${t("how.mask.body")}</li>
        <li><b>${t("how.report")}.</b> ${t("how.report.body")}</li>
      </ol>
    </section>`);
  bindAlertRows(main);
  bindChartTips(main);
};

views.alerts = async (main) => {
  const q = state.alertsQuery;
  const params = new URLSearchParams({ lang: state.lang, limit: "100", offset: String(q.offset) });
  if (q.severity) params.set("severity", q.severity);
  if (q.rule) params.set("rule", q.rule);
  if (q.status) params.set("status", q.status);
  if (q.incident) params.set("incident", q.incident);
  const data = await api(`/api/alerts?${params}`);
  const rules = (state.config?.rules || []).map((r) => r.rule_id);
  const opt = (value, label, current) => html`<option value="${value}" ${value === current ? raw("selected") : ""}>${label}</option>`;
  setHTML(main, html`
    <div class="page-head"><h1>${t("alerts.title")}</h1><p>${t("alerts.intro")}</p></div>
    ${q.incident ? html`<p class="btn-row"><span class="tag neutral plain">${t("col.incident")}: ${q.incident}</span><button class="btn" id="f-clear">${t("common.all")}</button></p>` : ""}
    <div class="btn-row" style="margin-bottom:12px">
      <label class="field" style="margin:0;min-width:150px"><span>${t("col.severity")}</span><select id="f-sev">${opt("", t("common.all"), q.severity)}${["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => opt(s, t(`severity.${s}`), q.severity))}</select></label>
      <label class="field" style="margin:0;min-width:240px"><span>${t("col.rule")}</span><select id="f-rule">${opt("", t("common.all"), q.rule)}${rules.map((r) => opt(r, `${r} ${t(`rule.${r}.name`)}`, q.rule))}</select></label>
      <label class="field" style="margin:0;min-width:200px"><span>${t("col.status")}</span><select id="f-status">${opt("", t("common.all"), q.status)}${opt("OPEN", t("alert.status.OPEN"), q.status)}${opt("AUTO_RESOLVED", t("alert.status.AUTO_RESOLVED"), q.status)}</select></label>
    </div>
    <div class="table-wrap"><table class="ledger">${alertHead()}<tbody>${alertRows(data.items, { fresh: false })}</tbody></table></div>
    <div class="btn-row" style="margin-top:12px;justify-content:space-between">
      <span class="muted small">${t("alerts.showing", { shown: fmtInt(data.items.length), total: fmtInt(data.total) })}</span>
      <span class="btn-row">
        <button class="btn" id="prev" ${q.offset ? "" : raw("disabled")}>${t("common.prev")}</button>
        <button class="btn" id="next" ${q.offset + 100 < data.total ? "" : raw("disabled")}>${t("common.next")}</button>
      </span>
    </div>`);
  const refilter = () => { q.severity = $("#f-sev").value; q.rule = $("#f-rule").value; q.status = $("#f-status").value; q.offset = 0; render(); };
  ["#f-sev", "#f-rule", "#f-status"].forEach((id) => $(id).addEventListener("change", refilter));
  $("#f-clear")?.addEventListener("click", () => { q.incident = ""; q.offset = 0; render(); });
  $("#prev").addEventListener("click", () => { q.offset = Math.max(0, q.offset - 100); render(); });
  $("#next").addEventListener("click", () => { q.offset += 100; render(); });
  bindAlertRows(main);
};

views.incidents = async (main) => {
  const items = await api(`/api/incidents?lang=${state.lang}`);
  const rows = items.map((i) => {
    const active = ["OPEN", "CONFIRMED"].includes(i.status);
    let right;
    if (active && i.reportable && i.deadline_at) {
      right = html`<div><span class="muted small">${t("incident.time_left")}</span> <b class="num" data-left>${fmtDuration(secondsLeft(i.deadline_at))}</b>${fuse(i.deadline_at, "red", false)}</div>`;
    } else if (active) {
      right = html`<span class="muted small">${t("incident.not_reportable")}</span>`;
    } else if (i.status === "REPORTED") {
      right = html`<span class="small">${t("incident.reported_as", { ref: i.daksh_ref })}</span>`;
    } else {
      right = html`<span class="muted small">${i.status === "DISMISSED" ? t("incident.dismissed_as", { reason: i.dismissed_reason || "" }) : t(`incident.status.${i.status}`)}</span>`;
    }
    return html`<a class="inc-row" href="#/incident/${i.incident_id}">
      <div><div class="id">${i.incident_id}</div><div>${i.family_label}</div>
        <div class="btn-row" style="margin-top:4px">${sevTag(i.severity, i.severity_label)}${statusTag(i.status)}</div></div>
      <div class="small"><div>${t("incident.alerts")}: <b class="num">${fmtInt(i.open_alert_count)}</b> / ${fmtInt(i.alert_count)}</div>
        <div>${t("incident.amount")}: <b class="num">${i.amount}</b></div>
        <div>${t("incident.accounts")}: <b class="num">${fmtInt(i.accounts)}</b></div></div>
      <div>${right}</div>
    </a>`;
  });
  setHTML(main, html`<div class="page-head"><h1>${t("incidents.title")}</h1><p>${t("incidents.intro")}</p></div>
    ${items.length ? html`<div class="inc-list">${rows}</div>` : html`<div class="inc-list"><p class="empty">${t("incidents.empty")}</p></div>`}`);
};

views.incident = async (main, id) => {
  const d = await api(`/api/incidents/${encodeURIComponent(id)}?lang=${state.lang}`);
  const shown = d.alerts.slice(0, 25);
  const i = d.incident;
  const active = ["OPEN", "CONFIRMED"].includes(i.status);
  const officer = store.get("sg.officer", "");
  let clock;
  if (active && i.reportable && i.deadline_at) clock = fuse(i.deadline_at, "red");
  else if (i.status === "REPORTED") clock = notice(t("incident.reported_as", { ref: i.daksh_ref }), "ok");
  else if (i.status === "DISMISSED") clock = notice(t("incident.dismissed_as", { reason: i.dismissed_reason || "" }));
  else if (!i.reportable) clock = notice(t("incident.not_reportable"));
  else clock = notice(t(`incident.status.${i.status}`), "ok");
  const reportLinks = ["en", "ta", "hi"].map((l) => html`<a class="btn" target="_blank" rel="noopener" href="${withKey(`/api/incidents/${i.incident_id}/report.html?lang=${l}`)}">${{ en: "English", ta: "தமிழ்", hi: "हिन्दी" }[l]}</a>`);
  setHTML(main, html`
    <p style="margin:0 0 10px"><a href="#/incidents">${t("incident.back")}</a></p>
    <div class="inc-head"><h1>${i.incident_id}</h1>${sevTag(i.severity, i.severity_label)}${statusTag(i.status)}</div>
    <p style="margin:0 0 16px;color:var(--ink-2)">${i.family_label}</p>
    <div class="cols" style="margin-top:0">
      <div>${clock}</div>
      <section class="panel"><h2>${t("incident.report")}</h2>
        <div class="btn-row">${t("incident.view_report")}: ${reportLinks}</div>
        <div class="btn-row" style="margin-top:10px"><a class="btn" href="${withKey(`/api/incidents/${i.incident_id}/report.json?lang=${state.lang}&download=true`)}">${t("incident.download_json")}</a></div>
      </section>
    </div>
    <div class="facts-grid">
      <div><div class="k">${t("incident.alerts")}</div><div class="v">${fmtInt(i.open_alert_count)}</div></div>
      <div><div class="k">${t("incident.amount")}</div><div class="v">${i.amount}</div></div>
      <div><div class="k">${t("incident.accounts")}</div><div class="v">${fmtInt(i.accounts)}</div></div>
      <div><div class="k">${t("incident.channels")}</div><div class="v">${i.channels.join(", ") || "-"}</div></div>
      <div><div class="k">${t("incident.first_event")}</div><div class="v small">${fmtTime(i.first_event_at)}</div></div>
      <div><div class="k">${t("incident.opened")}</div><div class="v small">${fmtTime(i.opened_at)}</div></div>
    </div>
    <div class="cols" style="margin-top:0">
      <section class="panel"><h2>${t("incident.actions")}</h2><ol class="steps">${(d.actions || []).map((a) => html`<li>${a}</li>`)}</ol></section>
      <section class="panel" id="officer"><h2>${t("incident.officer_actions")}</h2>
        ${active ? html`
          <label class="field"><span>${t("incident.officer")}</span><input type="text" id="o-name" value="${officer}" maxlength="120" autocomplete="name"></label>
          <div class="btn-row">
            ${i.status === "OPEN" ? html`<button class="btn primary" data-act="confirm">${t("incident.confirm")}</button>` : ""}
            ${i.reportable ? html`<button class="btn" data-act="report">${t("incident.mark_reported")}</button>` : ""}
            <button class="btn danger" data-act="dismiss">${t("incident.dismiss")}</button>
          </div>
          <div id="act-form" style="margin-top:12px"></div>
          <div id="act-msg" style="margin-top:10px"></div>` : html`<p class="muted">${i.officer ? `${t("incident.officer")}: ${i.officer}` : t(`incident.status.${i.status}`)}</p>`}
      </section>
    </div>
    <section><h2>${t("incident.alerts")} <span class="muted small">(${fmtInt(shown.length)} / ${fmtInt(d.alerts_total)})</span></h2>
      <div class="table-wrap"><table class="ledger">${alertHead()}<tbody>${alertRows(shown, { fresh: false })}</tbody></table></div>
      ${d.alerts_total > shown.length ? html`<p><a href="#/alerts" data-incident-filter="${i.incident_id}">${t("incident.all_alerts", { n: fmtInt(d.alerts_total) })}</a></p>` : ""}</section>
    <section><h2>${t("incident.timeline")}</h2>
      <ul class="timeline">${d.timeline.map((e) => html`<li><time>${fmtTime(e.at)}</time>${e.label}${e.actor && e.actor !== "system" ? ` · ${e.actor}` : ""}${e.note && !["OPENED", "NOTIFIED"].includes(e.action) ? html` <span class="muted">(${e.note})</span>` : ""}</li>`)}</ul>
    </section>`);
  bindAlertRows(main);
  $$("[data-incident-filter]", main).forEach((a) => a.addEventListener("click", () => {
    Object.assign(state.alertsQuery, { incident: a.dataset.incidentFilter, status: "", severity: "", rule: "", offset: 0 });
  }));
  $$("[data-act]", main).forEach((b) => b.addEventListener("click", () => showActionForm(i, b.dataset.act)));
};

function showActionForm(i, act) {
  const box = $("#act-form");
  const msg = $("#act-msg");
  setHTML(msg, "");
  const field = (id, label, extra = "") => html`<label class="field"><span>${label}</span><input type="text" id="${id}" maxlength="${extra || 200}"></label>`;
  let form;
  if (act === "confirm") form = html``;
  else if (act === "dismiss") form = field("o-reason", t("incident.reason"), "500");
  else form = html`${field("o-daksh", t("incident.daksh_ref"), "80")}${field("o-certin", t("incident.certin_ref"), "80")}`;
  setHTML(box, html`${form}<div class="btn-row"><button class="btn primary" id="o-save">${t("incident.save")}</button><button class="btn" id="o-cancel">${t("incident.cancel")}</button></div>`);
  $("#o-cancel").addEventListener("click", () => setHTML(box, ""));
  $("#o-save").addEventListener("click", async () => {
    const officer = $("#o-name").value.trim();
    store.set("sg.officer", officer);
    const path = { confirm: "confirm", dismiss: "dismiss", report: "reported" }[act];
    const body = { officer };
    if (act === "dismiss") body.reason = $("#o-reason").value.trim();
    if (act === "report") { body.daksh_ref = $("#o-daksh").value.trim(); body.certin_ref = $("#o-certin").value.trim(); }
    try {
      $("#o-save").disabled = true;
      await api(`/api/incidents/${encodeURIComponent(i.incident_id)}/${path}`, { method: "POST", json: body });
      await refreshSummary();
      render();
    } catch (err) {
      setHTML(msg, notice(err.message, "error"));
      $("#o-save").disabled = false;
    }
  });
}

/* ------------------------------------------------------------------ alert drawer */

async function openAlert(id) {
  const root = $("#drawer-root");
  const a = await api(`/api/alerts/${encodeURIComponent(id)}?lang=${state.lang}`);
  const ev = a.evidence || [];
  const p = a.params || {};
  let three = "";
  if (a.rule_id !== "SG-R5") {
    const network = ev.filter((e) => e.feed === "settlement").reduce((s, e) => s + Math.round(parseFloat(e.amount) * 100), 0);
    const sw = Number(p.switch_amount) || 0, lg = Number(p.ledger_amount) || 0;
    const swBad = a.rule_id === "SG-R6" || (a.rule_id === "SG-R3" && p.feed === "switch");
    const lgBad = ["SG-R1", "SG-R2", "SG-R3", "SG-R4", "SG-R7", "SG-R8"].includes(a.rule_id) && !(a.rule_id === "SG-R3" && p.feed === "switch");
    three = html`<div class="three-way">
      <div class="${swBad ? "bad" : ""}"><div class="k">${t("word.switch")}</div><div class="v">${rupees(sw)}</div></div>
      <div class="${lgBad ? "bad" : ""}"><div class="k">${t("word.ledger")}</div><div class="v">${rupees(lg)}</div></div>
      <div><div class="k">${t("word.network")}</div><div class="v">${network ? rupees(network) : "-"}</div></div>
    </div>`;
  }
  const cols = ["feed", "ts", "msg_type", "drcr", "direction", "amount", "response_code", "account", "card", "terminal_country", "narration", "cycle_id"];
  const used = cols.filter((c) => ev.some((e) => e[c] !== undefined && e[c] !== "" && e[c] !== null));
  setHTML(root, html`<div class="scrim" data-close></div>
    <aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
      <button class="btn close" data-close aria-label="${t("common.close")}">${t("common.close")}</button>
      <div class="btn-row">${sevTag(a.severity, a.severity_label)}<span class="tag neutral plain">${a.status_label}</span></div>
      <h2 id="drawer-title" style="font-size:21px;margin:10px 0 4px">${a.rule_id} · ${a.name}</h2>
      <p class="muted small" style="margin:0">${fmtTime(a.event_time)} · ${t("alerts.detected_after", { duration: fmtDuration(a.detected_after_seconds) })}</p>
      <h2 style="margin-top:18px">${t("alerts.explain")}</h2>
      <p style="margin:0">${a.message}</p>
      ${three}
      ${a.note ? notice(a.note, "ok") : ""}
      ${a.incident_id ? html`<p><a href="#/incident/${a.incident_id}" data-close>${t("status.open_incident")} ${a.incident_id}</a></p>` : ""}
      <h2 style="margin-top:18px">${t("alerts.evidence")}</h2>
      <div class="table-wrap"><table class="ledger"><thead><tr>${used.map((c) => html`<th>${c}</th>`)}</tr></thead>
        <tbody>${ev.map((e) => html`<tr>${used.map((c) => html`<td class="${c === "amount" ? "amt" : "ref"}">${c === "ts" ? fmtClock(e[c]) : e[c] === true ? "1" : e[c] === false ? "0" : (e[c] ?? "")}</td>`)}</tr>`)}</tbody></table></div>
    </aside>`);
  const close = () => { setHTML(root, ""); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  $$("[data-close]", root).forEach((el) => el.addEventListener("click", close));
  $(".drawer .close", root).focus();
}

/* ------------------------------------------------------------------ demo lab */

views.demo = async (main) => {
  const scenarios = state.config?.scenarios || [];
  const noise = new Set(["normal", "slowcbs"]);
  setHTML(main, html`
    <div class="page-head"><h1>${t("demo.title")}</h1><p>${t("demo.intro")}</p></div>
    <div class="demo">
      <div>
        <div class="scenarios" role="radiogroup" aria-label="${t("bench.scenario")}">
          ${scenarios.map((s) => html`<label class="scenario">
            <input type="radio" name="scenario" value="${s}" ${s === state.scenario ? raw("checked") : ""}>
            <b>${t(`scenario.${s}.name`)}<span class="kind">${noise.has(s) ? t("demo.kind.noise") : t("demo.kind.attack")}</span></b>
            <p>${t(`scenario.${s}.desc`)}</p></label>`)}
        </div>
      </div>
      <aside class="player" id="player"></aside>
    </div>`);
  $$("input[name=scenario]", main).forEach((r) => r.addEventListener("change", () => { state.scenario = r.value; store.set("sg.scenario", r.value); }));
  renderPlayer();
};

// The player is rendered in two layers so polling never resets what the user is typing:
// the controls are rebuilt only when the demo starts or stops; the status and the
// network section are refreshed in place on every poll.
function playerStatus(d, s) {
  return html`
    <div class="muted small">${t("demo.clock")}</div>
    <div class="clock">${fmtClock(d.sim_clock)}</div>
    <div class="phase">${d.sim_clock ? `${fmtDay(d.sim_clock)} · ` : ""}${t(`demo.phase.${d.phase}`)}${d.scenario ? ` · ${t(`scenario.${d.scenario}.name`)}` : ""}</div>
    <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round((d.progress || 0) * 100)}"><i style="width:${((d.progress || 0) * 100).toFixed(1)}%"></i></div>
    <dl>
      <dt>${t("demo.events")}</dt><dd>${fmtInt(d.events_done || 0)} / ${fmtInt(d.events_total || 0)}</dd>
      <dt>${t("demo.alerts_so_far")}</dt><dd>${fmtInt(d.new_alerts || 0)}</dd>
      <dt>${t("kpi.open_incidents")}</dt><dd>${fmtInt(s.kpi.open_incidents)}</dd>
    </dl>
    ${d.error ? notice(d.error, "error") : ""}`;
}

function renderPlayer() {
  const box = $("#player");
  if (!box || !state.summary) return;
  const s = state.summary;
  const d = s.demo || { phase: "idle" };
  const running = ACTIVE_DEMO.includes(d.phase);
  const mode = `${running}|${state.lang}`;
  if (box.dataset.mode === mode) {
    setHTML($("#p-status", box), playerStatus(d, s));
    const net = $("#d-net", box);
    if (net && document.activeElement !== net) net.checked = !s.network_online;
    setHTML($("#p-queue", box), html`${t("kpi.queued")}: <b class="num">${fmtInt(s.kpi.queued_messages)}</b> · ${t("outbox.sent")}: <b class="num">${fmtInt(s.outbox.SENT || 0)}</b>`);
    const flush = $("#d-flush", box);
    if (flush) flush.disabled = !s.kpi.queued_messages;
    return;
  }
  box.dataset.mode = mode;
  setHTML(box, html`
    <div id="p-status">${playerStatus(d, s)}</div>
    <div class="row2">
      <label class="field"><span>${t("demo.speed")}</span>
        <select id="d-speed" ${running ? raw("disabled") : ""}>${[30, 60, 120, 300, 600].map((v) => html`<option value="${v}" ${v === (running ? d.speed : state.speed) ? raw("selected") : ""}>×${v}</option>`)}</select></label>
      <label class="field"><span>${t("demo.seed")}</span><input type="number" id="d-seed" min="0" max="10000000" value="${store.get("sg.seed", "42")}" ${running ? raw("disabled") : ""}></label>
    </div>
    <div class="btn-row">
      ${running ? html`<button class="btn danger" id="d-stop">${t("demo.stop")}</button>`
        : html`<button class="btn primary" id="d-play">${t("demo.start")}</button><button class="btn" id="d-instant">${t("demo.instant")}</button>`}
    </div>
    <div id="d-msg" style="margin-top:10px"></div>
    <hr>
    <h2>${t("demo.network_title")}</h2>
    <label class="toggle"><input type="checkbox" id="d-net" ${s.network_online ? "" : raw("checked")}><span class="track"></span><span>${t("network.simulate")}</span></label>
    <p class="muted small">${t("network.offline.hint")}</p>
    <div class="btn-row"><span class="small" id="p-queue">${t("kpi.queued")}: <b class="num">${fmtInt(s.kpi.queued_messages)}</b> · ${t("outbox.sent")}: <b class="num">${fmtInt(s.outbox.SENT || 0)}</b></span>
      <button class="btn" id="d-flush" ${s.kpi.queued_messages ? "" : raw("disabled")}>${t("network.flush")}</button></div>
    <hr>
    <button class="btn danger" id="d-reset" ${running ? raw("disabled") : ""}>${t("demo.reset")}</button>`);
  const msg = $("#d-msg");
  const refresh = async () => { await refreshSummary(); updateShell(); renderPlayer(); };
  const start = async (instant) => {
    state.speed = Number($("#d-speed").value);
    store.set("sg.speed", String(state.speed));
    const seed = Math.max(0, Math.min(10000000, parseInt($("#d-seed").value || "42", 10) || 0));
    store.set("sg.seed", String(seed));
    try {
      await api("/api/demo/start", { method: "POST", json: { scenario: state.scenario, speed: state.speed, seed, instant } });
      state.seen.clear();
      await refresh();
      schedulePoll(0);
    } catch (err) { setHTML(msg, notice(err.message, "error")); }
  };
  $("#d-play")?.addEventListener("click", () => start(false));
  $("#d-instant")?.addEventListener("click", () => start(true));
  $("#d-stop")?.addEventListener("click", async () => {
    try { await api("/api/demo/stop", { method: "POST" }); } catch (err) { setHTML(msg, notice(err.message, "error")); }
  });
  $("#d-net").addEventListener("change", async (e) => {
    try { await api("/api/network", { method: "POST", json: { online: !e.target.checked } }); await refresh(); }
    catch (err) { setHTML(msg, notice(err.message, "error")); }
  });
  $("#d-flush").addEventListener("click", async () => {
    try { await api("/api/outbox/flush", { method: "POST" }); await refresh(); }
    catch (err) { setHTML(msg, notice(err.message, "error")); }
  });
  $("#d-reset").addEventListener("click", async () => {
    if (!window.confirm(t("demo.reset_confirm"))) return;
    try { await api("/api/reset", { method: "POST" }); state.seen.clear(); await refresh(); }
    catch (err) { setHTML(msg, notice(err.message, "error")); }
  });
}

/* ------------------------------------------------------------------ upload */

views.upload = async (main) => {
  const sample = (kind, label) => html`<a href="${withKey(`/api/samples/cosmos/${kind}.csv`)}" download>${label}</a>`;
  setHTML(main, html`
    <div class="page-head"><h1>${t("upload.title")}</h1><p>${t("upload.intro")}</p></div>
    <div class="split">
      <section class="panel">
        <label class="field"><span>${t("upload.switch")}</span><input type="file" id="u-switch" accept=".csv,text/csv"></label>
        <label class="field"><span>${t("upload.ledger")}</span><input type="file" id="u-ledger" accept=".csv,text/csv"></label>
        <label class="field"><span>${t("upload.settlement")}</span><input type="file" id="u-settlement" accept=".csv,text/csv"></label>
        <button class="btn primary" id="u-run">${t("upload.run")}</button>
        <p class="small muted" style="margin-bottom:0">${t("upload.samples")}: ${sample("switch", "switch_log.csv")} · ${sample("ledger", "cbs_ledger.csv")} · ${sample("settlement", "settlement.csv")}</p>
      </section>
      <section class="panel"><h2>${t("upload.result")}</h2><div id="u-out" class="muted">-</div></section>
    </div>`);
  $("#u-run").addEventListener("click", async () => {
    const out = $("#u-out");
    const files = ["switch", "ledger", "settlement"].map((k) => $(`#u-${k}`).files[0]).filter(Boolean);
    if (!$("#u-switch").files[0] || !$("#u-ledger").files[0]) { setHTML(out, notice(t("upload.need_files"), "error")); return; }
    const fd = new FormData();
    files.forEach((f) => fd.append("files", f, f.name));
    $("#u-run").disabled = true;
    setHTML(out, t("common.loading"));
    try {
      const r = await api("/api/upload", { method: "POST", body: fd });
      setHTML(out, html`
        ${notice(t("upload.new_alerts", { n: fmtInt(r.new_alerts) }), r.new_alerts ? "error" : "ok")}
        <div class="table-wrap" style="margin-top:12px"><table class="ledger"><thead><tr><th>${t("col.feed")}</th><th class="amt">${t("upload.rows")}</th><th class="amt">${t("upload.parsed")}</th><th class="amt">${t("upload.rejected")}</th></tr></thead>
        <tbody>${r.files.map((f) => html`<tr><td><b>${f.kind}</b><br><span class="small muted">${f.name}</span><br><span class="small muted ref">${t("upload.sha")}: ${f.sha256.slice(0, 16)}…</span>
          ${f.errors.length ? html`<ul class="small">${f.errors.slice(0, 5).map((e) => html`<li>#${e.line}: ${e.message}</li>`)}</ul>` : ""}</td>
          <td class="amt">${fmtInt(f.rows)}</td><td class="amt">${fmtInt(f.parsed)}</td><td class="amt">${fmtInt(f.rejected)}</td></tr>`)}</tbody></table></div>
        <div class="btn-row" style="margin-top:12px"><a class="btn" href="#/alerts">${t("nav.alerts")}</a><a class="btn" href="#/incidents">${t("nav.incidents")}</a></div>`);
      await refreshSummary(); updateShell();
    } catch (err) { setHTML(out, notice(err.message, "error")); }
    finally { $("#u-run").disabled = false; }
  });
};

/* ------------------------------------------------------------------ privacy */

const PRIVACY_SAMPLE = [
  "KYC UPDATE: Aadhaar 2345 6789 0124, PAN ABCPE1234F, mobile +91 98765 43210",
  "UPI/630511004211/kavitha.raman@oksbi/Rent for November",
  "IMPS from a/c no 001010001234567 to 9876543210@ybl, RRN 630511004219",
  "Card 6080 0112 3456 7896 used at ATMCGL004; customer email selvi.k@example.com",
].join("\n");

function highlightMasks(text) {
  const parts = String(text).split(/(X[X-]{2,}[0-9A-Z]*(?:@[A-Za-z0-9.]*[A-Za-z0-9])?|\w\*\*\*@[A-Za-z0-9.-]*[A-Za-z0-9])/g);
  return parts.map((p, i) => (i % 2 ? html`<mark>${p}</mark>` : p));
}

views.privacy = async (main) => {
  setHTML(main, html`
    <div class="page-head"><h1>${t("privacy.title")}</h1><p>${t("privacy.intro")}</p></div>
    <div class="split">
      <section>
        <label class="field"><span>${t("privacy.input")}</span><textarea id="p-in" spellcheck="false"></textarea></label>
        <div class="btn-row"><button class="btn primary" id="p-mask">${t("privacy.mask")}</button><button class="btn" id="p-sample">${t("privacy.sample")}</button></div>
      </section>
      <section>
        <div class="field"><span class="muted small">${t("privacy.output")}</span><div class="mask-out" id="p-out" aria-live="polite"></div></div>
        <div id="p-counts"></div>
      </section>
    </div>
    <section class="panel" style="margin-top:26px">
      <h2>${t("privacy.csv")}</h2><p class="muted small" style="margin-top:0">${t("privacy.csv.hint")}</p>
      <div class="btn-row"><input type="file" id="p-file" accept=".csv,text/csv" style="max-width:360px"><button class="btn primary" id="p-csv">${t("privacy.mask_file")}</button></div>
      <div id="p-csv-out" style="margin-top:14px"></div>
    </section>`);
  const chips = (counts) => {
    const entries = Object.entries(counts || {}).filter(([, n]) => n);
    return entries.length
      ? html`<p class="small" style="margin:10px 0 4px">${t("privacy.found")}</p><div class="chips">${entries.map(([k, n]) => html`<span class="tag ok plain">${t(`pii.${k}`)}: ${fmtInt(n)}</span>`)}</div>`
      : html`<p class="muted small">${t("privacy.none")}</p>`;
  };
  $("#p-sample").addEventListener("click", () => { $("#p-in").value = PRIVACY_SAMPLE; });
  $("#p-mask").addEventListener("click", async () => {
    try {
      const r = await api("/api/privacy/mask-text", { method: "POST", json: { text: $("#p-in").value } });
      setHTML($("#p-out"), html`${highlightMasks(r.text)}`);
      setHTML($("#p-counts"), chips(r.counts));
    } catch (err) { setHTML($("#p-counts"), notice(err.message, "error")); }
  });
  $("#p-csv").addEventListener("click", async () => {
    const out = $("#p-csv-out");
    const f = $("#p-file").files[0];
    if (!f) return;
    const fd = new FormData(); fd.append("file", f, f.name);
    try {
      const r = await api("/api/privacy/mask-csv", { method: "POST", body: fd });
      const url = URL.createObjectURL(new Blob([r.csv], { type: "text/csv;charset=utf-8" }));
      setHTML(out, html`<p>${t("upload.rows")}: <b class="num">${fmtInt(r.report.rows)}</b></p>${chips(r.report.counts)}
        <div class="table-wrap" style="margin:12px 0"><table class="ledger"><thead><tr><th>${t("col.details")}</th><th>${t("privacy.columns")}</th></tr></thead>
        <tbody>${Object.entries(r.report.columns).map(([c, p]) => html`<tr><td class="ref">${c}</td><td>${p}</td></tr>`)}</tbody></table></div>
        <a class="btn primary" href="${url}" download="${r.filename}">${t("privacy.download")}</a>`);
    } catch (err) { setHTML(out, notice(err.message, "error")); }
  });
};

/* ------------------------------------------------------------------ benchmark */

views.benchmark = async (main) => {
  const st = await api("/api/benchmark");
  const r = st.result;
  const running = st.phase === "running";
  const row = (x) => html`<tr>
    <td><b>${t(`scenario.${x.scenario}.name`)}</b><br><span class="small muted">${(x.rules_fired || []).join(", ") || "-"}</span></td>
    <td class="amt">${fmtInt(x.attack_transactions)}</td>
    <td>${x.detected === null ? "-" : x.detected ? html`<span class="tag ok plain">${t("common.yes")}</span>` : html`<span class="tag CRITICAL plain">${t("common.no")}</span>`}</td>
    <td class="amt">${x.recall === null ? "-" : `${(x.recall * 100).toFixed(1)}%`}</td>
    <td class="amt">${fmtInt(x.false_alerts)}</td>
    <td class="amt">${fmtInt(x.transient_alerts)}</td>
    <td class="amt">${fmtDuration(x.first_alert_seconds)}</td>
    <td class="amt">${fmtDuration(x.median_ttd_seconds)}</td>
    <td class="amt">${fmtDuration(x.p95_ttd_seconds)}</td>
    <td class="amt">${fmtDuration(x.eod_baseline_seconds)}</td></tr>`;
  setHTML(main, html`
    <div class="page-head"><h1>${t("bench.title")}</h1><p>${t("bench.intro")}</p></div>
    <div class="btn-row" style="margin-bottom:14px"><button class="btn primary" id="b-run" ${running ? raw("disabled") : ""}>${running ? t("bench.running") : t("bench.run")}</button>
      ${r ? html`<span class="muted small">${t("bench.generated")}: ${fmtTime(r.generated_at)} · ${t("bench.normal_events")}: ${fmtInt(r.transactions_per_day)} · ${t("bench.throughput")}: <b>${fmtInt(r.throughput_events_per_second)}</b> ${t("bench.events_per_sec")}</span>` : ""}</div>
    ${st.error ? notice(st.error, "error") : ""}
    ${r ? html`<div class="table-wrap"><table class="ledger bench"><thead><tr>
        <th>${t("bench.scenario")}</th><th class="amt">${t("bench.attack_txns")}</th><th>${t("bench.detected")}</th><th class="amt">${t("bench.recall")}</th>
        <th class="amt">${t("bench.false")}</th><th class="amt">${t("bench.transient")}</th><th class="amt">${t("bench.first")}</th><th class="amt">${t("bench.median")}</th>
        <th class="amt">${t("bench.p95")}</th><th class="amt">${t("bench.eod")}</th></tr></thead>
        <tbody>${r.results.map(row)}</tbody></table></div>` : html`<div class="panel"><p class="empty">${t("bench.none")}</p></div>`}`);
  $("#b-run").addEventListener("click", async () => {
    await api("/api/benchmark/run", { method: "POST", json: {} });
    render();
  });
  clearTimeout(state.benchTimer);
  if (running) state.benchTimer = setTimeout(() => { if (currentRoute().name === "benchmark") render(); }, 1500);
};

/* ------------------------------------------------------------------ about */

views.about = async (main) => {
  const rules = state.config?.rules || [];
  setHTML(main, html`
    <div class="page-head"><h1>${t("about.title")}</h1></div>
    <section style="max-width:72ch"><p>${t("about.p1")}</p><p>${t("about.p2")}</p></section>
    <section><h2>${t("about.rules")}</h2>
      <div class="table-wrap"><table class="ledger"><thead><tr><th>${t("col.rule")}</th><th>${t("col.details")}</th><th>${t("col.severity")}</th></tr></thead>
      <tbody>${rules.map((r) => html`<tr><td class="ref"><b>${r.rule_id}</b></td><td>${t(`rule.${r.rule_id}.name`)}<br><span class="small muted">${t(`family.${r.family}`)}</span></td><td>${sevTag(r.severity)}</td></tr>`)}</tbody></table></div>
    </section>
    <section style="max-width:72ch"><h2>${t("about.limits")}</h2>
      <ul><li>${t("about.l1")}</li><li>${t("about.l2")}</li><li>${t("about.l3")}</li><li>${t("about.l4")}</li></ul></section>
    <p class="footer">Sahakari-Guard ${state.config?.version || ""} · MIT licence · Hind / Hind Madurai fonts by Indian Type Foundry (SIL OFL) · ${t("app.synthetic")}</p>`);
};

/* ------------------------------------------------------------------ router & polling */

function currentRoute() {
  const parts = (location.hash.replace(/^#\/?/, "") || "overview").split("/");
  const name = views[parts[0]] ? parts[0] : "overview";
  return { name, arg: parts.slice(1).join("/") ? decodeURIComponent(parts.slice(1).join("/")) : null };
}

let renderSeq = 0;
async function render() {
  const { name, arg } = currentRoute();
  const nav = name === "incident" ? "incidents" : name;
  $$("#nav a").forEach((a) => (a.dataset.route === nav ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  const main = $("#main");
  const seq = ++renderSeq;
  try {
    await views[name](main, arg);
  } catch (err) {
    if (seq === renderSeq) setHTML(main, notice(`${t("common.error")}: ${err.message}`, "error"));
  }
  state.firstLoad = false;
}

async function refreshSummary() {
  const before = Date.now();
  const s = await api(`/api/summary?lang=${state.lang}`);
  const after = Date.now();
  state.skew = Date.parse(s.server_time) - (before + after) / 2;
  state.summary = s;
  return s;
}

function schedulePoll(delay) {
  clearTimeout(state.pollTimer);
  state.pollTimer = setTimeout(poll, delay);
}

async function poll() {
  let wasRunning = ACTIVE_DEMO.includes(state.summary?.demo?.phase);
  try {
    await refreshSummary();
    updateShell();
    const running = ACTIVE_DEMO.includes(state.summary.demo?.phase);
    const route = currentRoute().name;
    if (route === "overview") await views.overview($("#main"));
    if (route === "demo") renderPlayer();
    if (wasRunning && !running && (route === "alerts" || route === "incidents")) render();
    wasRunning = running;
  } catch (err) {
    console.warn("poll failed", err);
  }
  schedulePoll(ACTIVE_DEMO.includes(state.summary?.demo?.phase) ? 1000 : 4000);
}

async function boot() {
  try {
    await loadLang(state.lang);
    state.config = await api("/api/config");
    $("#bank-name").textContent = `${state.config.bank.name} · ${state.config.bank.location}`;
    await refreshSummary();
    updateShell();
  } catch (err) {
    setHTML($("#main"), notice(`${t("common.error")}: ${err.message}`, "error"));
    return;
  }
  $$(".langs button").forEach((b) => b.addEventListener("click", async () => {
    await loadLang(b.dataset.lang);
    await refreshSummary();
    updateShell();
    render();
  }));
  window.addEventListener("hashchange", () => { render(); $("#main").focus({ preventScroll: true }); window.scrollTo(0, 0); });
  await render();
  setInterval(tickFuses, 1000);
  schedulePoll(ACTIVE_DEMO.includes(state.summary?.demo?.phase) ? 1000 : 4000);
}

boot();
