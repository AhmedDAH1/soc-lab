"use strict";
/* SOC Lab live console.
   Polls /api/events, keeps a model of what the lab has done, and draws it.
   Every value from the lab (packet fields, User-Agents, tool output, incident
   titles) is attacker-influenced, so it only ever reaches the page as text
   (textContent), never as HTML. */

const $ = (id) => document.getElementById(id);

function el(tag, attrs, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "on") for (const [name, fn] of Object.entries(v)) node.addEventListener(name, fn);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return node;
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + "s")}`;
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false }) + "." + String(Math.floor((ts % 1) * 1000)).padStart(3, "0");

/* ── What the lab has done so far ───────────────────────── */
const M = {
  cursor: 0, epoch: null, live: false, state: null, down: false,
  lines: { scan: [], logs: [], email: [] },
  packets: [], tapFull: false,
  rules: [], alerts: [], webhooks: [], targetEvents: [],
  incidents: new Map(), triage: new Map(), asked: new Set(), lane: new Map(),
  forged: [],
  selected: "scan", open: {}, changed: new Set(["all"]),
};

const LANES = [
  { id: "scan", name: "Scan the network", go: "Start the scan",
    blurb: "NetScan, the attacker, probes the target's ports 1 to 100 and reads the versions of what answers. Suricata watches a copy of that traffic. When a packet matches one of the rules written for NetScan, the sensor signs an alert and sends it to SOAR-Lite, which opens an incident." },
  { id: "logs", name: "Replay the attack logs", go: "Analyse the logs",
    blurb: "Log Threat Detector reads its bundled SSH, web and firewall logs, the kind a server writes while it is being attacked. It finds brute-force logins and port scans, links the ones from the same address, and sends each finding to SOAR-Lite as a signed alert." },
  { id: "email", name: "Deliver a phishing email", go: "Analyse the email",
    blurb: "Email Threat Analyzer scores a sample phishing email: who it claims to be from, where its links really go, what is attached. It sends its verdict to SOAR-Lite as a signed alert." },
  { id: "forge", name: "Forge an alert", go: "Send a forged alert",
    blurb: "An attacker who can reach SOAR-Lite would like to plant fake alerts, or bury a real one under noise. This console does not have the webhook secret, so it is in the attacker's position: it sends one alert with no signature and one signed with a guessed secret." },
];
const lane = (id) => LANES.find((l) => l.id === id);

function touch(...parts) { for (const p of parts) M.changed.add(p); }

function reset() {
  Object.assign(M, { cursor: 0, live: false, lines: { scan: [], logs: [], email: [] }, packets: [], tapFull: false,
    rules: [], alerts: [], webhooks: [], targetEvents: [], forged: [] });
  M.incidents.clear(); M.triage.clear(); M.asked.clear(); M.lane.clear();
  touch("all");
}

function take(e) {
  const { stage, kind } = e;
  if (kind === "line" && M.lines[stage]) {
    M.lines[stage].push(e);
    if (e.incident_id) { M.lane.set(e.incident_id, stage); pulse(stage, "signed"); touch("soar"); }
    touch(stage);
  } else if (stage === "tap" && kind === "packet") {
    M.packets.push(e);
    if (e.flags === "S") pulse("scan", "packets");
    touch("scan");
  } else if (stage === "tap" && kind === "full") { M.tapFull = true; touch("scan");
  } else if (stage === "sensor" && kind === "rules") { M.rules = e.rules || []; touch("scan");
  } else if (stage === "sensor" && kind === "alert") { M.alerts.push(e); pulse("scan", "tap"); light("st-suricata"); touch("scan");
  } else if (stage === "sensor" && kind === "webhook") {
    M.webhooks.push(e);
    if (e.ok) { pulse("scan", "signed"); if (e.incident_id) M.lane.set(e.incident_id, "scan"); }
    touch("scan", "soar");
  } else if (stage === "target") { M.targetEvents.push(e); touch("scan");
  } else if (stage === "soar" && kind === "incident") { M.incidents.set(e.id, e); light("soar-box"); touch("soar", "scan", "logs", "email", "forge");
  } else if (stage === "soar" && kind === "triage") { M.triage.set(e.id, e); if (e.status !== "pending") M.asked.delete(e.id); touch("soar", "scan", "logs", "email");
  } else if (stage === "forger" && kind === "forged") {
    M.forged.push(e); pulse("forge", "unsigned");
    if (e.accepted && e.incident_id) M.lane.set(e.incident_id, "forge");
    touch("forge");
  } else if (LANES.some((l) => l.id === stage)) { touch(stage); }
  if (M.lines[stage] && (kind === "start" || kind === "requested")) touch(stage);
}

/* ── Motion: a dot travels a wire only when something really crossed it ── */
const lastPulse = {};
function pulse(laneId, linkClass) {
  if (!M.live) return;
  const key = laneId + linkClass, now = performance.now();
  if (now - (lastPulse[key] || 0) < 90) return;
  lastPulse[key] = now;
  const link = document.querySelector(`.lane[data-lane="${laneId}"] .link.${linkClass}`);
  if (!link || link.querySelectorAll(".dot").length > 7) return;
  const dot = el("i", { class: "dot" });
  dot.addEventListener("animationend", () => dot.remove());
  link.append(dot);
}
function light(id) {
  if (!M.live) return;
  const node = $(id);
  if (!node) return;
  node.classList.remove("lit"); void node.offsetWidth; node.classList.add("lit");
}

/* ── Facts worked out from the events ───────────────────── */
const probes = () => M.packets.filter((p) => p.flags === "S");
function scanFacts() {
  const sent = probes();
  const sources = new Set(sent.map((p) => p.src));
  const open = [...new Set(M.packets.filter((p) => p.flags === "SA" && sources.has(p.dst)).map((p) => p.sport))].sort((a, b) => a - b);
  const closed = new Set(M.packets.filter((p) => p.flags.includes("R") && sources.has(p.dst)).map((p) => p.sport));
  return { sent, sources: [...sources], ports: new Set(sent.map((p) => p.dport)).size, open, closed: closed.size };
}
const incidentsOf = (laneId) => [...M.incidents.values()].filter((i) => M.lane.get(i.id) === laneId).sort((a, b) => a.id - b.id);
const step = (id) => (M.state && M.state.steps[id]) || { status: "idle", run: 0 };
const soarUp = () => !!(M.state && M.state.soar.up);

function laneStatus(id) {
  if (id === "forge") {
    if (!M.forged.length) return ["", "Not tried yet"];
    const refused = M.forged.filter((f) => !f.accepted).length;
    return refused === M.forged.length ? ["done", `Refused ${refused} of ${M.forged.length}`] : ["running", "SOAR-Lite accepted a forged alert"];
  }
  const s = step(id), made = incidentsOf(id).length;
  if (s.status === "running") return ["running", "Running now"];
  if (s.status === "requested") return ["running", "Starting"];
  if (s.status === "done") return ["done", made ? `Done: ${plural(made, "incident")} opened` : "Done"];
  if (M.state && M.state.mode === "step") return ["", "Waiting for you"];
  return ["", "Not run yet"];
}

function blocked(id) {
  if (!M.state) return "Connecting";
  if (!soarUp()) return "SOAR-Lite is still starting";
  if (id === "scan" && !M.state.sensor_ready) return "Suricata is still starting";
  if (id !== "forge" && ["running", "requested"].includes(step(id).status)) return "Running";
  return null;
}

/* ── The map ─────────────────────────────────────────────── */
function station(id, cls, name, sub) {
  return el("div", { class: `station ${cls}`, id }, el("b", { text: name }), el("small", { text: sub }), el("span", { class: "count" }));
}
const link = (cls, label, extra) => el("div", { class: `link ${cls}` }, el("span", { text: label }), extra);

function buildMap() {
  const wires = {
    scan: [station("st-netscan", "attack", "NetScan", "the attacker, 172.28.0.20"), link("packets", "probe packets"),
           station("st-target", "", "Target", "decoy server, 172.28.0.10"), link("tap", "copy of the traffic"),
           station("st-suricata", "detect", "Suricata", "sensor with NetScan's rules"), link("signed last", "signed alert")],
    logs: [station("st-logs", "detect", "Log Threat Detector", "SSH, web and firewall logs"), link("signed last", "signed alerts")],
    email: [station("st-email", "detect", "Email Threat Analyzer", "one sample phishing email"), link("signed last", "signed alert")],
    forge: [station("st-forger", "forger", "Someone without the secret", "this console"), link("unsigned last", "unsigned alert", el("em", { text: "refused" }))],
  };
  const lanes = $("lanes");
  LANES.forEach((l, i) => {
    const row = el("div", { class: "lane", "data-lane": l.id, on: { click: () => select(l.id) } },
      el("div", { class: "lane-head" },
        el("div", { class: "lane-title" }, el("span", { class: "lane-num", text: i + 1, "aria-hidden": "true" }),
          el("button", { class: "lane-name", type: "button", text: l.name })),
        el("div", { class: "lane-status" }),
        el("button", { class: "go", type: "button", text: l.go, on: { click: (ev) => { ev.stopPropagation(); run(l.id); } } })),
      el("div", { class: "wire" }, wires[l.id]));
    lanes.append(row);
  });
  const box = $("soar-box");
  box.addEventListener("click", () => select("soar"));
  box.append(el("h2", { text: "SOAR-Lite" }), el("p", { class: "sub", text: "Checks each signature, opens an incident, pulls out the indicators." }),
    el("div", { class: "big", id: "soar-count" }), el("ul", { id: "soar-split" }), el("div", { class: "ai-line", id: "soar-ai" }),
    el("button", { class: "view", type: "button", text: "See every incident" }));
}

function setCount(id, text) { const node = $(id) && $(id).querySelector(".count"); if (node && node.textContent !== text) node.textContent = text; }

function drawMap() {
  for (const l of LANES) {
    const row = document.querySelector(`.lane[data-lane="${l.id}"]`);
    row.setAttribute("aria-current", String(M.selected === l.id));
    const [cls, text] = laneStatus(l.id);
    const status = row.querySelector(".lane-status");
    status.className = "lane-status " + cls; status.textContent = text;
    const button = row.querySelector(".go"), why = blocked(l.id);
    const again = l.id === "forge" ? M.forged.length > 0 : step(l.id).run > 0;
    button.disabled = !!why;
    button.className = "go" + (again ? " again" : "");
    button.textContent = why || (again ? "Run it again" : l.go);
  }
  const f = scanFacts();
  setCount("st-netscan", f.sent.length ? `${plural(f.sent.length, "probe")} sent` : "");
  setCount("st-target", f.open.length ? `answered on ${f.open.join(", ")}` : f.sent.length ? "no open port yet" : "");
  setCount("st-suricata", M.alerts.length ? `${plural(M.alerts.length, "rule")} fired` : M.rules.length ? `${plural(M.rules.length, "rule")} loaded` : "starting");
  for (const id of ["logs", "email"]) {
    const made = incidentsOf(id).length;
    setCount("st-" + id, made ? `${plural(made, "alert")} sent` : step(id).status === "running" ? "working" : "");
  }
  setCount("st-forger", M.forged.length ? `${plural(M.forged.length, "attempt")}` : "");
  const refusedLink = document.querySelector(".link.unsigned");
  refusedLink.classList.toggle("refused", M.forged.some((x) => !x.accepted));

  const box = $("soar-box");
  box.setAttribute("aria-current", String(M.selected === "soar"));
  const total = M.incidents.size;
  $("soar-count").replaceChildren(soarUp() ? String(total) : "", el("small", { text: soarUp() ? (total === 1 ? "incident" : "incidents") : "starting" }));
  const split = [["scan", "from Suricata"], ["logs", "from the log detector"], ["email", "from the email analyzer"]]
    .map(([id, label]) => [incidentsOf(id).length, label]);
  const other = total - split.reduce((n, [c]) => n + c, 0);
  if (other > 0) split.push([other, "from elsewhere (uploads)"]);
  $("soar-split").replaceChildren(...split.filter(([c]) => c).map(([c, label]) => el("li", {}, el("i", { text: c }), label)));
  const ai = M.state && M.state.ai;
  $("soar-ai").replaceChildren(...(ai && ai.configured
    ? ["AI triage: ", el("b", { text: ai.model || "on" }), ` in ${ai.mode} mode. It runs only when you ask.`]
    : ["AI triage is off. The README shows how to turn it on."]));
  if (M.state) {
    $("soar-link").href = M.state.soar.url;
    $("analyze-link").href = M.state.soar.url + "/analyze";
    $("mode-line").textContent = M.state.mode === "step"
      ? "Step-by-step mode: nothing attacks until you start it. Pick a lane, press its button and watch the evidence arrive below."
      : "Automatic mode: every step already ran once when the lab started. Pick a lane to see what happened, or run it again.";
  }
}

/* ── Evidence sections ───────────────────────────────────── */
function section(who, whoClass, title, text, body, waiting) {
  return el("div", { class: "ev" + (waiting ? " waiting" : "") },
    el("div", { class: "ev-what" }, el("span", { class: `who ${whoClass}`, text: who }), el("h3", { text: title }), text ? el("p", { text }) : null),
    el("div", { class: "ev-body" }, body));
}
const empty = (text) => el("div", { class: "empty", text });

function terminal(id) {
  const lines = M.lines[id];
  if (!lines.length) return null;
  const box = el("div", { class: "term", tabindex: "0", "data-term": id });
  let blank = false;
  for (const l of lines) {
    const t = l.text;
    if (!t.trim()) { if (!blank) box.append("\n"); blank = true; continue; }
    blank = false;
    const cls = /incident #\d+|accepted/.test(t) ? "sent" : /\[(HIGH|CRITICAL)\]|CVE-|\[\+\]|Score|Level/.test(t) ? "hot" : /^[\s─═=\-]+$/.test(t) ? "dim" : null;
    box.append(cls ? el("span", { class: cls, text: t }) : t, "\n");
  }
  return box;
}

function more(key, shown, total, noun) {
  if (total <= shown && !M.open[key]) return null;
  return el("button", { class: "more", type: "button",
    text: M.open[key] ? "Show fewer" : `Show all ${total} ${noun}`,
    on: { click: () => { M.open[key] = !M.open[key]; touch(M.selected); draw(); } } });
}

const FINGERPRINT = [["sport", 20, "source port"], ["seqno", 0, "sequence"], ["win", 8192, "window"], ["hdr", 20, "TCP header"]];

function packetSection() {
  const f = scanFacts();
  if (M.state && M.state.tap === "unavailable") return empty("The packet view is not available on this machine. Detection is not affected: Suricata reads the traffic itself.");
  if (!M.packets.length) return null;
  const all = f.sent, rows = M.open.probes ? all : all.slice(0, 6);
  const cell = (p, [key, want]) => el("td", { class: p[key] === want ? "hit" : "miss", text: key === "hdr" ? `${p[key]} bytes` : p[key] });
  const table = el("table", { class: "pk" },
    el("thead", {}, el("tr", {}, ["time", "from", "to", "flags", ...FINGERPRINT.map((x) => x[2])].map((h) => el("th", { text: h })))),
    el("tbody", {}, rows.map((p) => el("tr", {}, el("td", { text: clock(p.ts) }), el("td", { text: p.src }),
      el("td", { text: `${p.dst}:${p.dport}` }), el("td", { text: p.flags === "S" ? "SYN" : p.flags }), FINGERPRINT.map((x) => cell(p, x))))));
  const matching = all.filter((p) => FINGERPRINT.every(([k, v]) => p[k] === v)).length;
  const readable = M.packets.filter((p) => p.line).slice(0, M.open.payloads ? 400 : 6);
  const payloads = readable.length ? el("table", { class: "pk" },
    el("thead", {}, el("tr", {}, ["time", "from", "to", "what was said"].map((h) => el("th", { text: h })))),
    el("tbody", {}, readable.map((p) => el("tr", {}, el("td", { text: clock(p.ts) }), el("td", { text: `${p.src}:${p.sport}` }),
      el("td", { text: `${p.dst}:${p.dport}` }), el("td", { class: "wide" + (p.agent ? " hit" : ""), text: p.agent ? `${p.line}   User-Agent: ${p.agent}` : p.line }))))) : null;
  return [
    el("div", { class: "facts" },
      el("span", {}, el("b", { text: M.packets.length }), "TCP packets seen"),
      el("span", {}, el("b", { text: all.length }), `connection attempts (SYN) to ${plural(f.ports, "port")}`),
      el("span", {}, el("b", { text: f.open.length }), f.open.length ? `answered: port ${f.open.join(", ")}` : "answered so far"),
      el("span", {}, el("b", { text: f.closed }), "refused (closed)")),
    all.length ? el("div", { class: "scroll-x" }, table) : null,
    more("probes", 6, all.length, "connection attempts"),
    all.length ? el("p", { class: "note", text: `${matching} of ${all.length} attempts carry all four highlighted values. A normal computer picks a random source port and sequence number and adds TCP options, so its header is longer than 20 bytes. That combination is the fingerprint the first rule looks for.` }) : null,
    payloads ? el("p", { class: "note", text: "After the scan, NetScan connects to the open ports to read what is running there:" }) : null,
    payloads ? el("div", { class: "scroll-x" }, payloads) : null,
    payloads ? more("payloads", 6, M.packets.filter((p) => p.line).length, "readable packets") : null,
    M.tapFull ? el("p", { class: "note", text: "The packet view is full and stopped recording. Detection continues." }) : null,
  ];
}

/* A Suricata rule, one condition per line, each with what it means */
const MEANING = [
  [/^flags:S$/, "only the SYN flag is set: a new connection attempt"],
  [/^seq:0$/, "the sequence number is 0 (an operating system picks a random one)"],
  [/^window:8192$/, "the window size is exactly 8192"],
  [/^tcp\.hdr$/, null],
  [/^bsize:20$/, "the TCP header is 20 bytes, so it carries no options"],
  [/^flow:stateless$/, "judge every packet on its own"],
  [/^flow:established,to_server$/, "a request sent on an open connection"],
  [/^http\.user_agent$/, null],
  [/^content:"(.*)"$/, (m) => `the User-Agent contains "${m[1]}"`],
  [/^startswith$/, "and it starts with that text"],
  [/^threshold:.*count 1, seconds (\d+)/, (m) => `report once per source every ${m[1]} seconds, not once per packet`],
];
function ruleParts(rule) {
  const open = rule.indexOf("("), head = rule.slice(0, open).trim(), body = rule.slice(open + 1, rule.lastIndexOf(")"));
  const options = []; let current = "", quoted = false;
  for (const ch of body) {
    if (ch === '"') quoted = !quoted;
    if (ch === ";" && !quoted) { if (current.trim()) options.push(current.trim()); current = ""; } else current += ch;
  }
  const conds = [];
  const port = head.match(/^alert\s+(\S+)\s+\S+\s+(\S+)\s+->/);
  if (port && port[2] !== "any") conds.push([`${port[1]} from port ${port[2]}`, `the source port is ${port[2]}`]);
  else if (port) conds.push([port[1], `any ${port[1].toUpperCase()} traffic`]);
  for (const o of options) {
    for (const [re, meaning] of MEANING) {
      const m = o.match(re);
      if (m) { if (meaning) conds.push([o, typeof meaning === "function" ? meaning(m) : meaning]); break; }
    }
  }
  return conds;
}

function ruleSection() {
  if (!M.rules.length) return null;
  return M.rules.map((r) => {
    const hits = M.alerts.filter((a) => a.sid === r.sid), first = hits[0];
    return el("div", { class: "rule" + (first ? " fired" : "") },
      el("div", { class: "rule-top" }, el("b", { text: `Rule ${r.sid}: ${r.msg}` }),
        el("span", { class: "rule-state", text: first
          ? `Fired at ${clock(first.ts)} on ${first.src}:${first.sport} to ${first.dst}:${first.dport}` + (hits.length > 1 ? `, and ${hits.length - 1} more` : "")
          : "Loaded, no match yet" })),
      el("ul", { class: "conds" }, ruleParts(r.rule).map(([code, meaning]) => el("li", {}, el("code", { text: code }), el("span", { text: meaning })))),
      first && first.agent ? el("p", { class: "note", text: `Matched User-Agent: ${first.agent}` }) : null,
      el("details", {}, el("summary", { text: "The rule as Suricata reads it" }), el("pre", { text: r.rule })));
  });
}

function requestView(method, path, headers, body, answerClass, answerStrong, answerText, missing) {
  const pre = el("pre");
  for (const [k, v] of Object.entries(headers)) pre.append(el("span", { class: "h", text: `${k}: ` }), `${v}\n`);
  for (const m of missing || []) pre.append(el("span", { class: "none", text: `${m}: (missing)\n` }));
  return el("div", { class: "req" },
    el("div", { class: "req-line" }, el("span", { text: `${method} ${path}` })),
    pre,
    el("details", {}, el("summary", { text: "The alert inside" }), el("pre", { text: JSON.stringify(body, null, 2) })),
    el("div", { class: `req-answer ${answerClass}` }, answerStrong, " ", el("span", { text: answerText })));
}

function webhookSection() {
  if (!M.webhooks.length) return null;
  return [
    ...M.webhooks.map((w) => requestView("POST", w.path,
      { "X-Webhook-Timestamp": w.timestamp, "X-Webhook-Signature": `${w.signature} (shortened here)` }, w.body,
      w.ok ? "ok" : "no",
      w.ok ? `SOAR-Lite answered ${w.status}: accepted.` : `SOAR-Lite answered ${w.status || "nothing"}: not accepted.`,
      w.ok ? `It opened incident #${w.incident_id} for rule ${w.sid}.` : (w.detail || "The sensor will try again."))),
    el("p", { class: "note", text: "The signature is an HMAC-SHA256 of the timestamp and the alert, made with a secret only the sensor and SOAR-Lite know. Change one character of the alert, or replay it more than five minutes later, and the signature no longer matches." }),
  ];
}

const VERDICT = { true_positive: "Real attack", false_positive: "False alarm", needs_investigation: "Needs an analyst" };

function aiView(incident) {
  const t = M.triage.get(incident.id), ai = M.state && M.state.ai, box = el("div", { class: "ai" });
  const pending = M.asked.has(incident.id) || (t && t.status === "pending");
  if (t && t.status !== "pending") {
    if (t.status === "failed" || t.status === "disabled" || (t.error && !t.verdict))
      box.append(el("p", { class: "err", text: `The AI's answer could not be used, so this incident stays with an analyst. ${t.error || ""}` }));
    else {
      box.append(el("div", { class: "ai-verdict" }, el("b", { text: `AI suggests: ${VERDICT[t.verdict] || t.verdict}` }),
        t.severity ? el("span", { class: `sev ${t.severity}`, text: t.severity }) : null,
        t.confidence != null ? el("span", { text: `${Math.round(t.confidence * 100)}% confident` }) : null,
        t.injection ? el("span", { class: "warn", text: "Hidden instruction suspected in the alert" }) : null,
        t.decision ? el("span", { text: `Analyst: ${t.decision}ed` }) : null));
      if (t.evidence && t.evidence.length) box.append(el("p", { class: "cites", text: `Cites the SOC's records: ${t.evidence.join("; ")}` }));
      if (t.reasoning) box.append(el("p", { text: t.reasoning }));
      for (const o of t.overrides || []) box.append(el("p", { class: "note", text: `Guard: ${o}` }));
      box.append(el("p", { class: "note", text: `${t.model || "model"}, ${t.mode} mode. It is a suggestion: accept or reject it in SOAR-Lite.` }));
    }
  }
  if (ai && ai.configured) {
    box.append(el("div", {}, el("button", { type: "button", disabled: pending, text: pending ? "The AI is reading it" : t ? "Ask the AI again" : "Ask the AI about this incident",
      on: { click: () => askAi(incident.id) } }), el("span", { class: "cost", text: `one request to ${ai.model}` })));
  } else if (!t) return null;
  return box;
}

function incidentCard(i) {
  const url = M.state ? `${M.state.soar.url}/static/incident.html?id=${encodeURIComponent(i.id)}` : "#";
  return el("div", { class: "inc" },
    el("div", { class: "inc-top" }, el("b", { text: `#${i.id} ${i.title}` }), el("span", { class: `sev ${i.severity}`, text: i.severity }),
      el("a", { href: url, target: "_blank", rel: "noopener", text: "Open in SOAR-Lite" })),
    i.iocs && i.iocs.length ? el("div", { class: "iocs" }, "Indicators it pulled out:", i.iocs.map((x) => el("code", {}, el("em", { text: `${x.type} ` }), x.value))) : null,
    aiView(i));
}

function incidentSection(list, max, key) {
  if (!list.length) return null;
  const shown = M.open[key] ? list : list.slice(0, max);
  return [...shown.map(incidentCard), more(key, max, list.length, "incidents")];
}

/* ── Each lane's story ───────────────────────────────────── */
function scanStory() {
  const s = step("scan"), started = s.run > 0 || M.lines.scan.length > 0, f = scanFacts();
  const term = terminal("scan"), packets = packetSection(), rules = ruleSection(), hooks = webhookSection(), incs = incidentSection(incidentsOf("scan"), 4, "inc-scan");
  return [
    section("NetScan", "attack", "The attacker scans", "The scanner's own output: the open ports it found, the software behind them and the known vulnerabilities for those versions.",
      term || empty(started ? "The scanner is starting." : "Nothing has attacked yet. Press “Start the scan” in lane 1."), !term),
    section("On the wire", "attack", f.sent.length ? `${plural(f.sent.length, "connection attempt")} reached the target` : "Packets reach the target",
      "Read straight off the target's network interface, the same traffic Suricata inspects.",
      packets || empty("No packets yet."), !packets),
    section("Suricata", "detect", M.alerts.length ? `${plural(M.alerts.length, "rule")} recognised the scanner` : "Suricata compares each packet with its rules",
      "Two rules written for this scanner and tested on real traffic. Each line is one condition, and a packet must meet all of them.",
      rules || empty("Suricata is starting."), !M.alerts.length),
    section("Sensor to SOAR-Lite", "signed", M.webhooks.some((w) => w.ok) ? "The sensor signed each alert and sent it" : "The alert is signed and sent",
      "Each alert travels as a web request. SOAR-Lite only accepts it if the signature proves it came from the sensor.",
      hooks || empty("No alert has been sent yet."), !hooks),
    section("SOAR-Lite", "soar", incs ? `SOAR-Lite opened ${plural(incidentsOf("scan").length, "incident")}` : "SOAR-Lite opens an incident",
      "The alert is now a case an analyst can work on. The scanner's address is recorded as an indicator, so it can be searched for in every other incident.",
      incs || empty("No incident yet."), !incs),
  ];
}

function toolStory(id, who, runTitle, runText, idleText) {
  const term = terminal(id), list = incidentsOf(id), incs = incidentSection(list, 4, "inc-" + id);
  return [
    section(who, "detect", runTitle, runText, term || empty(step(id).run || step(id).status === "requested" ? "Starting." : idleText), !term),
    section("SOAR-Lite", "soar", incs ? `SOAR-Lite opened ${plural(list.length, "incident")}` : "SOAR-Lite opens an incident for each finding",
      "Each line above that mentions an incident number was a signed alert. These are the incidents they became.",
      incs || empty("No incident yet."), !incs),
  ];
}

function forgeStory() {
  const attempts = M.forged.slice(-2);
  const label = { unsigned: "Attempt 1: no signature at all", guessed: "Attempt 2: signed with a guessed secret" };
  const views = attempts.map((a) => el("div", {}, el("p", { class: "note", text: label[a.attempt] || a.attempt }),
    requestView("POST", a.path, a.headers || {}, a.body, a.accepted ? "ok" : "no",
      a.accepted ? `SOAR-Lite answered ${a.status}: accepted. That should not happen.` : `SOAR-Lite answered ${a.status || "nothing"}: refused.`,
      a.detail || "", a.attempt === "unsigned" ? ["X-Webhook-Timestamp", "X-Webhook-Signature"] : [])));
  const refused = attempts.length && attempts.every((a) => !a.accepted);
  return [
    section("Without the secret", "", refused ? "SOAR-Lite refused both forged alerts" : "A forged alert is sent",
      "Compare these with the signed request in lane 1. The alert inside is well formed. Only the proof of who sent it is missing or wrong.",
      views.length ? [...views, refused ? el("p", { class: "note", text: `No incident was opened: SOAR-Lite still holds ${plural(M.incidents.size, "incident")}. Before this check existed, anyone who could reach the server could create incidents.` }) : null]
        : empty("Nothing sent yet. Press “Send a forged alert” in lane 4."), !views.length),
  ];
}

function soarStory() {
  const all = [...M.incidents.values()].sort((a, b) => b.id - a.id);
  return [section("SOAR-Lite", "soar", all.length ? `${plural(all.length, "incident")}, newest first` : "No incidents yet",
    "Every incident SOAR-Lite holds, from the four lanes and from files uploaded on its Analyze page. Open one in SOAR-Lite to accept or reject the AI's suggestion and export the report.",
    incidentSection(all, 8, "inc-all") || empty("Run a lane to create the first incident."), !all.length)];
}

const STORIES = {
  scan: scanStory,
  logs: () => toolStory("logs", "Log Threat Detector", "The detector reads the logs", "Its own output: each finding, the address behind it and how many log lines prove it.", "Not run yet. Press “Analyse the logs” in lane 2."),
  email: () => toolStory("email", "Email Threat Analyzer", "The analyzer scores the email", "Its own report: the score out of 100 and every sign of phishing it found.", "Not run yet. Press “Analyse the email” in lane 3."),
  forge: forgeStory,
  soar: soarStory,
};

function drawDetail() {
  const id = M.selected, l = lane(id);
  const detail = $("detail");
  const scrolls = {};
  detail.querySelectorAll(".term").forEach((t) => { scrolls[t.dataset.term] = t.scrollTop + t.clientHeight >= t.scrollHeight - 8 ? "end" : t.scrollTop; });
  const openDetails = [...detail.querySelectorAll("details")].map((d) => d.open);
  detail.replaceChildren(
    el("div", { class: "detail-head" }, el("div", {},
      el("h2", { text: l ? `${LANES.indexOf(l) + 1}. ${l.name}` : "Every incident in SOAR-Lite" }),
      el("p", { text: l ? l.blurb : "This is where all four lanes end. In a real SOC an analyst works from this list." }))),
    ...STORIES[id]());
  detail.querySelectorAll(".term").forEach((t) => { const s = scrolls[t.dataset.term]; t.scrollTop = s === undefined || s === "end" ? t.scrollHeight : s; });
  detail.querySelectorAll("details").forEach((d, n) => { if (openDetails[n]) d.open = true; });
}

function draw() {
  const changed = M.changed;
  M.changed = new Set();
  drawMap();
  if (changed.has("all") || changed.has(M.selected) || (M.selected === "soar" && changed.size)) drawDetail();
}

function select(id) { if (M.selected !== id) { M.selected = id; touch("all"); draw(); } }

/* ── Talking to the console server ───────────────────────── */
async function post(path) {
  const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Lab-Console": "1" }, body: "{}" });
  const reply = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(reply.error || `The console answered ${response.status}`);
  return reply;
}

function notice(text) { const n = $("notice"); n.hidden = !text; n.textContent = text || ""; }

async function run(id) {
  select(id);
  try { await post(id === "forge" ? "/api/forge" : `/api/run/${id}`); notice(""); }
  catch (e) { notice(e.message); }
  poll(true);
}

async function askAi(id) {
  M.asked.add(id); touch("all"); draw();
  try { await post(`/api/triage/${id}`); notice(""); }
  catch (e) { M.asked.delete(id); notice(`AI triage: ${e.message}`); touch("all"); draw(); }
}

let polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  try {
    for (;;) {
      const response = await fetch(`/api/events?after=${M.cursor}`, { cache: "no-store" });
      const data = await response.json();
      if (M.epoch !== null && data.epoch !== M.epoch) reset();       // the lab was restarted
      M.epoch = data.epoch;
      if (JSON.stringify(data.state) !== JSON.stringify(M.state)) touch("all");
      M.state = data.state;
      for (const e of data.events) take(e);
      M.cursor = data.last;
      if (data.last >= data.head) break;
    }
    if (M.down) { M.down = false; notice(""); }
    draw();
    M.live = true;
  } catch (e) {
    if (!M.down) { M.down = true; notice("The lab is not answering. Start it with ./lab.sh --watch, then this page continues by itself."); }
  } finally { polling = false; }
}

buildMap();
draw();
poll();
setInterval(poll, 600);
