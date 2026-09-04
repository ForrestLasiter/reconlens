"use strict";

const $ = (s) => document.querySelector(s);
const el = (t, cls, html) => {
  const n = document.createElement(t);
  if (cls) n.className = cls;
  if (html != null) n.innerHTML = html;
  return n;
};
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const api = (p, opts) => fetch(p, opts).then((r) => r.json());
const ago = (ts) => {
  if (!ts) return "—";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return Math.floor(s) + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
};

let scanPoll = null;

// ISO alpha-2 -> flag emoji (regional indicator symbols).
const flag = (cc) => (cc && cc.length === 2)
  ? cc.toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)))
  : "";

// Common TCP port -> service label, for a readable inventory.
const PORT_NAMES = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
  80: "http", 110: "pop3", 111: "rpc", 123: "ntp", 135: "msrpc",
  139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
  445: "smb", 465: "smtps", 500: "ike", 514: "syslog", 515: "printer",
  587: "smtp", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
  1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
  1723: "pptp", 1883: "mqtt", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
  3000: "grafana/dev", 3306: "mysql", 3389: "rdp", 4443: "https-alt",
  5000: "upnp/dev", 5060: "sip", 5432: "postgres", 5555: "adb",
  5900: "vnc", 6379: "redis", 8006: "proxmox", 8080: "http-alt",
  8443: "https-alt", 8888: "http-alt", 9000: "portainer", 9090: "prometheus",
  9200: "elastic", 9929: "nping", 11211: "memcached", 27017: "mongodb",
  31337: "elite", 32400: "plex", 51820: "wireguard",
};

async function loadScope() {
  const s = await api("/api/scope");
  const bar = $("#scopeBar");
  const parts = [...s.domains, ...s.ips, ...s.cidrs];
  bar.innerHTML = parts.length
    ? "scope: " + parts.map((p) => `<span class="tag">${esc(p)}</span>`).join(" ")
    : 'scope: <span class="muted">empty — edit scope.yaml and restart</span>';

  const sel = $("#targetSelect");
  sel.innerHTML = "";
  s.targets.forEach((t) => {
    const o = el("option");
    o.value = t.value;
    o.textContent = `${t.value} (${t.kind})`;
    sel.appendChild(o);
  });

  const banner = $("#banner");
  if (s.missing_tools && s.missing_tools.length) {
    banner.hidden = false;
    banner.textContent = "⚠ Missing recon tools in image: " + s.missing_tools.join(", ");
  } else if (!s.targets.length) {
    banner.hidden = false;
    banner.textContent = "⚠ No targets in scope. Copy scope.example.yaml → scope.yaml, add your assets, and restart the container.";
  } else {
    banner.hidden = true;
  }
  $("#runBtn").disabled = !s.targets.length;
}

async function loadOverview() {
  const o = await api("/api/overview");
  const sev = o.severity || {};
  const cards = $("#cards");
  cards.innerHTML = "";
  const mk = (k, v, extra) => {
    const c = el("div", "card");
    c.appendChild(el("div", "k", k));
    c.appendChild(el("div", "v", v));
    if (extra) c.appendChild(extra);
    return c;
  };
  cards.appendChild(mk("Assets", o.assets));
  cards.appendChild(mk("Live hosts", o.alive));
  cards.appendChild(mk("Web services", o.services));

  const sevRow = el("div", "sev-row");
  [["crit", "critical"], ["high", "high"], ["med", "medium"], ["low", "low"], ["info", "info"]]
    .forEach(([c, key]) => {
      if (sev[key]) sevRow.appendChild(el("span", "pill " + c, `${sev[key]} ${key}`));
    });
  if (!sevRow.children.length) sevRow.appendChild(el("span", "muted", "none"));
  cards.appendChild(mk("Open findings", o.findings_open, sevRow));

  const last = o.last_scan;
  cards.appendChild(mk("Last scan",
    last ? esc(last.target) : "—",
    el("div", "muted", last
      ? `<span class="status ${last.status}">${last.status}</span> ${ago(last.finished_at || last.started_at)}`
      : "no scans yet")));
}

const renderers = {
  async events() {
    const rows = await api("/api/events?limit=150");
    if (!rows.length) return emptyPanel("tab-events", "No changes recorded yet. Run a scan.");
    const t = table(["When", "Change", "Subject", "Detail"]);
    rows.forEach((e) => {
      const tr = el("tr");
      tr.appendChild(td(ago(e.ts)));
      tr.appendChild(td(`<span class="sev ${e.severity}">${kindLabel(e.kind)}</span>`));
      tr.appendChild(td(esc(e.subject)));
      tr.appendChild(td(esc(e.detail), "wrap"));
      t.tBodies[0].appendChild(tr);
    });
    mount("tab-events", t);
  },

  async findings() {
    const rows = await api("/api/findings");
    if (!rows.length) return emptyPanel("tab-findings", "No open findings. (Good.)");
    const t = table(["Severity", "Finding", "Template", "Host", "Matched", "Seen"]);
    rows.forEach((f) => {
      const tr = el("tr");
      tr.appendChild(td(`<span class="sev ${f.severity}">${f.severity}</span>`));
      tr.appendChild(td(esc(f.name || "—")));
      tr.appendChild(td(`<span class="tag">${esc(f.template_id)}</span>`));
      tr.appendChild(td(esc(f.host)));
      tr.appendChild(td(esc(f.matched_at), "wrap"));
      tr.appendChild(td(ago(f.last_seen)));
      t.tBodies[0].appendChild(tr);
    });
    mount("tab-findings", t);
  },

  async services() {
    const rows = await api("/api/services");
    if (!rows.length) return emptyPanel("tab-services", "No live services yet.");
    const t = table(["Host", "Port", "Scheme", "Code", "Title", "Server", "Tech", "TLS expiry"]);
    rows.forEach((s) => {
      const tr = el("tr");
      tr.appendChild(td(esc(s.host)));
      tr.appendChild(td(s.port));
      tr.appendChild(td(esc(s.scheme)));
      tr.appendChild(td(s.status_code ?? "—"));
      tr.appendChild(td(esc(s.title || "—"), "wrap"));
      tr.appendChild(td(esc(s.webserver || "—")));
      tr.appendChild(td((s.tech || "").split(",").filter(Boolean)
        .map((x) => `<span class="tag">${esc(x)}</span>`).join("") || "—", "wrap"));
      tr.appendChild(td(esc((s.tls_expiry || "—").slice(0, 10))));
      t.tBodies[0].appendChild(tr);
    });
    mount("tab-services", t);
  },

  async inventory() {
    const rows = await api("/api/inventory");
    if (!rows.length) return emptyPanel("tab-inventory",
      "No hosts discovered yet. Add a CIDR (e.g. 192.168.1.0/24) to your scope and run a scan.");
    const t = table(["Name", "IP", "Open ports", "Services", "Last seen"]);
    rows.forEach((h) => {
      const tr = el("tr");
      tr.appendChild(td(esc(h.hostname || h.host || "—")));
      tr.appendChild(td(esc(h.ip || "—")));
      tr.appendChild(td(h.ports.map((p) =>
        `<span class="tag" title="${esc(PORT_NAMES[p] || "")}">${p}${PORT_NAMES[p] ? " " + esc(PORT_NAMES[p]) : ""}</span>`).join(" "), "wrap"));
      tr.appendChild(td(String(h.ports.length)));
      tr.appendChild(td(ago(h.last_seen)));
      t.tBodies[0].appendChild(tr);
    });
    mount("tab-inventory", t);
  },

  async assets() {
    const rows = await api("/api/assets");
    if (!rows.length) return emptyPanel("tab-assets", "No assets discovered yet.");
    const t = table(["Hostname", "IP", "Source", "First seen", "Last seen"]);
    rows.forEach((a) => {
      const tr = el("tr");
      tr.appendChild(td(esc(a.hostname)));
      tr.appendChild(td(esc(a.ip || "—")));
      tr.appendChild(td(esc(a.source)));
      tr.appendChild(td(ago(a.first_seen)));
      tr.appendChild(td(ago(a.last_seen)));
      t.tBodies[0].appendChild(tr);
    });
    mount("tab-assets", t);
  },

  async scans() {
    const rows = await api("/api/scans");
    if (!rows.length) return emptyPanel("tab-scans", "No scans run yet.");
    const t = table(["ID", "Target", "Profile", "Status", "Started", "Duration", "Summary"]);
    rows.forEach((s) => {
      const tr = el("tr");
      const dur = s.finished_at && s.started_at
        ? Math.round(s.finished_at - s.started_at) + "s" : "—";
      let summary = "—";
      try {
        const st = JSON.parse(s.stats || "{}");
        summary = `${st.subdomains ?? 0} subs · ${st.services ?? 0} svc · ${st.findings ?? 0} find`;
      } catch (e) {}
      tr.appendChild(td(`<span class="dot" data-scan="${s.id}">#${s.id}</span>`));
      tr.appendChild(td(esc(s.target)));
      tr.appendChild(td(esc(s.profile)));
      tr.appendChild(td(`<span class="status ${s.status}">${s.status}</span>`));
      tr.appendChild(td(ago(s.started_at)));
      tr.appendChild(td(dur));
      tr.appendChild(td(summary));
      t.tBodies[0].appendChild(tr);
    });
    mount("tab-scans", t);
    t.querySelectorAll("[data-scan]").forEach((n) =>
      n.addEventListener("click", () => openScan(n.dataset.scan)));
  },
};

function kindLabel(k) {
  return { new_asset: "NEW ASSET", new_service: "NEW SVC",
    closed_service: "CLOSED", new_finding: "NEW FINDING",
    resolved_finding: "RESOLVED" }[k] || k;
}
function table(cols) {
  const t = el("table");
  const thead = el("thead"), tr = el("tr");
  cols.forEach((c) => tr.appendChild(el("th", null, c)));
  thead.appendChild(tr);
  t.appendChild(thead);
  t.appendChild(el("tbody"));
  return t;
}
function td(html, cls) { return el("td", cls, html); }
function mount(id, node) { const p = $("#" + id); p.innerHTML = ""; p.appendChild(node); }
function emptyPanel(id, msg) { const p = $("#" + id); p.innerHTML = `<div class="empty">${esc(msg)}</div>`; }

async function openScan(id) {
  $("#drawer").hidden = false;
  $("#drawerTitle").textContent = "Scan #" + id;
  const s = await api("/api/scans/" + id);
  $("#drawerLog").textContent = s.log || "(no log)";
  if (s.status === "running" || s.status === "queued") {
    clearTimeout(scanPoll);
    scanPoll = setTimeout(() => openScan(id), 2000);
  }
}

let active = "events";
function switchTab(name) {
  active = name;
  document.querySelectorAll(".tabs button").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll("#section-outbound .panel").forEach((p) =>
    p.hidden = p.id !== "tab-" + name);
  renderers[name]();
}

let section = "outbound";
function setSection(name) {
  section = name;
  document.querySelectorAll(".section-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.section === name));
  $("#section-outbound").hidden = name !== "outbound";
  $("#section-inbound").hidden = name !== "inbound";
  refresh();
}

async function renderInbound() {
  const [sum, feed] = await Promise.all([
    api("/api/inbound/summary"), api("/api/inbound"),
  ]);
  const cards = $("#inbound-cards");
  cards.innerHTML = "";
  const mk = (k, v, extra) => {
    const c = el("div", "card");
    c.appendChild(el("div", "k", k));
    c.appendChild(el("div", "v", v));
    if (extra) c.appendChild(extra);
    return c;
  };
  cards.appendChild(mk("Total hits", sum.total));
  cards.appendChild(mk("Unique sources", sum.unique_sources));
  cards.appendChild(mk("Watched ports", sum.watched_ports.length,
    el("div", "muted", (sum.watched_ports.join(", ") || "none"))));
  cards.appendChild(mk("Last hit", sum.last_hit ? ago(sum.last_hit) : "—"));

  const b = $("#inbound-banner");
  if (!sum.enabled) {
    b.hidden = false;
    b.textContent = "⚠ Honeypot not enabled. Set RECONLENS_HONEYPOT_PORTS and publish those ports from the container.";
  } else if (sum.total === 0) {
    b.hidden = false;
    b.textContent = "Honeypot armed on ports " + sum.watched_ports.join(", ") +
      ". No hits yet — forward one of these ports on your router to start seeing internet scans.";
  } else { b.hidden = true; }

  // Top sources
  if (!sum.top_sources.length) {
    emptyPanel("inbound-sources", "No sources yet.");
  } else {
    const t = table(["Source", "Name", "Location", "Hits", "Ports", "Last"]);
    sum.top_sources.forEach((s) => {
      const tr = el("tr");
      tr.appendChild(td(esc(s.src_ip)));
      tr.appendChild(td(esc(s.hostname || "—"), "wrap"));
      const loc = [flag(s.country_code), esc(s.country || ""), s.org ? `<span class="muted">${esc(s.org)}</span>` : ""].filter(Boolean).join(" ");
      tr.appendChild(td(loc || "—", "wrap"));
      tr.appendChild(td(String(s.n)));
      tr.appendChild(td(String(s.ports)));
      tr.appendChild(td(ago(s.last)));
      t.tBodies[0].appendChild(tr);
    });
    mount("inbound-sources", t);
  }

  // Top ports
  if (!sum.top_ports.length) {
    emptyPanel("inbound-ports", "No ports hit yet.");
  } else {
    const t = table(["Port", "Service", "Hits"]);
    sum.top_ports.forEach((p) => {
      const tr = el("tr");
      tr.appendChild(td(String(p.dst_port)));
      tr.appendChild(td(esc(PORT_NAMES[p.dst_port] || "—")));
      tr.appendChild(td(String(p.n)));
      t.tBodies[0].appendChild(tr);
    });
    mount("inbound-ports", t);
  }

  // Recent feed
  if (!feed.length) {
    emptyPanel("inbound-feed", "No hits recorded yet.");
  } else {
    const t = table(["When", "Source IP", "Loc", "Name", "Port", "Banner"]);
    feed.forEach((h) => {
      const tr = el("tr");
      tr.appendChild(td(ago(h.ts)));
      tr.appendChild(td(esc(h.src_ip)));
      tr.appendChild(td((flag(h.country_code) || "") + (h.country ? " " + esc(h.country) : "") || "—"));
      tr.appendChild(td(esc(h.hostname || "—"), "wrap"));
      tr.appendChild(td(`${h.dst_port}${PORT_NAMES[h.dst_port] ? " " + esc(PORT_NAMES[h.dst_port]) : ""}`));
      tr.appendChild(td(h.banner ? `<span class="tag">${esc(h.banner)}</span>` : "—", "wrap"));
      t.tBodies[0].appendChild(tr);
    });
    mount("inbound-feed", t);
  }
}

async function refresh() {
  if (section === "inbound") { await renderInbound(); return; }
  await Promise.all([loadOverview(), renderers[active]()]);
}

function init() {
  document.querySelectorAll(".section-btn").forEach((b) =>
    b.addEventListener("click", () => setSection(b.dataset.section)));
  document.querySelectorAll(".tabs button").forEach((b) =>
    b.addEventListener("click", () => switchTab(b.dataset.tab)));
  $("#drawerClose").addEventListener("click", () => {
    $("#drawer").hidden = true; clearTimeout(scanPoll);
  });
  $("#runBtn").addEventListener("click", async () => {
    const target = $("#targetSelect").value;
    const profile = $("#profileSelect").value;
    if (!target) return;
    $("#runBtn").disabled = true;
    const res = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, profile }),
    });
    $("#runBtn").disabled = false;
    if (res.scan_id) { switchTab("scans"); openScan(res.scan_id); }
    else if (res.detail) alert(res.detail);
  });

  loadScope();
  refresh();
  setInterval(refresh, 5000);
}

init();
