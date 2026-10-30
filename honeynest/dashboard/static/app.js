// Painel do HoneyNest. Todos os dados vêm de atacantes: só usamos textContent, nunca innerHTML.
const REFRESH_MS = 10000;

// URLs absolutas sem usuário/senha: o fetch falha se a página foi aberta como http://usuario:senha@host.
const api = path => fetch(new URL(path, location.origin), { credentials: "same-origin" }).then(r => {
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
});
let timelineChart = null;
let map = null;
let markers = null;

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function fmt(n) {
  return Number(n || 0).toLocaleString("pt-BR");
}

function flag(code) {
  if (!code || code.length !== 2) return "";
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1f1a5 + c.charCodeAt(0))) + " ";
}

function fillRanking(id, rows, labelFn) {
  const table = document.getElementById(id);
  table.replaceChildren();
  if (!rows.length) {
    const tr = el("tr");
    tr.appendChild(el("td", "Sem dados ainda", "empty"));
    table.appendChild(tr);
    return;
  }
  for (const row of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", labelFn ? labelFn(row) : (row.label ?? "(vazio)"), "text"));
    tr.appendChild(el("td", fmt(row.count), "count"));
    table.appendChild(tr);
  }
}

function setKpis(t) {
  const map = { events: "k-events", unique_ips: "k-ips", login_attempts: "k-logins", login_success: "k-success",
                commands: "k-commands", downloads: "k-downloads", http_requests: "k-http", last_24h: "k-24h" };
  for (const [key, id] of Object.entries(map)) document.getElementById(id).textContent = fmt(t[key]);
}

function drawTimeline(rows) {
  // Preenche as 24 horas, inclusive as sem eventos.
  const counts = Object.fromEntries(rows.map(r => [r.label, r.count]));
  const labels = [], data = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600 * 1000);
    const key = d.toISOString().slice(0, 13);
    labels.push(d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }));
    data.push(counts[key] || 0);
  }

  if (timelineChart) {
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = data;
    timelineChart.update("none");
    return;
  }
  timelineChart = new Chart(document.getElementById("timeline"), {
    type: "bar",
    data: { labels, datasets: [{ label: "Eventos", data, backgroundColor: "#f0b429", borderRadius: 3 }] },
    options: {
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#8b949e", maxRotation: 0, autoSkip: true, maxTicksLimit: 12 }, grid: { display: false } },
        y: { beginAtZero: true, ticks: { color: "#8b949e", precision: 0 }, grid: { color: "#2a313c" } },
      },
    },
  });
}

function drawMap(points) {
  if (!map) {
    map = L.map("map", { worldCopyJump: true, attributionControl: true }).setView([20, 0], 1);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap", maxZoom: 10, className: "dark-tiles",
    }).addTo(map);
    markers = L.layerGroup().addTo(map);
  }
  markers.clearLayers();
  const max = Math.max(1, ...points.map(p => p.count));
  for (const p of points) {
    const marker = L.circleMarker([p.lat, p.lon], {
      radius: 4 + 12 * Math.sqrt(p.count / max), color: "#f85149", weight: 1, fillOpacity: 0.5,
    });
    const popup = el("div");
    popup.appendChild(el("strong", p.ip));
    popup.appendChild(el("div", [p.city, p.country].filter(Boolean).join(", ")));
    popup.appendChild(el("div", fmt(p.count) + " eventos"));
    marker.bindPopup(popup);
    markers.addLayer(marker);
  }
}

async function loadStats() {
  const s = await api("/api/stats");
  setKpis(s.totals);
  drawTimeline(s.timeline);
  fillRanking("t-credentials", s.top_credentials);
  fillRanking("t-usernames", s.top_usernames);
  fillRanking("t-passwords", s.top_passwords);
  fillRanking("t-commands", s.top_commands);
  fillRanking("t-ips", s.top_ips, r => flag(r.country_code) + r.label);
  fillRanking("t-countries", s.top_countries);
  fillRanking("t-http", s.http_attacks);
  fillRanking("t-services", s.by_service, r => r.label.toUpperCase());
  fillRanking("t-downloads", s.top_downloads);
}

async function loadMap() {
  drawMap(await api("/api/map"));
}

async function loadEvents() {
  const params = new URLSearchParams({ limit: 200 });
  const service = document.getElementById("f-service").value;
  const event = document.getElementById("f-event").value;
  if (service) params.set("service", service);
  if (event) params.set("event", event);

  const rows = await api("/api/events?" + params);
  const tbody = document.querySelector("#t-events tbody");
  tbody.replaceChildren();
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", new Date(r.ts).toLocaleString("pt-BR")));
    tr.appendChild(el("td", r.service.toUpperCase()));
    const evCell = el("td");
    evCell.appendChild(el("span", r.event, "badge " + r.event));
    tr.appendChild(evCell);
    tr.appendChild(el("td", r.src_ip, "mono"));
    tr.appendChild(el("td", flag(r.country_code) + (r.country || "")));
    tr.appendChild(el("td", r.username, "mono"));
    tr.appendChild(el("td", r.password, "mono"));
    let detail = r.detail || "";
    if (r.data && r.data.tags && r.data.tags.length) detail += "  [" + r.data.tags.join(", ") + "]";
    if (r.data && r.data.sha256) detail += "  sha256=" + r.data.sha256;
    tr.appendChild(el("td", detail, "mono detail"));
    tbody.appendChild(tr);
  }
}

async function refresh() {
  try {
    await Promise.all([loadStats(), loadMap(), loadEvents()]);
    document.getElementById("updated").textContent = "atualizado às " + new Date().toLocaleTimeString("pt-BR");
  } catch (err) {
    document.getElementById("updated").textContent = "erro ao atualizar: " + err.message;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("f-service").addEventListener("change", loadEvents);
  document.getElementById("f-event").addEventListener("change", loadEvents);
  refresh();
  setInterval(refresh, REFRESH_MS);
});
