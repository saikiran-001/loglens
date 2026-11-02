/* ==================================================================
   week3_visualization/static/dashboard.js
   ------------------------------------------------------------------
   All of Week 3's chart + map code lives here.

   THE FLOW
     1. Read the JSON the server embedded in the page.
     2. Build the Chart.js charts.
     3. Plot the Leaflet map markers.
     4. If a CDN failed to load (offline), show a friendly message
        instead of throwing a wall of red errors.

   Nothing here talks to the server: the data was already rendered
   into the page. Week 4 adds polling, and only then do we need fetch().
   ================================================================== */

// ------------------------------------------------------------------
// 1. READ THE EMBEDDED REPORT
// ------------------------------------------------------------------
// document.getElementById finds the <script id="report-data"> tag.
// .textContent is the JSON text inside it.
// JSON.parse turns that text into a real JavaScript object.
const REPORT = JSON.parse(document.getElementById("report-data").textContent);

// Shared colours, reused by every chart so the dashboard looks consistent.
const COLORS = {
  attacks: "#ef4444",          // red   - malicious
  requests: "#38bdf8",         // blue  - all traffic
  critical: "#f472b6",
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#38bdf8",
  palette: ["#38bdf8", "#ef4444", "#f59e0b", "#22c55e", "#a78bfa", "#f472b6", "#14b8a6"],
};

// A short label for an hour bucket: "2026-10-20 16:00" -> "16:00".
function shortHour(label) {
  return label.length >= 13 ? label.slice(11) : label;
}

// Escape user-controlled text before putting it into HTML.
// Log lines come from the internet, so treat them as hostile!
// Without this, an attacker could store <img onerror=...> in a URL and
// have it execute inside our dashboard (stored XSS - ironic but real).
function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// Show text in the middle of a chart box when there is nothing to draw.
function emptyState(canvasId, message) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const box = canvas.parentElement;
  box.innerHTML = '<p class="chart-empty">' + escapeHtml(message) + "</p>";
}

// Chart.js needs to know we are done with a canvas before reusing it.
// (Not strictly needed here, but it is the correct habit.)
let timelineChart = null;
let typeChart = null;
let countryChart = null;

// ------------------------------------------------------------------
// 2. LINE CHART - attacks per hour
// ------------------------------------------------------------------
function buildTimeline() {
  const rows = REPORT.by_hour || [];

  if (rows.length === 0) {
    emptyState("timelineChart", "No timestamped traffic in this file.");
    return;
  }
  if (typeof Chart === "undefined") {
    emptyState("timelineChart", "Chart.js could not load. Check your internet connection.");
    return;
  }

  const labels = rows.map((row) => shortHour(row.hour));          // x axis
  const attackSeries = rows.map((row) => row.attacks);            // red line
  const requestSeries = rows.map((row) => row.requests);          // blue line

  timelineChart = new Chart(document.getElementById("timelineChart"), {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Attacks",
          data: attackSeries,
          borderColor: COLORS.attacks,
          backgroundColor: "rgba(239, 68, 68, 0.15)",
          fill: true,             // shade the area under the line
          tension: 0.35,          // curve the line slightly
          pointRadius: 3,
          borderWidth: 2,
        },
        {
          label: "All requests",
          data: requestSeries,
          borderColor: COLORS.requests,
          borderDash: [4, 4],
          fill: false,
          tension: 0.35,
          pointRadius: 0,
          borderWidth: 1.5,
          // Requests are usually far more numerous than attacks, so this
          // series gets its own right-hand axis.
          yAxisID: "y1",
        },
      ],
    },
    options: {
      responsive: true,          // resize with the container
      maintainAspectRatio: false, // we control height with CSS
      interaction: { mode: "index", intersect: false }, // tooltip shows all series at that x
      plugins: {
        legend: { labels: { color: "#8b9ab5", boxWidth: 12 } },
        tooltip: {
          // Show the full hour in the tooltip even though the axis is short.
          callbacks: { title: (items) => rows[items[0].dataIndex].hour },
        },
      },
      scales: {
        x: { ticks: { color: "#8b9ab5", maxRotation: 0, autoSkip: true }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { beginAtZero: true, ticks: { color: COLORS.attacks, precision: 0 }, grid: { color: "rgba(255,255,255,0.05)" }, title: { display: true, text: "attacks", color: COLORS.attacks } },
        y1: { beginAtZero: true, position: "right", ticks: { color: COLORS.requests, precision: 0 }, grid: { drawOnChartArea: false }, title: { display: true, text: "requests", color: COLORS.requests } },
      },
    },
  });
}

// ------------------------------------------------------------------
// 3. DOUGHNUT - attack types
// ------------------------------------------------------------------
function buildTypes() {
  const byType = REPORT.summary.by_type || {};
  const labels = Object.keys(byType);
  const values = Object.values(byType);

  if (labels.length === 0) {
    emptyState("typeChart", "No attacks detected.");
    return;
  }
  if (typeof Chart === "undefined") {
    emptyState("typeChart", "Chart.js could not load.");
    return;
  }

  typeChart = new Chart(document.getElementById("typeChart"), {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: COLORS.palette,
        borderColor: "#131c31",
        borderWidth: 3,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "62%",                     // ring thickness
      plugins: {
        legend: { position: "bottom", labels: { color: "#8b9ab5", boxWidth: 12 } },
      },
    },
  });
}

// ------------------------------------------------------------------
// 4. HORIZONTAL BAR - attacks by country
// ------------------------------------------------------------------
function buildCountries() {
  const rows = REPORT.by_country || [];
  const withHits = rows.filter((row) => row.hits > 0);

  if (withHits.length === 0) {
    emptyState("countryChart", "No country data.");
    return;
  }
  if (typeof Chart === "undefined") {
    emptyState("countryChart", "Chart.js could not load.");
    return;
  }

  countryChart = new Chart(document.getElementById("countryChart"), {
    type: "bar",
    data: {
      labels: withHits.map((row) => row.flag + " " + row.country),
      datasets: [{
        label: "Attacks",
        data: withHits.map((row) => row.hits),
        backgroundColor: COLORS.palette,
        borderRadius: 5,
      }],
    },
    options: {
      indexAxis: "y",                    // horizontal bars read better for country names
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { color: "#8b9ab5", precision: 0 }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#e6ecf7" }, grid: { display: false } },
      },
    },
  });
}

// ------------------------------------------------------------------
// 5. MAP - Leaflet
// ------------------------------------------------------------------
function buildMap() {
  const container = document.getElementById("attackMap");
  if (!container) return;

  // Leaflet failed to load (offline) -> keep the layout tidy.
  if (typeof L === "undefined") {
    container.innerHTML = '<p class="chart-empty">Map library could not load. The country chart still works.</p>';
    return;
  }

  const attackers = (REPORT.attacks_by_ip || []).filter(
    (row) => row.lat !== null && row.lon !== null && row.lat !== undefined
  );

  // createMap: centre [lat, lon], zoom 2 = whole world.
  const map = L.map("attackMap", { worldCopyJump: true }).setView([20, 10], 2);

  // Tile layer = the actual map images. OpenStreetMap is free; their
  // usage policy requires the attribution line below.
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 18,
    attribution: "&copy; OpenStreetMap contributors",
  }).addTo(map);

  // No geo data at all -> show a note instead of an empty ocean.
  if (attackers.length === 0) {
    container.insertAdjacentHTML("beforeend", '<p class="chart-empty">No public IP addresses to map.</p>');
    return;
  }

  attackers.forEach((row) => {
    // Bigger circle = more attacks (capped so one attacker cannot
    // produce a circle that covers a continent).
    const radius = 6 + Math.min(row.hits, 30);

    const marker = L.circleMarker([row.lat, row.lon], {
      radius,
      color: "#ef4444",
      weight: 2,
      fillColor: "#ef4444",
      fillOpacity: 0.35,
    }).addTo(map);

    // Popup content is HTML, so every dynamic value must be escaped.
    const html =
      "<b>" + escapeHtml(row.ip) + "</b><br>" +
      escapeHtml(row.flag + " " + row.country + (row.city ? " · " + row.city : "")) + "<br>" +
      escapeHtml(row.hits) + " hits · worst " + escapeHtml(row.worst_severity) + "<br>" +
      "<span style='color:#8b9ab5'>" + escapeHtml(Object.keys(row.attack_types).join(", ")) + "</span>";

    marker.bindPopup(html);

    // Hover effect - small detail, big perceived quality difference.
    marker.on("mouseover", () => marker.setStyle({ fillOpacity: 0.7 }));
    marker.on("mouseout", () => marker.setStyle({ fillOpacity: 0.35 }));
  });
}

// ------------------------------------------------------------------
// 6. BOOT
// ------------------------------------------------------------------
// Each builder is independent; one failing must not stop the others.
[buildTimeline, buildTypes, buildCountries, buildMap].forEach((build) => {
  try {
    build();
  } catch (error) {
    console.error("Dashboard section failed:", build.name, error);
  }
});
