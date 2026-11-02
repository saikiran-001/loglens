# Week 3 — Visualization (The Dashboard)

> **Deadline goal:** "Build the Frontend charts. Integrate GeoIP lookup to map IP addresses to countries."

---

## 1. What this week delivers

| PDF task | Where it lives |
|---|---|
| Timeline chart (attacks per hour) | `static/dashboard.js` → `buildTimeline()` |
| GeoIP lookup | `geoip.py` → `GeoLookup.lookup()` |
| Geo map | `static/dashboard.js` → `buildMap()` (Leaflet) |
| Top attackers table | `templates/dashboard.html` |

```powershell
cd week3_visualization
python app.py          # port 5003
```

Open <http://127.0.0.1:5003> → **Load demo log**.

---

## 2. New flow: analyse, store, redirect

Week 2 rendered findings straight into the POST response. Week 3 does something slightly cleverer:

```
POST /analyze  →  run pipeline  →  save under a random id  →  302 /report/<id>
GET /report/<id>  →  look up the id  →  render dashboard
```

Why bother? Three reasons:

1. **Refresh-safe.** Pressing F5 on a rendered POST response would re-submit the file. A redirect turns the result into a plain GET.
2. **Shareable URL.** `/report/df4e3cb149` can be bookmarked or sent to a colleague.
3. **It is the shape Week 4 needs.** Jobs are also looked up by id — only there the id exists *before* the work finishes.

The store is a plain dict:

```python
REPORTS = {}                      # {report_id: report_dict}
REPORTS[report_id] = report
while len(REPORTS) > 20:          # keep memory bounded
    REPORTS.pop(next(iter(REPORTS)))
```

> ⚠️ This is **in-memory**. Restart the server and every report disappears. Run two workers and each has its own private dict. That limitation is deliberate — it makes Week 4's job store feel necessary instead of arbitrary.

---

## 3. Getting data from Python into JavaScript

You cannot just do `const data = {{ report }}` — Python's dict would print with single quotes and JavaScript would choke.

The reliable pattern is a **JSON data island**:

```html
<script id="report-data" type="application/json">{{ report | tojson }}</script>
```

```js
const REPORT = JSON.parse(document.getElementById("report-data").textContent);
```

Why `type="application/json"`? Because the browser does **not** execute it. It is inert data. If a malicious log path contained `</script><script>steal()</script>`, Flask's `tojson` filter escapes it (`\u003c/script\u003e`) and nothing breaks.

**Alternative:** `fetch('/api/report/<id>')` — also provided in `app.py`. Use that when the page must update without a reload (Week 4 does exactly this for job status).

---

## 4. The three charts

All three use **Chart.js** on a `<canvas>`.

### Timeline (`line`)

```js
datasets: [
  { label: "Attacks",       data: attackSeries,  borderColor: "#ef4444", fill: true },
  { label: "All requests",  data: requestSeries, borderColor: "#38bdf8", yAxisID: "y1" },
]
```

- Two **y axes** because request volume is usually 10–100× the attack volume. On one axis the attack line would be flat against zero.
- The x axis includes **hours with zero attacks** — otherwise the line would draw a misleading straight jump. That gap-filling happens in `aggregator.py`, not in JS.

### Attack types (`doughnut`)

One slice per `summary.by_type` key. `cutout: "62%"` makes a ring instead of a pie.

### Attacks by country (`bar`, horizontal)

`indexAxis: "y"` makes the bars horizontal, which is far more readable for names like "Netherlands".

---

## 5. GeoIP: the honest version

`geoip.py` has **two backends**:

| Backend | When it is used | Accuracy |
|---|---|---|
| MaxMind `GeoLite2-City.mmdb` | file exists in `data/` | City-level (the real thing) |
| `DEMO_GEO` dict | no file / no library | 9 hardcoded IPs, enough for the demo |

To enable the real backend:

1. Create a free MaxMind account → download **GeoLite2-City** (`.mmdb`).
2. Drop it at `week3_visualization/data/GeoLite2-City.mmdb`.
3. `python -m pip install maxminddb`
4. Restart. The console prints `GeoIP: using MaxMind database ...`

### The gotcha I hit (and you will too)

Python's `ipaddress` module reports documentation ranges like `203.0.113.0/24` as **not public**. The demo attackers live in those ranges, so a naive `if address.is_private: return "LAN"` labelled half the attackers as "Private network".

The fix in `lookup()` is ordering: check the **known demo table first**, then fall back to the private-range check. This is a real lesson: *a correct result in the wrong order is still wrong.*

### Private IPs and the map

`192.168.x.x` has no coordinates, so `buildMap()` filters rows where `lat`/`lon` are `null`. They still appear in the **country table** as 🏠 Private network — accurate and useful (that is your own LAN, not a threat source).

---

## 6. Leaflet, in six lines

```js
const map = L.map("attackMap").setView([20, 10], 2);   // centre + zoom
L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  attribution: "&copy; OpenStreetMap contributors"      // REQUIRED by OSM's terms
}).addTo(map);
L.circleMarker([lat, lon], { radius: 6 + Math.min(hits, 30) }).addTo(map);
```

- `radius` grows with attack count but is capped, so one noisy IP cannot paint over a continent.
- Markers use `circleMarker` (vector) rather than image icons — no assets to download.

### XSS in your own dashboard

The popup is HTML. If a log contains a path like `<img src=x onerror=alert(1)>` and you do `popup = "<b>" + ip + "</b>"`, **your security tool just became the vulnerability**.

Hence `escapeHtml()` in `dashboard.js`, applied to every dynamic value. Security tools are held to a higher standard than normal apps — never render untrusted log content as HTML.

---

## 7. Graceful degradation

Every chart function starts with a guard:

```js
if (typeof Chart === "undefined") {
  emptyState("timelineChart", "Chart.js could not load...");
  return;
}
```

If you are offline, the CDN scripts fail. Without these guards you would get blank boxes and a console full of errors; with them the user sees an explanation and all the tables still work. **A dashboard that fails loudly and usefully beats one that fails silently.**

---

## 8. Files

```
week3_visualization/
├── app.py                     routes, in-memory report store
├── parser.py                  (unchanged from Week 2)
├── detector.py                (unchanged from Week 2)
├── aggregator.py              (unchanged from Week 2)
├── signatures.json            (unchanged from Week 2)
├── geoip.py                   MaxMind + fallback + enrich_report()
├── data/                      put GeoLite2-City.mmdb here
├── templates/
│   ├── index.html             upload + recent reports
│   └── dashboard.html         charts, map, tables
└── static/
    ├── dashboard.js           all chart/map code
    └── style.css
```

---

## 9. Checkpoint

- [ ] Dashboard shows a red attack line peaking at **16:00** (brute force) and **03:00–05:00** (SQLi)
- [ ] Country chart lists 🇷🇺 Russia, 🇳🇱 Netherlands, 🇺🇸 United States, 🇨🇳 China, 🇮🇳 India
- [ ] Map has red circles in Moscow, Amsterdam, Ashburn, Beijing, Mumbai
- [ ] `/api/report/<id>` returns JSON in the browser
- [ ] Restarting the server makes old report links 404 — you can explain **why**
- [ ] You can explain why `escapeHtml()` is used inside a security dashboard

---

## 10. Practice

- Add a severity **stacked bar** per hour (critical/high/medium/low in one chart).
- Colour map markers by worst severity instead of always red.
- Replace the CDN links with local copies in `static/vendor/` so the demo works offline.
- Add `<a download>` to export the report as JSON (preview of Week 4's export).

---

**Next:** [`week4_optimization/README.md`](../week4_optimization/README.md) — streaming, job queue, export, deployment.
