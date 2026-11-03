# LogLens — Simplified Security Log Analysis

A SIEM-lite for sysadmins: upload an Apache/Nginx access log, get a dashboard showing **who attacked you, how, and when**.

Built as the four-week Persevex brief, **week by week, with a runnable app at the end of each week** and a comment on (almost) every line of code so you can learn from it.

```
Upload  →  parse  →  match 15 attack signatures  →  aggregate  →  timeline + map + tables
```

---

## Start here

```powershell
# 1. install dependencies (once)
python -m pip install -r requirements.txt

# 2. run the final app
cd week4_optimization
python app.py

# 3. open the browser
#    http://127.0.0.1:5004  →  click "Load demo log"
```

New to Python/Flask? Follow **[HOW_TO_RUN.md](HOW_TO_RUN.md)** — it assumes nothing and covers installation, virtual environments, ports and common errors.

---

## The four weeks

Each folder is a **complete, runnable snapshot** — you can open Week 3 without having run Week 1.

| Week | Goal | Folder | Port | Learn |
|---|---|---|---|---|
| **1** | Structure | [`week1_parsing/`](week1_parsing/README.md) | 5001 | regex named groups, multipart upload, `secure_filename`, generators |
| **2** | Identification | [`week2_detection/`](week2_detection/README.md) | 5002 | signature DB in JSON, URL decoding, severity ranking, aggregation |
| **3** | The dashboard | [`week3_visualization/`](week3_visualization/README.md) | 5003 | Chart.js, GeoIP, Leaflet, JSON data islands, XSS-safe rendering |
| **4** | Scale | [`week4_optimization/`](week4_optimization/README.md) | 5004 | streaming, profiling, thread pools, job polling, CSV export, deployment |

```powershell
cd week1_parsing      ; python app.py     # terminal 1
cd week2_detection    ; python app.py     # terminal 2
cd week3_visualization; python app.py     # terminal 3
cd week4_optimization ; python app.py     # terminal 4
```

The top navigation bar links all four, so you can compare the same log at each stage.

---

## What each week adds

### Week 1 — Parsing

```
192.168.1.15 - - [27/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"
        ↓  parse_line()
{"ip": "192.168.1.15", "method": "GET", "path": "/index.html", "status": 200, ...}
```

- Combined **and** Common Log Format support
- One bad line never kills the analysis (returns `None`, counted as an error)
- Upload API with extension allow-list, 32 MB cap, sanitised filenames

### Week 2 — Detection

15 signatures in [`signatures.json`](week2_detection/signatures.json):

| Type | Examples |
|---|---|
| `sql_injection` | `' OR 1=1`, `UNION SELECT`, `SLEEP(`, stacked `DROP TABLE` |
| `xss` | `<script>`, `onerror=`, `javascript:` |
| `path_traversal` | `../`, `/etc/passwd`, double-encoded `%252e` |
| `scanner` | sqlmap, nikto, nmap, gobuster in the User-Agent |
| `sensitive_file` | `.env`, `.git/config`, `wp-config.php` |
| `command_injection` | `; cat /etc/passwd`, `$(...)` |
| `exploit_attempt` | Log4Shell `${jndi:` |

Plus **brute force**: N failed `401/403` logins from one IP (threshold configurable in JSON and from the UI).

### Week 3 — Visualization

- **Timeline** — attacks vs total requests per hour, on two axes
- **Attack types** — doughnut
- **Country breakdown** — horizontal bar
- **World map** — Leaflet markers sized by attack count
- **Top attackers** — IP, country, city, hits, worst severity, techniques
- GeoIP uses MaxMind `GeoLite2-City.mmdb` when present, otherwise a built-in demo table (so it always runs)

### Week 4 — Scale

- **Streaming parser** — 1.3 MB peak RAM vs 26 MB for a 3.4 MB log (20×)
- **4× faster parsing** — hand-parsed timestamps instead of `strptime`
- **Async jobs** — `POST → job id → poll → report`
- **Export** — full JSON and incident CSV
- **Persistent reports** — `reports/<id>.json` survives restarts
- **Deployment** — Waitress/Gunicorn, Render, Docker ([guide](week4_optimization/DEPLOYMENT.md))
- **Performance note** — measured, with real numbers ([read it](week4_optimization/PERFORMANCE.md))

---

## Demo results

`demo_logs/demo_attacks.log` — 79 lines: 1 deliberately broken, 78 parsed, containing SQLi, XSS, traversal, brute force and scanner traffic from 7 IPs.

| Metric | Value |
|---|---:|
| Malicious requests | 35 |
| Signature incidents | 59 |
| Brute-force IPs | 2 (12 and 8 failed logins) |
| Countries | 6 (Russia, US, Netherlands, China, India, Germany) |
| Peak attack hour | 16:00 |

---

## Project layout

```
loglens/
├── README.md                  ← you are here
├── HOW_TO_RUN.md              ← beginner setup, ports, troubleshooting
├── requirements.txt
├── demo_logs/
│   └── demo_attacks.log       ← the "Load demo log" file
├── logs/
│   └── sample_access.log      ← original sample log
├── tools/
│   ├── make_demo_log.py       ← regenerates the demo log
│   ├── make_large_log.py      ← builds a big file for benchmarks
│   └── benchmark.py           ← list vs stream: time + peak memory
│
├── week1_parsing/             parser.py · app.py · templates/ · static/
├── week2_detection/           + signatures.json · detector.py · aggregator.py · cli.py
├── week3_visualization/       + geoip.py · dashboard.html · dashboard.js
└── week4_optimization/        + jobs.py · streaming parser · export · PERFORMANCE.md · DEPLOYMENT.md
```

### The command-line tools

```powershell
cd week2_detection
python cli.py ..\demo_logs\demo_attacks.log
python cli.py ..\demo_logs\demo_attacks.log -t 3 -o report.json
```

### Legacy scripts in the project root

`parser.py`, `detector.py`, `main.py` and `report.json` are the **original CLI** version written before the week folders. They still work:

```powershell
python main.py -f logs\sample_access.log
```

The week folders supersede them; they are kept so you can see the starting point and diff your progress.

---

## Design decisions worth knowing

| Decision | Why |
|---|---|
| Rules in **JSON**, not Python | analysts add signatures without a code change (as the brief requires) |
| **Decode before match** | `%27OR%271%27%3D%271` bypasses naive filters |
| **Streaming generators** | memory stays flat as files grow |
| **Counters, not lists** | aggregation needs totals, not every row |
| **Threads, not Celery** | zero setup, same architecture; swap later without touching the UI |
| **Reports on disk** | dashboard, JSON export and CSV export share one source of truth |
| **Report shape frozen after Week 2** | the frontend never had to be rewritten |
| **`escapeHtml()` in JS** | log content is hostile; a security tool must not become the XSS vector |

---

## Deliverables checklist (from the brief)

- [x] GitHub-ready repo with parser module and signature JSON
- [x] Deployed app instructions (Render / Docker / Waitress)
- [x] "Load Demo Log" button that populates the dashboard
- [x] Performance note: streaming vs loading, with measurements
- [x] Timeline (attacks/hour), GeoIP map, Top Attackers table
- [x] Async job queue: upload → job ID → poll → report
- [x] Export report (JSON + CSV)

---

## Where to go next

1. Read [`week1_parsing/README.md`](week1_parsing/README.md) and follow the code top-to-bottom.
2. Do one practice exercise per week (each README ends with a list).
3. Run `tools/benchmark.py` and explain the numbers in your own words — that is exactly what an interviewer will ask.
4. Deploy it, then write the one-paragraph performance note in your submission.

---

## Limitations (stated, not hidden)

- Job registry is **in memory** — restarting loses in-flight jobs (finished reports survive on disk).
- **Single-process** design — gunicorn must run `-w 1`.
- Brute-force window (`window_minutes`) is defined but only the threshold is enforced.
- No authentication or per-user quotas.
- The dashboard needs internet for Chart.js/Leaflet CDNs; all tables work offline.

These are deliberate scope choices for a four-week brief, and each has a clear upgrade path in [`week4_optimization/DEPLOYMENT.md`](week4_optimization/DEPLOYMENT.md).
