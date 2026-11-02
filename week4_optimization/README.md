# Week 4 — Optimization & Async (Scale)

> **Deadline goal:** "Implement Async Job Queue (if dealing with large files). Add 'Export Report' feature. Final Deployment."

This is the **final application**. Everything the brief asks for is here.

```powershell
cd week4_optimization
python app.py          # or: waitress-serve --listen=0.0.0.0:8000 app:app
```

Open <http://127.0.0.1:5004> → **Load demo log**.

---

## 1. What this week delivers

| PDF task | Where it lives |
|---|---|
| Async job queue | `jobs.py` → `JobStore` + `ThreadPoolExecutor` |
| Upload → Job ID → poll → report | `app.py` + `static/app.js` |
| Export report | `/export/<id>.json` and `/export/<id>.csv` |
| Streaming for large files | `parser.py` → `stream_lines()` / `iter_entries()` |
| Performance note | [`PERFORMANCE.md`](PERFORMANCE.md) |
| Deployment | [`DEPLOYMENT.md`](DEPLOYMENT.md) |
| Load demo log button | `templates/index.html` + `POST /demo` |

---

## 2. The async architecture

```
browser                     Flask                         worker thread
   |                           |                                |
   |-- POST /analyze --------->|                                |
   |   (multipart upload)      |-- STORE.submit(...) ---------->|
   |<-- 202 {job_id} ----------|                                |
   |                           |                                |-- stream file
   |-- GET /api/jobs/<id> ---->|  reads job dict under a lock   |-- 15 regexes
   |<-- {progress: 42} --------|                                |-- aggregate
   |          ...              |                                |-- GeoIP
   |-- GET /api/jobs/<id> ---->|                                |-- save JSON
   |<-- {status: "done"} ------|<-------------------------------|
   |-- GET /report/<id> ------>|  loads reports/<id>.json       |
```

Three rules that make it work:

1. **The POST never waits.** `submit()` returns an id in milliseconds. Analysis happens elsewhere.
2. **Polling is cheap.** `/api/jobs/<id>` returns ~15 fields, twice per second. That is nothing.
3. **Disk is the handoff.** The worker writes `reports/<id>.json`; the report page reads it. No shared memory needed between request and worker beyond the job dict.

### Why not just `async def`?

Flask's async views still block on CPU work unless you push it to a thread/process. Regex scanning is **CPU-bound**, so `asyncio` would only add complexity. A thread pool is the right tool; Celery is the right tool at larger scale.

### Thread safety in one paragraph

`JobStore` holds one `threading.Lock` and every read/write of the job dict happens inside it. Workers never touch Flask's request context (there is no request in a background thread — this is the #1 mistake people make). Any state a worker needs is passed in when `submit()` is called.

---

## 3. Streaming: the 20× memory win

| | Week 2 (`parse_file`) | Week 4 (`iter_entries`) |
|---|---:|---:|
| 3.4 MB file, peak RAM | 26.1 MB | **1.3 MB** |
| Time | 11.5 s | **2.9 s** |

Two changes produced that:

1. **Generators** — `stream_lines()` reads 256 KB at a time and keeps only the unfinished tail.
2. **Hand-parsed timestamps** — `strptime` was 68% of the runtime; a fixed-position parse + month dict replaced it.

Run the proof yourself:

```powershell
python ..\tools\make_large_log.py 300
python ..\tools\benchmark.py
```

Full explanation in [`PERFORMANCE.md`](PERFORMANCE.md).

---

## 4. Aggregation without a list

Week 2's `aggregate()` needed every entry in memory. Week 4 keeps counters instead:

```python
collector = StreamCollector()      # hour -> count, totals, errors
for entry in entries:
    collector.add(entry)           # O(1), entry is then discarded
report = collector.build(incidents, brute_force)
```

The report **shape is identical** to Week 3 — which is why `static/dashboard.js` did not change at all. Keeping the output contract stable while swapping the engine is the whole point.

---

## 5. Export

| Endpoint | Format | Use |
|---|---|---|
| `/export/<id>.json` | full report | re-import, API, archive |
| `/export/<id>.csv` | incidents + brute force | Excel, ticketing, SIEM import |

The CSV is built with Python's `csv` module, not string concatenation — payloads contain commas and quotes, so quoting is not optional. `lineterminator="\n"` avoids the classic blank-line-every-other-row problem in Excel.

---

## 6. Other things worth reading in this folder

| File | Why it is interesting |
|---|---|
| `jobs.py` | the queue itself; also shows `finally:` cleanup of uploaded files |
| `parser.py` | the chunk-boundary buffer — the heart of streaming |
| `aggregator.py` | `build_report()` as a pure function, `StreamCollector` as the incremental wrapper |
| `app.py` | 202 Accepted, `isalnum()` path-traversal guard, `send_file` attachment headers |
| `static/app.js` | XHR for upload progress vs `fetch` for polling — and why |
| `templates/job.html` | the no-JavaScript fallback (`meta refresh`) |

---

## 7. Checkpoint

- [ ] Upload returns immediately; the progress bar moves; report opens by itself
- [ ] `demo_logs/demo_attacks.log` gives **59 incidents, 35 malicious requests, 2 brute-force IPs**
- [ ] Export CSV has 59 incident rows and opens cleanly in Excel
- [ ] Restart the server → old report links still work (disk), but in-flight jobs are gone
- [ ] `python ..\tools\benchmark.py` shows the memory difference
- [ ] You can explain why `-w 1` is required in gunicorn
- [ ] `/healthz` returns `{"status":"ok"}`

---

## 8. Practice

- Add a **cancel** button: set `job["cancel"] = True` and check it inside the generator loop.
- Persist job status to SQLite so polling survives a restart.
- Add **pagination** to the incident table (currently capped at 100 rows).
- Add **rate limiting** per IP on `/analyze` (Flask-Limiter).
- Write a `pytest` suite: parser fixtures, a signature hit/miss table, and one end-to-end job test.

---

## 9. Final deliverable checklist (from the brief)

- [x] GitHub repository with parser module and `signatures.json`
- [x] Deployed application instructions (local + Render + Docker)
- [x] "Load Demo Log" button that populates the dashboard
- [x] Performance note explaining streaming vs loading
- [x] Timeline chart, GeoIP map, top attackers table
- [x] Async job queue with job id + status polling

Back to the [project README](../README.md) for the full tour.
